"""Detection engine: Presidio analyzer/anonymizer glued to TT labels.

Owns the Presidio <-> TT label mapping, span post-processing (DOB gating,
overlap dedupe) and the three output transforms (redact modes, reversible
anonymization, restore).
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from tt_pii_middleware.config import Settings
from tt_pii_middleware.recognizers import build_recognizers

SUPPORTED_LANGUAGES = ["pl", "en"]

# Presidio entity -> Thinking Typewriters label.
PRESIDIO_TO_TT = {
    "PERSON": "PERSON",
    "ORGANIZATION": "ORG",
    "PL_PESEL": "PESEL",
    "PL_NIP": "NIP",
    "PL_REGON": "REGON",
    "PL_KRS": "KRS",
    "PL_ID_CARD": "DOWOD",
    "PL_PASSPORT": "PASSPORT",
    "IBAN_CODE": "IBAN",
    "PHONE_NUMBER": "PHONE",
    "EMAIL_ADDRESS": "EMAIL",
    "PL_POSTAL_CODE": "POSTAL",
    "PL_ADDRESS": "ADDRESS",
    "LOCATION": "ADDRESS",  # spaCy place/geo names count as address parts
    "PL_DOB": "DOB",  # kept only with a birth keyword nearby, see below
    "DATE_TIME": "DOB",  # same gating applies to spaCy dates
    "CREDIT_CARD": "CARD",
    "PL_PLATE": "PLATE",
}

TT_LABELS = sorted(set(PRESIDIO_TO_TT.values()))

TT_TO_PRESIDIO: dict[str, list[str]] = {}
for _presidio, _tt in PRESIDIO_TO_TT.items():
    TT_TO_PRESIDIO.setdefault(_tt, []).append(_presidio)

# Looks back up to 48 chars for a birth keyword directly before a date span.
_BIRTH_CONTEXT = re.compile(
    r"(?:\bur\.?|\burodzon\w*|\burodzi[łl]\w*|\burodzeni[ae]"
    r"|\bborn\b|\bbirth\w*|\bd\.?o\.?b\.?)[\s:,.-]*$",
    re.IGNORECASE,
)
_BIRTH_WINDOW = 48

_TOKEN_RE = re.compile(r"\[[A-Z]+_\d{3,}\]")

_MASK_ALL = 1_000_000  # > any allowed text length, so the whole span is masked

# NER spans that are just the *name* of an identifier ("KRS 0000123456"
# tends to get "KRS" tagged as an organization) carry no PII themselves.
_NER_KEYWORD_DENYLIST = {"PESEL", "NIP", "REGON", "KRS", "IBAN", "VAT", "DOWÓD", "DOWOD"}

# When two checksum/pattern labels claim the same digits, prefer the one whose
# keyword appears in a short window before the span (KRS vs NIP, REGON vs CARD).
_CONTEXT_HINTS: dict[str, tuple[str, ...]] = {
    "KRS": ("krs",),
    "NIP": ("nip", "vat", "podatkowy"),
    "REGON": ("regon",),
    "CARD": ("karta", "card", "credit", "płatnicza", "platnicza", "visa", "mastercard"),
    "PESEL": ("pesel",),
    "IBAN": ("iban", "konto", "rachunek", "account", "przelew"),
    "POSTAL": ("kod pocztowy", "pocztowy", "adres", "ul.", "ulica", "al.", "os.", "zamieszka"),
    "PLATE": ("tablica", "rejestracyjn", "pojazd", "samochód", "auto", "rej."),
}
_CONTEXT_WINDOW = 48

# spaCy LOCATION/PERSON often latches onto IBAN/PESEL-shaped tokens; drop those.
_ID_SHAPED = re.compile(
    r"^(?:"
    r"PL\d{2}\d{24}"  # IBAN compact
    r"|\d{11}"  # PESEL
    r"|\d{10}"  # NIP / KRS
    r"|\d{9}(?:\d{5})?"  # REGON 9/14
    r"|[A-Z]{3}\d{6}"  # DOWOD
    r")$",
    re.IGNORECASE,
)


@dataclass
class Span:
    start: int
    end: int
    label: str
    score: float
    text: str
    # "pattern" (regex/checksum recognizers) or "ner" (spaCy). Internal only:
    # pattern spans win overlap resolution because checksummed identifiers
    # are far more precise than statistical NER.
    source: str = "pattern"

    def to_dict(self, include_text: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "score": self.score,
        }
        if include_text:
            d["text"] = self.text
        return d


def _has_birth_context(text: str, start: int) -> bool:
    window = text[max(0, start - _BIRTH_WINDOW) : start]
    return _BIRTH_CONTEXT.search(window) is not None


def _has_label_context(text: str, start: int, label: str) -> bool:
    hints = _CONTEXT_HINTS.get(label)
    if not hints:
        return False
    window = text[max(0, start - _CONTEXT_WINDOW) : start].lower()
    return any(h in window for h in hints)


def _context_boost(text: str, start: int, label: str) -> float:
    """Return a small score bump when a label-specific keyword precedes the span."""
    return 0.25 if _has_label_context(text, start, label) else 0.0


# "00-950 Warszawa" — city name right after a postal code is strong evidence.
_POSTAL_CITY_AFTER = re.compile(r"^\s+[A-ZĄĆĘŁŃÓŚŹŻ][A-Za-ząćęłńóśźżĄĆĘŁŃÓŚŹŻ-]{1,}")


def _postal_city_boost(text: str, end: int) -> float:
    return 0.25 if _POSTAL_CITY_AFTER.match(text[end : end + 40]) else 0.0


def _dedupe(spans: list[Span]) -> list[Span]:
    """Resolve overlaps: pattern beats NER, then higher score, longer span."""
    ordered = sorted(
        spans, key=lambda s: (s.source == "ner", -s.score, s.start - s.end, s.start)
    )
    kept: list[Span] = []
    for span in ordered:
        if all(span.end <= k.start or span.start >= k.end for k in kept):
            kept.append(span)
    return sorted(kept, key=lambda s: (s.start, s.end))


def build_nlp_engine(settings: Settings):
    return NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "pl", "model_name": settings.spacy_model},
                {"lang_code": "en", "model_name": settings.spacy_model_en},
            ],
            "ner_model_configuration": {
                "model_to_presidio_entity_mapping": {
                    # pl_core_news_* label scheme
                    "persName": "PERSON",
                    "orgName": "ORGANIZATION",
                    "placeName": "LOCATION",
                    "geogName": "LOCATION",
                    "date": "DATE_TIME",
                    # en_core_web_* label scheme
                    "PERSON": "PERSON",
                    "ORG": "ORGANIZATION",
                    "GPE": "LOCATION",
                    "LOC": "LOCATION",
                    "FAC": "LOCATION",
                    "DATE": "DATE_TIME",
                },
                "labels_to_ignore": [
                    "time", "TIME", "CARDINAL", "ORDINAL", "QUANTITY", "MONEY",
                    "PERCENT", "LANGUAGE", "LAW", "WORK_OF_ART", "EVENT",
                    "PRODUCT", "NORP",
                ],
                "low_confidence_score_multiplier": 0.4,
                "low_score_entity_names": [],
            },
        }
    ).create_engine()


def build_analyzer(settings: Settings) -> AnalyzerEngine:
    registry = RecognizerRegistry(supported_languages=SUPPORTED_LANGUAGES)
    for language in SUPPORTED_LANGUAGES:
        for recognizer in build_recognizers(language, settings):
            registry.add_recognizer(recognizer)
    return AnalyzerEngine(
        nlp_engine=build_nlp_engine(settings),
        registry=registry,
        supported_languages=SUPPORTED_LANGUAGES,
        default_score_threshold=0.0,  # thresholding happens after DOB gating
    )


class PiiEngine:
    """One instance per process; safe to share across requests."""

    def __init__(self, settings: Settings, pseudonymizer=None) -> None:
        self.settings = settings
        self.analyzer = build_analyzer(settings)
        self.anonymizer = AnonymizerEngine()
        self.pseudonymizer = pseudonymizer

    # -- introspection (for /health) ------------------------------------

    def info(self) -> dict[str, Any]:
        recognizer_names = sorted(
            {r.name for r in self.analyzer.registry.recognizers}
        )
        out: dict[str, Any] = {
            "languages": SUPPORTED_LANGUAGES,
            "models": {
                "pl": self.settings.spacy_model,
                "en": self.settings.spacy_model_en,
            },
            "recognizers": recognizer_names,
            "labels": TT_LABELS,
        }
        store = getattr(getattr(self, "pseudonymizer", None), "store", None)
        if store is not None:
            out["pseudonym"] = store.health()
        else:
            out["pseudonym"] = {"enabled": False}
        return out

    # -- detection -------------------------------------------------------

    def analyze(
        self,
        text: str,
        language: str | None = None,
        labels: list[str] | None = None,
        threshold: float | None = None,
    ) -> list[Span]:
        language = language or self.settings.default_language
        threshold = self.settings.score_threshold if threshold is None else threshold
        entities = None
        if labels:
            entities = sorted({e for label in labels for e in TT_TO_PRESIDIO[label]})

        raw = self.analyzer.analyze(
            text=text, language=language, entities=entities, score_threshold=0.0
        )
        spans: list[Span] = []
        for result in raw:
            tt_label = PRESIDIO_TO_TT.get(result.entity_type)
            if tt_label is None:
                continue
            metadata = result.recognition_metadata or {}
            source = (
                "ner"
                if metadata.get(RecognizerResult.RECOGNIZER_NAME_KEY) == "SpacyRecognizer"
                else "pattern"
            )
            span_text = text[result.start : result.end]
            stripped = span_text.strip(" .,:;")
            if source == "ner" and stripped.upper() in _NER_KEYWORD_DENYLIST:
                continue
            # Drop NER spans that are clearly identifier-shaped (IBAN/PESEL/…).
            if source == "ner" and _ID_SHAPED.match(stripped.replace(" ", "")):
                continue
            score = result.score
            if tt_label == "DOB":
                if not _has_birth_context(text, result.start):
                    continue
                score = max(score, 0.6)
            # Keyword context disambiguates colliding 10/14-digit identifiers
            # (KRS↔NIP, REGON↔CARD) before overlap resolution.
            has_ctx = _has_label_context(text, result.start, tt_label)
            score = min(score + (0.25 if has_ctx else 0.0), 1.0)
            if tt_label == "POSTAL":
                score = min(score + _postal_city_boost(text, result.end), 1.0)
                # "kod produktu" / bare ranges: keep only with real address evidence
                if not has_ctx and _postal_city_boost(text, result.end) == 0.0:
                    # still allow if street prefix appears a bit further back
                    back = text[max(0, result.start - 80) : result.start].lower()
                    if not any(tok in back for tok in ("ul.", "ulica", "al.", "os.", "adres", "poczt")):
                        continue
            # Continuous 13-16 digit runs without card context are usually REGON/other IDs
            if tt_label == "CARD":
                compact = span_text.replace(" ", "").replace("-", "")
                if (" " not in span_text and "-" not in span_text) and not has_ctx:
                    continue
                if len(compact) == 14 and _has_label_context(text, result.start, "REGON"):
                    continue
            # Bare checksum-valid NIP/REGON without keyword: keep score but do not
            # invent them from random digit runs in noise — require context OR
            # hyphenated/formatted form (invoices write "NIP: …").
            if tt_label in {"NIP", "REGON"} and not has_ctx:
                # Hyphenated NIP (xxx-xxx-xx-xx) is distinctive enough.
                if tt_label == "NIP" and "-" in span_text:
                    pass
                else:
                    continue
            if score < threshold:
                continue
            spans.append(
                Span(
                    start=result.start,
                    end=result.end,
                    label=tt_label,
                    score=round(min(score, 1.0), 4),
                    text=span_text,
                    source=source,
                )
            )
        return _dedupe(spans)

    # -- transforms --------------------------------------------------------

    def redact(
        self,
        text: str,
        mode: str = "replace",
        language: str | None = None,
        labels: list[str] | None = None,
        threshold: float | None = None,
        *,
        profile: str | None = None,
        purpose: str | None = None,
        tenant_id: str | None = None,
        key_id: str | None = None,
        token_bytes: int | None = None,
        strict_pseudonym: bool = False,
        pseudonymizer=None,
    ) -> tuple[str, list[Span], dict]:
        """Redact or pseudonymise.

        Returns ``(text, spans, meta)`` where meta carries privacy/profile stats
        (empty for legacy replace/mask/hash).
        """
        from tt_pii_middleware.pseudo.profiles import Profile, resolve_profile
        from tt_pii_middleware.pseudo.pseudonymizer import Pseudonymizer

        resolved = resolve_profile(profile, mode)
        spans = self.analyze(text, language=language, labels=labels, threshold=threshold)

        if resolved in {Profile.LINKABLE, Profile.LINKABLE_STRICT}:
            engine = pseudonymizer or getattr(self, "pseudonymizer", None)
            if engine is None:
                engine = Pseudonymizer(None)
            result = engine.apply(
                text,
                spans,
                profile=resolved,
                purpose=purpose or self.settings.default_pseudonym_purpose,
                tenant_id=tenant_id or "_",
                key_id=key_id,
                token_bytes=token_bytes or self.settings.default_token_bytes,
                strict_pseudonym=strict_pseudonym,
            )
            meta = {
                "profile": result.profile,
                "purpose": result.purpose,
                "key_id": result.key_id,
                "privacy": result.privacy,
                "stats": result.stats,
            }
            return result.text, result.spans, meta

        results = [
            RecognizerResult(entity_type=s.label, start=s.start, end=s.end, score=s.score)
            for s in spans
        ]
        if resolved == Profile.MASK or mode == "mask":
            operators = {
                "DEFAULT": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": _MASK_ALL, "from_end": False},
                )
            }
            legacy_mode = "mask"
        elif resolved == Profile.HASH or mode == "hash":
            operators = {"DEFAULT": OperatorConfig("custom", {"lambda": self._hash_value})}
            legacy_mode = "hash"
        else:
            operators = {
                label: OperatorConfig("replace", {"new_value": f"<{label}>"})
                for label in TT_LABELS
            }
            legacy_mode = "replace"

        redacted = self.anonymizer.anonymize(
            text=text, analyzer_results=results, operators=operators
        )
        meta = {
            "profile": resolved.value,
            "privacy": {
                "classification": (
                    "pseudonymised_personal_data"
                    if legacy_mode == "hash"
                    else "redacted"
                ),
                "linkable": legacy_mode == "hash",
                "reversible": False,
                "algorithm": "SHA256-salt-truncated" if legacy_mode == "hash" else legacy_mode,
                "deprecated_hash": legacy_mode == "hash",
            },
            "stats": {},
        }
        return redacted.text, spans, meta

    def _hash_value(self, value: str) -> str:
        digest = hashlib.sha256(
            (self.settings.hash_salt + value).encode("utf-8")
        ).hexdigest()
        return digest[:16]

    def anonymize(
        self,
        text: str,
        language: str | None = None,
        labels: list[str] | None = None,
        threshold: float | None = None,
    ) -> tuple[str, list[Span], dict[str, str]]:
        """Reversible pseudonymization with ``[LABEL_NNN]`` tokens.

        The same (label, value) pair always maps to the same token within a
        request, so co-reference survives the round trip. The mapping is
        request-scoped: it is returned to the caller (and optionally parked
        in Redis under a short TTL) but never persisted by this service.
        """
        spans = self.analyze(text, language=language, labels=labels, threshold=threshold)
        mapping: dict[str, str] = {}
        token_for_value: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = {}
        parts: list[str] = []
        cursor = 0
        for span in spans:  # already sorted, non-overlapping
            key = (span.label, span.text)
            token = token_for_value.get(key)
            if token is None:
                counters[span.label] = counters.get(span.label, 0) + 1
                token = f"[{span.label}_{counters[span.label]:03d}]"
                token_for_value[key] = token
                mapping[token] = span.text
            parts.append(text[cursor : span.start])
            parts.append(token)
            cursor = span.end
        parts.append(text[cursor:])
        return "".join(parts), spans, mapping

    @staticmethod
    def restore(text: str, mapping: dict[str, str]) -> str:
        """Replace ``[LABEL_NNN]`` tokens with their original values."""
        return _TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)
