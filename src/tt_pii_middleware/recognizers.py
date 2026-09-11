"""Recognizer assembly for the TT PII stack.

Three layers, all self-hosted (no SaaS DLP in the path):

1. ``pii-presidio`` / ``pii-core``: checksum-validated Polish identifiers
   (PESEL, NIP, REGON, PL IBAN) plus Luhn-validated credit cards, e-mail and
   the regex-only passport detector, wrapped as Presidio ``PatternRecognizer``s.
2. Presidio built-ins: multi-country IBAN (mod-97), spaCy NER
   (PERSON / ORG / LOCATION / dates).
3. Custom recognizers closing the gaps found in the 3k-doc eval:
   checksum-validated DOWOD (pii-core's is regex-only -> 100% FP on
   lookalikes), broader Polish phone formats, vehicle PLATE, postal code,
   street ADDRESS, DOB date shapes, and context-gated opt-in KRS.
"""

import regex

from pii_core import (
    CreditCardDetector,
    EmailDetector,
    PlIbanDetector,
    PlNipDetector,
    PlPassportDetector,
    PlPeselDetector,
    PlRegonDetector,
)
from pii_presidio import PiiCoreRecognizer
from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer.predefined_recognizers import IbanRecognizer, SpacyRecognizer

from tt_pii_middleware.config import Settings

# Case-sensitive matching for identifiers that are uppercase by spec
# (Presidio's default flags include IGNORECASE, which would triple the FP
# rate on plates / ID-card serials appearing lowercase in ordinary words).
_CASE_SENSITIVE = regex.MULTILINE | regex.DOTALL

# --------------------------------------------------------------------------
# DOWOD (Polish ID card, "dowód osobisty"): 3 letters + 6 digits where the
# first digit is a check digit over the remaining 8 characters.
# Letters map to 10..35 (A..Z); weights are the official 7-3-1 cycle.
# --------------------------------------------------------------------------
_DOWOD_WEIGHTS = (7, 3, 1, 0, 7, 3, 1, 7, 3)  # position 4 is the check digit


def _char_value(ch: str) -> int:
    return int(ch) if ch.isdigit() else ord(ch) - ord("A") + 10


def is_valid_dowod(candidate: str) -> bool:
    """Validate a Polish ID-card number (e.g. ``ABA300000``)."""
    c = candidate.replace(" ", "").upper()
    if len(c) != 9 or not c[:3].isalpha() or not c[3:].isdigit():
        return False
    checksum = sum(w * _char_value(ch) for w, ch in zip(_DOWOD_WEIGHTS, c)) % 10
    return checksum == int(c[3])


class DowodRecognizer(PatternRecognizer):
    """Checksum-validated Polish ID card. Valid checksum -> score 1.0,
    invalid -> dropped, which removes the regex-lookalike FPs seen in eval."""

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PL_ID_CARD",
            name="DowodRecognizer",
            supported_language=supported_language,
            patterns=[Pattern("pl_dowod", r"\b[A-Z]{3} ?\d{6}\b", 0.5)],
            context=["dowód", "dowod", "osobisty", "seria", "tożsamości"],
            global_regex_flags=_CASE_SENSITIVE,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return is_valid_dowod(pattern_text)


class PlPhoneRecognizer(PatternRecognizer):
    """Polish phone formats from the eval gap list.

    ``+48``-prefixed numbers score high on their own; separator-grouped
    national formats score 0.5; a bare 9-digit run scores 0.3 and only
    crosses the default 0.4 threshold with nearby context ("tel", ...).
    """

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PHONE_NUMBER",
            name="PlPhoneRecognizer",
            supported_language=supported_language,
            patterns=[
                # +48 601 234 567 / +48601234567 / +48 22 123 45 67
                Pattern(
                    "pl_phone_intl",
                    r"(?<!\w)\+48[ -]?(?:\d{3}[ -]?\d{3}[ -]?\d{3}"
                    r"|\d{2}[ -]?\d{3}[ -]?\d{2}[ -]?\d{2})(?!\d)",
                    0.75,
                ),
                # 601 234 567 (mobile grouping XXX XXX XXX)
                Pattern(
                    "pl_phone_mobile_grouped",
                    r"(?<!\d)(?<!\d[ -])\d{3}[ -]\d{3}[ -]\d{3}(?![ -]?\d)",
                    0.5,
                ),
                # 22 123 45 67 (landline grouping XX XXX XX XX)
                Pattern(
                    "pl_phone_landline_grouped",
                    r"(?<!\d)(?<!\d[ -])\d{2}[ -]\d{3}[ -]\d{2}[ -]\d{2}(?![ -]?\d)",
                    0.5,
                ),
                # 601234567 -- too ambiguous alone, needs context boost
                Pattern("pl_phone_bare", r"(?<![\d+])\d{9}(?!\d)", 0.3),
            ],
            context=["tel", "telefon", "kom", "komórka", "phone", "mobile", "fax", "kontakt", "dzwoń"],
        )


# Standards / catalogue codes that share the plate letter shape and must never
# be reported as vehicle plates (synthetic eval + real invoices).
# Only block prefixes that are *not* real PL district codes. Two-letter
# denylist entries like PO/WO/TO/FA would false-negative real plates
# (Poznań, Warszawa-ochota, Toruń, …). Bare standards codes ("PN 12345")
# stay under threshold via base score 0.3 + missing vehicle context.
_PLATE_PREFIX_DENYLIST = {
    "ISO", "DIN", "IEC", "AST", "ANSI", "SKU", "VAT", "NIP", "REG", "KRS",
    "REF", "UE", "UN", "ID",
}


def _plate_prefix_denied(pattern_text: str) -> bool:
    compact = pattern_text.replace(" ", "")
    return compact[:2] in _PLATE_PREFIX_DENYLIST or compact[:3] in _PLATE_PREFIX_DENYLIST


class PlPlateRecognizer(PatternRecognizer):
    """Polish vehicle registration plates, e.g. ``WW 12345``, ``KR 1A234``.

    FP risk (documented): the shape "2-3 uppercase letters + 4-5
    alphanumerics" collides with standard references ("PN 12345"),
    invoice/serial numbers and similar codes. Mitigations: voivodeship
    first letter, plate-legal suffix alphabet, case-sensitive match,
    denylist of standards prefixes (PN/EN/ISO/...), and base score 0.3 so
    bare plates need context ("tablica", "rej.", ...) to cross 0.4.

    Note: we deliberately do **not** implement validate_result — Presidio
    promotes any True validation to score 1.0, which would defeat the
    context gate. Denylist drops happen in analyze instead.
    """

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PL_PLATE",
            name="PlPlateRecognizer",
            supported_language=supported_language,
            patterns=[
                Pattern(
                    "pl_plate",
                    r"\b[BCDEFGKLNOPRSTWZ][A-PR-Z]{1,2} ?"
                    r"(?=[0-9ACEFGHJKLMNPRSTUVWXY]{0,4}\d)"
                    r"[0-9ACEFGHJKLMNPRSTUVWXY]{4,5}\b",
                    0.3,
                )
            ],
            context=[
                "rejestracyjny", "rejestracyjne", "tablica", "tablice",
                "pojazd", "samochód", "auto", "rej", "rej.", "nr rej",
            ],
            global_regex_flags=_CASE_SENSITIVE,
        )

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):  # noqa: ANN001
        results = super().analyze(
            text, entities, nlp_artifacts=nlp_artifacts, regex_flags=regex_flags
        )
        kept = []
        for result in results:
            candidate = text[result.start : result.end]
            if _plate_prefix_denied(candidate):
                continue
            kept.append(result)
        return kept


class PlPostalCodeRecognizer(PatternRecognizer):
    """Polish postal code ``XX-XXX``.

    FP risk: numeric ranges ("10-100"). Base score 0.3 stays under the
    default 0.4 threshold unless address/postal context is nearby; the
    common templates always provide that context ("adres:", city name).
    """

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PL_POSTAL_CODE",
            name="PlPostalCodeRecognizer",
            supported_language=supported_language,
            patterns=[Pattern("pl_postal_code", r"\b\d{2}-\d{3}\b", 0.3)],
            context=[
                "pocztowy", "adres", "ul", "ul.", "ulica", "al.", "os.",
                "mieszka", "zamieszkania", "korespondencji", "zamieszkały",
                "zamieszkała",
            ],
        )


class PlKrsRecognizer(PatternRecognizer):
    """KRS court-register number: 10 digits, **no checksum** -> matches any
    10-digit run (including valid NIPs). Context-gated: base score 0.1 stays
    under the default 0.4 threshold and only Presidio's context enhancer
    (the word "KRS" nearby) lifts it above. Registered only when
    ``ENABLE_KRS=true``.
    """

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PL_KRS",
            name="PlKrsRecognizer",
            supported_language=supported_language,
            patterns=[Pattern("pl_krs", r"(?<!\d)\d{10}(?!\d)", 0.1)],
            context=["krs"],
        )


class PlAddressRecognizer(PatternRecognizer):
    """Street-level addresses introduced by ul./ulica/al./aleja/os./pl.

    Eval showed ADDRESS exact-match ~0 for pure NER; this pattern catches
    the common "ul. Marszałkowska 1/5" shape. City/region names still come
    from spaCy NER (LOCATION -> ADDRESS). Streets starting with a number
    ("ul. 3 Maja 5") are a known gap.
    """

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PL_ADDRESS",
            name="PlAddressRecognizer",
            supported_language=supported_language,
            patterns=[
                Pattern(
                    "pl_street_address",
                    r"\b(?:[Uu]l\.|[Uu]lica|[Aa]l\.|[Aa]leja|[Oo]s\.|[Oo]siedle|[Pp]l\.|[Pp]lac)"
                    r"\s+\p{Lu}[\p{L}0-9. -]{1,40}?"
                    r"\s*\d{1,4}[A-Za-z]?(?:\s?/\s?\d{1,4}[A-Za-z]?)?\b",
                    0.6,
                )
            ],
            context=["adres", "zamieszkania", "korespondencji", "mieszka"],
            global_regex_flags=_CASE_SENSITIVE,
        )


class PlDobRecognizer(PatternRecognizer):
    """Numeric date shapes as DOB candidates.

    Base score 0.2 keeps them below the threshold; ``analyzer.py``
    relabels/boosts them (and spaCy DATE_TIME spans) to DOB only when a
    birth keyword ("ur.", "urodzony", "data urodzenia", "born", ...)
    precedes the span, and drops them otherwise.
    """

    def __init__(self, supported_language: str) -> None:
        super().__init__(
            supported_entity="PL_DOB",
            name="PlDobRecognizer",
            supported_language=supported_language,
            patterns=[
                Pattern("dob_dmy", r"\b\d{1,2}[./-]\d{1,2}[./-]\d{4}\b", 0.2),
                Pattern("dob_iso", r"\b\d{4}-\d{2}-\d{2}\b", 0.2),
            ],
        )


# (detector factory, base score, context words) for the pii-core detectors we
# keep. Checksum-backed detectors get score 1.0 on valid checksums via
# PiiCoreRecognizer.validate_result regardless of the base score. Excluded on
# purpose: PlIdCardDetector + PlPhoneDetector (replaced by the customs above)
# and the KRS/postal opt-ins (replaced by the gated customs above).
# EmailDetector is used instead of Presidio's built-in EmailRecognizer because
# the built-in validates through tldextract, which downloads the public suffix
# list at runtime -- forbidden egress inside the VPC (and it stalls requests
# when the download can't complete).
_PII_CORE_SPECS = [
    (PlPeselDetector, 0.85, ["pesel"]),
    (PlNipDetector, 0.85, ["nip", "podatkowy", "vat"]),
    (PlRegonDetector, 0.85, ["regon"]),
    (PlIbanDetector, 0.85, ["iban", "konto", "rachunek", "account"]),
    (PlPassportDetector, 0.4, ["paszport", "passport", "seria"]),
    (CreditCardDetector, 0.85, ["karta", "card", "credit", "płatnicza"]),
    (EmailDetector, 0.6, ["email", "e-mail", "mail", "kontakt"]),
]

# Entities SpacyRecognizer should surface (NRP et al. are ignored).
_SPACY_ENTITIES = ["PERSON", "ORGANIZATION", "LOCATION", "DATE_TIME"]



class PlOrgRecognizer(PatternRecognizer):
    """Polish company legal forms: Sp. z o.o., S.A., sp.j., etc.

    spaCy ORG recall on synthetic company names is near-zero; this pattern
    catches the legal-form tail so invoice/CRM templates get an ORG span.
    """

    def __init__(self, supported_language: str) -> None:
        name_char = r"[\p{L}0-9&.'\-]"
        company = (
            rf"\b\p{{Lu}}{name_char}{{1,40}}?"
            rf"(?:\s+\p{{Lu}}{name_char}{{1,30}}){{0,4}}"
            r"\s+(?:Sp(?:ólka|\.)\s+z\s*o\.?\s*o\.?"
            r"|S\.?A\.?"
            r"|sp\.?\s*j\.?"
            r"|sp\.?\s*k\.?"
            r"|Sp\.\s*k\.)"
        )
        super().__init__(
            supported_entity="ORGANIZATION",
            name="PlOrgRecognizer",
            supported_language=supported_language,
            patterns=[Pattern("pl_company_legal_form", company, 0.7)],
            context=["firma", "sprzedawca", "nabywca", "spółka", "company", "regon", "nip"],
            global_regex_flags=_CASE_SENSITIVE,
        )


def build_recognizers(language: str, settings: Settings) -> list[PatternRecognizer | SpacyRecognizer]:
    """All recognizers for one language, ready for a RecognizerRegistry."""
    recognizers: list[PatternRecognizer | SpacyRecognizer] = [
        PiiCoreRecognizer(det(), supported_language=language, score=score, context=ctx)
        for det, score, ctx in _PII_CORE_SPECS
    ]
    recognizers += [
        DowodRecognizer(language),
        PlPhoneRecognizer(language),
        PlPlateRecognizer(language),
        PlPostalCodeRecognizer(language),
        PlAddressRecognizer(language),
        PlDobRecognizer(language),
        PlOrgRecognizer(language),
        IbanRecognizer(supported_language=language, context=["iban", "konto", "rachunek", "account", "bank"]),
        SpacyRecognizer(supported_language=language, supported_entities=list(_SPACY_ENTITIES)),
    ]
    if settings.enable_krs:
        recognizers.append(PlKrsRecognizer(language))
    return recognizers
