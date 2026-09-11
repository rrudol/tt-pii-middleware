"""Apply HMAC linkable tokens to analyzed spans."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from tt_pii_middleware.analyzer import Span
from tt_pii_middleware.pseudo.canonical import CHECKSUM_LIKE_LABELS, canonicalize
from tt_pii_middleware.pseudo.kdf import mac_message
from tt_pii_middleware.pseudo.keystore import KeystoreError, MasterKeyStore
from tt_pii_middleware.pseudo.profiles import Profile
from tt_pii_middleware.pseudo.tokens import DEFAULT_TOKEN_BYTES, format_token, looks_like_token


@dataclass
class PseudonymResult:
    text: str
    spans: list[Span]  # spans with .text replaced by token where applied
    stats: dict = field(default_factory=dict)
    privacy: dict = field(default_factory=dict)
    key_id: str = ""
    purpose: str = ""
    profile: str = ""


class Pseudonymizer:
    def __init__(self, store: MasterKeyStore | None) -> None:
        self.store = store

    def apply(
        self,
        text: str,
        spans: list[Span],
        *,
        profile: Profile,
        purpose: str = "default",
        tenant_id: str = "_",
        key_id: str | None = None,
        token_bytes: int = DEFAULT_TOKEN_BYTES,
        strict_pseudonym: bool = False,
    ) -> PseudonymResult:
        if profile in {Profile.LINKABLE, Profile.LINKABLE_STRICT}:
            if self.store is None:
                raise KeystoreError(
                    "linkable profile requires PSEUDONYM_MASTER_KEY_FILE "
                    "or PSEUDONYM_MASTER_KEY_B64 (fail closed)"
                )
            kid = key_id or self.store.active_kid
            return self._linkable(
                text,
                spans,
                profile=profile,
                purpose=purpose,
                tenant_id=tenant_id,
                kid=kid,
                token_bytes=token_bytes,
                strict_pseudonym=strict_pseudonym,
            )
        raise ValueError(f"Pseudonymizer does not handle profile {profile}")

    def _linkable(
        self,
        text: str,
        spans: list[Span],
        *,
        profile: Profile,
        purpose: str,
        tenant_id: str,
        kid: str,
        token_bytes: int,
        strict_pseudonym: bool,
    ) -> PseudonymResult:
        assert self.store is not None
        purpose_key = self.store.derive(kid, purpose, tenant_id)
        parts: list[str] = []
        cursor = 0
        out_spans: list[Span] = []
        pseudo_n = 0
        fallback_n = 0
        by_label: dict[str, int] = {}

        for span in spans:
            parts.append(text[cursor : span.start])
            raw = span.text
            # Already tokenised — leave as-is (idempotent).
            if looks_like_token(raw):
                token = raw.strip()
                parts.append(token)
                out_spans.append(
                    Span(span.start, span.start + len(token), span.label, span.score, token, span.source)
                )
                cursor = span.end
                continue

            use_hmac = True
            if profile == Profile.LINKABLE_STRICT and span.label not in CHECKSUM_LIKE_LABELS:
                use_hmac = False

            token: str
            if use_hmac:
                can = canonicalize(span.label, raw)
                if can is None:
                    if strict_pseudonym:
                        raise KeystoreError(
                            f"cannot canonicalize {span.label} span for strict pseudonym"
                        )
                    token = f"<{span.label}>"
                    fallback_n += 1
                else:
                    mac = hmac.new(
                        purpose_key, mac_message(span.label, can), hashlib.sha256
                    ).digest()
                    token = format_token(span.label, kid, mac, token_bytes)
                    pseudo_n += 1
                    by_label[span.label] = by_label.get(span.label, 0) + 1
            else:
                token = f"<{span.label}>"
                fallback_n += 1

            # Rebuild span offsets relative to output — callers of API use
            # original span offsets on *input*; for response we expose token
            # as entity text and keep input offsets for location in source.
            out_spans.append(
                Span(span.start, span.end, span.label, span.score, token, span.source)
            )
            parts.append(token)
            cursor = span.end

        parts.append(text[cursor:])
        redacted = "".join(parts)
        return PseudonymResult(
            text=redacted,
            spans=out_spans,
            key_id=kid,
            purpose=purpose,
            profile=profile.value,
            stats={
                "pseudonymised": pseudo_n,
                "replaced_fallback": fallback_n,
                "by_label": by_label,
            },
            privacy={
                "classification": "pseudonymised_personal_data",
                "linkable": True,
                "reversible": False,
                "algorithm": "HMAC-SHA256-HKDF-v1",
            },
        )
