"""Canonical forms for identifiers before HMAC (stability = correctness)."""

from __future__ import annotations

import re
import unicodedata

_WS = re.compile(r"\s+")
_NON_DIGIT = re.compile(r"\D+")
_PHONE_JUNK = re.compile(r"[^\d+]")

# Labels that participate in linkable_strict (checksum / structured IDs).
CHECKSUM_LIKE_LABELS = frozenset(
    {
        "PESEL",
        "NIP",
        "REGON",
        "DOWOD",
        "IBAN",
        "CARD",
        "EMAIL",
        "PHONE",
        "PASSPORT",
        "PLATE",
        "KRS",
        "POSTAL",
    }
)


def canonicalize(label: str, raw: str) -> str | None:
    """Return canonical string for MAC input, or None if span cannot be stabilised."""
    if not raw or not raw.strip():
        return None
    text = unicodedata.normalize("NFKC", raw).strip()
    label = label.upper()

    if label == "PESEL":
        digits = _NON_DIGIT.sub("", text)
        return digits if len(digits) == 11 and digits.isdigit() else None

    if label == "NIP":
        digits = _NON_DIGIT.sub("", text)
        return digits if len(digits) == 10 and digits.isdigit() else None

    if label == "REGON":
        digits = _NON_DIGIT.sub("", text)
        return digits if len(digits) in (9, 14) and digits.isdigit() else None

    if label == "KRS":
        digits = _NON_DIGIT.sub("", text)
        return digits if len(digits) == 10 and digits.isdigit() else None

    if label == "DOWOD":
        compact = text.replace(" ", "").upper()
        if len(compact) == 9 and compact[:3].isalpha() and compact[3:].isdigit():
            return compact
        return None

    if label == "IBAN":
        compact = text.replace(" ", "").upper()
        if len(compact) >= 15 and compact[:2].isalpha() and compact[2:4].isdigit():
            return compact
        return None

    if label == "CARD":
        digits = _NON_DIGIT.sub("", text)
        return digits if 13 <= len(digits) <= 19 and digits.isdigit() else None

    if label == "EMAIL":
        if "@" not in text:
            return None
        local, _, domain = text.partition("@")
        if not local or not domain:
            return None
        return f"{local}@{domain.lower()}"

    if label == "PHONE":
        # Prefer E.164-ish: keep leading +, digits only after.
        cleaned = _PHONE_JUNK.sub("", text)
        if cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        digits = cleaned[1:] if cleaned.startswith("+") else cleaned
        if not digits.isdigit() or len(digits) < 7:
            return None
        if cleaned.startswith("+"):
            return "+" + digits
        # Bare PL 9-digit mobile → +48
        if len(digits) == 9:
            return "+48" + digits
        return digits

    if label == "PASSPORT":
        compact = text.replace(" ", "").upper()
        return compact if len(compact) >= 6 and compact.isalnum() else None

    if label == "PLATE":
        compact = _WS.sub(" ", text.upper()).strip()
        return compact if len(compact) >= 4 else None

    if label == "POSTAL":
        m = re.fullmatch(r"(\d{2})-?(\d{3})", text.replace(" ", ""))
        return f"{m.group(1)}-{m.group(2)}" if m else None

    if label in {"PERSON", "ORG", "ADDRESS", "DOB"}:
        collapsed = _WS.sub(" ", text).strip()
        return collapsed if collapsed else None

    # Unknown label: still allow stable MAC on NFKC+trim.
    return text or None
