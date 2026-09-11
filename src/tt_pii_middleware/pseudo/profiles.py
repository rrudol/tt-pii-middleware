"""Named redaction / pseudonym profiles."""

from __future__ import annotations

from enum import Enum


class Profile(str, Enum):
    STRICT = "strict"  # replace all
    MASK = "mask"
    SESSION = "session"  # [LABEL_NNN] + mapping (use /v1/anonymize)
    LINKABLE = "linkable"  # HMAC all labels
    LINKABLE_STRICT = "linkable_strict"  # HMAC checksum-like; NER → replace
    HASH = "hash"  # legacy weak SHA — deprecated


def resolve_profile(profile: str | None, mode: str | None) -> Profile:
    if profile:
        try:
            return Profile(profile)
        except ValueError as exc:
            raise ValueError(f"unknown profile: {profile!r}") from exc
    # Legacy mode mapping
    mode = mode or "replace"
    mapping = {
        "replace": Profile.STRICT,
        "mask": Profile.MASK,
        "hash": Profile.HASH,
    }
    if mode not in mapping:
        raise ValueError(f"unknown redaction mode: {mode!r}")
    return mapping[mode]
