"""Token wire format: LABEL_kid_base64url(mac_prefix)."""

from __future__ import annotations

import base64
import re

# PESEL_v1_xK9mQ2nL0pRsT7uVwXyZ
TOKEN_RE = re.compile(
    r"\b([A-Z]{2,12})_([a-z0-9]{1,8})_([A-Za-z0-9_-]{10,64})\b"
)

DEFAULT_TOKEN_BYTES = 15  # 120-bit truncated MAC


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def format_token(label: str, kid: str, mac: bytes, n: int = DEFAULT_TOKEN_BYTES) -> str:
    if n < 8 or n > len(mac):
        raise ValueError(f"token byte length must be in [8, {len(mac)}], got {n}")
    if not re.fullmatch(r"[a-z0-9]{1,8}", kid):
        raise ValueError(f"invalid kid: {kid!r}")
    return f"{label.upper()}_{kid}_{b64url(mac[:n])}"


def looks_like_token(text: str) -> bool:
    return TOKEN_RE.fullmatch(text.strip()) is not None
