"""HKDF-SHA256 (RFC 5869) — no third-party dependency."""

from __future__ import annotations

import hashlib
import hmac


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if length < 1 or length > 255 * 32:
        raise ValueError("HKDF length out of range")
    if not salt:
        salt = bytes(32)  # HashLen zeros per RFC if salt empty; we always pass explicit salt
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(previous)
        counter += 1
    return bytes(okm[:length])


HKDF_SALT = b"tt-pii-hkdf-salt/v1"
MSG_PREFIX = b"tt-pii/v1\n"


def purpose_info(purpose: str, tenant: str) -> bytes:
    return f"tt-pii-pseudo/v1|{purpose}|{tenant}".encode("utf-8")


def mac_message(label: str, canonical: str) -> bytes:
    return MSG_PREFIX + label.encode("utf-8") + b"\n" + canonical.encode("utf-8")
