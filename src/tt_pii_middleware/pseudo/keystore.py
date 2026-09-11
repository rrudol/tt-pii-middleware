"""Master key loading + purpose-key derive (never log key material)."""

from __future__ import annotations

import base64
import os
import re
import threading
from pathlib import Path

from tt_pii_middleware.pseudo.kdf import HKDF_SALT, hkdf_sha256, purpose_info

_KID_RE = re.compile(r"^[a-z0-9]{1,8}$")


class KeystoreError(RuntimeError):
    """Fail-closed configuration / missing key."""


class MasterKeyStore:
    """In-process store of master secrets keyed by kid (e.g. v1, v2)."""

    def __init__(self, masters: dict[str, bytes], active_kid: str) -> None:
        if not masters:
            raise KeystoreError("no pseudonym master keys configured")
        for kid, secret in masters.items():
            if not _KID_RE.fullmatch(kid):
                raise KeystoreError(f"invalid kid {kid!r}")
            if len(secret) < 32:
                raise KeystoreError(f"master key {kid!r} must be >= 32 bytes")
        if active_kid not in masters:
            raise KeystoreError(f"active kid {active_kid!r} not in key store")
        self._masters = dict(masters)
        self.active_kid = active_kid
        self._cache: dict[tuple[str, str, str], bytes] = {}
        self._lock = threading.Lock()

    @property
    def kids(self) -> list[str]:
        return sorted(self._masters)

    def derive(self, kid: str, purpose: str, tenant: str) -> bytes:
        if kid not in self._masters:
            raise KeystoreError(f"unknown kid {kid!r}")
        purpose = (purpose or "default").strip() or "default"
        tenant = (tenant or "_").strip() or "_"
        if len(purpose) > 64 or len(tenant) > 64:
            raise KeystoreError("purpose/tenant too long")
        cache_key = (kid, purpose, tenant)
        with self._lock:
            hit = self._cache.get(cache_key)
            if hit is not None:
                return hit
        key = hkdf_sha256(
            self._masters[kid],
            salt=HKDF_SALT,
            info=purpose_info(purpose, tenant),
            length=32,
        )
        with self._lock:
            if len(self._cache) > 256:
                self._cache.clear()
            self._cache[cache_key] = key
        return key

    def health(self) -> dict:
        return {
            "enabled": True,
            "active_kid": self.active_kid,
            "kids": self.kids,
        }


def _load_secret_bytes(raw: bytes) -> bytes:
    text = raw.strip()
    # Try base64 if it looks like it
    try:
        decoded = base64.b64decode(text, validate=True)
        if len(decoded) >= 32:
            return decoded
    except Exception:
        pass
    if len(raw) >= 32:
        return raw
    raise KeystoreError("master key material too short or invalid encoding")


def load_from_settings(
    *,
    master_key_b64: str | None,
    master_key_file: str | None,
    master_keys: str | None,
    active_kid: str,
    fail_closed: bool,
) -> MasterKeyStore | None:
    """Build store from env-style settings. None if unconfigured and not fail-closed."""
    masters: dict[str, bytes] = {}

    # PSEUDONYM_MASTER_KEYS=v1:/path/to/key,v2:/other
    if master_keys:
        for part in master_keys.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" not in part:
                raise KeystoreError(f"bad PSEUDONYM_MASTER_KEYS entry: {part!r}")
            kid, path = part.split(":", 1)
            kid, path = kid.strip(), path.strip()
            data = Path(path).read_bytes()
            masters[kid] = _load_secret_bytes(data)

    if master_key_file and "v1" not in masters and active_kid not in masters:
        data = Path(master_key_file).read_bytes()
        masters[active_kid] = _load_secret_bytes(data)

    if master_key_b64 and active_kid not in masters:
        try:
            masters[active_kid] = _load_secret_bytes(master_key_b64.encode("ascii"))
        except Exception as exc:
            raise KeystoreError(f"invalid PSEUDONYM_MASTER_KEY_B64: {exc}") from exc

    if not masters:
        if fail_closed:
            # Still allow service start; linkable requests fail at call time.
            return None
        return None

    return MasterKeyStore(masters, active_kid=active_kid if active_kid in masters else next(iter(masters)))
