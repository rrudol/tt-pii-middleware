"""Environment-driven configuration (12-factor style)."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All knobs are plain environment variables (case-insensitive).

    Example: ``SCORE_THRESHOLD=0.5 LOG_LEVEL=DEBUG uvicorn tt_pii_middleware.app:app``
    """

    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    log_level: str = "INFO"
    spacy_model: str = "pl_core_news_md"
    spacy_model_en: str = "en_core_web_sm"
    default_language: Literal["pl", "en"] = "pl"
    score_threshold: float = 0.4
    # Optional Redis vault for anonymization mappings (short TTL).
    redis_url: str | None = None
    mapping_ttl_seconds: int = 900
    # KRS is 10 digits with no checksum -> high FP risk; opt-in and
    # context-gated (base score below threshold, boosted only near "KRS").
    enable_krs: bool = False
    # Salt mixed into legacy `mode=hash` digests (DEPRECATED — prefer linkable).
    hash_salt: str = ""
    # DoS guard: reject request bodies with text longer than this (chars).
    max_text_length: int = 100_000

    # --- linkable pseudonyms (HMAC-HKDF) ---
    # 32+ byte master as base64 (dev). Prefer PSEUDONYM_MASTER_KEY_FILE in prod.
    pseudonym_master_key_b64: str | None = None
    pseudonym_master_key_file: str | None = None
    # Optional multi-key: "v1:/path/k1,v2:/path/k2"
    pseudonym_master_keys: str | None = None
    pseudonym_active_kid: str = "v1"
    # If true, missing keys only fail at linkable call time (service still boots).
    pseudonym_fail_closed: bool = True
    # Comma list; empty = any purpose allowed.
    pseudonym_allowed_purposes: str = ""
    default_pseudonym_purpose: str = "default"
    default_token_bytes: int = 15


@lru_cache
def get_settings() -> Settings:
    return Settings()
