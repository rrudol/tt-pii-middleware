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
    # Salt mixed into `mode=hash` digests so identical values across
    # deployments don't produce linkable hashes.
    hash_salt: str = ""
    # DoS guard: reject request bodies with text longer than this (chars).
    max_text_length: int = 100_000


@lru_cache
def get_settings() -> Settings:
    return Settings()
