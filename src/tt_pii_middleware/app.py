"""HTTP surface: /health, /v1/analyze, /v1/redact, /v1/anonymize, /v1/restore.

Also speaks Microsoft Presidio's ``POST /analyze`` + ``POST /anonymize`` so
Bifrost guardrails (`type=presidio`) can use this service as the analyzer.

Designed to sit in front of an LLM gateway (e.g. a LiteLLM pre-call hook):
POST the prompt to /v1/redact or /v1/anonymize, forward the sanitized text
upstream, and (for anonymize) restore the response with the returned mapping.
"""

import json
import logging
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from typing import Any, Literal

import redis as redis_lib
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from tt_pii_middleware import __version__
from tt_pii_middleware.analyzer import TT_LABELS, PiiEngine
from tt_pii_middleware.config import Settings, get_settings
from tt_pii_middleware.presidio_compat import (
    PresidioAnalyzeRequest,
    PresidioAnonymizeRequest,
    apply_analyzer_results,
    coerce_language,
    map_incoming_entities,
    spans_to_presidio,
)
from tt_pii_middleware.pseudo.keystore import KeystoreError, load_from_settings
from tt_pii_middleware.pseudo.profiles import Profile, resolve_profile
from tt_pii_middleware.pseudo.pseudonymizer import Pseudonymizer
from tt_pii_middleware.logging import configure_logging, log_event

logger = logging.getLogger("tt_pii_middleware")

_SESSION_KEY_PREFIX = "ttpii:mapping:"

Language = Literal["pl", "en"]
TTLabel = Literal[
    "PERSON", "ORG", "PESEL", "NIP", "REGON", "KRS", "DOWOD", "PASSPORT",
    "IBAN", "PHONE", "EMAIL", "POSTAL", "ADDRESS", "DOB", "CARD", "PLATE",
]


class AnalyzeRequest(BaseModel):
    text: str
    language: Language | None = None
    entities: list[TTLabel] | None = Field(
        default=None, description="Restrict detection to these TT labels."
    )
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    include_text: bool = Field(
        default=True, description="Include the matched substring in each span."
    )


class SpanModel(BaseModel):
    start: int
    end: int
    label: str
    score: float
    text: str | None = None


class AnalyzeResponse(BaseModel):
    language: str
    spans: list[SpanModel]


class RedactRequest(BaseModel):
    text: str
    mode: Literal["mask", "replace", "hash"] | None = Field(
        default=None,
        description="Legacy mode. Prefer `profile`. hash is deprecated (weak for PESEL).",
    )
    profile: Literal["strict", "mask", "linkable", "linkable_strict", "hash"] | None = Field(
        default=None,
        description="Policy profile. linkable/linkable_strict need HMAC master key.",
    )
    purpose: str | None = Field(
        default=None,
        description="HKDF purpose label (e.g. llm-gateway, eval). Default from settings.",
        max_length=64,
    )
    tenant_id: str | None = Field(default=None, max_length=64)
    key_id: str | None = Field(default=None, description="Master key id / version (e.g. v1).")
    language: Language | None = None
    entities: list[TTLabel] | None = None
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    token_bytes: int | None = Field(default=None, ge=8, le=32)
    strict_pseudonym: bool = False


class RedactResponse(BaseModel):
    language: str
    redacted_text: str
    entities: list[SpanModel]
    profile: str | None = None
    purpose: str | None = None
    key_id: str | None = None
    privacy: dict[str, Any] | None = None
    stats: dict[str, Any] | None = None


class AnonymizeRequest(BaseModel):
    text: str
    language: Language | None = None
    entities: list[TTLabel] | None = None
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class AnonymizeResponse(BaseModel):
    language: str
    anonymized_text: str
    entities: list[SpanModel]
    mapping: dict[str, str]
    session_id: str | None = Field(
        default=None,
        description="Set when REDIS_URL is configured; pass to /v1/restore "
        "instead of the mapping. Expires after MAPPING_TTL_SECONDS.",
    )


class RestoreRequest(BaseModel):
    text: str
    mapping: dict[str, str] | None = None
    session_id: str | None = None


class RestoreResponse(BaseModel):
    restored_text: str


def _entity_counts(spans: list[Any]) -> dict[str, int]:
    return dict(Counter(s.label for s in spans))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    started = time.perf_counter()
    app.state.settings = settings
    store = load_from_settings(
        master_key_b64=settings.pseudonym_master_key_b64,
        master_key_file=settings.pseudonym_master_key_file,
        master_keys=settings.pseudonym_master_keys,
        active_kid=settings.pseudonym_active_kid,
        fail_closed=settings.pseudonym_fail_closed,
    )
    app.state.pseudonymizer = Pseudonymizer(store)
    app.state.engine = PiiEngine(settings, pseudonymizer=app.state.pseudonymizer)
    # Short socket timeouts: the vault is best-effort, so an unreachable
    # Redis must degrade to "mapping only in the response" instead of
    # parking worker threads on blocking connects.
    app.state.redis = (
        redis_lib.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        if settings.redis_url
        else None
    )
    log_event(
        logger,
        "engine_ready",
        startup_seconds=round(time.perf_counter() - started, 2),
        models=app.state.engine.info()["models"],
        recognizers=len(app.state.engine.info()["recognizers"]),
        redis_vault=bool(app.state.redis),
    )
    yield


app = FastAPI(
    title="TT PII Middleware",
    version=__version__,
    description="Thinking Typewriters PII detection & redaction middleware "
    "(Polish + universal identifiers). Self-hosted; no text leaves the service.",
    lifespan=lifespan,
)


def _check_text_size(settings: Settings, text: str) -> None:
    if len(text) > settings.max_text_length:
        raise HTTPException(
            status_code=413,
            detail=f"text exceeds MAX_TEXT_LENGTH={settings.max_text_length} characters",
        )


def _redis_status(client: redis_lib.Redis | None) -> str:
    if client is None:
        return "disabled"
    try:
        client.ping()
        return "connected"
    except redis_lib.RedisError:
        return "unreachable"


@app.get("/health")
def health(request: Request) -> dict[str, Any]:
    engine: PiiEngine = request.app.state.engine
    info = engine.info()
    return {
        "status": "ok",
        "version": __version__,
        "models_loaded": info["models"],
        "languages": info["languages"],
        "recognizers_loaded": info["recognizers"],
        "labels": info["labels"],
        "redis_vault": _redis_status(request.app.state.redis),
    }


@app.post("/analyze")
def presidio_analyze(req: PresidioAnalyzeRequest, request: Request) -> list[dict[str, Any]]:
    """Microsoft Presidio analyzer wire format (Bifrost `type=presidio`)."""
    engine: PiiEngine = request.app.state.engine
    _check_text_size(request.app.state.settings, req.text)
    started = time.perf_counter()
    language = coerce_language(req.language, engine.settings.default_language)
    labels = map_incoming_entities(req.entities)
    if req.entities and not labels:
        return []
    spans = engine.analyze(
        req.text, language=language, labels=labels, threshold=req.score_threshold
    )
    log_event(
        logger,
        "presidio_analyze",
        language=language,
        text_chars=len(req.text),
        entity_counts=_entity_counts(spans),
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
    )
    return spans_to_presidio(spans)


@app.post("/anonymize")
def presidio_anonymize(req: PresidioAnonymizeRequest, request: Request) -> dict[str, Any]:
    """Microsoft Presidio anonymizer wire format (Bifrost redact with anonymizer_url)."""
    _check_text_size(request.app.state.settings, req.text)
    outcome = apply_analyzer_results(req.text, req.analyzer_results)
    log_event(
        logger,
        "presidio_anonymize",
        text_chars=len(req.text),
        entity_counts=dict(Counter(item["entity_type"] for item in outcome["items"])),
    )
    return outcome


@app.post("/v1/analyze", response_model=AnalyzeResponse, response_model_exclude_none=True)
def analyze(req: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    engine: PiiEngine = request.app.state.engine
    _check_text_size(request.app.state.settings, req.text)
    started = time.perf_counter()
    language = req.language or engine.settings.default_language
    spans = engine.analyze(
        req.text, language=language, labels=req.entities, threshold=req.score_threshold
    )
    log_event(
        logger,
        "analyze",
        language=language,
        text_chars=len(req.text),
        entity_counts=_entity_counts(spans),
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
    )
    return AnalyzeResponse(
        language=language,
        spans=[SpanModel(**s.to_dict(include_text=req.include_text)) for s in spans],
    )


@app.post("/v1/redact", response_model=RedactResponse, response_model_exclude_none=True)
def redact(req: RedactRequest, request: Request) -> RedactResponse:
    engine: PiiEngine = request.app.state.engine
    settings: Settings = request.app.state.settings
    _check_text_size(settings, req.text)
    started = time.perf_counter()
    language = req.language or engine.settings.default_language

    mode = req.mode if req.mode is not None else "replace"
    try:
        profile = resolve_profile(req.profile, mode if req.profile is None else None)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    purpose = req.purpose or settings.default_pseudonym_purpose
    allowed = {
        p.strip()
        for p in (settings.pseudonym_allowed_purposes or "").split(",")
        if p.strip()
    }
    if allowed and purpose not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"purpose {purpose!r} not in PSEUDONYM_ALLOWED_PURPOSES",
        )

    try:
        redacted_text, spans, meta = engine.redact(
            req.text,
            mode=mode,
            language=language,
            labels=req.entities,
            threshold=req.score_threshold,
            profile=profile.value,
            purpose=purpose,
            tenant_id=req.tenant_id or "_",
            key_id=req.key_id,
            token_bytes=req.token_bytes,
            strict_pseudonym=req.strict_pseudonym,
            pseudonymizer=request.app.state.pseudonymizer,
        )
    except KeystoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    log_event(
        logger,
        "redact",
        language=language,
        profile=meta.get("profile"),
        purpose=meta.get("purpose"),
        key_id=meta.get("key_id"),
        text_chars=len(req.text),
        entity_counts=_entity_counts(spans),
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
    )
    return RedactResponse(
        language=language,
        redacted_text=redacted_text,
        entities=[SpanModel(**s.to_dict()) for s in spans],
        profile=meta.get("profile"),
        purpose=meta.get("purpose"),
        key_id=meta.get("key_id"),
        privacy=meta.get("privacy"),
        stats=meta.get("stats") or None,
    )


@app.post("/v1/anonymize", response_model=AnonymizeResponse, response_model_exclude_none=True)
def anonymize(req: AnonymizeRequest, request: Request) -> AnonymizeResponse:
    engine: PiiEngine = request.app.state.engine
    settings: Settings = request.app.state.settings
    _check_text_size(settings, req.text)
    started = time.perf_counter()
    language = req.language or engine.settings.default_language
    anonymized_text, spans, mapping = engine.anonymize(
        req.text, language=language, labels=req.entities, threshold=req.score_threshold
    )

    session_id: str | None = None
    client: redis_lib.Redis | None = request.app.state.redis
    if client is not None and mapping:
        session_id = uuid.uuid4().hex
        try:
            client.set(
                _SESSION_KEY_PREFIX + session_id,
                json.dumps(mapping, ensure_ascii=False),
                ex=settings.mapping_ttl_seconds,
            )
        except redis_lib.RedisError:
            # The vault is best-effort; the mapping is still in the response.
            log_event(logger, "mapping_vault_error", language=language)
            session_id = None

    log_event(
        logger,
        "anonymize",
        language=language,
        text_chars=len(req.text),
        entity_counts=_entity_counts(spans),
        vaulted=session_id is not None,
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
    )
    return AnonymizeResponse(
        language=language,
        anonymized_text=anonymized_text,
        entities=[SpanModel(**s.to_dict()) for s in spans],
        mapping=mapping,
        session_id=session_id,
    )


@app.post("/v1/restore", response_model=RestoreResponse)
def restore(req: RestoreRequest, request: Request) -> RestoreResponse:
    engine: PiiEngine = request.app.state.engine
    settings: Settings = request.app.state.settings
    _check_text_size(settings, req.text)

    mapping: dict[str, str] = {}
    if req.session_id is not None:
        client: redis_lib.Redis | None = request.app.state.redis
        if client is None:
            raise HTTPException(
                status_code=400, detail="session_id given but no Redis vault configured"
            )
        stored = client.get(_SESSION_KEY_PREFIX + req.session_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="session_id unknown or expired")
        mapping.update(json.loads(stored))
    if req.mapping:
        mapping.update(req.mapping)
    if not mapping:
        raise HTTPException(status_code=400, detail="provide mapping or session_id")

    restored = engine.restore(req.text, mapping)
    log_event(logger, "restore", tokens=len(mapping))
    return RestoreResponse(restored_text=restored)
