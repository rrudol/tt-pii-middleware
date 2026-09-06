"""Shared fixtures. All PII in tests is synthetic (checksum-valid but fake)."""

import pytest
from fastapi.testclient import TestClient

from tt_pii_middleware.analyzer import PiiEngine
from tt_pii_middleware.app import app
from tt_pii_middleware.config import Settings


@pytest.fixture(scope="session")
def engine() -> PiiEngine:
    """Engine with the KRS opt-in enabled so gating can be exercised."""
    return PiiEngine(Settings(enable_krs=True, redis_url=None))


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


def labels_of(engine: PiiEngine, text: str, **kwargs) -> dict[str, list[str]]:
    """Detected {label: [matched texts]} for readable assertions."""
    found: dict[str, list[str]] = {}
    for span in engine.analyze(text, **kwargs):
        found.setdefault(span.label, []).append(span.text)
    return found
