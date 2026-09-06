# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Builder: install pinned dependencies + bake the spaCy models into the image
# so the runtime container needs zero egress (EU VPC requirement) and /health
# is ready as soon as the models are loaded from disk (~15-30 s).
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . \
    && pip install \
        https://github.com/explosion/spacy-models/releases/download/pl_core_news_md-3.8.0/pl_core_news_md-3.8.0-py3-none-any.whl \
        https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

# ---------------------------------------------------------------------------
# Runtime: slim image, non-root user, venv copied from the builder.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 appuser
COPY --from=builder /opt/venv /opt/venv

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --retries=10 --start-period=90s \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status == 200 else 1)"]

CMD ["uvicorn", "tt_pii_middleware.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
