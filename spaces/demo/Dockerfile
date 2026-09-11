# Guardrailed redact demo for HF Spaces (Docker SDK).
# Builds the published Apache-2.0 package from GitHub main + small spaCy models.
FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    SPACY_MODEL=pl_core_news_sm \
    SPACY_MODEL_EN=en_core_web_sm \
    DEFAULT_LANGUAGE=pl \
    SCORE_THRESHOLD=0.4 \
    MAX_TEXT_LENGTH=2000 \
    ENABLE_KRS=true \
    DEMO_RATE_LIMIT=20 \
    DEMO_RATE_WINDOW_SEC=60 \
    LOG_LEVEL=INFO

RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pin to main; Spaces rebuild picks up releases. For stricter pins, set GIT_REF.
ARG GIT_REF=main
RUN git clone --depth 1 --branch "${GIT_REF}" \
      https://github.com/rrudol/tt-pii-middleware.git /src \
 && pip install /src \
 && pip install \
      gradio==4.44.1 httpx==0.28.1 \
      https://github.com/explosion/spacy-models/releases/download/pl_core_news_sm-3.8.0/pl_core_news_sm-3.8.0-py3-none-any.whl \
      https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl \
 && cp /src/spaces/demo/app.py /app/app.py \
 && rm -rf /src

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 7860
CMD ["python", "app.py"]
