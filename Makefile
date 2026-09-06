VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

SPACY_PL := https://github.com/explosion/spacy-models/releases/download/pl_core_news_md-3.8.0/pl_core_news_md-3.8.0-py3-none-any.whl
SPACY_EN := https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

.PHONY: install test run docker-build docker-up clean

$(VENV)/bin/pip:
	python3 -m venv $(VENV)

install: $(VENV)/bin/pip  ## venv + package + dev deps + spaCy models
	$(PIP) install -e ".[dev]"
	$(PIP) install $(SPACY_PL) $(SPACY_EN)

test:
	$(PY) -m pytest

run:  ## local dev server on :8080
	$(VENV)/bin/uvicorn tt_pii_middleware.app:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t tt-pii-middleware:latest .

docker-up:
	docker compose up --build

clean:
	rm -rf $(VENV) .pytest_cache dist *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
