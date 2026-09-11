VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

SPACY_PL := https://github.com/explosion/spacy-models/releases/download/pl_core_news_md-3.8.0/pl_core_news_md-3.8.0-py3-none-any.whl
SPACY_EN := https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

CORPUS ?= data/synthetic/pl_pii_v1.jsonl
CORPUS_N ?= 3000
CORPUS_SEED ?= 42
EVAL_OUT ?= eval/results/latest.json
GATES_MVP ?= eval/gates_mvp.json
GATES_PUBLIC ?= eval/gates_public.json

.PHONY: install test run docker-build docker-up clean corpus eval eval-public smoke demo-local

$(VENV)/bin/pip:
	python3 -m venv $(VENV)

install: $(VENV)/bin/pip  ## venv + package + dev deps + spaCy models
	$(PIP) install -e ".[dev]"
	$(PIP) install $(SPACY_PL) $(SPACY_EN)

test:
	$(PY) -m pytest

corpus:  ## generate synthetic PL PII JSONL corpus (deterministic)
	$(PY) scripts/generate_corpus.py --n $(CORPUS_N) --seed $(CORPUS_SEED) -o $(CORPUS)

eval: corpus  ## run exact-span eval + MVP quality gates
	$(PY) scripts/eval_corpus.py $(CORPUS) --out $(EVAL_OUT) --fail-under $(GATES_MVP)

eval-public: corpus  ## stricter public-release gates (checksum + structured labels)
	$(PY) scripts/eval_corpus.py $(CORPUS) --out eval/results/public.json \
		--fail-under $(GATES_PUBLIC) \
		--labels PESEL,NIP,REGON,IBAN,DOWOD,CARD,EMAIL,PHONE,POSTAL,PLATE,PASSPORT,KRS,DOB

smoke:  ## quick 200-doc sanity eval (no gates)
	$(PY) scripts/generate_corpus.py --n 200 --seed $(CORPUS_SEED) -o data/synthetic/smoke.jsonl
	$(PY) scripts/eval_corpus.py data/synthetic/smoke.jsonl --out eval/results/smoke.json

run:  ## local dev server on :8080
	$(VENV)/bin/uvicorn tt_pii_middleware.app:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t tt-pii-middleware:latest .

docker-up:
	docker compose up --build

clean:
	rm -rf $(VENV) .pytest_cache dist *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +

demo-local:  ## build & run guardrailed Gradio demo locally (Docker)
	docker build -f spaces/demo/Dockerfile.local -t pl-pii-demo:local .
	docker run --rm -p 7860:7860 pl-pii-demo:local

demo-tailnet-deploy:  ## build & deploy redact demo on tailnet host (radium-226-ovh)
	./deploy/tailnet/deploy.sh
