# Public release plan — Hugging Face + OSS path

Goal: publish something **honest, reproducible, and useful** for Polish PII
detection without leaking proprietary glue or claiming GDPR magic.

## Decision matrix

| Option | What ships | Effort | Risk | Recommendation |
|---|---|---|---|---|
| **A. Dataset-only** | `PL-PII-Synthetic-v1` JSONL + card + metrics | 0.5 d | low | **Ship first** |
| **B. Dataset + Space demo** | Gradio/Streamlit calling a **rate-limited** public API or in-browser-incapable server | 1–2 d | medium (abuse, cost) | Ship after A |
| **C. Full OSS service** | Apache-2.0/MIT on `src/` + Docker | 2–3 d (license audit of pii-core) | license + support | After legal OK |
| **D. Model weights only** | Fine-tuned GLiNER/XLM-R | 1–2 w | high (quality, misuse) | Later, optional |

**Shipped: A + B + C.** (D = fine-tuned weights — still optional, see ROADMAP.)

## Why not “just put the Docker image on HF”?

- Image embeds spaCy models (OK) **and** proprietary TT code (not OK without license).
- HF Spaces free tier will OOM on `pl_core_news_md` + Presidio cold start unless
  we switch to `sm` and accept quality drop.
- Unauthenticated redaction APIs become free PII-scrubbing SaaS (cost + ToS).

## Phase 0 — already done in-repo

- [x] Audit of recognizers, API, threat model
- [x] Synthetic ID generators (checksum-valid)
- [x] 11 document templates + negative sets
- [x] Exact-span eval harness + MVP/public gates
- [x] 3000-doc run: micro F1 0.955; checksum labels 1.0; 0 invalid FPs
- [x] Hardening: plate denylist, postal context, KRS↔NIP, REGON↔CARD, ORG legal form
- [x] Dataset card + model card drafts (`docs/hf/`)

## Phase 1 — HF Dataset ✅ shipped

**Live (public):**

| Artifact | URL |
|---|---|
| Dataset `PL-PII-Synthetic-v1` | https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1 |
| Docs-only model card | https://huggingface.co/rafalrudol/tt-pii-middleware |
| Source / eval harness | https://github.com/rrudol/tt-pii-middleware |

Contents on the dataset repo: `data/pl_pii_v1.jsonl` (n=3000, seed=42),
`RESULTS.md`, `gates_*.json`, `GENERATION.md`, dataset card README.

Re-upload after generator changes:

```bash
make corpus
# HF_TOKEN from 1Password / env
huggingface-cli upload rafalrudol/pl-pii-synthetic-v1 \
  data/synthetic/pl_pii_v1.jsonl data/pl_pii_v1.jsonl \
  --repo-type dataset
```

## Phase 2 — Metrics Space ✅ shipped

- Source: `spaces/metrics/`
- Live: https://huggingface.co/spaces/rafalrudol/pl-pii-metrics
- Static Gradio: embedded `RESULTS.md`, no model load, no user text.

## Phase 3 — Interactive demo ✅ shipped (guardrailed)

- Source: `spaces/demo/` (Docker SDK, `pl_core_news_sm`)
- Live: https://huggingface.co/spaces/rafalrudol/pl-pii-redact-demo
- Guardrails: max 2000 chars, 20 req/IP/min, **redact-only** (no mapping),
  entity-type logs only, synthetic UI examples.

## Phase 4 — OSS the service ✅ shipped

- License: **Apache-2.0** (`LICENSE`, `NOTICE`, `pyproject.toml`)
- Audit: `docs/LICENSE_AUDIT.md` (pii-toolkit A2.0, Presidio/spaCy/FastAPI MIT)
- GitHub repo set **public**
- Tag: `v0.1.0-public`
- Next packaging (GHCR) tracked in `docs/ROADMAP.md`


## What we will claim publicly (allowed)

- “Checksum-validated PESEL/NIP/REGON/IBAN/DOWOD/CARD with **0 invalid FPs** on
  the synthetic suite (n=3000, seed=42).”
- “Exact-span micro-F1 **0.95+** on the full synthetic mix; public-label subset
  near-perfect.”
- “Self-hosted, no SaaS DLP, no runtime egress.”
- “Redaction is risk reduction, not a compliance certificate.”

## What we will **not** claim

- “GDPR compliant out of the box”
- “100% recall on real Polish documents”
- “Production NER for PERSON/ORG” (report the softer numbers honestly)
- Any metric on **real** customer data

## Oracle / review checklist before push to HF

- [x] Dataset contains **only** synthetic values (spot-check 50 random docs)
- [x] No employee names, real NIP/PESEL, customer emails
- [x] Card states matching policy (exact span) and limitations
- [x] Gates green: `make eval` && `make eval-public`
- [x] License text matches audit (`docs/LICENSE_AUDIT.md`); Apache-2.0 chosen
- [x] README links dataset ↔ metrics ↔ demo Space ↔ metrics ↔ (optional) Space

## Success criteria

| Signal | Target |
|---|---|
| HF dataset live | ✅ https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1 |
| External user reproduces micro-F1 ±0.01 | `make eval` on clean clone |
| Zero privacy incidents | no real PII in artifact |
| Clear upgrade path | ✅ Apache-2.0 + `docs/ROADMAP.md` |
