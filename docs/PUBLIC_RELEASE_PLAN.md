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

**MVP public package = A**, with B as the marketing surface once A is live.

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

## Phase 1 — HF Dataset (public, this week)

1. Create HF dataset repo e.g. `thinking-typewriters/pl-pii-synthetic-v1`
   (or personal `rrudol/…` until org exists).
2. Upload **only**:
   - `pl_pii_v1.jsonl` (from `make corpus`)
   - `README.md` = contents of `docs/hf/DATASET_CARD.md`
   - `LICENSE` snippet: “synthetic evaluation data, no real PII”
3. Pin generation command + seed in the card (reproducibility).
4. Do **not** upload Redis dumps, production logs, or real tickets.

```bash
make corpus
# pip install huggingface_hub
huggingface-cli upload thinking-typewriters/pl-pii-synthetic-v1 \
  data/synthetic/pl_pii_v1.jsonl . \
  --repo-type dataset
# then set README via web UI or `README.md` upload
```

## Phase 2 — Metrics Space (optional, low cost)

Static Space: render `eval/RESULTS.md` + allow visitors to **download** the
dataset and run `scripts/eval_corpus.py` locally against **their** detector.
No GPU, no always-on Presidio process.

## Phase 3 — Interactive demo (only with guardrails)

If we want a live “paste text → redacted” demo:

- Use `pl_core_news_sm` on Space CPU **or** call a private backend with:
  - auth token / waiting room
  - `MAX_TEXT_LENGTH=2000`
  - per-IP rate limit
  - no `/v1/anonymize` mapping returned (redact-only)
  - abuse monitoring
- Publish **API contract + example curls** in the model card, not unrestricted access.

## Phase 4 — OSS the service (legal gate)

Before `src/` goes public:

1. License audit: `pii-core`, `pii-presidio`, `pii-veil`, Presidio, spaCy.
2. Choose MIT or Apache-2.0; update `NOTICE`, `pyproject.toml`, README badge.
3. Strip internal LiteLLM / VPC runbooks if any secrets remain.
4. Tag `v0.1.0-public`, push GHCR image `ghcr.io/…/tt-pii-middleware:0.1.0`.
5. Point model card `library_name` / links at the OSS repo.

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

- [ ] Dataset contains **only** synthetic values (spot-check 50 random docs)
- [ ] No employee names, real NIP/PESEL, customer emails
- [ ] Card states matching policy (exact span) and limitations
- [ ] Gates green: `make eval` && `make eval-public`
- [ ] License text matches what legal approved
- [ ] README links dataset ↔ metrics ↔ (optional) Space

## Success criteria

| Signal | Target |
|---|---|
| HF dataset live | Phase 1 done |
| External user reproduces micro-F1 ±0.01 | `make eval` on clean clone |
| Zero privacy incidents | no real PII in artifact |
| Clear upgrade path | Phase 4 ticket filed with license choice |
