---
license: other
license_name: proprietary-pending-oss
language:
  - pl
  - en
library_name: presidio
tags:
  - pii
  - privacy
  - redaction
  - poland
  - fastapi
pipeline_tag: token-classification
---

# TT PII Middleware (Polish + universal)

Self-hosted PII detection & redaction service aimed at **EU inference
gateways**. Detects Polish national identifiers (PESEL, NIP, REGON, DOWOD,
KRS, plates, postal, …) plus universal EMAIL / PHONE / IBAN / CARD, then
redacts or reversibly pseudonymizes them **before prompts leave the VPC**.

Runtime needs **no network egress** — spaCy models are baked into the image.

## What is public vs private

| Artifact | Status | Notes |
|---|---|---|
| Synthetic eval corpus `PL-PII-Synthetic-v1` | **public (HF dataset)** | this repo `make corpus` |
| Eval metrics + gates | **public** | `eval/RESULTS.md`, `eval/gates_*.json` |
| HTTP API design + Docker recipe | **public** (when OSS license lands) | FastAPI surface |
| Application source (`src/tt_pii_middleware`) | **proprietary today** | OSS decision pending |
| Production deployment / LiteLLM hooks | private | customer VPC |

Until an OSS license is chosen, treat the **dataset + metrics + API contract**
as the public surface; the service binary stays internal.

## Stack

1. **pii-core / pii-presidio** — checksum PESEL, NIP, REGON, PL-IBAN, Luhn CARD, EMAIL  
2. **Custom recognizers** — DOWOD (7-3-1 checksum), PL phones, plates, postal, address, DOB gating, KRS (opt-in), company legal forms  
3. **spaCy** `pl_core_news_md` + `en_core_web_sm` — PERSON / LOCATION / soft ORG  
4. **Presidio** Analyzer + Anonymizer — mask / replace / hash / `[LABEL_NNN]`  

## Quick eval (reproduce)

```bash
git clone https://github.com/rrudol/tt-pii-middleware
cd tt-pii-middleware
make install
make eval          # 3000 docs, MVP gates
make eval-public   # checksum + structured labels only
```

## Benchmark (seed=42, n=3000, exact span)

See [`eval/RESULTS.md`](../../eval/RESULTS.md) for the full table. Headline:

| bucket | micro F1 | notes |
|---|---:|---|
| All labels | **0.955** | includes soft NER |
| Public claim set (no PERSON/ORG/ADDRESS) | **~1.00** | PESEL/NIP/REGON/IBAN/DOWOD/CARD/EMAIL/PHONE/POSTAL/KRS/DOB = 1.0; PLATE ≥ 0.97 |
| Invalid checksum FPs | **0** | PESEL/NIP/REGON/IBAN/DOWOD/CARD |

Soft labels (PERSON ≈ 0.83 F1, ORG ≈ 0.78 F1 with legal-form pattern, ADDRESS ≈ 0.93 F1)
are **heuristic** — do not market them as perfect NER.

## API (contract)

```
POST /v1/analyze   → spans[{start,end,label,score,text?}]
POST /v1/redact    → {redacted_text, entities}   mode=replace|mask|hash
POST /v1/anonymize → {anonymized_text, mapping, session_id?}
POST /v1/restore   → {restored_text}
GET  /health
```

## Threat model (short)

Redaction ≠ GDPR compliance. Residual risk remains (OCR noise, adversarial
encodings, re-identification from non-PII context). Mappings from `/v1/anonymize`
re-identify; guard them. Logs carry entity **types/counts only**, never text.

## License

Application source: proprietary (Thinking Typewriters) until OSS license is
published. Synthetic dataset: free for eval/demo with the dataset card notice.
spaCy / Presidio / pii-core: their respective upstream licenses.
