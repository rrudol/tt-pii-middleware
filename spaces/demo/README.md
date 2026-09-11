---
title: PL-PII Redact Demo
emoji: 🔒
colorFrom: green
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
license: apache-2.0
suggested_hardware: cpu-basic
datasets:
  - rafalrudol/pl-pii-synthetic-v1
tags:
  - pii
  - redaction
  - poland
  - privacy
---

# PL-PII Redact Demo (guardrailed)

Interactive **one-way redaction** for Polish + universal PII.

## Guardrails

- **Redact only** — no reversible mapping returned
- **Max 2 000 characters** per request
- **In-process rate limit** (~20 req / IP / minute)
- **spaCy `pl_core_news_sm`** (CPU-friendly; slightly softer NER than `md`)
- Logs: entity **types/counts only**, never raw text
- Synthetic examples only in the UI presets

Do **not** paste real production PII. This is a demo, not a compliance product.
