---
title: PL-PII Synthetic Metrics
emoji: 📊
colorFrom: blue
colorTo: indigo
sdk: static
pinned: false
license: apache-2.0
datasets:
  - rafalrudol/pl-pii-synthetic-v1
tags:
  - pii
  - poland
  - evaluation
  - privacy
---

# PL-PII Synthetic Metrics

Static benchmark dashboard for
[`rafalrudol/pl-pii-synthetic-v1`](https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1).

No PII is processed here — numbers only. To score **your** detector:

```bash
git clone https://github.com/rrudol/tt-pii-middleware
cd tt-pii-middleware && make install
huggingface-cli download rafalrudol/pl-pii-synthetic-v1 data/pl_pii_v1.jsonl --local-dir /tmp/pl-pii
python scripts/eval_corpus.py /tmp/pl-pii/data/pl_pii_v1.jsonl --fail-under eval/gates_public.json
```


> **Hosting note:** HF free accounts cannot create Gradio/Docker Spaces (402 PRO). This Space ships as **Static** HTML (`static/index.html`). The Gradio `app.py` remains for local use.
