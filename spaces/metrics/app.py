"""Static metrics dashboard — no model load, no user text processing."""

from pathlib import Path

import gradio as gr

RESULTS = Path(__file__).with_name("results_embedded.md").read_text(encoding="utf-8")

INTRO = """
# Polish PII — synthetic benchmark

Exact-span evaluation of **tt-pii-middleware** on
[`pl-pii-synthetic-v1`](https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1)
(n=3000, seed=42). **All identifiers are synthetic.**

| Claim bucket | micro F1 |
|---|---:|
| All labels (incl. soft NER) | **0.956** |
| Public claim set (checksum + structured) | **1.000** |
| Invalid checksum false positives | **0** |

## Reproduce locally

```bash
git clone https://github.com/rrudol/tt-pii-middleware
cd tt-pii-middleware && make install && make eval-public
```

## Honest limits

- Soft labels (PERSON / ORG / ADDRESS) are heuristic — not production NER claims.
- Redaction ≠ GDPR compliance.
- This Space does **not** accept text and does **not** run the detector.
  For interactive redact-only demo see the companion Space.
"""

with gr.Blocks(title="PL-PII Synthetic Metrics") as demo:
    gr.Markdown(INTRO)
    gr.Markdown(RESULTS)
    gr.Markdown(
        "Dataset · [HF](https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1) · "
        "Code · [GitHub](https://github.com/rrudol/tt-pii-middleware) · "
        "Demo · [Space](https://huggingface.co/spaces/rafalrudol/pl-pii-redact-demo)"
    )

if __name__ == "__main__":
    demo.launch()
