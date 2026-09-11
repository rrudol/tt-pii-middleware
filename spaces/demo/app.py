"""Guardrailed redact-only Gradio demo for Hugging Face Spaces."""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

import gradio as gr

from tt_pii_middleware.analyzer import PiiEngine
from tt_pii_middleware.config import Settings

MAX_CHARS = int(os.environ.get("MAX_TEXT_LENGTH", "2000"))
RATE_LIMIT = int(os.environ.get("DEMO_RATE_LIMIT", "20"))  # per window
RATE_WINDOW = float(os.environ.get("DEMO_RATE_WINDOW_SEC", "60"))

_settings = Settings(
    spacy_model=os.environ.get("SPACY_MODEL", "pl_core_news_sm"),
    spacy_model_en=os.environ.get("SPACY_MODEL_EN", "en_core_web_sm"),
    max_text_length=MAX_CHARS,
    enable_krs=True,
    redis_url=None,
)
_engine = PiiEngine(_settings)

_lock = threading.Lock()
_hits: dict[str, deque[float]] = defaultdict(deque)

EXAMPLES = [
    "Klient Jan Kowalski, PESEL 44051401359, tel. +48 601 234 567, mail jan@example.pl",
    "Faktura: NIP 123-456-32-18, REGON 123456785, IBAN PL61109010140000071219812874",
    "Dowód ABA300000, tablica rejestracyjna WW 12345, adres ul. Długa 5, 00-950 Warszawa",
]


def _client_ip(request: gr.Request | None) -> str:
    if request is None:
        return "unknown"
    # Gradio / HF may forward client IP; fall back safely.
    headers = getattr(request, "headers", None) or {}
    forwarded = headers.get("x-forwarded-for") or headers.get("x-real-ip")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", None) or "unknown"


def _allow(ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


def redact(text: str, mode: str, request: gr.Request | None = None) -> tuple[str, str]:
    text = (text or "").strip()
    if not text:
        return "", "empty input"
    if len(text) > MAX_CHARS:
        return "", f"text exceeds demo limit of {MAX_CHARS} characters"
    ip = _client_ip(request)
    if not _allow(ip):
        return "", f"rate limit: max {RATE_LIMIT} requests / {int(RATE_WINDOW)}s per IP"

    mode = mode if mode in {"replace", "mask", "hash"} else "replace"
    redacted, spans = _engine.redact(text, mode=mode)
    # Metadata only — never echo original entity strings in the summary table
    # beyond what's already visible in the (user-supplied) input box.
    counts: dict[str, int] = {}
    for s in spans:
        counts[s.label] = counts.get(s.label, 0) + 1
    summary = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items())) or "(none)"
    detail_rows = "\n".join(
        f"| {s.label} | {s.start}–{s.end} | {s.score:.2f} |" for s in spans
    ) or "| — | — | — |"
    meta = (
        f"**entities:** {summary}\n\n"
        f"| label | span | score |\n|---|---|---|\n{detail_rows}\n\n"
        "_Demo is redact-only. Mappings are never returned. "
        "Do not paste real production PII._"
    )
    return redacted, meta


INTRO = f"""
# Polish PII redaction demo

Self-hosted stack (Presidio + pii-core + spaCy) with **Polish** identifiers:
PESEL, NIP, REGON, DOWOD, IBAN, plates, phones, …

## Guardrails
- max **{MAX_CHARS}** characters
- **{RATE_LIMIT}** requests / IP / {int(RATE_WINDOW)}s
- **redact only** (no `/anonymize` mapping)
- model: `{_settings.spacy_model}` (CPU)

Synthetic examples only. Redaction ≠ GDPR compliance.
Benchmark: [metrics Space](https://huggingface.co/spaces/rafalrudol/pl-pii-metrics) ·
[dataset](https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1) ·
[source](https://github.com/rrudol/tt-pii-middleware)
"""

with gr.Blocks(title="PL-PII Redact Demo") as demo:
    gr.Markdown(INTRO)
    with gr.Row():
        inp = gr.Textbox(label="Text", lines=8, max_lines=20, placeholder="Wklej tekst…")
    mode = gr.Radio(["replace", "mask", "hash"], value="replace", label="Mode")
    btn = gr.Button("Redact", variant="primary")
    out = gr.Textbox(label="Redacted", lines=8)
    meta = gr.Markdown()
    btn.click(redact, inputs=[inp, mode], outputs=[out, meta])
    gr.Examples(EXAMPLES, inputs=inp)

if __name__ == "__main__":
    demo.queue(default_concurrency_limit=2).launch(
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", "7860")),
        show_api=False,
    )
