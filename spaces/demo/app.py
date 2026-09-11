"""Guardrailed redact-only demo for Tailscale (FastAPI + simple HTML, no Gradio)."""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from html import escape

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from tt_pii_middleware.analyzer import PiiEngine
from tt_pii_middleware.config import Settings

MAX_CHARS = int(os.environ.get("MAX_TEXT_LENGTH", "2000"))
RATE_LIMIT = int(os.environ.get("DEMO_RATE_LIMIT", "30"))
RATE_WINDOW = float(os.environ.get("DEMO_RATE_WINDOW_SEC", "60"))
PORT = int(os.environ.get("PORT", "7860"))

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

app = FastAPI(title="PL-PII Tailnet Demo", docs_url=None, redoc_url=None)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


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


def _page(
    *,
    text: str = "",
    redacted: str = "",
    meta: str = "",
    error: str = "",
    mode: str = "replace",
) -> str:
    examples_html = "".join(
        f'<button type="button" class="ex" data-text="{escape(ex, quote=True)}">'
        f"example {i+1}</button>"
        for i, ex in enumerate(EXAMPLES)
    )
    return f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>PL-PII redact (tailnet)</title>
<style>
  :root {{ font-family: ui-sans-serif, system-ui, sans-serif; color: #0f172a; }}
  body {{ max-width: 920px; margin: 1.5rem auto; padding: 0 1rem; line-height: 1.45; }}
  h1 {{ font-size: 1.35rem; margin-bottom: 0.25rem; }}
  .muted {{ color: #64748b; font-size: 0.92rem; }}
  .warn {{ background: #fff7ed; border: 1px solid #fed7aa; padding: 0.7rem 0.9rem;
           border-radius: 8px; margin: 0.8rem 0 1rem; font-size: 0.92rem; }}
  .err {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b;
          padding: 0.7rem 0.9rem; border-radius: 8px; margin-bottom: 0.8rem; }}
  label {{ display: block; font-weight: 600; margin: 0.6rem 0 0.25rem; }}
  textarea {{ width: 100%; min-height: 140px; box-sizing: border-box;
              border: 1px solid #cbd5e1; border-radius: 8px; padding: 0.6rem; font: inherit; }}
  select, button.primary {{ font: inherit; padding: 0.45rem 0.8rem; border-radius: 8px; }}
  button.primary {{ background: #1d4ed8; color: #fff; border: 0; cursor: pointer; margin-top: 0.6rem; }}
  button.ex {{ margin: 0.2rem 0.3rem 0 0; font: inherit; padding: 0.25rem 0.55rem;
               border: 1px solid #cbd5e1; border-radius: 6px; background: #f8fafc; cursor: pointer; }}
  pre {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
         padding: 0.75rem; white-space: pre-wrap; word-break: break-word; }}
  .meta {{ font-size: 0.9rem; color: #334155; }}
  footer {{ margin-top: 1.5rem; color: #64748b; font-size: 0.85rem; border-top: 1px solid #e2e8f0; padding-top: 0.8rem; }}
</style>
</head>
<body>
  <h1>Polish PII redaction — tailnet demo</h1>
  <p class="muted">Presidio + pii-core + spaCy (<code>{escape(_settings.spacy_model)}</code>).
  Bound to Tailscale only. Redact-only · max {MAX_CHARS} chars · {RATE_LIMIT} req/IP/{int(RATE_WINDOW)}s.</p>
  <div class="warn"><strong>Do not paste real production PII.</strong>
  Synthetic examples only. Redaction ≠ GDPR compliance.</div>
  {"<div class='err'>" + escape(error) + "</div>" if error else ""}
  <form method="post" action="/redact">
    <label for="text">Text</label>
    <textarea id="text" name="text" maxlength="{MAX_CHARS}" required>{escape(text)}</textarea>
    <div>{examples_html}</div>
    <label for="mode">Mode</label>
    <select id="mode" name="mode">
      <option value="replace" {"selected" if mode=="replace" else ""}>replace (&lt;LABEL&gt;)</option>
      <option value="mask" {"selected" if mode=="mask" else ""}>mask (***)</option>
      <option value="hash" {"selected" if mode=="hash" else ""}>hash</option>
    </select>
    <div><button class="primary" type="submit">Redact</button></div>
  </form>
  {"<label>Redacted</label><pre>" + escape(redacted) + "</pre>" if redacted else ""}
  {"<p class='meta'>" + meta + "</p>" if meta else ""}
  <footer>
    Source: <a href="https://github.com/rrudol/tt-pii-middleware">tt-pii-middleware</a>
    · Dataset: <a href="https://huggingface.co/datasets/rafalrudol/pl-pii-synthetic-v1">pl-pii-synthetic-v1</a>
    · JSON: <code>POST /api/redact</code>
  </footer>
  <script>
    document.querySelectorAll('button.ex').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.getElementById('text').value = btn.getAttribute('data-text');
      }});
    }});
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _page()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "pl-pii-tailnet-demo", "model": _settings.spacy_model}


@app.post("/redact", response_class=HTMLResponse)
def redact_form(
    request: Request,
    text: str = Form(""),
    mode: str = Form("replace"),
) -> HTMLResponse:
    text = (text or "").strip()
    mode = mode if mode in {"replace", "mask", "hash"} else "replace"
    if not text:
        return HTMLResponse(_page(error="empty input", mode=mode))
    if len(text) > MAX_CHARS:
        return HTMLResponse(_page(text=text[:MAX_CHARS], error=f"max {MAX_CHARS} characters", mode=mode))
    ip = _client_ip(request)
    if not _allow(ip):
        return HTMLResponse(
            _page(text=text, error=f"rate limit: {RATE_LIMIT}/{int(RATE_WINDOW)}s per IP", mode=mode)
        )
    redacted, spans = _engine.redact(text, mode=mode)
    counts: dict[str, int] = {}
    for s in spans:
        counts[s.label] = counts.get(s.label, 0) + 1
    summary = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items())) or "(none)"
    rows = " · ".join(f"{s.label}@{s.start}-{s.end}" for s in spans) or "—"
    meta = f"entities: <strong>{escape(summary)}</strong><br/>spans: {escape(rows)}"
    return HTMLResponse(_page(text=text, redacted=redacted, meta=meta, mode=mode))


@app.post("/api/redact")
async def redact_api(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    text = str(body.get("text") or "").strip()
    mode = body.get("mode") or "replace"
    if mode not in {"replace", "mask", "hash"}:
        return JSONResponse({"error": "mode must be replace|mask|hash"}, status_code=400)
    if not text:
        return JSONResponse({"error": "empty text"}, status_code=400)
    if len(text) > MAX_CHARS:
        return JSONResponse({"error": f"max {MAX_CHARS} characters"}, status_code=413)
    if not _allow(_client_ip(request)):
        return JSONResponse({"error": "rate limited"}, status_code=429)
    redacted, spans = _engine.redact(text, mode=mode)
    return JSONResponse(
        {
            "redacted_text": redacted,
            "entities": [
                {"start": s.start, "end": s.end, "label": s.label, "score": s.score}
                for s in spans
            ],
            # deliberately omit matched text substrings in API demo response
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT, access_log=False)
