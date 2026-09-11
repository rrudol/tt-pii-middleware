# tt-pii-middleware

Thinking Typewriters PII detection & redaction middleware for the EU inference
gateway. Detects and redacts Polish + universal PII **before prompts leave the
in-VPC perimeter**. Fully self-hosted: no SaaS DLP (Nightfall, Azure DLP, …)
anywhere in the path, and the runtime container needs no network egress —
models are baked into the image at build time.

## Architecture

```
                   ┌────────────────────────────────────────────────┐
 client /          │  tt-pii-middleware (FastAPI, port 8080)        │
 LiteLLM hook ───► │                                                │
                   │  Presidio AnalyzerEngine                       │
                   │   ├─ pii-presidio / pii-core  (checksums)      │
                   │   │    PESEL · NIP · REGON · PL-IBAN ·         │
                   │   │    passport · credit card (Luhn) · EMAIL   │
                   │   ├─ custom TT recognizers   (eval gap fixes)  │
                   │   │    DOWOD (checksum!) · PHONE (PL formats)  │
                   │   │    PLATE · POSTAL · ADDRESS · DOB ·        │
                   │   │    KRS (context-gated opt-in)              │
                   │   ├─ Presidio built-ins                        │
                   │   │    IBAN (multi-country mod-97)             │
                   │   └─ spaCy NER  pl_core_news_md / en_core_web_sm
                   │        PERSON · ORG · LOCATION · dates         │
                   │                                                │
                   │  post-processing: TT label mapping, DOB        │
                   │  gating, overlap dedupe (pattern beats NER)    │
                   │                                                │
                   │  Presidio AnonymizerEngine (mask/replace/hash) │
                   │  + reversible [LABEL_NNN] pseudonymization     │
                   └───────────────┬────────────────────────────────┘
                                   │ optional (profile: vault)
                              ┌────▼────┐
                              │  Redis  │  short-TTL mapping vault
                              └─────────┘
```

Layout: `src/tt_pii_middleware/{app,analyzer,recognizers,config,logging}.py`
— HTTP surface, engine + label mapping, recognizer definitions, env config,
and JSON logging respectively.

## Quick start

```bash
docker compose up --build
```

**First boot:** the *image build* downloads the two spaCy models (~60 MB) from
GitHub releases; at *runtime* nothing is downloaded — the container just loads
the models from disk, which takes ~15–30 s. The compose healthcheck allows a
90 s start period. After that:

```bash
curl -s localhost:8080/health | python3 -m json.tool
```

Interactive OpenAPI docs: <http://localhost:8080/docs>.

With the optional Redis mapping vault:

```bash
REDIS_URL=redis://redis:6379/0 docker compose --profile vault up --build
```

Local development (Python 3.11+):

```bash
make install   # venv + pinned deps + spaCy models
make test      # pytest
make run       # uvicorn on :8080 with reload
```

## API

All example identifiers below are synthetic (checksum-valid but never issued).

### `GET /health`

Liveness + loaded model/recognizer flags:

```bash
curl -s localhost:8080/health
# {"status":"ok","version":"0.1.0","models_loaded":{"pl":"pl_core_news_md","en":"en_core_web_sm"},
#  "languages":["pl","en"],"recognizers_loaded":[...],"labels":[...],"redis_vault":"disabled"}
```

### `POST /v1/analyze` — detection only

```bash
curl -s localhost:8080/v1/analyze -H 'content-type: application/json' -d '{
  "text": "Jan Kowalski, PESEL 44051401359, tel. +48 601 234 567"
}'
# {"language":"pl","spans":[
#   {"start":0,"end":12,"label":"PERSON","score":0.85,"text":"Jan Kowalski"},
#   {"start":20,"end":31,"label":"PESEL","score":1.0,"text":"44051401359"},
#   {"start":38,"end":53,"label":"PHONE","score":1.0,"text":"+48 601 234 567"}]}
```

Optional fields: `language` (`"pl"` default, `"en"`), `entities` (restrict to
TT labels), `score_threshold` (override), `include_text: false` (omit matched
substrings from the response).

### `POST /v1/redact` — one-way redaction

`mode` is `"replace"` (default), `"mask"` or `"hash"`:

```bash
curl -s localhost:8080/v1/redact -H 'content-type: application/json' -d '{
  "text": "PESEL 44051401359, NIP 123-456-32-18, REGON 123456785, mail jan@example.pl"
}'
# {"redacted_text":"PESEL <PESEL>, NIP <NIP>, REGON <REGON>, mail <EMAIL>", ...}

curl -s localhost:8080/v1/redact -H 'content-type: application/json' \
  -d '{"text": "PESEL 44051401359", "mode": "mask"}'
# {"redacted_text":"PESEL ***********", ...}
```

`hash` emits a salted (env `HASH_SALT`) truncated SHA-256, so the same value
maps to the same stable pseudonym without being reversible.

### `POST /v1/anonymize` — reversible pseudonymization

Replaces each entity with a `[LABEL_NNN]` token; the same value always gets
the same token within a request. The mapping is returned to the caller and is
**not persisted** by the service — unless `REDIS_URL` is configured, in which
case it is also parked under a random `session_id` with a short TTL
(`MAPPING_TTL_SECONDS`, default 900 s).

```bash
curl -s localhost:8080/v1/anonymize -H 'content-type: application/json' -d '{
  "text": "Klient 44051401359, kontakt jan@example.pl. PESEL 44051401359 ponownie."
}'
# {"anonymized_text":"Klient [PESEL_001], kontakt [EMAIL_001]. PESEL [PESEL_001] ponownie.",
#  "mapping":{"[PESEL_001]":"44051401359","[EMAIL_001]":"jan@example.pl"}, ...}
```

### `POST /v1/restore`

Restores tokens from a `mapping` (or a `session_id` when the Redis vault is
enabled) — e.g. to re-personalize an LLM response:

```bash
curl -s localhost:8080/v1/restore -H 'content-type: application/json' -d '{
  "text": "Napisz do [EMAIL_001] w sprawie [PESEL_001].",
  "mapping": {"[PESEL_001]":"44051401359","[EMAIL_001]":"jan@example.pl"}
}'
# {"restored_text":"Napisz do jan@example.pl w sprawie 44051401359."}
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Log verbosity (JSON logs on stdout). |
| `SPACY_MODEL` | `pl_core_news_md` | Polish spaCy model (use `pl_core_news_sm` on small nodes). |
| `SPACY_MODEL_EN` | `en_core_web_sm` | English spaCy model. |
| `DEFAULT_LANGUAGE` | `pl` | Language used when a request omits `language`. |
| `SCORE_THRESHOLD` | `0.4` | Minimum score for a span to be reported. |
| `REDIS_URL` | *(unset)* | Enables the short-TTL anonymization-mapping vault. |
| `MAPPING_TTL_SECONDS` | `900` | Vault TTL. |
| `ENABLE_KRS` | `false` | Opt-in KRS recognizer (context-gated, see below). |
| `HASH_SALT` | *(empty)* | Salt for `mode=hash` digests. |
| `MAX_TEXT_LENGTH` | `100000` | Requests with longer `text` get HTTP 413. |

## Detection stack & label mapping

Eval baseline (3000 synthetic PL docs): PESEL/NIP/REGON/IBAN ≈ R 1.0 with 0 FP
on invalid checksums; EMAIL/POSTAL/PASSPORT/CARD excellent; gaps closed here:
PLATE (was 0), PHONE formats, DOWOD FPs. ORG/DOB/ADDRESS remain approximate.

| TT label | Presidio entity | Source | Validation |
|---|---|---|---|
| PESEL | `PL_PESEL` | pii-core via pii-presidio | weighted checksum |
| NIP | `PL_NIP` | pii-core via pii-presidio | mod-11 checksum |
| REGON | `PL_REGON` | pii-core via pii-presidio | checksum (9 & 14 digit) |
| IBAN | `IBAN_CODE` | pii-core (PL) + Presidio built-in (multi-country) | mod-97 |
| CARD | `CREDIT_CARD` | pii-core via pii-presidio | Luhn |
| PASSPORT | `PL_PASSPORT` | pii-core via pii-presidio | regex + context |
| DOWOD | `PL_ID_CARD` | **custom** `DowodRecognizer` | official 7-3-1 checksum — invalid serials are dropped (fixes the 100 % FP-on-lookalikes eval finding) |
| PHONE | `PHONE_NUMBER` | **custom** `PlPhoneRecognizer` | `+48XXXXXXXXX`, `+48 XX XXX XX XX`, `XXX XXX XXX`, `XX XXX XX XX`; bare 9 digits only with context ("tel", …) |
| PLATE | `PL_PLATE` | **custom** `PlPlateRecognizer` | shape + voivodeship first letter + plate-legal suffix letters |
| POSTAL | `PL_POSTAL_CODE` | **custom** | `XX-XXX` |
| KRS | `PL_KRS` | **custom**, `ENABLE_KRS=true` only | context-gated: base score 0.1, only boosted past the threshold by "KRS" nearby |
| ADDRESS | `PL_ADDRESS` + `LOCATION` | **custom** street regex (`ul./al./os./pl. Name 1/5`) + spaCy place/geo NER | heuristic |
| DOB | `PL_DOB` + `DATE_TIME` | **custom** date shapes + spaCy dates | kept **only** when a birth keyword ("ur.", "urodzony", "data urodzenia", "born", …) directly precedes; other dates are dropped |
| PERSON | `PERSON` | spaCy NER | statistical |
| ORG | `ORGANIZATION` | spaCy NER | statistical |
| EMAIL | `EMAIL_ADDRESS` | pii-core via pii-presidio | regex + context (Presidio's built-in e-mail recognizer is deliberately **not** used: it validates via `tldextract`, which downloads the public suffix list at runtime — forbidden egress in the VPC) |

Post-processing (in `analyzer.py`): overlap dedupe where checksum/pattern
matches always beat statistical NER spans (prevents spaCy's fondness for
tagging "KR"-style tokens as ORG from eating plate/ID matches), plus a
denylist dropping NER spans that are just identifier keywords ("KRS", "NIP").

### Documented FP/FN risks

- **PLATE**: the "2–3 letters + 4–5 alphanumerics" shape collides with
  standard references ("PN 12345"), invoice and serial numbers. Mitigations:
  case-sensitive matching, voivodeship first letter, plate-legal suffix
  alphabet, **standards-prefix denylist** (PN/EN/ISO/…), base score 0.3 so
  bare plates need vehicle context ("tablica", "rej.") to cross 0.4.
- **POSTAL**: `XX-XXX` also matches numeric ranges ("10-100"). Base score 0.3
  plus address/city context; bare ranges are dropped.
- **KRS**: 10 digits with **no checksum** — that's why it is opt-in and
  context-gated (a bare 10-digit number is more often a NIP or nothing).
- **ADDRESS**: street regex covers the common `ul. Nazwa 12/3` shape; streets
  starting with a number ("ul. 3 Maja 5") and free-form addresses rely on
  spaCy NER, which the eval showed is approximate (exact-match ≈ 0).
- **ORG / DOB**: statistical NER, weak per eval; DOB additionally requires a
  birth keyword, so unlabeled birth dates are missed by design (favoring
  precision).
- **Bare 9-digit phones** need nearby context words to cross the threshold.

### Remaining gaps / next steps

- **GLiNER** (or another transformer NER) as an optional second NER pass to
  lift PERSON recall further — legal-form ORG pattern covers `Sp. z o.o.` / `S.A.`
  in v0.1.1; free-form org names remain approximate.
- Passport checksum validation (currently regex + context, matching eval).
- Cross-request pseudonym consistency (mapping is request-scoped by design).
- Public Hugging Face dataset + optional demo Space — see
  [`docs/PUBLIC_RELEASE_PLAN.md`](docs/PUBLIC_RELEASE_PLAN.md).

## Synthetic evaluation (Polish docs)

Reproducible exact-span suite (checksum-valid synthetic IDs only):

```bash
make corpus        # data/synthetic/pl_pii_v1.jsonl  (n=3000, seed=42)
make eval          # MVP gates  → eval/results/latest.json
make eval-public   # public claim set (no soft NER labels)
```

Headline numbers (seed=42, n=3000, ~30 ms/doc on Apple Silicon):

| bucket | micro F1 |
|---|---:|
| All labels | **0.955** |
| Public claim set (PESEL/NIP/REGON/IBAN/DOWOD/CARD/EMAIL/PHONE/POSTAL/PLATE/PASSPORT/KRS/DOB) | **≥ 0.99** |
| Invalid checksum false positives | **0** |

Per-label table: [`eval/RESULTS.md`](eval/RESULTS.md). Gates:
`eval/gates_mvp.json`, `eval/gates_public.json`.

## Public release (Hugging Face)

Plan and cards:

- [`docs/PUBLIC_RELEASE_PLAN.md`](docs/PUBLIC_RELEASE_PLAN.md) — phased HF dataset → Space → OSS
- [`docs/hf/DATASET_CARD.md`](docs/hf/DATASET_CARD.md) — card for `PL-PII-Synthetic-v1`
- [`docs/hf/MODEL_CARD.md`](docs/hf/MODEL_CARD.md) — service card (claims + limitations)

**Recommended first public artifact:** the synthetic dataset only (no real PII,
reproducible, useful to others). Shipping the full service image requires an
OSS license decision on `src/`.

## Threat model — redaction ≠ GDPR compliance

This service is a **risk-reduction layer**, not a compliance guarantee:

- Detection is probabilistic. Misspelled names, novel identifier formats,
  OCR noise and adversarial encodings (base64, homoglyphs, "four four zero
  five…") will get through. Assume non-zero residual PII downstream.
- Re-identification remains possible from context that is not PII per se
  ("the CFO of the only bakery in Głogów").
- `/v1/anonymize` mappings are returned to the caller; whoever holds the
  mapping (or the Redis vault) can re-identify. Guard the vault like the
  original data; keep `MAPPING_TTL_SECONDS` short.
- `mode=hash` pseudonyms are stable per salt: rotate `HASH_SALT` if linkage
  across datasets becomes a risk, and treat the salt as a secret.
- The service logs **entity types and counts only, never text** — keep it
  that way when extending (`logging.py` docstring).
- Trust boundary: anyone who can reach this HTTP API can submit text and read
  results. Run it inside the VPC, unexposed, with TLS/authn at the gateway in
  front of it.

GDPR lawfulness of processing, data-subject rights, DPIAs, retention and the
question whether redacted text still counts as personal data remain the
responsibility of the calling system and your DPO.

## LiteLLM hook

Wire it as a pre/post-call hook so prompts are cleaned before leaving the VPC:

```python
# custom_callbacks.py (LiteLLM proxy) - sketch
import httpx

PII = "http://pii-middleware:8080"

async def async_pre_call_hook(user_api_key_dict, cache, data, call_type):
    for message in data.get("messages", []):
        if isinstance(message.get("content"), str):
            response = httpx.post(
                f"{PII}/v1/anonymize", json={"text": message["content"]}
            ).json()
            message["content"] = response["anonymized_text"]
            # stash response["mapping"] (or session_id) in request metadata
            # and call /v1/restore on the model output in the post-call hook
    return data
```

`/v1/redact` (one-way) is the safer default if you don't need restoration.

## Tests

```bash
make test          # unit + API (synthetic IDs only)
make eval          # 3000-doc exact-span suite + quality gates
```

Unit/API covers: DOWOD/PESEL/NIP/REGON/IBAN/Luhn checksums (valid + invalid),
sample Polish strings for every label, phone formats, KRS/DOB/PLATE/POSTAL
context gating, standards-prefix plate rejection, REGON↔CARD / KRS↔NIP
disambiguation, overlap dedupe, redact modes, anonymize/restore round-trip,
request validation and `/health`. No real PII appears anywhere in the suite.

## License

Proprietary — Copyright (c) 2026 Thinking Typewriters. All rights reserved.
See [NOTICE](NOTICE).
