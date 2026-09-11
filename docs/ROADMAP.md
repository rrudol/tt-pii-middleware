# Roadmap (after public v0.1)

Shipped in v0.1.0-public: Polish PII middleware, synthetic eval suite, HF dataset,
metrics Space, guardrailed redact demo, Apache-2.0.

## Phase 5+ backlog (planned next)

Ordered for the next public cycle after v0.1.0-public:

1. **Tailnet demo (done)** — https://guard.rudol.dev (`deploy/tailnet` + radium-226 `apps-static/guard`).
1b. ~~HF live Space~~ — declined; free tier blocks Gradio/Docker (402 PRO).
2. **GHCR multi-arch image** — `ghcr.io/rrudol/tt-pii-middleware:0.1.0` (amd64/arm64), SBOM, cosign.
3. **CI badge + release automation** — tag → build → push image → refresh Spaces.
4. **Org namespace** — transfer GH/HF artifacts to `thinking-typewriters` when org is ready.
5. **Passport checksum + adversarial eval pack** — close known gaps, publish residual-risk numbers.
6. **LiteLLM plugin package** — installable callback, not just README sketch.
7. **Optional GLiNER extra** — `pip install tt-pii-middleware[gliner]`.
8. **Human-licensed PL eval slice** — small consented set; keep synthetic as regression.

## Now / next (P0 — 1–2 weeks)

| Item | Why | Notes |
|---|---|---|
| CI on GitHub Actions | `make test` + `make eval-public` on PR | cache spaCy wheels |
| Tag & GHCR image | `ghcr.io/rrudol/tt-pii-middleware:0.1.0` | multi-arch amd64/arm64 |
| HF org transfer | move dataset/spaces under `thinking-typewriters` when org exists | keep redirects |
| Demo uptime check | weekly canary curl on Space | alert on cold-start failures |
| Changelog | Keep a CHANGELOG.md from here on | |

## Near-term quality (P1 — 2–6 weeks)

| Item | Why |
|---|---|
| Passport checksum (PL) | regex+context only today |
| GLiNER / transformer NER optional pass | lift PERSON recall without tanking precision |
| Better ORG beyond legal-form suffix | gazetteer + NER hybrid |
| Address: numbered streets (`ul. 3 Maja`) | known FN |
| Multi-country IBAN already OK; add CZ/SK/DE national IDs as opt-in packs | EU gateway expansion |
| Adversarial suite | base64, homoglyphs, digit words — measure residual risk honestly |

## Product / integration (P1)

| Item | Why |
|---|---|
| Official LiteLLM callback package | sketch exists in README |
| OpenAI-compatible middleware sidecar helm chart | k8s one-liner |
| OpenTelemetry spans (entity counts only) | ops |
| Cross-request pseudonym vault with explicit TTL API | today request-scoped |
| Policy profiles (`strict-pl`, `finance`, `hr`) | entity allow-lists per use case |

## Research / stretch (P2)

| Item | Why |
|---|---|
| Fine-tuned PL token classifier on synthetic+augmented data | publish weights on HF |
| OCR-aware pre-processor | scanned invoices |
| Differential privacy / k-anonymity guidance docs | education, not a feature |
| Human eval set (consented, licensed) | synthetic alone overfits templates |

## Explicit non-goals

- Claiming GDPR certification
- Hosting a free unlimited redaction SaaS
- Training on real customer prompts
