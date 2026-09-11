# License audit (Phase 4 gate)

Audit date: 2026-09-11. All direct runtime dependencies are OSI-approved
and compatible with releasing **this repository** under **Apache-2.0**.

| Package | Version pinned | License | Upstream |
|---|---|---|---|
| pii-core | 0.1.0 | Apache-2.0 | https://github.com/pii-toolkit/pii-core |
| pii-presidio | 0.1.0 | Apache-2.0 | https://github.com/pii-toolkit/pii-presidio |
| pii-veil | 0.1.0 | Apache-2.0 | https://github.com/pii-toolkit/pii-veil |
| presidio-analyzer | 2.2.364 | MIT | https://github.com/data-privacy-stack/presidio |
| presidio-anonymizer | 2.2.364 | MIT | https://github.com/data-privacy-stack/presidio |
| spacy | 3.8.16 | MIT | https://spacy.io |
| pl_core_news_md / sm | 3.8.0 | MIT (spaCy model license) | Explosion releases |
| en_core_web_sm | 3.8.0 | MIT | Explosion releases |
| fastapi | 0.141.1 | MIT | https://github.com/fastapi/fastapi |
| uvicorn | 0.52.4 | BSD-3-Clause | encode/uvicorn |
| pydantic-settings | 2.15.0 | MIT | pydantic |
| redis (redis-py) | 8.1.0 | MIT | redis/redis-py |
| gradio (demo Space only) | 4.44.1 | Apache-2.0 | gradio-app/gradio |

## Decision

- **Project license:** Apache-2.0 (aligns with pii-toolkit; patent grant useful
  for a security/privacy middleware).
- **No copyleft** dependencies in the runtime path.
- **spaCy models** are downloaded at image build / `make install` from GitHub
  releases under their model licenses (MIT); not vendored in git.

## Residual notes

- Redis server (optional vault) is a separate process; image is Redis' own license.
- Hugging Face Spaces may add their own ToS on top of this license for hosted demos.
- Trademark: "Thinking Typewriters" name remains with the authors; license covers code.

## Verification commands

```bash
python -c "from importlib.metadata import metadata
for n in ['pii-core','pii-presidio','pii-veil','presidio-analyzer','presidio-anonymizer','spacy','fastapi']:
 print(n, metadata(n).get('License') or metadata(n).get('License-Expression'))"
```
