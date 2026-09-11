---
license: other
license_name: synthetic-eval-only
license_link: https://github.com/rrudol/tt-pii-middleware
language:
  - pl
  - en
task_categories:
  - token-classification
pretty_name: PL-PII-Synthetic-v1
tags:
  - pii
  - privacy
  - poland
  - pesel
  - nip
  - synthetic
size_categories:
  - 1K<n<10K
---

# PL-PII-Synthetic-v1

**Synthetic** Polish (+ light English) PII evaluation corpus for exact-span
detection benchmarks. **No real personal data.** Every PESEL / NIP / REGON /
IBAN / DOWOD / CARD value is checksum-valid but invented; names, streets and
companies are drawn from fixed fictional lists.

> **Do not train production NER on this corpus alone.** Templates are
> regular and will overfit. Intended use: regression tests, detector
> comparison, CI quality gates, demos.

## Generation

```bash
make corpus          # data/synthetic/pl_pii_v1.jsonl  (n=3000, seed=42)
# or
python scripts/generate_corpus.py --n 3000 --seed 42 -o pl_pii_v1.jsonl
```

Deterministic: same seed → bit-identical JSONL on any machine with the same
`scripts/synthetic_ids.py` + `scripts/generate_corpus.py`.

## Schema (JSONL)

```json
{
  "id": "doc-000042",
  "template": "umowa",
  "language": "pl",
  "text": "…",
  "entities": [
    {"start": 12, "end": 23, "label": "PESEL", "text": "44051401359"}
  ]
}
```

Offsets are Python string indices (`text[start:end] == entity["text"]`).

## Templates

| template | share (seed=42) | content |
|---|---:|---|
| umowa | ~15% | contract: PERSON, PESEL, DOWOD, DOB, ADDRESS, POSTAL, EMAIL, PHONE |
| faktura | ~13% | invoice: ORG, NIP, REGON, IBAN, ADDRESS, POSTAL, EMAIL |
| mixed | ~10% | dense multi-label kitchen sink |
| crm / email / przelew / pojazd / paszport | ~40% | operational docs |
| neg_checksum | ~6% | invalid PESEL/NIP/IBAN/DOWOD (gold empty for those IDs) |
| neg_noise | ~6% | standards codes, ranges, bare digits (gold empty) |
| en_mixed | ~4% | English wrapper around PL identifiers |

## Labels

`PESEL NIP REGON KRS DOWOD PASSPORT IBAN PHONE EMAIL POSTAL ADDRESS DOB CARD PLATE PERSON ORG`

## Matching policy (recommended)

- **Exact span**: `(start, end, label)` must match gold.
- Checksum labels: any prediction whose text fails the official checksum is an
  **invalid FP** (must be 0 for a trustworthy detector).
- Soft NER labels (`PERSON`, `ORG`, `ADDRESS`) are approximate; do not claim
  production-grade NER from this set alone.

## Ethics / privacy

- All identifiers are synthetic. Checksum validity ≠ issuance.
- Do not attempt to reverse any value into a real person — there is none.
- Redistribute freely with this card; keep the “synthetic only” notice.

## Citation

```
@software{tt_pii_middleware_2026,
  title  = {tt-pii-middleware and PL-PII-Synthetic-v1},
  author = {Thinking Typewriters},
  year   = {2026},
  url    = {https://github.com/rrudol/tt-pii-middleware}
}
```
