# Synthetic eval snapshot

Regenerate with `make eval` / `make eval-public` (seed=42, n=3000).

- docs: **3000**
- avg latency: **31.72 ms/doc**
- micro F1 (all labels): **0.9558** (P=0.9269 R=0.9865)
- public-label micro F1: **1.0000** (P=1.0000 R=1.0000)
- invalid checksum FPs: **0** across PESEL/NIP/REGON/IBAN/DOWOD/CARD

| label | P | R | F1 | support | invalid_fp |
|---|---:|---:|---:|---:|---:|
| ADDRESS | 0.897 | 0.969 | 0.932 | 2702 | 0 |
| CARD | 1.000 | 1.000 | 1.000 | 747 | 0 |
| DOB | 1.000 | 1.000 | 1.000 | 689 | 0 |
| DOWOD | 1.000 | 1.000 | 1.000 | 757 | 0 |
| EMAIL | 1.000 | 1.000 | 1.000 | 2069 | 0 |
| IBAN | 1.000 | 1.000 | 1.000 | 958 | 0 |
| KRS | 1.000 | 1.000 | 1.000 | 309 | 0 |
| NIP | 1.000 | 1.000 | 1.000 | 958 | 0 |
| ORG | 0.645 | 1.000 | 0.784 | 693 | 0 |
| PASSPORT | 1.000 | 1.000 | 1.000 | 245 | 0 |
| PERSON | 0.743 | 0.929 | 0.825 | 2242 | 0 |
| PESEL | 1.000 | 1.000 | 1.000 | 1672 | 0 |
| PHONE | 1.000 | 1.000 | 1.000 | 1367 | 0 |
| PLATE | 1.000 | 1.000 | 1.000 | 557 | 0 |
| POSTAL | 1.000 | 1.000 | 1.000 | 1385 | 0 |
| REGON | 1.000 | 1.000 | 1.000 | 697 | 0 |
