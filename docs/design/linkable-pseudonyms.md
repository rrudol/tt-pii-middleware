# Design: hard linkable pseudonyms (v1)

> Implementation blueprint for ADR 0002.  
> Goal: **maximum practical strength** for “same PESEL → same token” without lying about GDPR.

---

## 1. Goals and non-goals

### Goals

| ID | Goal |
|---|---|
| G1 | Deterministic: identical canonical identifier + purpose + key version → identical token |
| G2 | Different purposes/tenants → **unlinkable** tokens by default |
| G3 | No raw PESEL/NIP/… in outbound prompt/body when policy says linkable |
| G4 | Fail closed if key material missing/invalid for linkable profiles |
| G5 | Key rotation with explicit version in the token |
| G6 | Constant-time MAC verify path for any future check API; no secret in logs |
| G7 | Honest API: response metadata marks `pseudonymised: true`, never `anonymised` |

### Non-goals (v1)

- Full anonymisation / k-anonymity / differential privacy
- Format-preserving PESEL lookalikes as default
- Multi-party computation / blind HMAC service (v2 option)
- Automatic DSAR reverse across all historical tokens without vault

---

## 2. Threat model

| Threat | Severity | Mitigation |
|---|---|---|
| T1 Dictionary attack on PESEL given token stream | High | HMAC with 256-bit key; key not in dataset; optional pepper in HSM |
| T2 Key leak from env/Docker image | High | Prefer KMS/file mode 0400; never bake key in image; rotate |
| T3 Cross-tenant join via shared global hash | High | HKDF purpose includes `tenant_id` |
| T4 Cross-purpose join (logs ↔ LLM ↔ analytics) | Med | Separate `purpose` labels → separate derived keys |
| T5 Prompt injection asking model to echo secrets | Med | Tokens carry no invertible material; still don’t put key near model |
| T6 Timing/oracle on compare | Low | No online “is this PESEL?” API in v1; if added, use `hmac.compare_digest` |
| T7 Token shortened too much → collisions | Med | Default 15 bytes binary → 20 base64url chars; document birthday bound |
| T8 Re-ident via context (“CFO of only bakery in X”) | Residual | Out of scope of crypto; policy/minimise context |
| T9 Demo/prod key mix-up | High | Separate key paths; `guard.rudol.dev` **refuses** linkable without explicit demo key |

**Assumed adversary:** can read all redacted prompts/logs; cannot read KMS/HMAC key; may know algorithm.

**Not assumed:** adversary with key + PESEL dictionary — then linkable mode **fails open to re-ID**. Treat key like production DB credentials.

---

## 3. Architecture

```
                    ┌─────────────────────────────────────────────┐
  text + policy ──► │  PiiEngine.analyze (unchanged detection)    │
                    └──────────────────┬──────────────────────────┘
                                       │ spans[{label,start,end,text}]
                    ┌──────────────────▼──────────────────────────┐
                    │  Pseudonymizer (new module)                 │
                    │  1. canonicalize(label, text)               │
                    │  2. derive_key(master, purpose, kid)        │
                    │  3. mac = HMAC-SHA256(key, msg)             │
                    │  4. token = format(label, kid, mac)         │
                    └──────────────────┬──────────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
        redacted_text            token_index              audit event
        (safe to egress)         (optional opaque         (counts + kid +
                                  handles, no PII)         purpose only)
```

### Modules

| Module | Responsibility |
|---|---|
| `canonical.py` | Normalise identifier **before** MAC (critical for stability) |
| `keystore.py` | Load master secrets; HKDF derive; cache; never log |
| `pseudonymizer.py` | HMAC + token format; batch map for a request |
| `profiles.py` | Named policies → concrete transform graph |
| `app.py` | Wire `/v1/redact` profile + fields; reject weak config |

Detection stack stays as-is. Pseudonym plane is **post-detect only**.

---

## 4. Cryptography (normative)

### 4.1 Master secret

- Length: **≥ 32 bytes** cryptographically random (`secrets.token_bytes(32)`).
- Storage (priority order):
  1. **KMS/HSM envelope** (AWS KMS, GCP KMS, Vault transit) — v1 can start with “file + external encrypt”
  2. File path `PSEUDONYM_MASTER_KEY_FILE` (raw 32+ bytes or base64), mode `0400`, not in git
  3. Env `PSEUDONYM_MASTER_KEY_B64` — **dev only**, refuse if `ENV=prod` and this is the sole source (configurable hard gate)

**Never** reuse `HASH_SALT` as HMAC key. Migrate `hash` → new material.

### 4.2 Key derivation (per purpose)

```text
master_key_id = "v1" | "v2" | ...     # explicit rotation label
purpose       = "llm-gateway" | "eval" | "logs" | "demo" | ...
tenant        = caller tenant id or "_" 

IKM  = master_secret[master_key_id]
info = UTF8( "tt-pii-pseudo/v1|" || purpose || "|" || tenant )
salt = UTF8( "tt-pii-hkdf-salt/v1" )   # fixed public salt for HKDF; domain separation only

purpose_key = HKDF-SHA256(
                ikm  = IKM,
                salt = salt,
                info = info,
                L    = 32)
```

- Same PESEL under `purpose=llm-gateway, tenant=acme` ≠ under `purpose=logs, tenant=acme`.
- Demo purpose key **must** be a separate master or at least separate purpose with non-prod IKM.

### 4.3 Message construction

```text
canonical = canonicalize(label, raw_span_text)   # see §5
msg = UTF8( "tt-pii/v1\n" || label || "\n" || canonical )
mac = HMAC-SHA256(purpose_key, msg)              # 32 bytes
```

Domain separation string prevents cross-protocol MAC reuse.

### 4.4 Token format (wire)

```text
{LABEL}_{kid}_{base64url(mac[0:N])}

Examples:
  PESEL_v1_xK9mQ2nL0pRsT7uVwXyZ
  NIP_v1_aBcdEfGhIjKlMnOpQrSt
```

| Field | Rule |
|---|---|
| `LABEL` | TT label uppercase (`PESEL`, `NIP`, …) |
| `kid` | key id / version (`v1`); regex `[a-z0-9]{1,8}` |
| payload | base64url **without padding**, from first **N=15** bytes of MAC (120 bits) |
| charset | `A–Za–z0–9_-` only — safe in prompts/JSON |

**Birthday bound:** 120-bit truncated MAC → collision ~2^60 (negligible for practical PESEL sets).

**Optional long form** (`N=32`, full MAC) for storage/index systems that never touch LLMs.

### 4.5 Why not AES-SIV / FPE as default

| Primitive | Use in this design |
|---|---|
| HMAC | **Default linkable** outbound |
| AES-SIV deterministic | Optional **v1.1** `reversible=true` when DSAR reverse required without vault blob |
| FF1 FPE | **Opt-in only** if a downstream system requires 11-digit shape; never default |

AES-SIV sketch (v1.1): `token = LABEL_kid_SIV_` ‖ base64url(AES-SIV-encrypt(purpose_key, msg)). Reverse endpoint requires authz + audit.

---

## 5. Canonicalization (stability = correctness)

If canonicalize is wrong, the **same human PESEL** becomes two tokens.

| Label | Canonical form |
|---|---|
| PESEL | strip spaces; digits only; reject if not 11 digits |
| NIP | strip spaces/dashes; digits only; 10 digits |
| REGON | digits only; 9 or 14 |
| DOWOD | upper A–Z + digits; strip spaces; length 9 |
| IBAN | upper; strip spaces; full IBAN string |
| CARD | digits only (Luhn input); never keep spaces |
| EMAIL | NFKC; trim; **lower-case** domain; local-part as-is unless policy `email_local_lower` |
| PHONE | E.164 if parseable (`+48…`); else digits with leading country if present |
| PASSPORT | upper alnum strip spaces |
| PLATE | upper; single space collapsed; strip |
| PERSON/ORG/ADDRESS/DOB | NFKC; trim; collapse internal whitespace to single space; casefold for PERSON/ORG **optional flag** (default: preserve case for display fidelity → may split “Kowalski”/“kowalski”) |

**Rule:** MAC input is canonical; **display token never embeds canonical**. Failed canonicalize → fall back to `replace` (`<LABEL>`) for that span and count `pseudo_fallback` (don’t fail whole request unless `strict_pseudonym=true`).

---

## 6. Policy profiles

Named profiles beat raw `mode=` soup.

| Profile | Detection | Transform | Linkable | Reverse | Typical use |
|---|---|---|---|---|---|
| `strict` | all | `replace` | no | no | external LLM, max privacy |
| `mask` | all | `mask` | no | no | human screenshots |
| `session` | all | `[LABEL_NNN]` + mapping | request-local | yes (mapping/vault) | chat turn restore |
| `linkable` | all | HMAC tokens | **cross-request** | no | gateway co-ref, eval |
| `linkable_strict` | checksum labels only* | HMAC; NER → replace | partial | no | when names are too re-ID heavy |
| `dual` | all | HMAC in text **and** encrypted sidecar map | yes | yes (authz) | rare; regulated analytics |

\*checksum-ish: PESEL NIP REGON DOWOD IBAN CARD EMAIL PHONE PASSPORT PLATE KRS (+ optional POSTAL)

### Request shape (proposed)

```json
POST /v1/redact
{
  "text": "…",
  "profile": "linkable",
  "purpose": "llm-gateway",
  "tenant_id": "acme",
  "key_id": "v1",
  "language": "pl",
  "entities": null,
  "options": {
    "token_bytes": 15,
    "strict_pseudonym": false,
    "include_entity_text": false
  }
}
```

### Response shape

```json
{
  "language": "pl",
  "profile": "linkable",
  "purpose": "llm-gateway",
  "key_id": "v1",
  "redacted_text": "Klient PESEL_v1_xK9m… ",
  "entities": [
    {
      "start": 7,
      "end": 28,
      "label": "PESEL",
      "score": 1.0,
      "token": "PESEL_v1_xK9m…",
      "canonical_fp": "sha256:…"
    }
  ],
  "privacy": {
    "classification": "pseudonymised_personal_data",
    "linkable": true,
    "reversible": false,
    "algorithm": "HMAC-SHA256-HKDF-v1"
  },
  "stats": {
    "pseudonymised": 3,
    "replaced_fallback": 0,
    "by_label": {"PESEL": 2, "EMAIL": 1}
  }
}
```

Notes:

- `canonical_fp` = `SHA-256(canonical)` **without** key — only for debugging collisions **inside** trusted boundary; **omit by default** on egress APIs (`include_canonical_fp: false`).
- Never return raw `text` of entity when profile is linkable unless explicitly `include_entity_text: true` (break-glass).

Legacy: `mode=hash` remains but documented **deprecated**; if `HASH_SALT` set and profile absent, emit warning header `Warning: 299 hash-mode-weak`.

---

## 7. Key lifecycle

```text
mint master v1 ──► store KMS/file ──► derive purpose keys on the fly (cached in memory)
         │
         ├── rotate: mint v2, dual-read (accept v1+v2), write v2 only
         │            after TTL, disable v1 derive
         └── destroy: cryptographic erasure of future MAC capability
                      (historical tokens become opaque forever)
```

| Operation | API / ops |
|---|---|
| Mint | offline `tt-pii-keygen` CLI → 32 bytes → KMS |
| Rotate | set `PSEUDONYM_ACTIVE_KID=v2`; keep `v1` in decrypt/derive set for N days |
| Emergency revoke | drop kid from keystore; linkable requests with that kid fail |
| Tenant offboard | remove tenant-specific IKM if using per-tenant masters (v1.1) |

**In-memory cache:** purpose_key cache with max entries + process lifetime; zeroize on reload if language allows (best-effort in Python).

---

## 8. Request-time algorithm

```
function redact_linkable(text, purpose, tenant, kid, labels):
  spans = analyze(text, labels)
  out = []
  cursor = 0
  for span in spans:  # already non-overlapping, sorted
    out.append(text[cursor:span.start])
    can = canonicalize(span.label, span.text)
    if can is None:
      if strict: error
      else: token = f"<{span.label}>"; fallback++
    else:
      key = derive(kid, purpose, tenant)
      mac = HMAC_SHA256(key, msg(span.label, can))
      token = f"{span.label}_{kid}_{b64url(mac[:N])}"
    out.append(token)
    cursor = span.end
  out.append(text[cursor:])
  return join(out)
```

Idempotent on already-tokenised input: if span text matches `TOKEN_RE`, leave unchanged (prevents double-MAC).

---

## 9. Hardening checklist (must-have before prod)

### Crypto / config

- [ ] Refuse start if profile allows linkable and no master key
- [ ] Refuse `purpose=demo` master == prod master (fingerprint check)
- [ ] `guard.rudol.dev` / public demo: only `strict` or demo-purpose key
- [ ] Unit tests: known-answer HMAC vectors; PESEL with/without spaces → same token
- [ ] Property: different purpose → different token for same PESEL
- [ ] Property: key rotation kid changes token

### Privacy engineering

- [ ] Logs: entity counts + kid + purpose; **never** canonical, never MAC key
- [ ] Metrics: `pseudo_tokens_total{label,purpose}` 
- [ ] No `/v1/unhash` in v1
- [ ] Response header or body `privacy.classification=pseudonymised_personal_data`

### Operational

- [ ] Runbook: rotate kid; revoke kid; “key leak” playbook
- [ ] SBOM + secret scan CI (block key material in PRs)
- [ ] Pentest note: PESEL dictionary + stolen key

### Legal (process, not code)

- [ ] Record linkable mode in RoPA / processing inventory
- [ ] DPIA trigger when enabling on production LLM traffic
- [ ] Processor clauses cover pseudonymised egress

---

## 10. API surface changes (concrete)

| Endpoint | Change |
|---|---|
| `POST /v1/redact` | add `profile`, `purpose`, `tenant_id`, `key_id`, `options`; keep `mode` deprecated |
| `POST /v1/analyze` | unchanged |
| `POST /v1/anonymize` | stays session-reversible; may accept `profile=session` alias |
| `POST /v1/restore` | unchanged (mapping only) |
| `GET /health` | `pseudonym: {enabled, active_kid, purposes_configured}` **no key material** |
| `POST /v1/pseudo/check` | **not in v1** (oracle risk) |

Env:

```text
PSEUDONYM_MASTER_KEY_FILE=/run/secrets/tt_pii_master_v1
PSEUDONYM_MASTER_KEYS=v1:/run/secrets/tt_pii_master_v1,v2:/run/secrets/tt_pii_master_v2
PSEUDONYM_ACTIVE_KID=v1
PSEUDONYM_FAIL_CLOSED=true
PSEUDONYM_ALLOWED_PURPOSES=llm-gateway,eval,logs
HASH_SALT=…   # legacy hash mode only
```

---

## 11. Migration

| Phase | Action |
|---|---|
| M0 | Ship design (this doc + ADR) |
| M1 | Implement `pseudonymizer` + tests; `profile=linkable` behind flag |
| M2 | Deprecate `mode=hash` in docs; warn header |
| M3 | LiteLLM hook example uses `profile=linkable` + purpose |
| M4 | Remove bare `hash` or make it call HMAC with dedicated legacy purpose |

Dual-write not required (tokens aren’t stored as FKs in v0 product).

---

## 12. Test plan (normative vectors)

```text
key_v1 = 32×0x11
purpose = "eval"
tenant = "_"
PESEL raw "44051401359" and "4405 1401 359" → identical token
PESEL "02211301378" → different token
purpose "logs" → different from eval
kid v2 different master → different token
NIP "123-456-32-18" vs "1234563218" → identical
EMAIL "Jan@Example.PL" → canonical domain lower
```

Publish **synthetic** test vectors in `tests/testdata/pseudo_vectors.json` (no real PII).

---

## 13. Worked example

Input:

```text
Klient 44051401359 dzwonił wczoraj. Dziś 44051401359 napisał mail jan@example.pl.
```

Output (`profile=linkable`, `purpose=llm-gateway`, `tenant=acme`, `kid=v1`):

```text
Klient PESEL_v1_AbCdEfGhIjKlMnOpQrSt dzwonił wczoraj.
Dziś PESEL_v1_AbCdEfGhIjKlMnOpQrSt napisał mail EMAIL_v1_ZyXwVuTsRqPoNmLkJiHg.
```

Model can bind “ten sam klient” across sentences; operator with join on token can correlate tickets; attacker without key cannot recover PESEL.

---

## 14. Implementation sketch (modules)

```text
src/tt_pii_middleware/
  pseudo/
    __init__.py
    canonical.py      # label → canonical | None
    kdf.py            # HKDF-SHA256
    keystore.py       # MasterKeyStore
    tokens.py         # format/parse TOKEN_RE
    pseudonymizer.py  # Pseudonymizer.apply(spans, text, ctx) -> (text, meta)
    profiles.py       # Profile enum + resolution
```

Dependencies: stdlib `hmac`, `hashlib`, `base64`; HKDF via `hashlib.hkdf` (3.14+) or small internal HKDF (prefer **no new deps** — implement HKDF-SHA256 in ~30 lines per RFC 5869).

---

## 15. Decision summary

| Question | Answer |
|---|---|
| Default linkable primitive | **HMAC-SHA256** over canonical form |
| Key separation | **HKDF** by purpose + tenant + kid |
| Token shape | `LABEL_kid_base64url(mac[:15])` |
| GDPR class | **Pseudonymised personal data** |
| Legacy `hash` | Deprecated |
| Reverse | Not in linkable v1; use `session` vault or future AES-SIV |
| Demo `guard.rudol.dev` | No prod master; strict or demo purpose only |

---

## 16. Open points (need human product call)

1. Default profile for LiteLLM sketch: `session` vs `linkable`?
2. Per-tenant master keys (stronger isolation, more ops) in v1 or v1.1?
3. Should PERSON/ORG be linkable by default or always `replace` in `linkable_strict`?
4. Token byte length 15 vs 10 (shorter prompts vs collision margin)?

---

## 17. Suggested implementation order

1. `canonical.py` + golden tests  
2. `kdf.py` + `keystore.py` + refuse-empty  
3. `pseudonymizer.py` + `/v1/redact?profile=linkable`  
4. Profiles + health  
5. Docs: README privacy section + LiteLLM example  
6. Deprecate `mode=hash`  

Estimate: **1.5–3 eng-days** for M1 solid MVP; **+1 day** hardening/runbooks.
