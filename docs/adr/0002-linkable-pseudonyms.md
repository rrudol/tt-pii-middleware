# ADR 0002 — Linkable pseudonyms for redacted identifiers

- **Status:** Proposed
- **Date:** 2026-09-11
- **Deciders:** Thinking Typewriters / tt-pii-middleware maintainers
- **Related:** threat model in README; ENISA pseudonymisation guidance; GDPR Art. 4(5), 25, 32

## Context

Callers (LLM gateways, fraud, eval) need redacted text where **the same PESEL/NIP/… appearing in different places maps to the same token**, so models and joins can co-reference entities — without putting raw identifiers into prompts, logs, or third-party APIs.

Today:

| Mode | Linkable? | Reversible? | Crypto strength |
|---|---|---|---|
| `replace` / `mask` | no | n/a | n/a |
| `hash` (`SHA-256(salt‖value)[:16]`) | yes (global per salt) | offline dict if salt leaks | **weak for PESEL** |
| `anonymize` (`[LABEL_NNN]`) | yes (request / vault) | yes via mapping | vault is the secret |

`hash` is not production-grade for national IDs (small domain → dictionary attack once salt is known).

## Decision

Introduce a **first-class linkable-pseudonym plane** separate from one-way redaction and from reversible session vaults:

1. **Default linkable algorithm:** `HMAC-SHA-256` over a **canonicalized** identifier, with **HKDF-derived per-purpose keys**, never raw `SHA-256(salt‖value)`.
2. **Identity of a token** includes: key version, purpose, entity type, and truncated MAC — so rotation and cross-purpose isolation are explicit.
3. **Profiles** select policy (`strict` / `session` / `linkable` / `linkable+restore`) instead of ad-hoc mode flags.
4. **Keys live outside the app** (file/KMS reference); empty/missing key **fails closed** for linkable profiles (no silent fallback to unsalted hash).
5. **Compliance posture:** linkable output is **pseudonymised personal data**, not anonymised data. Documentation and API must say so.

## Consequences

### Positive

- Stable co-reference across requests/docs without returning raw PII in the prompt.
- Tenant/purpose isolation via HKDF info strings.
- Key rotation without ambiguity (`v1`, `v2` in token).
- Clear split: detection → transform policy → key material.

### Negative / costs

- Operational burden: KMS, rotation, purpose registry.
- Join across purposes/tenants requires deliberate dual-key or re-pseudonymisation jobs.
- PESEL dictionary risk remains **if the purpose key leaks** — mitigated by KMS + short token exposure surface, not eliminated.
- Slightly larger tokens than `<PESEL>`.

### Compliance

- DPIA recommended when linkable mode is used on production traffic.
- DPA/SCC still required for any egress of pseudonymised text.
- DSAR/erasure: HMAC tokens are not a substitute for deletion of raw data in source systems; optional reversible vault is a separate control with its own retention.

## Alternatives considered

| Alternative | Why rejected as default |
|---|---|
| Keep `SHA-256 + HASH_SALT` | Salt often co-located; not MAC; PESEL-bruteforce-friendly |
| Format-preserving encryption (FF1) | Looks like real PESEL → higher misuse/confusion; weaker story without length need |
| Blinded Bloom membership only | Answers “seen before?”, not stable in-text co-reference |
| Always reversible vault | Wrong default for external LLM prompts (mapping is hotter than HMAC) |
| True anonymisation (k-anon / DP) | Destroys the join property the feature exists for |

## References

- ENISA, *Pseudonymisation techniques and best practices*
- EDPS/AEPD, *Introduction to the hash function as a personal data pseudonymisation technique*
- NIST FIPS 198-1 (HMAC), SP 800-108 (KDF), SP 800-38G (FPE — non-default)
- Google Cloud DLP pseudonymisation methods (HMAC / AES-SIV / FPE comparison)
