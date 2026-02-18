# ADR-0005: Security Contract Hardening (Signing Inputs, Scopes, Registries)

Status: Accepted
Date: 2026-02-04

## Context
ADR-0004 introduced security conventions for signed envelopes and manifests. The implementation
now exists in `crates/rulia/src/security.rs`, but tooling interoperability requires explicit,
unambiguous signing inputs, domain separators, scope semantics, and algorithm registries. This
ADR closes the open questions from ADR-0004 without changing the core language or binary format.

## Decision
This ADR defines the v1 security contract for signing and verification.

### A) Signing input (v1)
Primary rule: signatures are computed over the digest of canonical bytes, not over raw bytes
or text.

```
payload_bytes = encode_canonical(payload)
payload_digest = hash(payload_bytes, digest_alg)
signature_input = domain_separator_bytes || payload_digest_bytes
```

- `payload_digest_bytes` are the raw 32-byte digest.
- `signature_input` is the exact byte concatenation; no map wrapping.
- Metadata fields (`created`, `purpose`, `claims`, `key_id`, `alg`, `scope`) are not part of
  the signature input in v1. If metadata must be signed, include it inside `payload` or
  define a v2 signature input.

### B) Domain separators (exact bytes)
The following UTF-8 strings are used verbatim as domain separator bytes:

- `rulia:signed:v1`
- `rulia:manifest:v1`

### C) Scope semantics (canonical)
Scope is a keyword derived from the domain separator by replacing `:` with `_`.

- `rulia:signed:v1` -> `:rulia_signed_v1`
- `rulia:manifest:v1` -> `:rulia_manifest_v1`

This mapping is normative and stable for v1.

### D) Manifest signing canonicalization
The manifest body is signed without signatures.

```
manifest_to_sign = manifest with signatures = []
```

- `signatures` must be present and empty for signing.
- For verification, a missing `signatures` field is treated as equivalent to
  `signatures = []` by deterministic canonicalization.

### E) Algorithm registries (v1)
Digest algorithms: `sha256`, `blake3`.
Signature algorithms: `ed25519`.

Identifiers are lowercase keywords with no namespace and must be stable across languages.

Governance: adding algorithms requires a new ADR and a version bump (for example a new
domain separator `rulia:signed:v2`), or an explicit registry extension ADR. There is no
ad-hoc extension mechanism in v1.

### F) Extension mechanism (v1)
Unknown keys are rejected in `Digest`, `Signature`, `Signed`, and `Manifest` maps. There is
no extension namespace in v1.

### G) Timestamp semantics (`created`)
`created` is optional, must be a UTF-8 string if present, and is treated as policy metadata
only. This field is not part of the signature input in v1. If policy enforces semantics,
use RFC 3339 UTC format (`YYYY-MM-DDTHH:MM:SSZ`).

## Evidence alignment (current implementation)
- Signing over digest only: `verify_signed` computes `canonical_digest` of payload and passes
  the digest into signature verification (`crates/rulia/src/security.rs:86-213`).
- Domain separator and scope mapping: `VerifyPolicy.domain` holds the domain string and
  `expected_scope` maps `:` to `_` for keyword scope comparison
  (`crates/rulia/src/security.rs:71-272, 451-453`).
- Strict key handling: `collect_map_entries` rejects non-keyword and unknown keys for
  `Signed`, `Manifest`, `Signature`, and `Digest` (`crates/rulia/src/security.rs:90-416`).
- Manifest signing canonicalization: verifier accepts signatures over the digest of the
  manifest body with `signatures` removed or set to empty
  (`crates/rulia/src/security.rs:169-187`).

## Consequences
- Interoperability: all tooling signs identical bytes (`domain || digest`) and uses stable
  scope keywords.
- Metadata fields are policy metadata only in v1; they are not cryptographically bound
  unless included in the payload.
- Registries are closed in v1; adding algorithms is a versioned change.
- Strict rejection of unknown keys limits extension without a new ADR.

## Follow-ups
- If future policy needs signed metadata fields, define a v2 signature input that includes
  them.
- If extension keys are required, create a new ADR defining namespaced keys and update
  verifiers accordingly.
