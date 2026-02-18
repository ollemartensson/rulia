# ADR-0004: Security Conventions - Signed Envelope and Manifest Chain of Custody

Status: Proposed
Date: 2026-02-04

## Context
Rulia already provides canonical binary encoding, content-addressable digests, hash-verified
imports, and hermetic/deterministic parsing modes. However, there is no standardized
convention for expressing signatures, provenance, or chain-of-custody metadata in Rulia
values. We want a convention layer that makes security and provenance attractive and
interoperable without changing the core syntax or binary format.

## Decision
### 1) Standard Data Shapes (Conventions Only)
Define the following tagged-value conventions. These are data shapes only and do not
introduce new syntax.

- Digest
  - `Digest(alg = :sha256|:blake3, hex = "...")`
  - `hex` is lowercase, 64 hex characters, computed from canonical bytes.
- Signature
  - `Signature(key_id = ..., alg = ..., scope = ..., payload_digest = Digest(...), sig = 0x[...], created = "..."?, purpose = ...?, claims = (...)?)`
  - `key_id` is a stable identifier for key lookup (string or keyword).
  - `alg` is the signature algorithm keyword (for example `:ed25519`).
  - `scope` is a domain or intent keyword (for example `:rulia_signed_v1`).
  - `sig` is the raw signature bytes.
  - Optional fields (`created`, `purpose`, `claims`) are policy-governed and part of the
    signature input when present.
- Signed
  - `Signed(payload = <value>, signatures = [Signature(...)], meta = (...)?)`
  - `payload` is the only value whose digest is signed (see signing rules).
- Manifest
  - `Manifest(format = ..., root = Digest(...), objects = [...], policy = (...), attestations = ...?, signatures = [Signature(...)])`
  - `objects` is a vector of maps that minimally include `id` (string) and `digest`.
  - `attestations` is an optional vector of `Signed` values or maps referencing `Signed` values.

### 2) Signing Rules (Deterministic)
- Sign canonical bytes (or canonical digest) only:
  - `payload_bytes = encode_canonical(payload)`
  - `payload_digest = Digest(alg, hex = hash(payload_bytes))`
- Primary rule: signatures are computed over `payload_digest` to keep inputs bounded and
  deterministic. Payload bytes are never signed in text form.
- Signature input MUST include a stable domain separator. Example domain strings:
  - `"rulia:signed:v1"` for `Signed`
  - `"rulia:manifest:v1"` for `Manifest`
- A deterministic signature input is constructed as canonical bytes of a map:
  - `(domain = "rulia:signed:v1", payload_digest = payload_digest, key_id = key_id, alg = alg, scope = scope, created = created?, purpose = purpose?, claims = claims?)`
- The `sig` bytes are the signature over the canonical bytes of that map.
- `Signed` signatures cover `payload` only. The `signatures` vector is not included in the
  digest to avoid circularity.
- `Manifest` signatures cover the manifest body without its `signatures` field (or with
  `signatures = []`).
- Never sign text form. Always sign canonical bytes or the canonical digest of those bytes.

### 3) Verification Rules
- Recompute `payload_digest` from canonical bytes of `payload` and compare it to
  `Signature.payload_digest`.
- Verify the signature over the canonical signature input.
- Enforce policy: allowed digest algorithms, allowed signature algorithms, trusted keys,
  required claims, and threshold rules.

### 4) Import Chain Rules
- In hermetic/deterministic mode, imports are resolved via an explicit resolver.
- Imports must be pinned by digest.
- Policies MAY require imported values to be wrapped in `Signed` and validated as part of
  chain-of-custody enforcement.

### 5) Security Profiles
Define named profiles as policy rules. The initial profile is `:bankgrade`:
- Deterministic parsing required.
- Hermetic import resolution required.
- Imports pinned by digest required.
- Signed values required for root and imports.
- Threshold signatures required (for example `threshold = 2` over `trusted_keys`).
- Allowed algorithms are explicitly enumerated (for example `digest_algs = [:sha256]`).

## Consequences
- Enables unbroken chain-of-custody for configs, workflows, and policy documents.
- Interoperability: different tools can agree on the same digest and signature semantics.
- Conventions stay out of the core syntax and binary format.
- Non-goal: this does not mandate a crypto implementation, key management system, or
  operational process.

## Open Questions
- How should the algorithm registry be governed and versioned?
- Should signatures be defined strictly over digests (recommended) or over canonical bytes?
- What are the canonical semantics for timestamps (`created`) and their policy enforcement?
Resolved by ADR-0005 (2026-02-04): v1 registries are fixed, signatures are over digest-only
inputs with explicit domain separators, and `created` is optional policy metadata.
