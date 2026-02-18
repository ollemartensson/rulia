# ADR-0013: Fact/Event Envelope v1 (Conventional Map Shape)

Status: Proposed
Date: 2026-02-04

## Context
Rulia needs a standard envelope to carry facts, events, decision receipts, and factflow
transactions through streams and storage while preserving deterministic identity and
replay. The envelope must separate semantic fact content from metadata and interoperate
with existing conventions.

Relevant building blocks already exist:
- FactDigest vs ObjectDigest (ADR-0009).
- Signed and Manifest conventions (ADR-0004, ADR-0005).
- Stream Framing v1 (ADR-0012).

The envelope is a value-level convention only. It must not introduce a new core type or
change the specification.

## Decision
### A) Envelope v1 is a conventional map shape
Define Envelope v1 as a conventional map with the following fields. Key names are
conventional; map keys MUST be explicit and canonical per ADR-0008.

Required:
- `kind`: keyword or string (example: `:event`, `:fact`, `:decision`).
- `payload`: Rulia value containing semantic content; generator-free (ADR-0009).

Optional (non-semantic by default):
- `id`: ULID/UUID/string/Digest/Ref; assigned or derived identifier.
- `time`: Instant (canonical representation per ADR-0011).
- `meta`: map for annotations, docs, provenance hints.
- `headers`: map for transport or contextual metadata.
- `trace`: map or vector of correlation ids/paths.
- `signatures`: list of `Signature(...)` per ADR-0004/0005.

Illustrative shape (Rulia):
```rulia
(
    kind = :event,
    payload = (type = :user/created, data = (user_id = "u_123")),
    id = ULID("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    time = Instant("2026-02-04T18:20:00Z"),
    meta = (producer = "svc/users"),
    headers = (partition = "p3"),
    trace = (trace_id = "abc", span_id = "def"),
    signatures = [Signature(...)]
)
```

### B) Identity rules
- `FactDigest(envelope)` is defined as the digest of canonical `payload` only:
  - `FactDigest(envelope) = hash(canonical(unwrap_annotations(payload)))`.
- `ObjectDigest(envelope) = hash(canonical(envelope))`.
- Changes to `meta`, `headers`, `trace`, `time`, `id`, or `signatures` MUST NOT affect
  `FactDigest` unless those fields are intentionally placed inside `payload`.
- Any change to `payload` MUST change `FactDigest`.
- `id` MAY be assigned (non-semantic) or derived. If derived, it MUST reference either
  `FactDigest` or `ObjectDigest` explicitly (for example as `Digest(...)`).

### C) Generator and determinism rules
- `payload` MUST be generator-free (no `@new(...)` or `Generator(...)`).
- The envelope MUST be fully materialized before encoding, digesting, or signing.
- Runtime-derived fields (`time`, `headers`, `id`, etc.) MAY be present, but they MUST
  not affect `FactDigest` and MUST be materialized before computing `ObjectDigest`.

### D) Signing and verification
- The envelope MAY be wrapped in `Signed(payload = envelope, signatures = [...])`, or
  MAY include a `signatures` field per ADR-0004/0005.
- Signatures SHOULD cover `ObjectDigest(envelope)` for transport integrity and audit
  continuity. `FactDigest(payload)` remains the semantic identity for replay.
- If the `signatures` field is used, compute the signature input over the envelope with
  `signatures` omitted or set to an empty list to avoid circularity; populate signatures
  last.

### E) Stream Framing v1 composition
- One framed message equals one envelope encoded as canonical Rulia binary bytes.
- No envelope-level framing is required beyond Stream Framing v1.

### F) Non-goals / rejections
- No implicit schema or execution semantics.
- No required ordering beyond canonical map key ordering (ADR-0008).
- No new core types or changes to `docs/SPECIFICATION.md`.

## Consequences
- A minimal, interoperable envelope for facts, events, and receipts without core changes.
- Clear separation of semantic identity (FactDigest) from transport identity (ObjectDigest).
- Composes with Signed/Manifest and Stream Framing v1 without additional framing.
