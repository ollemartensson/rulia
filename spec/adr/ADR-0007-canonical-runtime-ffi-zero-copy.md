# ADR-0007: Canonical Runtime via FFI and Zero-Copy Invariants

Status: Accepted
Date: 2026-02-04

## Context
Rulia is designed around canonical bytes, content-addressable digests, and zero-copy access
from binary encoding. The Rust implementation is the canonical reference for these behaviors.
Full evaluation semantics and verification features are not practical to reimplement in every
language, yet cross-language adoption is a core goal. We need an explicit tiered model that
keeps the portable data model open while keeping canonical behavior centralized and safe.

## Decision
### A) Tiered specification model
Tier 1 (Portable):
- Value model, canonical encoding, digest rules.
- Basic parse/print for interchange and storage.
- Permitted to be implemented in non-Rust languages.

Tier 2 (Canonical-core-only):
- Evaluation semantics, import resolution, deterministic profiles.
- Security verification and decisioning receipts.
- Must call the Rust canonical runtime via FFI for canonical behavior.
- Non-Rust reimplementations of Tier 2 are explicitly non-canonical.

### B) FFI is a first-class API surface
- The C ABI is treated as a product surface, not a best-effort add-on.
- APIs must be stable, ergonomic, and safe to use from higher-level bindings.
- Rust changes that affect FFI require explicit review for API and ABI stability.

### C) Zero-copy invariants (MUST)
- Decode must support borrowing slices from caller-provided buffers.
- FFI must accept raw bytes (ptr, len) and return handles or views without forced copying.
- Any change introducing hidden copies in hot paths is a regression and requires:
  - an ADR documenting the tradeoff, and
  - benchmark evidence showing the impact.

### D) ABI v1 stability policy
- Introduce and document a named C ABI surface: "C ABI v1".
- Additive-only changes are allowed within a major ABI version.
- Breaking changes require a new ABI version (e.g., v2) and parallel support during migration.
- Error codes are stable and versioned; never renumber within a major ABI version.
- A runtime version query function is required and exposed via FFI.

### E) Ergonomics goals
- Small set of powerful primitives: parse, eval, verify, encode, decode, value_ref traversal.
- Explicit ownership rules (who allocates, who frees) for every handle and buffer.
- Streaming-friendly buffers: (ptr, len) pairs and handle/offset-based traversal.
- Bindings are thin wrappers over the canonical runtime, not reimplementations.

## Consequences
- "SQLite-like" semantics engine is available everywhere via FFI.
- Feature complexity is centralized and safer to evolve.
- Zero-copy becomes a product differentiator that must be defended over time.

## Guardrails / Follow-ups
- Add allocation and zero-copy regression tripwires (benchmarks and tests).
- Add an FFI conformance harness.
- Document the FFI ownership model and error contract.
- Publish the C ABI v1 definition and migration policy.
