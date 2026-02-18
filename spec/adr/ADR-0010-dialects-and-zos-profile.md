# ADR-0010: Dialects and Rulia/zOS Profile v1

Status: Proposed
Date: 2026-02-04

## Context
Rulia needs profile-specific syntax, validation, and interoperability features without
fragmenting core semantics or canonical encoding. A formal dialect model is required
so profiles (such as z/OS integrations) can add sugar and constraints while remaining
strictly aligned to the canonical core Value model.

## Decision
### A) Dialect definition
- Dialect = syntax sugar + constraints + extension tags.
- Dialects MUST deterministically lower to core Values defined by `docs/SPECIFICATION.md`.
- Lowering is pure and side-effect-free; no IO, time, or randomness.
- Dialect IDs are stable, versioned identifiers (e.g., `rulia:zos:v1`).

### B) Digest model
- CoreDigest = `hash(canonical(core_value))`.
- DialectDigest (optional) = `hash(dialect_id_bytes || 0x00 || CoreDigest)`.
- `dialect_id_bytes` are UTF-8 bytes of the dialect id string; the separator prevents
  ambiguity.
- Canonical encoding and CoreDigest remain unchanged.

### C) Rulia/zOS profile v1
- Dialect id: `rulia:zos:v1`.
- Constraints:
  - Floats are forbidden.
  - Money values MUST use scaled decimals (extension tag).
- Syntax sugar:
  - Hyphenated field names are allowed in map keys and lower to keyword literals.
    Example: `total-amount = 10` lowers to `(Keyword("total-amount") = 10)`.
- Extension tags / metadata (standardized):
  - `Dec` (scaled decimal), `EBCDIC` (text bytes), `COMP-3` (packed decimal), `@layout` metadata.
- Deterministic error model:
  - Parsing and validation errors must be deterministic, code-based, and avoid ambient context.

## Non-goals
- Dialects do not redefine semantics.
- Dialects do not change canonical encoding.

## Consequences
- Profiles can add ergonomic syntax and validation without fragmenting core meaning.
- CoreDigest remains authoritative for identity; DialectDigest is a scoped assertion.
- z/OS integrations are expressed as a profile rather than a fork.

## Guardrails / Follow-ups
- Publish `docs/design/DIALECTS.md` with lifecycle and profile details.
- Add conformance tests once dialect parsing/validation hooks exist.
