# ADR-0008: Canonical Ordering and Explicit Map Keys

Status: Accepted
Date: 2026-02-04

## Context
Rulia uses canonical binary encoding and content-addressable digests as identity. Events-as-facts
require cross-language determinism, including stable ordering rules and unambiguous map keys.

## Decision
### A) Canonical ordering (normative)
- Maps: entries are sorted by canonical-encoded key bytes (type tag + encoded key bytes).
- Sets: elements are sorted by canonical-encoded value bytes.

### B) Duplicate keys
- Duplicate map keys are rejected deterministically at parse and encode time.

### C) Map key expressiveness
- Map entries MAY use:
  - identifier = value
  - :keyword = value
  - "string-key" = value
- Keys MUST be compile-time literals (no arbitrary expressions).

## Consequences
- Stable digests across implementations.
- Events can represent CloudEvents / HTTP headers / COBOL fields.

## Guardrails / Follow-ups
- Update the specification to define canonical ordering and literal-only map keys.
- Add conformance tests for ordering and duplicate-key rejection across encoders.
