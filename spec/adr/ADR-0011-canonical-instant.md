# ADR-0011: Canonical Instant Representation

Status: Accepted
Date: 2026-02-04

## Context
Instant is used across dialects and profiles but is not yet specified as a canonical core atom.
Without a deterministic, enforceable representation, identity and digest stability can drift across
implementations. We need a canonical Instant form that is stable across languages, safe for WASM/JS
interop, and mechanically validatable.

## Decision
### A) Canonical Instant value form
- Instant is a tagged value with tag `instant` and a string payload.
- Text representation uses the constructor: `Instant("...")`.
- The payload string MUST be a canonical RFC3339 / ISO-8601 UTC timestamp with the
  exact shape: `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
- The timestamp MUST end with `Z` and MUST NOT include timezone offsets.
- Fractional seconds:
  - Optional; if present, it MUST have 1 to 9 digits.
  - It MUST be minimal: no trailing zeros.
  - If the fractional value is zero, the fractional part MUST be omitted.
- No whitespace is permitted anywhere in the string.
- Validity is strict and deterministic:
  - Year, month, and day MUST form a valid calendar date.
  - Hour MUST be 00-23, minute 00-59, second 00-59 (no leap seconds).

### B) Validation
- Non-canonical strings are rejected deterministically in strict profiles.
- Implementations MUST NOT silently normalize or coerce non-canonical Instants.

### C) Identity
- Instant participates in digests as its canonical encoding (tag + canonical string bytes).
- Any change in the string payload changes ObjectDigest and FactDigest.

### D) JSON projection guidance (recommended)
- Encode as an object wrapper: `{ "$instant": "..." }`.
- Avoid numeric epoch values to prevent unit ambiguity and JS precision loss.

## Consequences
- Stable, cross-language identity and digest behavior for time values.
- Deterministic validation rules that reject ambiguous or non-canonical strings.
- Safe WASM/JS interop via string representation without precision loss.

## Rationale for Acceptance
- Behavior is already enforced or relied upon by SPEC/design docs.
- No competing alternatives remain open.

## Open questions
- None.
