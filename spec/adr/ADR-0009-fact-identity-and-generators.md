# ADR-0009: Fact Identity and Generator Restrictions

Status: Accepted
Date: 2026-02-04

## Context
Rulia uses content-addressable digests for identity. Documentation and metadata must not
change fact identity, and generator constructs must not introduce nondeterminism inside
stored or transmitted facts.

## Decision
### A) Two digests
- ObjectDigest = `hash(canonical(value))`
- FactDigest = `hash(canonical(unwrap_annotations(value)))`

### B) Annotations are non-semantic for FactDigest
- `@meta` and docstrings do not affect FactDigest.
- Annotation layers are stripped for FactDigest, but remain part of ObjectDigest.

### C) Generator restrictions
- `@new(...)` and `Generator(...)` are forbidden anywhere inside a stored or transmitted Fact.

### D) Fact materialization
- Facts MUST be fully materialized before encoding or digesting.

## Consequences
- Human documentation does not break identity.
- Events are immutable facts: FactDigest is stable even with annotation changes.
- Ingestion pipelines must materialize generator output before persistence.
- Producers and consumers can compute FactDigest without a dependency on metadata/docstrings.

## Examples
- Annotated value: FactDigest hashes `unwrap_annotations(value)` while ObjectDigest hashes the full annotated value.
- Invalid fact: any structure containing `@new(...)` or `Generator(...)` anywhere within the value graph.

## Guardrails / Follow-ups
- Update the specification to define FactDigest vs ObjectDigest and the generator ban.
- Add conformance tests for fact materialization and annotation stripping.
