# ADR-0012: Stream Framing v1 (Length-Prefixed Binary Messages)

Status: Accepted
Date: 2026-02-04

## Context
Events, factflow, gateways, and WASM hosts need a standard, deterministic way to concatenate
multiple Rulia binary messages into a single stream or file. Transit-style streaming patterns are
useful, but Rulia requires explicit framing, deterministic error handling, and enforceable limits
that are language-neutral and easy to implement across C, COBOL, and JS/WASM.

## Decision
- Stream Framing v1 (length-prefixed framing for canonical binary payloads) is accepted.
- Canonical framing schema and deterministic error codes are authoritative in
  `docs/SPECIFICATION.md` -> `Binary Format` -> `Framing / Streaming (v1)`.
- Stream framing continues to use existing message digest trailers for integrity when required;
  no additional per-frame digest is added in v1.
- This ADR records rationale and adoption history; it does not define a competing framing schema
  block.

## Consequences
- Enables deterministic log files, message queue payloads, websocket streams, and replication
  pipelines for Rulia binary messages.
- Keeps content identity rooted in canonical message bytes and existing digest trailers.
- Avoids additional framing digests or global headers in v1, keeping framing minimal.

## Rationale for Acceptance
- Behavior is already enforced or relied upon by SPEC/design docs.
- No competing alternatives remain open.

## Alternatives considered
- Delimiter-based framing: rejected due to ambiguity, escaping, and non-constant-time scanning.
- CBOR/JSONL framing: rejected due to identity ambiguity, type loss, and non-canonical encoding.
