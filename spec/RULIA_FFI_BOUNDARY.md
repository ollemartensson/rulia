# Rulia FFI Boundary

## Scope
Rulia defines the FFI boundary as a semantic firewall between host languages and the canonical kernel.

## Why the FFI Exists
Rulia requires one cross-language contract that preserves canonical meaning.
The FFI exists to prevent host-language differences from changing parse, encode, hash, verification, or workflow semantics.

## What Crosses the Boundary
Rulia requires boundary payloads to be canonical bytes and explicit opaque handles derived from those bytes.
Cross-boundary data includes:
- Canonical binary payloads.
- Explicit digest bytes and algorithm identifiers.
- Explicit handles with lifetime rules.
- Explicit error codes.

## What Never Crosses the Boundary
Rulia forbids crossing these as implicit behavior:
- Semantic reinterpretation.
- Policy decisions.
- Side-effect execution.
- Host runtime internals.
- Hidden mutable state.

The boundary transports artifacts; it does not transport authority.

## Host vs Kernel Responsibilities
Rulia defines host responsibilities:
- Manage application lifecycle.
- Supply explicit inputs and external artifacts.
- Invoke kernel operations through published ABI calls.
- Handle transport, storage, and UI concerns.

Rulia defines kernel responsibilities:
- Parse and encode canonical artifacts.
- Compute canonical digests.
- Evaluate protocol, capability, and workflow semantics deterministically.
- Return explicit artifacts, statuses, and errors.

## Semantic Firewall Rules
Rulia requires:
- ABI calls to have explicit ownership and lifetime contracts.
- Deterministic results for identical call inputs.
- No host callback path that mutates semantic meaning inside core/protocol/workflow evaluation.

Rulia forbids treating FFI calls as direct side-effect execution endpoints.

## Multi-Language Correctness
Rulia guarantees multi-language correctness through one rule:
all language bindings must observe the same canonical kernel behavior.

Bindings may vary in ergonomics, but they must not vary in canonical outputs, identity derivation, or verification results.
