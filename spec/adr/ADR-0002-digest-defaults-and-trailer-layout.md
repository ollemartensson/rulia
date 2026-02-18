# ADR-0002: Digest Defaults and Trailer Layout

Status: Accepted
Date: 2026-02-03

## Context
At the time this ADR was proposed, the draft spec implied Blake3 as the default digest and did not
fully pin digest-trailer behavior. Digest bytes and trailer structure are format-critical and affect
interoperability and verification behavior.
We aligned the spec with implementation behavior to preserve determinism and one canonical wire shape.

## Decision
- The default digest algorithm used by `encode_with_digest` is SHA-256.
- Canonical digest trailer wire schema is authoritative in `docs/SPECIFICATION.md`:
  - `Binary Format` -> `With Digest`
  - `Binary Format` -> `Digest Trailer`
  - `Binary Format` -> `Verification`
- This ADR records the accepted default-selection decision and migration rationale; it does not
  define a competing digest-trailer schema block.

## Consequences
- Canonical shape continuity: existing encoded data remains valid under the current digest defaults and trailer layout.
- Adding or renumbering algorithm IDs is format-affecting and requires a new ADR; unknown IDs are rejected by current decoders.
- Digest verification is deterministic because it hashes canonical bytes and uses explicit trailer layout.

## Evidence
- `crates/rulia/src/binary/mod.rs:31-80` (default algorithm, trailer append, verification logic and digest coverage).
- `crates/rulia/src/hash.rs:4-49` (algorithm registry, IDs, digest length).
- `crates/rulia/src/binary/header.rs:5-8` (digest flag constant).
- `crates/rulia/src/binary/reader.rs:24-63` (digest trailer parsing and verification in reader).
