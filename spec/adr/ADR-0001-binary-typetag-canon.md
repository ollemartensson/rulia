# ADR-0001: Binary TypeTag Canon

Status: Accepted
Date: 2026-02-03

## Context
The binary TypeTag table in `docs/SPECIFICATION.md` diverged from the mapping used in code.
Type tags are format-critical: tag numbering affects canonical bytes and content-addressable digests.
This mismatch is therefore a P0 risk to determinism, canonical decoding, and digest stability.

## Decision
The canonical binary TypeTag mapping is defined by the current code mapping and is fixed as follows:

| Tag | Type |
|-----|------|
| 0 | Nil |
| 1 | Bool |
| 2 | Int |
| 3 | UInt |
| 4 | BigInt |
| 5 | Float32 |
| 6 | Float64 |
| 7 | String |
| 8 | Bytes |
| 9 | Symbol |
| 10 | Keyword |
| 11 | Vector |
| 12 | Set |
| 13 | Map |
| 14 | Tagged |
| 15 | Annotated |

## Consequences
- Canonical decoding continuity: existing encoded data remains decodable under the current code mapping.
- Any change to tag numbers is breaking and requires a new major version or explicit format v2 strategy.
- Digests are derived from canonical bytes; tag renumbering changes digests.

## Migration Policy
- No renumbering in v1.
- If a v2 is introduced, it must include a version byte bump and a dual-decoder strategy to distinguish and decode v1 vs v2 data.

## Evidence
- `crates/rulia/src/binary/pointer.rs:5-44` defines the canonical `TypeTag` enum values and decoding mapping.
