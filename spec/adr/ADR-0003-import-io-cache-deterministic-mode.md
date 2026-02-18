# ADR-0003: Import IO, Cache Policy, and Deterministic/No-IO Mode

Status: Accepted
Date: 2026-02-03

## Context
The text parser currently resolves `import` by reading the filesystem, verifying optional digests,
canonicalizing paths, and maintaining a digest cache that may write to disk. These behaviors are
not yet codified as policy, which creates ambiguity around determinism and IO boundaries.
Additionally, the `@new` macro generates time- and randomness-dependent values at parse time.
We need an explicit, testable rule that separates core parsing from edge evaluation and defines
what a deterministic/no-IO mode must guarantee.

## Decision
### 1) Core Parse vs Edge Evaluation
- **Core parse**: lexing, parsing, and evaluation of pure expressions that depend only on the
  input string and explicit parameters. Core parse must not perform filesystem IO, environment
  lookups, or time/randomness access.
- **Edge evaluation**: features that require external effects (filesystem IO or time/randomness).
  In v1, `import`, `parse_file`, and `@new` are classified as edge evaluation.

### 2) Import IO Policy (Normal Mode)
- Parsing is allowed to read files for `import` and `parse_file` in normal mode.
- Import paths are canonicalized before resolution to ensure stable, cycle-safe lookup.
- If an import hash is provided, the parser verifies it against the file bytes and errors on
  mismatch.
- In-memory caching of already-imported values is permitted.

### 3) Cache Policy (Normal Mode)
- A digest cache may be used to avoid recomputing import hashes.
- The cache directory is discovered via environment variables and may be created on demand.
- Cache files may be read and written as part of import digest verification.

### 4) Deterministic / No-IO Mode (Policy Requirement)
Deterministic/no-IO mode is a **required behavior** (even if not implemented yet) with the
following testable properties:
- **No filesystem access**: no file reads, no metadata calls, and no cache reads/writes.
- **No environment-dependent paths**: do not consult `RULIA_CACHE_DIR`, `XDG_CACHE_HOME`, or `HOME`.
- **No path canonicalization via filesystem**: path resolution must be purely lexical or bypassed.
- **Import handling**: `import` must fail unless the caller supplies an explicit in-memory
  resolver (to be designed). If no resolver is provided, `import` errors deterministically.
- **No implicit time/randomness**: `@new` must either be disabled or use explicit injected
  generators. If no generator is provided, `@new` errors deterministically.

### 5) @new and Generator Policy
- `@new` is explicitly allowed in normal mode as an edge evaluation feature that uses
  system time and randomness.
- `Generator(:uuid|:ulid|:now)` remains a deterministic tagged value (deferred generation);
  it does not generate values at parse time.
- Deterministic/no-IO mode must require explicit generator injection for `@new`.

## Consequences
- Current behavior (filesystem imports, digest cache reads/writes, and `@new` time/randomness)
  is allowed only under the normal mode policy.
- Deterministic/no-IO mode requires new configuration or API surface to enforce these rules.
- Adding new IO-affecting features must explicitly classify them as core parse or edge evaluation.

## Follow-ups
- Add a parse configuration/strategy that enforces deterministic/no-IO mode.
- Introduce an explicit import resolver interface for in-memory imports.
- Introduce injectable time/randomness providers for `@new`.
- Add tests that assert deterministic/no-IO mode performs zero IO and rejects `import`/`@new`
  without explicit providers.

## Evidence
- `crates/rulia/src/text.rs:140-145` (`parse_file` performs filesystem read).
- `crates/rulia/src/text.rs:702-712` (import path canonicalization via `fs::canonicalize`).
- `crates/rulia/src/text.rs:714-735` (import reads file metadata and bytes).
- `crates/rulia/src/text.rs:743-786` (import digest verification and default sha256 behavior).
- `crates/rulia/src/text.rs:789-833` (digest cache read and invalidation via filesystem).
- `crates/rulia/src/text.rs:847-874` (digest cache writes to disk).
- `crates/rulia/src/text.rs:2441-2451` (cache dir discovery via env vars).
- `crates/rulia/src/text.rs:2454-2463` (cache key uses canonicalized path).
- `crates/rulia/src/text.rs:1534-1584` (`@new` uses UUID/ULID/time at parse time).
- `crates/rulia/src/text.rs:1392-1405` (`Generator` is deferred generation tagging).
