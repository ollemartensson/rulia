# Rulia System Architecture

## Overview
Rulia is a system for **content-addressable, deterministic workflow execution**. It consists of a data format (Core), a deterministic execution engine (Kernel), and domain-specific structural definitions (Profiles).

## Architectural Layers

### 1. The Core (Data Format)
**Scope:** Universal data serialization and identity.
- **Value Model:** Rich types (`Map`, `Set`, `Vector`, `Tagged`).
- **Binary Format:** Canonical, deterministic encoding with content hashing.
- **Text Format:** Human-readable notation with strict parsing.
- **Standard Dialect:** The core language includes built-in constructors for `Instant`, `ULID`, and `Ref`.

### 2. The Kernel (Execution Engine)
**Scope:** Deterministic logic processing.
- **EvalIR:** A minimal instruction set (`assign`, `emit`, `request`).
- **Isolation:** Execution is pure. No ambient IO, no system clock.
- **Determinism:** Replay of the same artifact + history always yields the same result.

### 3. Profiles (Domain Semantics)
**Scope:** Structure and constraints for specific domains.
- A **Profile** defines a valid data shape (Schema) and a mapping to Kernel primitives (Lowering).
- Profiles do not change the Core parser or Kernel execution.
- Examples: `Mediation` (Integration), `z/OS` (COBOL layouts).

### 4. Capabilities (External World)
**Scope:** Interfacing with side-effects.
- **Connector Pattern:** The Kernel requests an effect (e.g., `read_file`), and the Host provides a Capability implementation.
- **Protocol:** All interactions use `Request` (intent) and `Receipt` (evidence) objects.

## Design Principles
1.  **Bank Grade:** Canonical binary identity is authoritative. No hidden state.
2.  **Zero Copy:** The data format is designed for efficient, zero-copy reading.
3.  **Content Addressable:** Imports and Dependencies are pinned by cryptographic hash.
