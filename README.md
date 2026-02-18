<p>
    <img src="assets/logo.png" alt="Rulia Logo" width="200">
</p>

Rulia is a system for preserving meaning across language, runtime, and time.

It defines a deterministic [intermediate representation (IR)](https://en.wikipedia.org/wiki/Intermediate_representation) for data that must be portable, replayable, and [content-addressable](https://en.wikipedia.org/wiki/Content-addressable_storage). Rulia exists to move intent across systems without changing its [semantic identity](https://en.wikipedia.org/wiki/Semantics_(computer_science)).

## The Core Philosophy

In [distributed systems](https://en.wikipedia.org/wiki/Distributed_computing), meaning often evaporates at the boundary. A data structure in one language becomes an approximation in another; a rule executed today may yield a different result tomorrow due to ambient side-effects or implicit dependencies.

Rulia addresses this through three non-negotiable pillars:

### 1. Canonical Identity
Every Rulia value has exactly one binary representation and exactly one [cryptographic digest](https://en.wikipedia.org/wiki/Cryptographic_hash_function). Identity is a property of the data itself, not its location, its variable name, or its container. If two systems hold the same digest, they are guaranteed to be operating on the same meaning.

### 2. Determinism by Design
Every operation in Rulia—parsing, encoding, and evaluation—is isolated from the host environment. It cannot observe the system clock, it cannot generate randomness, and it cannot perform undeclared I/O. This ensures that a Rulia artifact behaves identically regardless of where or when it is processed (see [Deterministic algorithm](https://en.wikipedia.org/wiki/Deterministic_algorithm)).

### 3. Data as Intent
Rulia represents rules, expressions, and workflows as [declarative data](https://en.wikipedia.org/wiki/Declarative_programming) rather than executable source code. Because Rulia always halts (avoiding the [Halting problem](https://en.wikipedia.org/wiki/Halting_problem)) and is [side-effect](https://en.wikipedia.org/wiki/Side_effect_(computer_science)) free, a Rulia artifact is a stable, auditable contract of intent that can be verified and replayed without the risks of arbitrary code execution.

## Why Rulia Exists & When to Use It

Rulia was created to solve the problem of **semantic drift** in long-lived, high-integrity systems. When data moves between services, languages, or storage layers, its precise meaning often degrades—integers become floats, sets become lists, and business rules subtly change behavior due to different runtime implementations.

### What can you do with Rulia?
*   **Create Unambiguous Contracts:** Define strict data schemas and business rules that are enforced identically in Rust, Java, and Julia.
*   **Build Replayable Audit Trails:** Store every decision, input, and outcome as a content-addressable chain of evidence that can be re-executed years later with bit-for-bit identical results.
*   **Orchestrate Long-Running Workflows:** Define processes that survive system restarts and upgrades without losing state, using a deterministic intermediate representation.
*   **Secure Configuration Distribution:** Deploy complex configurations to edge devices or untrusted environments, knowing that the configuration's identity (hash) guarantees its content and behavior.

### When should you use Rulia?
*   **High-Stakes Correctness:** When a calculation error or data misinterpretation has significant financial or safety consequences (e.g., financial ledgers, regulatory compliance).
*   **Long-Term Archival:** When you need to prove *exactly* what happened and why, 10 years from now, without relying on the original code or runtime being available.
*   **Zero-Trust Data Exchange:** When you need to verify the integrity and provenance of data independently of the transport mechanism or sender.

### When is Rulia not worth it?
*   **Ephemeral Data Streams:** If you are processing high-frequency sensor data that is discarded seconds later, the overhead of canonicalization and hashing is unnecessary. Use Protobuf or Cap'n Proto.
*   **Rapid Prototyping:** If you need to quickly iterate on a UI and don't care about precise decimal behavior or canonical ordering, JSON is faster and simpler.
*   **Arbitrary Computation:** If your problem requires complex simulations, infinite loops, or nondeterministic behavior (like random number generation within the logic itself), Rulia is the wrong tool. It is designed for *deciding*, not *computing*.

## The Rulia Stack

Rulia is layered to ensure that core integrity is maintained while supporting complex semantics.

*   **The Core Format**: A notation for values, maps, and tagged structures with a strict canonical binary encoding and a human-authorable text form.
*   **Semantic Protocols**: A layer for representing requests, receipts, and evidence (obligations) as content-addressable facts.
*   **Workflow Model**: A deterministic orchestration layer (EvalIR) that manages state transitions and control flow as data.
*   **The Host Boundary**: A minimal interface that separates the deterministic Rulia core from host-specific concerns like storage, networking, and side-effect execution.

## Navigation

The repository is organized to separate specification from implementation.

### Specification (The Source of Truth)
Normative documents are located in the [`spec/`](spec/) directory:
*   [**Rulia Index**](spec/RULIA_INDEX.md) — The entry point for the normative corpus.
*   [**Core Specification**](spec/SPECIFICATION.md) — Canonical encoding, syntax, and type system.
*   [**Workflow Model**](spec/RULIA_WORKFLOW_MODEL.md) — Deterministic orchestration and EvalIR.
*   [**Capability Model**](spec/RULIA_CAPABILITY_MODEL.md) — Contract matching and evidence verification.

### Implementation & Tooling
*   [**Engine**](engine/) — The core implementation including the CLI, FFI, and WASM modules.
*   [**SDKs**](sdk/) — Language bindings for JavaScript, the JVM, and Julia.
*   [**Examples**](examples/) — Reference implementations and system demonstrations.
*   [**Editors**](editors/) — Support for VS Code, Zed, and IntelliJ.
*   [**Benchmarks**](benchmarks/canonical-json/README.md) — Cross-language performance suite and regression checks.

## Quality Gates

Run the repository QA smoke gate (tests + performance regression check):

```bash
tools/qa/test-and-benchmark.sh --mode smoke
```

Use `--mode full` for the full benchmark iteration profile.

## Licensing

Rulia is licensed under the **GNU General Public License v3.0**. Commercial license grants are available for institutional partners to supersede GPLv3 obligations for specific delivery artifacts. See [LICENSE](LICENSE) and [LICENSE_COMMERCIAL_TEMPLATE.txt](LICENSE_COMMERCIAL_TEMPLATE.txt) for details.
