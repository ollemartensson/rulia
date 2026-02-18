# Rulia Overview

## Purpose
Rulia defines a deterministic intermediate representation (IR) for data that must be portable, replayable, and content-addressable.
Rulia exists to move intent across systems without changing meaning.

## What Rulia Is
Rulia defines:
- A canonical value model.
- A canonical text form for human authoring and review.
- A canonical binary form for transport and storage.
- Identity from canonical bytes through cryptographic digests.
- Layered semantics for protocols, capabilities, workflows, and language boundaries.

Rulia guarantees that the same value and options produce the same canonical bytes and the same digest.

## What Rulia Is Not
Rulia is not:
- A general-purpose programming language.
- A transport protocol by itself.
- A policy engine by itself.
- A database by itself.
- A side-effect runtime.

Rulia requires execution and IO concerns to stay outside the core format layer.

## Why Rulia Exists
Distributed systems fail when representation changes meaning across tools, languages, or time.
Rulia defines one canonical representation so authors, verifiers, and executors operate on the same bytes.
This enables:
- Stable identity for facts and artifacts.
- Deterministic verification and replay.
- Explicit trust and evidence contracts.
- Cross-language correctness through a strict boundary model.

## Design Principles
Rulia defines these principles as non-negotiable:
- Determinism over convenience.
- Canonicality over stylistic freedom.
- Data-not-code in all portable artifacts.
- Explicit boundaries over implicit behavior.
- Replayability and evidence over optimism.

Rulia requires each concept to have one meaning and one layer owner.

## Boundary-First Philosophy
Rulia defines boundaries before features.
Each layer owns a narrow contract and must not absorb responsibilities from higher layers.
This keeps guarantees local, testable, and enforceable.

Rulia requires every cross-layer dependency to be explicit.
No layer may smuggle semantics through ad-hoc metadata, host side channels, or hidden execution.

## Why Rulia Is an IR
Rulia defines an IR because an IR carries meaning between systems without prescribing one host runtime.
A language centers authoring and execution in one stack.
A config format centers static parameters for one application family.
Rulia centers canonical artifacts that any conforming system can parse, hash, verify, and replay.

## System Diagram (Text)
```text
Authoring Surface
  -> Rulia Canonical Text
  -> Core Canonical Value
  -> Rulia Canonical Binary + Digest
  -> Semantic Protocol Objects (requests, receipts, obligations)
  -> Workflow/Capability Interpretation
  -> Host Execution Environments

Verification Surface
  -> Canonical Binary + Digest
  -> Protocol and Workflow Verification
  -> Evidence and Replay
```

Rulia guarantees that all layers consume the same canonical artifact base.
