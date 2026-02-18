# Rulia Governance

## Status
Rulia defines this corpus as the public draft specification.

Rulia requires every normative statement in this corpus to use testable language.
Rulia defines non-normative content as explanatory and non-binding.

## Frozen Surface
Rulia defines these surfaces as frozen for this draft line:
- Layer boundaries in the layer model.
- Core canonicality rules for value, text, binary, and digest derivation.
- Determinism requirements across core, protocol verification, and workflow evaluation.
- FFI semantic firewall rule: canonical artifacts cross; semantic authority stays in the kernel.

Changes to frozen surfaces require a formal decision record and conformance update.

## Open Surface
Rulia defines these surfaces as open within this draft line:
- Domain-specific protocol object profiles.
- Capability taxonomies and profile libraries.
- Workflow profile packs and authoring guidance.
- Tooling ergonomics and packaging conventions.

Open-surface changes must not violate frozen guarantees.

## Authority Model
Rulia defines authority roles:
- Spec Editors: maintain normative text and release tags.
- Architect Reviewer: validates layer boundaries, determinism, and canonical identity rules.
- Test Strategist: defines minimum conformance evidence for normative changes.
- Security and Reliability Reviewer: validates trust, verification, and boundary hardening requirements.
- Driver: accepts scoped work slices and enforces definition-of-done evidence.

A normative change is accepted only when all required roles sign off for the affected layer.

## Change Process
Rulia requires this process for normative evolution:
1. Propose a scoped decision with explicit affected layer and invariants.
2. Record rationale and alternatives in a formal decision artifact.
3. Update normative text in the owning document.
4. Add or update conformance tests and vectors.
5. Publish a draft release tag with evidence.
6. Mark the change frozen when acceptance criteria are met.

## Version Introduction
Rulia defines a new spec version when any frozen invariant changes.
A new version must include:
- A complete normative corpus snapshot.
- A conformance suite snapshot.
- A machine-readable registry snapshot for tags and algorithms.
- Clear activation criteria for implementations.

Rulia requires version identity to be explicit in release artifacts.

## Conformance Evidence
Rulia requires each normative release to publish:
- Canonical encoding vectors.
- Digest vectors.
- Protocol verification vectors.
- Workflow replay vectors.
- FFI conformance checks across supported bindings.

Rulia defines absence of required evidence as release-blocking.
