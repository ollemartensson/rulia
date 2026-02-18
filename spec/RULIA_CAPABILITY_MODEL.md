# Rulia Capability Model

## Scope
Rulia defines capabilities as semantic contracts.
A capability states what is requested and what evidence is required.

## Non-Negotiable Placement
Rulia requires:
- Capabilities are not core-format primitives.
- Capabilities are explicit protocol objects.
- Capability semantics remain independent from any host runtime API.

Capabilities live above core format and protocol identity rules.

## Capability Contract
Rulia defines a capability contract with these logical parts:
- Capability descriptor: operation class and semantic intent.
- Constraint set: allowed inputs, limits, and preconditions.
- Trust anchors: keys, issuers, or policy roots used for verification.
- Evidence requirements: artifacts required to prove fulfillment.
- Decision form: canonical fields that participate in capability decision identity.

Rulia requires capability decisions to be derivable from canonical protocol artifacts.

## Artifact-Neutral Semantics
Rulia defines capability meaning independently from transport and storage artifacts.
A capability may be expressed in different envelopes, but its decision form remains canonical.

Rulia requires hash inputs for capability decision identity to be explicit and deterministic.

## Capability Use Modes
Rulia defines two valid modes:
- Standalone protocol mode: capabilities govern request and receipt verification directly.
- Workflow-integrated mode: capabilities govern specific workflow steps while preserving the same contract.

Rulia guarantees both modes share the same semantic rules.

## What Capabilities Must Not Do
Capabilities must not:
- Invoke side effects by definition alone.
- Encode host-specific invocation details as normative meaning.
- Smuggle hidden policy through non-canonical metadata.

## Verification
Rulia defines capability verification as:
1. Canonicalize the capability decision form.
2. Recompute capability decision identity.
3. Validate required evidence against constraints and trust anchors.
4. Emit a deterministic decision result artifact.

Rulia requires verification results to be replayable from the same canonical artifact set.
