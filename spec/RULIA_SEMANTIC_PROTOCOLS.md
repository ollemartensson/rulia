# Rulia Semantic Protocols

## Scope
Rulia defines semantic protocols as the layer where interaction meaning begins.
This layer builds on canonical artifacts from the core format.

## Protocol Objects
Rulia defines four protocol object families:
- Request: a canonical statement of intent to obtain a result under explicit constraints.
- Receipt: a canonical statement of what occurred for a request, including result status and evidence pointers.
- Obligation: a canonical statement of required evidence or required action to complete verification.
- Evidence Record: a canonical artifact set used to justify receipt claims.

Protocol objects are data.
Protocol objects do not execute side effects by themselves.

## Requests
Rulia defines a request as a hashable object with:
- Subject: what is requested.
- Inputs: canonical argument payload.
- Constraints: semantic limits and required conditions.
- Context references: explicit external anchors by digest or identifier.

Rulia requires request identity to be derived from a canonical request seed.
Rulia guarantees identical request semantics produce identical request identity.

## Receipts
Rulia defines a receipt as a canonical artifact that binds:
- The request identity.
- Outcome status.
- Produced artifacts or references.
- Verification-relevant metadata.

Rulia requires receipts to include enough information to verify claimed outcomes against obligations.

## Obligations
Rulia defines obligations as explicit proof requirements.

Obligations may require:
- Presence of named artifacts.
- Digest matches over canonical bytes.
- Signature checks under declared trust anchors.
- Context consistency checks.

Rulia requires obligation evaluation to be deterministic from canonical artifacts and declared verification rules.

## Verification Model
Rulia defines verification as a deterministic procedure:
1. Recompute request identity from canonical request data.
2. Confirm receipt binding to the request identity.
3. Evaluate each obligation against evidence records.
4. Produce a verification result artifact.

Rulia requires verification results to be replayable from the same evidence set.

## Evidence and Replay
Rulia defines evidence as canonical artifacts addressed by digest.

Rulia requires:
- Evidence scope to be explicit.
- Verification-relevant bytes to be unambiguous.
- Replay to consume the same canonical request, receipt, obligations, and evidence set.

Rulia guarantees that replay over an unchanged evidence set yields the same verification result.

## Out of Scope
This layer does not define:
- Transport protocols.
- Storage engines.
- Host execution APIs.
- User interface behavior.
