# ADR-0006: Decisioning Conventions - Policy Bundles, Decision Requests, and Receipts

Status: Proposed
Date: 2026-02-04

## Context
Rulia already provides canonical binary encoding, content-addressable digests, Signed/Manifest
conventions, and deterministic or hermetic parsing modes. Regulated decisioning systems
need reproducible outcomes, clear audit trails, and consistent chain-of-custody semantics
across independent tools without changing the core language or binary format.

## Decision
### A) Canonical convention shapes (v1)
These are conventions only and do not change core syntax or binary encoding.

PolicyBundle:
```rulia
PolicyBundle(
    format = :rulia_policy_bundle_v1,
    id = Digest(alg = :sha256, hex = "..."),
    policy = (name = "fraud_policy", version = 12, rules = [...]),
    imports = [
        (id = "shared_rules.rjl", digest = Digest(alg = :sha256, hex = "..."))
    ],
    enforcement = (profile = :bankgrade, require_signed_imports = true),
    signatures = [Signature(...)]
)
```

DecisionRequest:
```rulia
DecisionRequest(
    format = :rulia_decision_request_v1,
    bundle_id = Digest(alg = :sha256, hex = "..."),
    request_id = "req-2026-02-04-0001",
    subject = (type = :account, id = "acct-123"),
    input = (amount = 12500, country = :us),
    context = (channel = :web, received_at = "2026-02-04T18:20:00Z")
)
```

DecisionReceipt:
```rulia
DecisionReceipt(
    format = :rulia_decision_receipt_v1,
    receipt_id = Digest(alg = :sha256, hex = "..."),
    bundle_id = Digest(alg = :sha256, hex = "..."),
    policy_digest = Digest(alg = :sha256, hex = "..."),
    request_id = "req-2026-02-04-0001",
    input_digest = Digest(alg = :sha256, hex = "..."),
    evaluation = (decision = :deny, output = (reason = :velocity), trace_digest = Digest(...)),
    output_digest = Digest(alg = :sha256, hex = "..."),
    runtime = (engine = "fraud-core", version = "3.9.1", profile = :bankgrade),
    chain = (request_digest = Digest(...)),
    signatures = [Signature(...)]
)
```

### B) Canonical hashing and signing rules (v1)
All digests are computed from canonical bytes produced by the Rulia binary encoder.

Definitions:
- `canonical_digest(value, alg)` = digest of canonical bytes for `value`.
- `payload_digest(value, alg)` = `canonical_digest(Signed.payload, alg)` if `value` is
  `Signed`, otherwise `canonical_digest(value, alg)`.

Rules:
- `bundle_body = PolicyBundle` with `signatures = []` and `id` omitted or set to `nil`.
- `bundle_id = canonical_digest(bundle_body, alg)` and `PolicyBundle.id` must match it.
- `policy_digest = payload_digest(PolicyBundle.policy, alg)`.
- `input_digest = payload_digest(DecisionRequest.input, alg)`.
- `output_digest = canonical_digest(DecisionReceipt.evaluation.output, alg)`.
- `receipt_body = DecisionReceipt` with `signatures = []` and `receipt_id` omitted or set to `nil`.
- `receipt_id = canonical_digest(receipt_body, alg)` and `DecisionReceipt.receipt_id` must match it.
- `PolicyBundle.signatures` sign `bundle_body` using ADR-0005 v1 rules with domain
  `rulia:policy_bundle:v1` and scope `:rulia_policy_bundle_v1`.
- `DecisionReceipt.signatures` sign `receipt_body` using ADR-0005 v1 rules with domain
  `rulia:decision_receipt:v1` and scope `:rulia_decision_receipt_v1`.
- Decision requests MAY be wrapped in `Signed`; if so, verify `Signed` with
  domain `rulia:signed:v1` and scope `:rulia_signed_v1` before using `payload_digest`.
- Never sign text form; only sign canonical bytes or their canonical digest.

### C) Bankgrade decisioning profile (policy)
The `:bankgrade` profile is a named policy rule set:
- Deterministic parsing required for all inputs and policy bundles.
- Hermetic import resolution required; no ambient filesystem imports.
- Imports pinned by digest required.
- Signature threshold required for bundle activation.
- Receipts must be signed by platform keys.
- Allowed digest and signature algorithms are explicitly enumerated.

### D) Privacy guidance
Receipts may store only digests and high-level outcome metadata. Raw inputs and outputs
may be stored encrypted elsewhere, referenced by digest, and revealed only through
authorized audit workflows.

## Consequences
- Auditable, replayable decisions without requiring a blockchain.
- Interoperability: different systems can verify bundles and receipts consistently.
- Clear chain-of-custody story for policy distribution and decision execution.

## Open Questions
- Rule trace representation: full trace vs hashed trace vs trace digests only.
- Multi-tenant key governance and rotation strategy across platforms.
