# Conformance Matrix (Demo v0)

## What this demo proves
- Deterministic canonical identity and digest contracts hold across Julia and Java.
- End-to-end evidence is content-addressed, auditable, and replayable offline.
- Tampering or contract drift is detected deterministically at the first mismatch.

## How to run the proof (minimal)
```bash
cd demo
cp env.example .env
make up
make seed && sleep 5 && make verify
BUNDLE="$(make export | awk -F= '/^bundle_path=/{print $2}')"
make down
make replay BUNDLE="$BUNDLE" && make replay-negative BUNDLE="$BUNDLE"
```

## 1) Determinism
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Canonical JSON byte identity (Julia↔Java) + SDK surface coverage | Both runtimes verify identical canonical bytes and SHA-256 against the shared vector suite, and `canon-check` also runs SDK surface checks. | `cd demo && make canon-check` | Output: `canonical verification passed: 3 vector(s)` (Julia + Java) and `sdk javascript surface demo passed`; vectors in `demo/contracts/canon_vectors/vec001.*`, `demo/contracts/canon_vectors/vec002.*`, `demo/contracts/canon_vectors/vec003.*`. |
| Artifact identity by digest (content-addressed store) | Workflow artifacts are stored as canonical JSON bytes under `sha256(canon_json(obj))` filename. | `cd demo && rg -n "function store_artifact|digest = sha256_hex\(bytes\)|artifact_path\(digest\)" services/workflow-host-julia/src/main.jl` | Code path: `demo/services/workflow-host-julia/src/main.jl`; runtime store path: `demo/volumes/artifacts/<digest>`. |
| Receipt digest stability (no timestamps in digest scope) | Receipts compute `receipt_digest` from deterministic canonical JSON of `receipt_wo_digest` / `receiptNoDigest`. | `cd demo && rg -n "receipt_wo_digest|receiptNoDigest|receipt_digest|receiptDigest" services/adapters-julia/crm-mock/src/main.jl services/adapters-julia/webhook-mock/src/main.jl services/adapters-julia/signing-mock/src/main.jl services/java-services/audit-ledger/src/main/java/com/rulia/demo/AuditLedgerServer.java services/workflow-host-julia/src/main.jl` | Code paths: `demo/services/adapters-julia/crm-mock/src/main.jl`, `demo/services/adapters-julia/webhook-mock/src/main.jl`, `demo/services/adapters-julia/signing-mock/src/main.jl`, `demo/services/java-services/audit-ledger/src/main/java/com/rulia/demo/AuditLedgerServer.java`, `demo/services/workflow-host-julia/src/main.jl` (file delivery receipt). |

## 2) Audit & Evidence
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Obligations captured as artifacts (including distribution obligations) | `S2b distribute_fanout` writes deterministic webhook/file obligations; downstream capability requests are also persisted and referenced in `obligation_digests`. | `cd demo && rg -n "obligation_digests|webhook_obligation_digest|file_obligation_digest|crm_obligation_digest|ledger_obligation_digest|sign_obligation_digest" services/workflow-host-julia/src/main.jl` | Code path: `demo/services/workflow-host-julia/src/main.jl`; replay evidence path: `demo/volumes/bundles/<bundle-id>/manifest.json` (`obligation_digests`). |
| Receipts captured as artifacts (including distribution receipts) | `S2b` writes deterministic webhook/file receipts by digest; capability receipts are also persisted and linked in `receipt_digests`. | `cd demo && rg -n "receipt_digests|webhook_receipt_digest|file_receipt_digest|crm_digest|ledger_digest|sign_digest" services/workflow-host-julia/src/main.jl` | Code path: `demo/services/workflow-host-julia/src/main.jl`; replay evidence path: `demo/volumes/bundles/<bundle-id>/manifest.json` (`receipt_digests`). |
| Manifest includes digests of trace/obligations/receipts/final artifact | Bundle export writes `manifest.json` with `run_trace_digest`, `obligation_digests`, `receipt_digests`, `final_digest`, and full `artifact_digests`. | `cd demo && rg -n "manifest = Dict|run_trace_digest|obligation_digests|receipt_digests|final_digest|artifact_digests" services/workflow-host-julia/src/main.jl` | Code path: `demo/services/workflow-host-julia/src/main.jl`; runtime evidence path: `demo/volumes/bundles/<bundle-id>/manifest.json`. |

## 3) Replayability
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Offline replay requires no network (`Sockets.connect` blocked) | Replay overrides socket connect and errors immediately on any network attempt. | `cd demo && rg -n "import Sockets: connect|network calls are forbidden during offline replay" services/workflow-host-julia/src/replay.jl` | Code path: `demo/services/workflow-host-julia/src/replay.jl`. |
| Step-by-step verification using `run_trace.jsonl` | Replay parses trace rows, validates schema, and enforces ordered `STEP_PLAN` `S1`, `S2a`, `S2b`, `S3`, `S4`, `S5`, `S5a`, `S5b`, `S5c`, `S6`, `S7`. | `cd demo && rg -n "STEP_PLAN|mediate_transform|distribute_fanout|parse_trace|replay_step!|run_trace\.jsonl" services/workflow-host-julia/src/replay.jl` | Code path: `demo/services/workflow-host-julia/src/replay.jl`; runtime evidence path: `demo/volumes/bundles/<bundle-id>/run_trace.jsonl`. |
| Final PASS digest match | Replay recomputes final digest and fails unless `replayed_final_digest == expected_final_digest`. | `cd demo && rg -n "expected_final_digest|replayed_final_digest|match \|\| exit\(2\)" services/workflow-host-julia/src/replay.jl` | Code path: `demo/services/workflow-host-julia/src/replay.jl`; output JSON from replay includes `"match":true`. |

## 4) Tamper detection
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Mutation of exported ledger chain fails replay at PII audit verification step | `replay-negative` flips a byte in `ledger_chain.jsonl`; replay exits non-zero with mismatch at `PII-AUDIT pii_audit_chain_verify`. | `cd demo && make replay-negative BUNDLE=volumes/bundles/<bundle-id>` | Make logic: `demo/Makefile` (`replay-negative` target); output includes `tampered_ledger_chain=...`, `replay mismatch`, and `step_id=PII-AUDIT step_type=pii_audit_chain_verify`. |

## 5) Legacy integration
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Fixed-width outbox contract + checksum validation | Record layout is fixed-width with checksum formula; bridge re-parses slices and validates `record_checksum_valid`. | `cd demo && rg -n "record_checksum|148 bytes|Checksum derivation" mainframe/outbox-spec/record_layout.md && rg -n "parse_record|record_checksum_valid|record_checksum_computed" services/mf-outbox-bridge-julia/src/main.jl` | Spec path: `demo/mainframe/outbox-spec/record_layout.md`; implementation path: `demo/services/mf-outbox-bridge-julia/src/main.jl`; sample records: `demo/mainframe/outbox-spec/example_records/`. |
| Outbox → Kafka topic `legacy.outbox.v0` | Bridge publishes canonical event to configured Kafka topic. | `cd demo && rg -n "KAFKA_TOPIC|legacy\.outbox\.v0|kcat" services/mf-outbox-bridge-julia/src/main.jl podman-compose.yml` | Evidence paths: `demo/services/mf-outbox-bridge-julia/src/main.jl`, `demo/podman-compose.yml`; optional runtime evidence: Redpanda Console topic `legacy.outbox.v0`. |
| Runtime SDK-backed workflow inspection | `workflow-host-julia` calls `sdk-gateway` (`@rulia/js`) to inspect workflow text and records SDK digest metadata in exported `workflow_files`. | `cd demo && rg -n "SDK_GATEWAY_URL|inspect_workflow_with_sdk|sdk_canonical_digest" services/workflow-host-julia/src/main.jl podman-compose.yml` | Code paths: `demo/services/workflow-host-julia/src/main.jl`, `demo/services/sdk-gateway/src/main.js`, `demo/podman-compose.yml`; manifest evidence: `workflow_files[].sdk_canonical_digest`. |

## 6) Portability
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Bundle export contents | Export endpoint creates `manifest.json`, `run_trace.jsonl`, `artifacts/`, and `workflows/` for a run. | `cd demo && rg -n "bundle_path|artifacts_path|workflows_path|manifest.json|run_trace.jsonl" services/workflow-host-julia/src/main.jl` | Code path: `demo/services/workflow-host-julia/src/main.jl`; runtime evidence path: `demo/volumes/bundles/<bundle-id>/`. |
| Replay from bundle only ("USB-stick mode simulation") | Replay takes only `<bundle_path>`, verifies mediation + distribution + downstream steps from bundled trace/artifacts, verifies exported ledger chain continuity, and does not call network. | `cd demo && make replay BUNDLE=volumes/bundles/<bundle-id>` | Runtime output: `step_ok ...` for `S1`, `S2a`, `S2b`, `S3`, `S4`, `S5`, `S5a`, `S5b`, `S5c`, `S6`, `S7`, `PII-AUDIT` and final JSON with `"match":true`; loader paths in `demo/services/workflow-host-julia/src/replay.jl`. |

## 7) Polyglot safety
| Guarantee | Mechanism | Proof (command) | Evidence (file path/output) |
| --- | --- | --- | --- |
| Java audit-ledger uses the same canonicalizer as verification tool | Audit server and canon verifier both call `CanonJson.canonJson(...)` and `CanonJson.sha256Hex(...)`. | `cd demo && rg -n "CanonJson\.canonJson|CanonJson\.sha256Hex" services/java-services/audit-ledger/src/main/java/com/rulia/demo/AuditLedgerServer.java services/java-services/audit-ledger/src/main/java/com/rulia/demo/CanonVerifyMain.java` | Code paths: `demo/services/java-services/audit-ledger/src/main/java/com/rulia/demo/AuditLedgerServer.java`, `demo/services/java-services/audit-ledger/src/main/java/com/rulia/demo/CanonVerifyMain.java`, `demo/services/java-services/audit-ledger/src/main/java/com/rulia/demo/CanonJson.java`. |
| Canon vectors are shared contract suite (3 vectors currently) | Julia and Java both read `demo/contracts/canon_vectors/*.json` with matching `.canon.hex` and `.sha256`. | `cd demo && ls contracts/canon_vectors/*.json | wc -l && rg -n "contracts/canon_vectors" services/workflow-host-julia/src/canon_verify.jl services/java-services/audit-ledger/src/main/java/com/rulia/demo/CanonVerifyMain.java` | Output count: `3`; contract path: `demo/contracts/canon_vectors/`. |
| Make targets: `canon-check`, `sdk-examples`, `replay`, `replay-negative` | Makefile exposes conformance entry points for cross-runtime canonical checks, SDK surface checks, and positive/negative replay. | `cd demo && rg -n "^canon-check:|^sdk-examples:|^replay:|^replay-negative:" Makefile` | Evidence path: `demo/Makefile`. |

## What is stubbed
- Mainframe runtime is stubbed (`hercules-stub`); external integration path is documented in `demo/mainframe/README.md`.
- Step topology is fixed to `S1`, `S2a`, `S2b`, `S3`, `S4`, `S5`, `S5a`, `S5b`, `S5c`, `S6`, `S7` for this demo; changing it requires synchronized trace schema + replay validator updates in `demo/services/workflow-host-julia/src/main.jl` and `demo/services/workflow-host-julia/src/replay.jl`.

## Pointers
- [Architecture](ARCHITECTURE.md)
- [Demo Script](DEMO_SCRIPT.md)
- [Storyboard](STORYBOARD.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Canon contract vectors](../contracts/canon_vectors/)
