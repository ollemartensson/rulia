# Architecture

## Topology

1. Fixed-width legacy record is placed in `demo/volumes/tk4/outbox/`.
2. `mf-outbox-bridge-julia` parses deterministically, validates `record_checksum`, computes raw digest.
3. Bridge publishes the canonical event to Kafka topic `legacy.outbox.v0` using `kcat`.
4. Bridge also forwards the same event to `workflow-host-julia` via HTTP (`/workflow/seed`) for deterministic orchestration.
5. `workflow-host-julia` canonicalizes inputs into artifacts by digest and executes:
   - `S1 validate`
   - `S2a mediate_transform` (creates canonical `MediatedEvent` artifact)
   - `S2b distribute_fanout` (webhook + file delivery with obligations/receipts)
   - `S3 crm_update`
   - `S4 audit_append`
   - `S5 sign_bundle`
   - `S5a signing_links`
   - `S5b signature_gate_parent`
   - `S5c signature_gate_child`
   - `S6 mainframe_open_account`
   - `S7 finalize`
6. Internal UI can trigger `POST /workflow/runs/{id}/pii/reveal`, which calls `pii-vault-mock`, appends a hash-chained ledger event, and stores both PII + ledger receipts as artifacts.
7. Bundle export includes `ledger_chain.jsonl` + head hash so replay can verify audit-chain continuity offline.
8. Distribution fan-out media:
   - HTTP webhook adapter: `webhook-mock` (Julia) at `/webhook/deliver`
   - File drop egress: `demo/volumes/egress/files/<mediated_event_digest>.json`
9. Workflow host calls downstream capabilities via HTTP:
   - `crm-mock` (Julia)
   - `audit-ledger` (Java)
   - `signing-mock` (Julia)
   - `pii-vault-mock` (Julia)
10. Each delivery/capability returns a deterministic receipt with stable `receipt_digest`.
11. Workflow host writes final `verification PASS` artifact and supports bundle export/replay.
12. `dialog-ui` (Vite + React + Ant Design) provides a read-only dialog lens over workflow host runs, trace steps, obligations, receipts, and artifacts by digest.
13. `sdk-gateway` (Node + `@rulia/js`) provides SDK-backed workflow inspection used by `workflow-host-julia` during bundle export.

## Why HTTP proxy for workflow ingest

To keep demo reliability high in mixed local environments, this demo uses:
- Kafka publication for observability (`legacy.outbox.v0`)
- direct deterministic HTTP ingestion for workflow execution

This avoids depending on Julia Kafka client behavior while still proving outbox -> Kafka + workflow coordination.

## Deterministic digest scope

- Canonical format: UTF-8 JSON with sorted object keys
- Arrays preserve order
- Floats are normalized to canonical text if present; NaN/Inf are rejected
- No timestamps or random UUIDs in digest scope

## Artifact store

- Artifacts are canonical bytes stored as files:
  - `demo/volumes/artifacts/<digest>`
- Bundle exports are under:
  - `demo/volumes/bundles/<run-id>-<digest-prefix>/`
- File egress outputs are under:
  - `demo/volumes/egress/files/<mediated_event_digest>.json`

## Dialog UI lens

- Built with Vite + React plugin and Ant Design components (`antd`).
- Served under Traefik at `/ui/` from `dialog-ui`.
- Read-only by design: fetches runs, run detail, artifacts, and bundle export metadata from `/workflow/*`.
- Replay actions remain explicit and deterministic by showing exact `make replay` / `make replay-negative` commands.

## Gateway routes

- `/workflow` -> `workflow-host-julia`
- `/crm` -> `crm-mock`
- `/webhook` -> `webhook-mock`
- `/sign` -> `signing-mock`
- `/ledger` -> `audit-ledger`
- `/pii` -> `pii-vault-mock`
- `/sdk` -> `sdk-gateway`
- `/ui` -> `dialog-ui`

## Mainframe emulation status

`hercules-stub` is included as a placeholder for rootless Podman portability.
For full TK4-/MVS 3.8j with 3270 terminal flow, see `demo/mainframe/README.md`.
