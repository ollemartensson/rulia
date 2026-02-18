# workflow-host-julia

Deterministic orchestration host.

## Endpoints

- `GET /workflow/runs`
- `GET /workflow/runs/{id}`
- `GET /workflow/artifacts/{digest}`
- `GET /workflow/signing/token/{token}`
- `POST /workflow/seed`
- `POST /workflow/signatures/submit`
- `POST /workflow/runs/{id}/pii/reveal`
- `GET /workflow/bundles/{run_id}/export`

## Determinism notes

- Artifact identity = `sha256(canon_json(obj))`
- Run id derived from input artifact digest prefix
- No nondeterministic fields in digest scope
- Explicit workflow topology:
  - `S1 validate`
  - `S2a mediate_transform`
  - `S2b distribute_fanout`
  - `S3 crm_update`
  - `S4 audit_append`
  - `S5 sign_bundle`
  - `S5a signing_links`
  - `S5b signature_gate_parent`
  - `S5c signature_gate_child`
  - `S6 mainframe_open_account`
  - `S7 finalize`
- PII reveal actions are audited out-of-band and stored as artifacts with hash-chained ledger references.
- Signing tokens are deterministic HMAC payloads derived from run id, role, signing package digest, and nonce.
- Configure signing HMAC secret via `WORKFLOW_SIGNING_TOKEN_SECRET` (set in runtime env for non-default behavior).

## Replay

Offline replay utility:

```bash
julia --project=. src/replay.jl /app/volumes/bundles/<bundle-id>
```
