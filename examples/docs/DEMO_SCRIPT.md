# Demo Script

For a guarantee-to-proof map (determinism, replayability, tamper detection, portability, and polyglot safety), see [CONFORMANCE_MATRIX.md](CONFORMANCE_MATRIX.md).

## 1. Bring stack up

```bash
cd demo
cp env.example .env
grep -q '^WORKFLOW_SIGNING_TOKEN_SECRET=' .env || echo "WORKFLOW_SIGNING_TOKEN_SECRET=change-me-demo-secret" >> .env
make up
```

Check status:

```bash
make ps
```

## 2. Open UIs

- Redpanda Console: `http://localhost:18082`
- Traefik Dashboard: `http://localhost:8081`
- Dialog UI: `http://localhost:8080/ui/`

## 2a. Dialogs (Dialog UI)

1. Open `http://localhost:8080/ui/`.
2. Select the latest run in the runs table.
3. Inspect `S1..SN` in the step trace table (`Inspect` on each row).
4. In the step dialog, open tabs for Inputs / Outputs / Obligations / Receipts and click digests to view canonical JSON.
5. Open Replay actions and show the copyable commands for:
   - `Replay offline`
   - `Replay negative (tamper)`

## 2b. Public signing UI tests

```bash
$ cd demo
$ make test-ui
```

## 3. Seed legacy outbox record

```bash
make seed
```

Wait a few seconds, then confirm topic traffic in Redpanda Console:
- Topic: `legacy.outbox.v0`

## 4. Verify workflow run and final digest

```bash
make verify
curl -s http://localhost:8080/workflow/runs | jq .
```

## 5. Export replay bundle

```bash
make export
ls -la volumes/bundles
```

## 6. Stop online stack

```bash
make down
```

## 7. Semantic replay (step-by-step proof)

Use the printed bundle path from `make export`.

```bash
# bring only dependencies needed for `podman-compose run`
cp env.example .env
make replay BUNDLE=volumes/bundles/<bundle-id>
make replay-negative BUNDLE=volumes/bundles/<bundle-id>
```

The trace-backed replay proves:
- Step ordering is deterministic (`S1`, `S2a`, `S2b`, `S3`, `S4`, `S5`, `S5a`, `S5b`, `S5c`, `S6`, `S7` in fixed order and type).
- Step outputs are recomputable offline from bundled artifacts and receipts.
- Tampering is detected at the first diverging step with expected vs actual digest output.
- PII audit chain continuity is verified offline from exported `ledger_chain.jsonl`.

## 8. Shared account opening demo (E2E)

1. Start stack in mock mode.

```bash
cd demo
make up
```

2. Open internal UI and create a run.
- Internal UI: `http://localhost:8080/ui/`
- Create run via API:

```bash
curl -sS http://localhost:8080/workflow/ingest \
  -H 'content-type: application/json' \
  -d '{"event":{"customer_id":"190000000000","change_type":"shared_account.open","new_value":"joint-account-v1","correlation_id":"demo-shared-account-v0"}}' | jq .
```

3. Open parent + child signing links from the run detail, sign both in public pages.

4. Return to internal run detail page and verify:
- `S5b signature_gate_parent` is `ok`
- `S5c signature_gate_child` is `ok`
- `S6 mainframe_open_account` is `ok`
- `S7 finalize` is `ok`
- Run status is `PASS`

5. Click `Reveal PII (audited)` and verify:
- `Latest PII receipt digest` is `sha256:<hex64>`
- `Current audit chain head hash` is `<hex64>`

6. Open `PII Audit` tab and show unbroken chain evidence:
- Chain status is `VERIFIED`
- `Audit head hash` is present
- At least one PII access row is present with decision `ALLOW`
- Open a receipt digest to show artifact JSON
- Open `View ledger chain` to show JSONL chain events linked to event/head hashes

7. Export and replay proof.

```bash
make export
make replay BUNDLE=volumes/bundles/<bundle-id>
make replay-negative BUNDLE=volumes/bundles/<bundle-id>
```

Expected:
- replay returns `\"match\":true`
- replay-negative reports deterministic tamper detection at `PII-AUDIT pii_audit_chain_verify`

## 9. Automated proof

```bash
cd demo
make test-all
```
