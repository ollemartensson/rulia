# Mainframe-ish Environment Notes

This demo includes a `hercules-stub` container for portability and licensing hygiene.

## Why stubbed

Distributing a full TK4-/MVS 3.8j image in-repo is typically impractical due to size and legal/licensing constraints.

## What is implemented

- Deterministic fixed-width outbox record format
- Sample records under `outbox-spec/example_records/`
- Bridge behavior equivalent to batch-exported legacy file handoff

## Optional full 3270 path (manual)

1. Run Hercules/TK4- externally.
2. Configure spool/JCL job to write fixed-width records matching `record_layout.md`.
3. Mount or copy those records into `demo/volumes/tk4/outbox/`.
4. Use this demo stack unchanged for bridge/workflow/evidence/replay.
