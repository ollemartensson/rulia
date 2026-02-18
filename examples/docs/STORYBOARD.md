# Storyboard

1. A legacy operator flow (mainframe-ish) emits fixed-width account-change records.
2. Record lands in outbox volume (`tk4/outbox`).
3. Bridge captures record, validates checksum, publishes event to Redpanda topic.
4. Bridge forwards deterministic event to workflow-host.
5. Workflow-host creates canonical parsed input artifact and derives run id from digest.
6. Workflow-host performs deterministic mediation and stores a canonical `MediatedEvent` artifact by digest.
7. Workflow-host fans out distribution to webhook + file egress and stores obligations/receipts for each medium.
8. Workflow-host invokes CRM adapter and receives deterministic receipt.
9. Workflow-host invokes Java audit-ledger and receives deterministic receipt.
10. Workflow-host invokes signing adapter and receives deterministic receipt.
11. Workflow-host stores final PASS artifact and exposes digests through API.
12. Internal UI can trigger audited PII reveal; PII vault appends a hash-chained ledger event first and returns a linked access receipt.
13. Operator exports a replay bundle (including `ledger_chain.jsonl`) and can replay offline with identical final digest + verified audit chain.
