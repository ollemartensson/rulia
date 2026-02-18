# audit-ledger (Java)

Append-only deterministic receipt service.

## Endpoints

- `POST /ledger/append`
- `GET /ledger/entries`
- `GET /ledger/chain?head_hash=<hex64>`
- `GET /ledger/health`

`/ledger/append` writes canonical hash-chained JSONL rows to `ledger_chain.jsonl`, linking each row via:
- `sequence`
- `prev_hash`
- `event_hash`

Receipts include deterministic `receipt_digest` plus `sequence`, `prev_hash`, `event_hash`, and `head_hash`.
