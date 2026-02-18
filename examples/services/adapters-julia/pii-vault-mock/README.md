# pii-vault-mock adapter (Julia)

Deterministic mock PII vault.

## Endpoints

- `GET /pii/health`
- `POST /pii/reveal`

`/pii/reveal` appends a hash-chained ledger event first, then returns a deterministic PII access receipt that references:
- `audit_event_hash`
- `head_hash`
- `ledger_receipt_digest`
