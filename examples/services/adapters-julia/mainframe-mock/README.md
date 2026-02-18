# mainframe-mock

Deterministic adapter that models the external mainframe open-account capability.

## Endpoints

- `GET /mainframe/health`
- `POST /mainframe/open-account`

`/mainframe/open-account` returns a deterministic receipt with:
- `receipt_type = mainframe.open_account`
- `request_digest = sha256:<canon-request-digest>`
- `account_id = ACC-<first12(request_digest_hex)>`
- `outputs_digest = sha256:<canon-outputs-digest>`
- `evidence.policy = mainframe-mock-v1`
- `receipt_digest = sha256:<canon-receipt-digest>`
