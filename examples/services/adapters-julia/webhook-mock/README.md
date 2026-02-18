# webhook-mock

Deterministic webhook delivery adapter.

## Endpoints

- `GET /webhook/health`
- `POST /webhook/deliver`

## Receipt contract

`POST /webhook/deliver` returns a deterministic receipt:
- `receipt_type = "webhook.delivery"`
- `request_id` from request object
- `inputs_digest = mediated_event_digest`
- `outputs_digest = sha256(canon_json({"status":"DELIVERED"}))`
- `receipt_digest = sha256(canon_json(receipt_without_digest))`
