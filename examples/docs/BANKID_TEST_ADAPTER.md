# BankID Test Adapter (Julia)

This adapter is an external capability endpoint for BankID signing in the demo stack.

## Service and route

- Service name: `bankid-test`
- Public route via Traefik: `/bankid`
- Health endpoint: `GET /bankid/health`

## Endpoints

- `POST /bankid/sign/start`
- `POST /bankid/sign/collect`

### Start request

```json
{
  "signing_package_digest": "sha256:...",
  "signer_role": "parent|child",
  "end_user_ip": "1.2.3.4",
  "user_visible_text": "base64..."
}
```

### Start response

```json
{
  "order_ref": "...",
  "auto_start_token": "...",
  "status": "pending"
}
```

### Collect request

```json
{ "order_ref": "..." }
```

### Collect response (pending)

```json
{ "status": "pending", "hint_code": "..." }
```

### Collect response (complete)

```json
{
  "status": "complete",
  "receipt": {
    "receipt_type": "signature.bankid",
    "bankid_environment": "test",
    "signer_role": "parent|child",
    "signing_package_digest": "sha256:...",
    "completion_data_digest": "...",
    "signature_digest": "...",
    "evidence": { "policy": "bankid-test-sign-v1" }
  },
  "receipt_digest": "sha256:..."
}
```

## Deterministic receipt rules

- `completion_data_digest = sha256(canon_json(completion_data_subset))`
- `signature_digest = sha256(canon_json(signature_scope_from_subset))`
- `receipt_digest = sha256(canon_json(receipt_object))`
- Digest scope excludes request-time transport values such as `orderRef`, `autoStartToken`, and timestamps.

## Modes

- `BANKID_MODE=mock` (default):
  - No outbound BankID calls.
  - First collect returns `pending`, subsequent collect returns `complete` with deterministic mock completion data.
- `BANKID_MODE=real`:
  - Calls BankID RP API v6.0 (`/sign`, `/collect`) over mTLS.

## Required environment variables

These keys are in `demo/env.example`:

- `BANKID_BASE_URL=https://appapi2.test.bankid.com/rp/v6.0`
- `BANKID_PFX_PATH=/certs/bankid-test.pfx`
- `BANKID_PFX_PASSWORD=...`
- `BANKID_CA_PATH=/certs/ca.pem` (optional; leave empty for system CA roots)
- `BANKID_CERTS_DIR=./volumes/certs` (host path mounted into `/certs`)

## Certificates and secrets

- Do not commit PFX/PEM/cert files into the repo.
- Mount certs as a volume via `BANKID_CERTS_DIR`.
- Keep secrets in `.env` only; never in versioned files.
