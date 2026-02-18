# bankid-test adapter (Julia)

Endpoints:
- `GET /bankid/health`
- `POST /bankid/sign/start`
- `POST /bankid/sign/collect`

Modes:
- `BANKID_MODE=mock` (default): no outbound BankID calls.
- `BANKID_MODE=real`: calls BankID RP API v6.0 over mTLS using mounted certs.

Required env in real mode:
- `BANKID_BASE_URL` (default `https://appapi2.test.bankid.com/rp/v6.0`)
- `BANKID_PFX_PATH`
- `BANKID_PFX_PASSWORD`
- `BANKID_CA_PATH` (optional; defaults to system CA roots)
