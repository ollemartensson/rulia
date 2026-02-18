# signing-mock adapter (Julia)

Endpoint: `POST /sign`

Input includes a `manifest` object.
Output includes deterministic signature `sha256(canon_json(manifest))` within a uniform receipt envelope.
