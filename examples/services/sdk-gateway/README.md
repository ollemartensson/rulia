# SDK Gateway

Node service that exposes a small HTTP API backed by the JavaScript SDK (`@rulia/js`).

Endpoints:

- `GET /sdk/health`
- `POST /sdk/workflow/inspect` with JSON body `{ "text": "<rulia-workflow-text>" }`

`workflow-host-julia` uses this service during bundle export to attach SDK-derived workflow metadata.
