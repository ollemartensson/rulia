# Rulia Podman Demo (Julia-first, Determinism-first)

This folder provides a runnable showcase for:
- legacy-style fixed-width outbox records
- outbox bridge to Redpanda (Kafka API)
- deterministic workflow orchestration in Julia
- Julia adapters + Java audit-ledger capability
- receipts/evidence + artifact digests + bundle export/replay

## Quick start

```bash
cd demo
cp env.example .env
make up
make seed
sleep 5
make verify
make export
```

Replay exported bundle (offline workflow host mode):

```bash
make replay BUNDLE=volumes/bundles/<bundle-id>
```

## Services

- `traefik` gateway: [http://localhost:8080](http://localhost:8080)
- `traefik` dashboard: [http://localhost:8081](http://localhost:8081)
- Redpanda console: [http://localhost:18082](http://localhost:18082)
- `workflow-host-julia` routed at `/workflow`
- `crm-mock` routed at `/crm`
- `webhook-mock` routed at `/webhook`
- `signing-mock` routed at `/sign`
- `audit-ledger` (Java) routed at `/ledger`
- `pii-vault-mock` routed at `/pii`
- `sdk-gateway` routed at `/sdk` (backs SDK-based workflow inspection)
- `mf-outbox-bridge-julia` watches `volumes/tk4/outbox`

## Mainframe note

This demo ships a `hercules-stub` container and fixed-width outbox files instead of a distributable TK4- image.
See `mainframe/README.md` for full constraints and optional real 3270 integration notes.

## Determinism contract used here

- Canonical JSON in digest scope: UTF-8, sorted keys, stable array order
- No timestamps / random UUIDs in digest scope
- Receipts share a uniform schema
- Artifact identity is `sha256(canon_json(obj))`
- Explicit workflow topology: `S1 validate` -> `S2a mediate_transform` -> `S2b distribute_fanout` -> `S3 crm_update` -> `S4 audit_append` -> `S5 sign_bundle` -> `S5a signing_links` -> `S5b signature_gate_parent` -> `S5c signature_gate_child` -> `S6 mainframe_open_account` -> `S7 finalize`
- PII reads are audited via hash-chained ledger events; bundle export includes `ledger_chain.jsonl` for offline verification.

## Commands

- `make up`: build and run stack
- `make down`: stop stack
- `make logs`: tail logs
- `make seed`: copy sample fixed-width record to outbox
- `make verify`: print latest run PASS digest
- `make export`: export latest run bundle
- `make replay BUNDLE=...`: offline replay from bundle (must match final digest)
- `make canon-check`: canonical vectors + SDK surface checks
- `make sdk-js-example`: run JavaScript SDK surface example
- `make sdk-julia-example`: run Julia SDK surface example
- `make sdk-jvm-example`: run JVM SDK surface example
- `make sdk-examples`: run all SDK surface examples

## SDK examples

SDK-focused runnable examples live under `sdk/`.
See `sdk/README.md` for commands, prerequisites, and runtime loading options (`RULIA_MANIFEST_URL` / `RULIA_LIB_PATH`).
`make canon-check` now includes SDK checks (`sdk-examples`) so the demo verification path exercises SDKs directly.

## File layout

See `docs/ARCHITECTURE.md` and `docs/STORYBOARD.md`.
