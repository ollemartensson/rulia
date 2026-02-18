# mf-outbox-bridge-julia

Watches legacy outbox records and performs deterministic bridge steps:

1. Parse fixed-width record.
2. Validate record checksum.
3. Publish canonical event to Redpanda/Kafka topic `legacy.outbox.v0`.
4. Forward event to workflow host HTTP seed endpoint.

Publishing uses `kcat` in-container for predictable demo behavior.
