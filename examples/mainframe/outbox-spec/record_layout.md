# Legacy Outbox Record Layout (v0)

Fixed-width ASCII record, 148 bytes (excluding newline):

1. `customer_id` bytes 1-10 (10 chars)
2. `change_type` bytes 11-12 (2 chars)
3. `new_value` bytes 13-52 (40 chars, right padded with spaces)
4. `correlation_id` bytes 53-84 (32 chars)
5. `record_checksum` bytes 85-148 (64 hex chars)

## Checksum derivation

`record_checksum = sha256(customer_id_raw + "|" + change_type_raw + "|" + new_value_raw + "|" + correlation_id_raw)`

Where each `*_raw` is the exact fixed-width slice from the record.

## Notes

- UTF-8/ASCII only.
- No timestamps/random ids in digest scope.
- `change_type` examples: `UP` (update), `AD` (address change).
