# rulia-wasm

WASM bindings for the canonical Rulia runtime.

This crate now exposes the same high-level runtime operations used in the JVM/Julia SDKs:

- `format_text`, `format_check`
- `encode`, `encode_canonical`, `decode_text`, `canonicalize_binary`, `canonicalize_value_text`
- `parse_typed`, `decode_typed`
- `encode_with_digest`, `verify_digest`, `has_valid_digest`
- `frame_encode`, `frame_encode_with_limit`, `FrameDecoder`
- Reader/JS-view APIs: `reader_new`, `reader_root`, `value_kind`, `value_as_string`, `value_as_bytes`, `to_js_view`, `to_json`

Notes:
- WASM formatting uses canonical parse/encode/decode text normalization from `rulia` core.
- Tree-sitter formatter behavior remains available through native `rulia-fmt` tooling.
