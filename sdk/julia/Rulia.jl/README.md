# Rulia.jl

ABI-first Julia bindings for the Rulia runtime (C ABI v1.1).

## Install + Load

```julia
using Rulia

manifest_url = "https://example.com/manifest.json"
lib_path = install_tools(manifest_url, "0.1.0")

# Or load a library you've already installed
# load_library("/path/to/librulia.so")
```

## Formatting

```julia
using Rulia

canonical = format_text("(b = 2, a = 1)")
@assert format_check(canonical) == true
```

## Binary + Digest

```julia
using Rulia

canonical_bytes = encode_canonical("(b = 2, a = 1)")
roundtrip_text = decode_text(canonical_bytes)
recanonicalized = canonicalize_binary(canonical_bytes)
@assert recanonicalized == canonical_bytes
canonical_value_text = canonicalize_value_text("Tagged(\"complex_ns/tag\", \"data\")")

digested = encode_with_digest("(a = 1, b = 2)")
@assert verify_digest(digested.bytes) == RULIA_DIGEST_SHA256
@assert has_valid_digest(digested.bytes)

typed = parse_typed("(user_first_name = \"Ada\", marker = Tagged(\"complex_ns/tag\", \"data\"))")
first = typed[1]
@assert first.key isa RuliaKeywordValue

annotated = parse_typed("@meta(author = \"ops\", :doc = \"large id\") 12345678901234567890N")
@assert annotated isa RuliaAnnotatedValue
@assert annotated.value isa BigInt
```

## Framing

```julia
using Rulia

payload = UInt8[0x01, 0x02, 0x03]
frame = frame_encode(payload)

decoder = frame_decoder_new(1024)
frames, consumed, need_more, eof = frame_decoder_push!(decoder, frame)
@assert length(frames) == 1
@assert frames[1] == payload
```

## Notes

- The installer enforces sha256 checksums and fails closed on mismatch.
- The shared library is searched under `<artifact_dir>/<target>/lib/` then `<artifact_dir>/lib/`.
