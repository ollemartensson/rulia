using Rulia

function require_condition(condition::Bool, message::AbstractString)
    condition || error(message)
end

function ensure_loaded!()
    manifest_url = get(ENV, "RULIA_MANIFEST_URL", "")
    version = get(ENV, "RULIA_VERSION", "0.1.0")
    lib_path = get(ENV, "RULIA_LIB_PATH", "")

    if !isempty(manifest_url)
        installed = install_tools(manifest_url, version)
        println("loaded via manifest from: " * installed)
        return
    end

    if isempty(lib_path)
        error("set RULIA_MANIFEST_URL (and optionally RULIA_VERSION) or RULIA_LIB_PATH")
    end
    isfile(lib_path) || error("RULIA_LIB_PATH does not exist: " * lib_path)
    load_library(lib_path)
    println("loaded via library path: " * lib_path)
end

ensure_loaded!()

formatted = format_text("(b = 2, a = 1)")
require_condition(format_check(formatted), "formatted text should be canonical")

canonical_bytes = encode_canonical("(b = 2, a = 1)")
decoded_text = decode_text(canonical_bytes)
require_condition(format_check(decoded_text), "decoded canonical bytes should be canonical text")
require_condition(format_check(canonicalize_value_text("(b = 2, a = 1)")), "canonicalize_value_text should return canonical text")
require_condition(canonicalize_binary(canonical_bytes) == canonical_bytes, "binary recanonicalization mismatch")

typed = parse_typed("(user_first_name = \"Ada\", marker = Tagged(\"complex_ns/tag\", \"data\"))")
require_condition(typed isa Vector{RuliaMapEntry}, "typed parse should return map entries")
entries = typed::Vector{RuliaMapEntry}

found_first_name = any(entries) do entry
    if entry.key isa RuliaKeywordValue
        key = entry.key::RuliaKeywordValue
        return key.namespace == "user" && key.name == "first_name" && entry.value == "Ada"
    end
    return false
end
require_condition(found_first_name, "missing typed user/first_name")

decoded_typed = decode_typed(canonical_bytes)
require_condition(decoded_typed isa Vector{RuliaMapEntry}, "typed decode should return map entries")

digested = encode_with_digest("(a = 1, b = 2)")
require_condition(length(digested.digest) == 32, "sha256 digest length mismatch")
require_condition(verify_digest(digested.bytes) == RULIA_DIGEST_SHA256, "digest verification mismatch")
require_condition(has_valid_digest(digested.bytes), "has_valid_digest expected true")

payload = UInt8[0x01, 0x02, 0x03]
frame = frame_encode(payload)
decoder = frame_decoder_new(1024)

first_frames, _, first_need_more, _ = frame_decoder_push!(decoder, frame[1:2])
require_condition(isempty(first_frames), "first chunk should not produce a frame")
require_condition(first_need_more, "first chunk should require more data")

second_frames, _, second_need_more, _ = frame_decoder_push!(decoder, frame[3:end])
require_condition(length(second_frames) == 1, "second chunk should produce one frame")
require_condition(second_frames[1] == payload, "frame payload mismatch")
require_condition(!second_need_more, "second chunk should complete frame")

println("sdk julia surface demo passed")
