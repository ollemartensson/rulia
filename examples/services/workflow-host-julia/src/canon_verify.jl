using JSON3

include("canon.jl")
using .Canon

function to_plain(x)
    if x isa JSON3.Object
        d = Dict{String, Any}()
        for (k, v) in pairs(x)
            d[String(k)] = to_plain(v)
        end
        return d
    elseif x isa JSON3.Array
        return [to_plain(v) for v in x]
    else
        return x
    end
end

function first_diff_index(expected::Vector{UInt8}, actual::Vector{UInt8})::Int
    n = min(length(expected), length(actual))
    for i in 1:n
        if expected[i] != actual[i]
            return i
        end
    end
    return length(expected) == length(actual) ? 0 : (n + 1)
end

function byte_hex_at(bytes::Vector{UInt8}, idx::Int)::String
    if idx < 1 || idx > length(bytes)
        return "<eof>"
    end
    return string(bytes[idx], base = 16, pad = 2)
end

function main()
    vectors_dir = normpath(joinpath(@__DIR__, "..", "..", "..", "contracts", "canon_vectors"))
    json_files = sort(filter(f -> endswith(f, ".json"), readdir(vectors_dir; join = true)))

    isempty(json_files) && error("no vector files found in $(vectors_dir)")

    failures = 0

    for json_path in json_files
        stem = splitext(basename(json_path))[1]
        expected_hex_path = joinpath(vectors_dir, stem * ".canon.hex")
        expected_sha_path = joinpath(vectors_dir, stem * ".sha256")

        expected_hex = lowercase(strip(read(expected_hex_path, String)))
        expected_sha = lowercase(strip(read(expected_sha_path, String)))

        parsed = to_plain(JSON3.read(read(json_path, String)))
        actual_bytes = canon_json(parsed)
        actual_hex = bytes2hex(actual_bytes)
        actual_sha = sha256_hex(actual_bytes)

        expected_bytes = hex2bytes(expected_hex)

        if actual_hex != expected_hex
            failures += 1
            diff_idx = first_diff_index(expected_bytes, actual_bytes)
            println(stderr, "[FAIL] $(stem): canonical bytes mismatch")
            println(stderr, "  expected_len=$(length(expected_bytes)) actual_len=$(length(actual_bytes))")
            println(stderr, "  first_diff_byte_index=$(diff_idx)")
            println(stderr, "  expected_byte=$(byte_hex_at(expected_bytes, diff_idx)) actual_byte=$(byte_hex_at(actual_bytes, diff_idx))")
            println(stderr, "  expected_json=$(String(expected_bytes))")
            println(stderr, "  actual_json=$(String(actual_bytes))")
            continue
        end

        if actual_sha != expected_sha
            failures += 1
            println(stderr, "[FAIL] $(stem): sha256 mismatch")
            println(stderr, "  expected_sha=$(expected_sha)")
            println(stderr, "  actual_sha=$(actual_sha)")
            println(stderr, "  canonical_json=$(String(actual_bytes))")
            continue
        end

        println("[OK] $(stem) bytes+sha256 match")
    end

    if failures > 0
        println(stderr, "canonical verification failed: $(failures) vector(s) mismatched")
        exit(1)
    end

    println("canonical verification passed: $(length(json_files)) vector(s)")
end

main()
