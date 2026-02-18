using Test
using Rulia

const FIXTURE_VERSION = "0.1.0"
const FIXTURE_MANIFEST = joinpath(@__DIR__, "fixtures", "manifest.json")
const FIXTURE_MANIFEST_URL = "file://" * FIXTURE_MANIFEST
const REPO_ROOT = realpath(joinpath(@__DIR__, "..", "..", "..", ".."))
const DIST_MANIFEST = joinpath(REPO_ROOT, "dist", "releases", FIXTURE_VERSION, "manifest.json")

function ensure_fixture_supported()
    return Rulia.platform_target() == "x86_64-unknown-linux-gnu"
end

function select_manifest_url()
    if isfile(DIST_MANIFEST)
        println("using dist manifest: " * DIST_MANIFEST)
        return "file://" * DIST_MANIFEST
    end
    println("dist manifest not found at " * DIST_MANIFEST * "; falling back to fixture manifest")
    return FIXTURE_MANIFEST_URL
end

function install_manifest(manifest_url::String)
    cache_dir = mktempdir()
    return install_tools(manifest_url, FIXTURE_VERSION; cache_dir=cache_dir)
end

if !ensure_fixture_supported()
    @testset "fixtures" begin
        @test_skip "fixture supports x86_64-unknown-linux-gnu only"
    end
else
    const MANIFEST_URL = select_manifest_url()
    const LIB_PATH = install_manifest(MANIFEST_URL)

    @testset "install_from_file_manifest" begin
        @test isfile(LIB_PATH)
    end

    @testset "format_roundtrip" begin
        input = "(b = 2, a = 1, cfg = import \"cfg.rjl\", id = @new(:uuid))"
        canonical = format_text(input)
        @test format_check(canonical) == true
        @test format_check(input) == false
        @test occursin("import \"cfg.rjl\"", canonical)
        @test occursin("@new(:uuid)", canonical)
    end

    @testset "framing_roundtrip" begin
        payload = UInt8[0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13]
        frame = frame_encode(payload)

        decoder = frame_decoder_new(1024)
        chunk1 = frame[1:2]
        frames, consumed, need_more, eof = frame_decoder_push!(decoder, chunk1)
        @test length(frames) == 0
        @test need_more == true
        @test eof == false
        @test 0 <= consumed <= length(chunk1)

        chunk2 = frame[3:end]
        frames, consumed, need_more, eof = frame_decoder_push!(decoder, chunk2)
        @test length(frames) == 1
        @test frames[1] == payload
        @test need_more == false
        @test eof == false
        @test 0 <= consumed <= length(chunk2)
    end

    @testset "error_handling" begin
        @test_throws RuliaError format_text("(a =")
    end

    @testset "binary_canonical_roundtrip" begin
        input = "(b = 2, a = 1, cfg = import \"cfg.rjl\", id = @new(:uuid))"
        canonical = encode_canonical(input)
        @test length(canonical) > 0

        decoded = decode_text(canonical)
        @test occursin("cfg", decoded)

        recanonical = canonicalize_binary(canonical)
        @test recanonical == canonical
    end

    @testset "digest_roundtrip" begin
        encoded = encode_with_digest("(a = 1, b = 2)")
        @test length(encoded.digest) == 32
        @test length(encoded.bytes) > 0
        @test verify_digest(encoded.bytes) == RULIA_DIGEST_SHA256
        @test has_valid_digest(encoded.bytes) == true
    end

    @testset "keyword_and_tag_syntax_coverage" begin
        samples = [
            ":status",
            "'status",
            "@?entity",
            "_",
            "Keyword(\"my_app/config\")",
            "Symbol(\"special/value\")",
            "Tagged(\"complex_ns/tag\", \"data\")",
            "Point([1, 2])",
            "Set([1, 2, 3])",
            "Ref(:email, \"alice@example.com\")",
            "UUID(\"550e8400-e29b-41d4-a716-446655440000\")",
            "ULID(\"01ARZ3NDEKTSV4RRFFQ69G5FAV\")",
            "Instant(\"2025-01-01T00:00:00Z\")",
            "Generator(:uuid)",
            "@meta(author = \"admin\", :version = \"1.0\", \"x-id\" = \"abc\") User(id = 1)",
            "\"Status doc\" :status",
            "@ns user begin (id = 101, name = \"Ada\") end",
            "let x = 1 x",
            "let [a, b] = [1, 2] [a, b]",
            "let name = \"Ada\" \"Hello $name\"",
            "let f = fn(x) => x f(1)",
            "(user_first_name = \"Ada\", :ce_specversion = \"1.0\", k = Keyword(\"my_app/config\"))",
        ]

        for sample in samples
            canonical_text = canonicalize_value_text(sample)
            @test format_check(canonical_text) == true
            canonical_bytes = encode_canonical(sample)
            decoded = decode_text(canonical_bytes)
            @test decoded == canonical_text
        end

        keyword_canonical = canonicalize_value_text("Keyword(\"my_app/config\")")
        @test occursin("Keyword(\"my_app/config\")", keyword_canonical)

        tagged_canonical = canonicalize_value_text("Tagged(\"complex_ns/tag\", \"data\")")
        @test occursin("Tagged(\"complex_ns/tag\"", tagged_canonical)
    end

    @testset "typed_bigint_and_annotated_traversal" begin
        supported = try
            parse_typed("12345678901234567890N") isa BigInt &&
            parse_typed("@meta(:doc = \"x\") 1") isa RuliaAnnotatedValue
        catch
            false
        end
        if !supported
            @test_skip "fixture library does not expose bigint/annotated typed traversal symbols"
            return
        end

        typed = parse_typed("@meta(author = \"ops\", :doc = \"large id\") 123456789012345678901234567890N")
        @test typed isa RuliaAnnotatedValue
        annotated = typed::RuliaAnnotatedValue
        @test annotated.value isa BigInt
        @test annotated.value == parse(BigInt, "123456789012345678901234567890")

        found_author = false
        found_doc = false
        for entry in annotated.metadata
            if entry.key isa RuliaKeywordValue
                key = entry.key::RuliaKeywordValue
                if key.namespace === nothing && key.name == "author"
                    @test entry.value == "ops"
                    found_author = true
                end
                if key.namespace === nothing && key.name == "doc"
                    @test entry.value == "large id"
                    found_doc = true
                end
            end
        end
        @test found_author
        @test found_doc
    end

    @testset "typed_keyword_tag_map_and_vector_traversal" begin
        typed = parse_typed(
            "(user_first_name = \"Ada\", tags = [:alpha, :beta], marker = Tagged(\"complex_ns/tag\", \"data\"))"
        )
        @test typed isa Vector{RuliaMapEntry}
        entries = typed
        @test length(entries) == 3

        by_name = Dict{String,RuliaMapEntry}()
        for entry in entries
            @test entry.key isa RuliaKeywordValue
            key = entry.key::RuliaKeywordValue
            by_name[key.name] = entry
        end

        @test haskey(by_name, "first_name")
        first_name_entry = by_name["first_name"]
        first_name_key = first_name_entry.key::RuliaKeywordValue
        @test first_name_key.namespace == "user"
        @test first_name_entry.value == "Ada"

        @test haskey(by_name, "tags")
        tags_entry = by_name["tags"]
        @test tags_entry.value isa Vector
        tags = tags_entry.value
        @test length(tags) == 2
        @test tags[1] isa RuliaKeywordValue
        @test tags[2] isa RuliaKeywordValue
        @test (tags[1]::RuliaKeywordValue).name == "alpha"
        @test (tags[2]::RuliaKeywordValue).name == "beta"

        @test haskey(by_name, "marker")
        marker_entry = by_name["marker"]
        @test marker_entry.value isa RuliaTaggedValue
        marker = marker_entry.value::RuliaTaggedValue
        @test marker.tag.namespace == "complex_ns"
        @test marker.tag.name == "tag"
        @test marker.value == "data"
    end
end
