using JSON3

include("canon.jl")
using .Canon

# Hard block network access during replay. Any attempted socket connect fails fast.
import Sockets: connect
function connect(args...)
    error("network calls are forbidden during offline replay")
end

const TRACE_SCHEMA_FIELDS = [
    "step_id",
    "step_type",
    "input_digests",
    "output_digests",
    "obligation_digests",
    "receipt_digests",
]

const STEP_PLAN = [
    ("S1", "validate"),
    ("S2a", "mediate_transform"),
    ("S2b", "distribute_fanout"),
    ("S3", "crm_update"),
    ("S4", "audit_append"),
    ("S5", "sign_bundle"),
    ("S5a", "signing_links"),
    ("S5b", "signature_gate_parent"),
    ("S5c", "signature_gate_child"),
    ("S6", "mainframe_open_account"),
    ("S7", "finalize"),
]
const HEX64_RE = r"^[0-9a-f]{64}$"
const SHA256_LABEL_RE = r"^sha256:([0-9a-f]{64})$"

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

function canon_str(x)::String
    if x isa AbstractString
        return String(x)
    end
    return String(canon_json(x))
end

function as_string(x)::String
    x === nothing && return ""
    return x isa AbstractString ? String(x) : string(x)
end

function as_dict(x)::Dict{String, Any}
    if x isa Dict{String, Any}
        return x
    elseif x isa Dict
        out = Dict{String, Any}()
        for (k, v) in pairs(x)
            out[string(k)] = v
        end
        return out
    end
    return Dict{String, Any}()
end

function normalize_artifact_digest(digest)::Union{Nothing, String}
    digest_str = lowercase(strip(as_string(digest)))
    isempty(digest_str) && return nothing
    occursin(HEX64_RE, digest_str) && return digest_str
    m = match(SHA256_LABEL_RE, digest_str)
    m === nothing && return nothing
    return String(m.captures[1])
end

function fail_mismatch(step::Dict{String, Any}, mismatch::String, expected, actual)
    println("replay mismatch")
    println("step_id=$(step["step_id"]) step_type=$(step["step_type"]) mismatch=$(mismatch)")
    println("expected=$(canon_str(expected))")
    println("actual=$(canon_str(actual))")
    exit(2)
end

function fail_global(reason::String, expected, actual)
    println("replay mismatch")
    println("scope=bundle mismatch=$(reason)")
    println("expected=$(canon_str(expected))")
    println("actual=$(canon_str(actual))")
    exit(2)
end

function assert_equals(step::Dict{String, Any}, mismatch::String, expected, actual)
    expected == actual || fail_mismatch(step, mismatch, expected, actual)
end

function ensure_string_array(step::Dict{String, Any}, field::String)::Vector{String}
    haskey(step, field) || fail_mismatch(step, "schema.$(field)", "field present", "field missing")
    raw = step[field]
    raw isa AbstractVector || fail_mismatch(step, "schema.$(field)", "array", typeof(raw))
    out = String[]
    for v in raw
        v isa AbstractString || fail_mismatch(step, "schema.$(field)", "array<string>", typeof(v))
        push!(out, String(v))
    end
    return out
end

function parse_trace(trace_path::String)::Vector{Dict{String, Any}}
    isfile(trace_path) || error("run trace not found: $(trace_path)")
    steps = Dict{String, Any}[]
    for line in eachline(trace_path)
        isempty(strip(line)) && continue
        push!(steps, to_plain(JSON3.read(line)))
    end
    return steps
end

function artifact_path(bundle_path::String, digest::String)::String
    normalized = normalize_artifact_digest(digest)
    normalized === nothing && error("invalid artifact digest: $(digest)")
    return joinpath(bundle_path, "artifacts", normalized)
end

function load_artifact_bytes(step::Dict{String, Any}, category::String, bundle_path::String, digest::String)::Vector{UInt8}
    path = artifact_path(bundle_path, digest)
    isfile(path) || fail_mismatch(step, "$(category).exists", digest, "missing artifact $(path)")
    bytes = read(path)
    actual_digest = sha256_hex(bytes)
    expected_digest = normalize_artifact_digest(digest)
    expected_digest === nothing && fail_mismatch(step, "$(category).digest", "valid digest", digest)
    actual_digest == expected_digest || fail_mismatch(step, "$(category).digest", expected_digest, actual_digest)
    return bytes
end

function load_artifact_obj(step::Dict{String, Any}, category::String, bundle_path::String, digest::String)::Dict{String, Any}
    bytes = load_artifact_bytes(step, category, bundle_path, digest)
    obj = to_plain(JSON3.read(String(bytes)))
    obj isa Dict{String, Any} || fail_mismatch(step, "$(category).json", "object", typeof(obj))
    return obj
end

function mediated_event_from(input_obj::Dict{String, Any})::Dict{String, Any}
    raw_event = get(input_obj, "event", Dict{String, Any}())
    raw_event isa Dict{String, Any} || error("input event must be object")

    customer_id = as_string(get(raw_event, "customer_id", ""))
    change_type = as_string(get(raw_event, "change_type", ""))
    new_value = as_string(get(raw_event, "new_value", ""))
    correlation_id = as_string(get(raw_event, "correlation_id", ""))

    return Dict(
        "event_type" => "customer.change",
        "subject" => "customer/$(customer_id)",
        "source" => "legacy.outbox.v0",
        "correlation_id" => correlation_id,
        "payload" => Dict(
            "customer_id" => customer_id,
            "change_type" => change_type,
            "new_value" => new_value,
        ),
    )
end

function webhook_receipt_for(request::Dict{String, Any})::Dict{String, Any}
    outputs = Dict("status" => "DELIVERED")

    receipt_wo_digest = Dict(
        "receipt_type" => "webhook.delivery",
        "request_id" => as_string(get(request, "request_id", "webhook-unknown")),
        "inputs_digest" => as_string(get(request, "mediated_event_digest", "")),
        "outputs_digest" => sha256_hex(canon_json(outputs)),
        "evidence" => Dict(
            "adapter" => "webhook-mock-julia",
            "version" => "v0",
            "outputs" => outputs,
        ),
    )

    return merge(receipt_wo_digest, Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))))
end

function file_receipt_for(request::Dict{String, Any}, mediated_bytes::Vector{UInt8})::Dict{String, Any}
    inputs_digest = as_string(get(request, "mediated_event_digest", ""))
    path_hint = as_string(get(request, "path_hint", "egress/files/$(inputs_digest).json"))

    receipt_wo_digest = Dict(
        "receipt_type" => "file.delivery",
        "request_id" => as_string(get(request, "request_id", "file-unknown")),
        "inputs_digest" => inputs_digest,
        "outputs_digest" => sha256_hex(mediated_bytes),
        "evidence" => Dict("path_hint" => path_hint),
    )

    return merge(receipt_wo_digest, Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))))
end

function crm_receipt_for(request::Dict{String, Any})::Dict{String, Any}
    outputs = Dict(
        "status" => "OK",
        "customer_id" => get(request, "customer_id", ""),
        "change_type" => get(request, "change_type", ""),
    )
    receipt_wo_digest = Dict(
        "receipt_type" => "crm.update.v0",
        "request_id" => get(request, "request_id", "crm-unknown"),
        "inputs_digest" => sha256_hex(canon_json(request)),
        "outputs_digest" => sha256_hex(canon_json(outputs)),
        "evidence" => Dict(
            "adapter" => "crm-mock-julia",
            "version" => "v0",
            "outputs" => outputs,
        ),
    )
    return merge(receipt_wo_digest, Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))))
end

function pii_audit_step()::Dict{String, Any}
    return Dict(
        "step_id" => "PII-AUDIT",
        "step_type" => "pii_audit_chain_verify",
        "input_digests" => String[],
        "output_digests" => String[],
        "obligation_digests" => String[],
        "receipt_digests" => String[],
    )
end

function normalize_hex64(step::Dict{String, Any}, mismatch::String, value)::String
    normalized = lowercase(strip(as_string(value)))
    occursin(HEX64_RE, normalized) || fail_mismatch(step, mismatch, "hex64", value)
    return normalized
end

function parse_int_field(step::Dict{String, Any}, mismatch::String, value)::Int
    if value isa Integer
        return Int(value)
    elseif value isa AbstractFloat
        value == floor(value) || fail_mismatch(step, mismatch, "integer", value)
        return Int(value)
    end

    raw = strip(as_string(value))
    isempty(raw) && fail_mismatch(step, mismatch, "integer", value)
    parsed = try
        parse(Int, raw)
    catch
        fail_mismatch(step, mismatch, "integer", value)
    end
    return parsed
end

function ledger_hash_scope(sequence::Int, prev_hash::String, event_obj)::Dict{String, Any}
    return Dict(
        "sequence" => sequence,
        "prev_hash" => prev_hash,
        "event" => event_obj,
    )
end

function verify_ledger_receipt!(
    step::Dict{String, Any},
    ledger_receipt::Dict{String, Any};
    expect_event_in_chain::Union{Nothing, Dict{String, Int}} = nothing,
)
    assert_equals(step, "ledger_receipt.receipt_type", "ledger.append.v1", as_string(get(ledger_receipt, "receipt_type", "")))

    sequence = parse_int_field(step, "ledger_receipt.sequence", get(ledger_receipt, "sequence", nothing))
    prev_hash = normalize_hex64(step, "ledger_receipt.prev_hash", get(ledger_receipt, "prev_hash", ""))
    event_hash = normalize_hex64(step, "ledger_receipt.event_hash", get(ledger_receipt, "event_hash", ""))
    head_hash = normalize_hex64(step, "ledger_receipt.head_hash", get(ledger_receipt, "head_hash", ""))
    assert_equals(step, "ledger_receipt.head_hash", event_hash, head_hash)

    evidence = as_dict(get(ledger_receipt, "evidence", Dict{String, Any}()))
    event_obj = get(evidence, "event", nothing)
    event_obj === nothing && fail_mismatch(step, "ledger_receipt.evidence.event", "present", "missing")

    computed_event_hash = sha256_hex(canon_json(ledger_hash_scope(sequence, prev_hash, event_obj)))
    assert_equals(step, "ledger_receipt.event_hash.computed", computed_event_hash, event_hash)

    computed_inputs_digest = sha256_hex(canon_json(event_obj))
    assert_equals(step, "ledger_receipt.inputs_digest", computed_inputs_digest, as_string(get(ledger_receipt, "inputs_digest", "")))

    outputs_scope = Dict(
        "ledger_status" => "APPENDED",
        "sequence" => sequence,
        "prev_hash" => prev_hash,
        "event_hash" => event_hash,
        "head_hash" => head_hash,
    )
    computed_outputs_digest = sha256_hex(canon_json(outputs_scope))
    assert_equals(step, "ledger_receipt.outputs_digest", computed_outputs_digest, as_string(get(ledger_receipt, "outputs_digest", "")))

    receipt_wo_digest = copy(ledger_receipt)
    delete!(receipt_wo_digest, "receipt_digest")
    computed_receipt_digest = sha256_hex(canon_json(receipt_wo_digest))
    receipt_digest = normalize_artifact_digest(get(ledger_receipt, "receipt_digest", nothing))
    receipt_digest === nothing && fail_mismatch(step, "ledger_receipt.receipt_digest", "sha256 digest", get(ledger_receipt, "receipt_digest", nothing))
    assert_equals(step, "ledger_receipt.receipt_digest.computed", computed_receipt_digest, receipt_digest)

    if expect_event_in_chain !== nothing
        haskey(expect_event_in_chain, event_hash) || fail_mismatch(step, "ledger_receipt.event_hash.chain", "event hash present in chain", event_hash)
    end
end

function sign_receipt_for(request::Dict{String, Any})::Dict{String, Any}
    manifest = get(request, "manifest", Dict{String, Any}())
    signature = sha256_hex(canon_json(manifest))
    outputs = Dict(
        "signature" => signature,
        "algorithm" => "demo-sha256",
    )
    receipt_wo_digest = Dict(
        "receipt_type" => "sign.mock.v0",
        "request_id" => get(request, "request_id", "sign-unknown"),
        "inputs_digest" => sha256_hex(canon_json(request)),
        "outputs_digest" => sha256_hex(canon_json(outputs)),
        "evidence" => Dict(
            "adapter" => "signing-mock-julia",
            "version" => "v0",
            "outputs" => outputs,
        ),
    )
    return merge(receipt_wo_digest, Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))))
end

function mainframe_receipt_for(request::Dict{String, Any})::Dict{String, Any}
    request_digest = sha256_hex(canon_json(request))
    account_id = "ACC-" * request_digest[1:12]
    outputs_scope = Dict(
        "account_id" => account_id,
        "run_id" => as_string(get(request, "run_id", "")),
    )

    receipt_wo_digest = Dict(
        "receipt_type" => "mainframe.open_account",
        "request_digest" => "sha256:" * request_digest,
        "account_id" => account_id,
        "outputs_digest" => "sha256:" * sha256_hex(canon_json(outputs_scope)),
        "evidence" => Dict("policy" => "mainframe-mock-v1"),
    )

    return merge(receipt_wo_digest, Dict("receipt_digest" => "sha256:" * sha256_hex(canon_json(receipt_wo_digest))))
end

function signing_package_for(run_id::String, mediated_payload::Dict)::Dict{String, Any}
    terms_scope = Dict(
        "terms_id" => "rulia-parent-child-signing-terms-v1",
        "policy" => "bankid-test-sign-v1",
    )
    product_summary = Dict(
        "customer_id" => as_string(get(mediated_payload, "customer_id", "")),
        "change_type" => as_string(get(mediated_payload, "change_type", "")),
        "new_value" => as_string(get(mediated_payload, "new_value", "")),
    )

    return Dict(
        "artifact_type" => "signing.package.v0",
        "run_id" => run_id,
        "terms_hash" => "sha256:" * sha256_hex(canon_json(terms_scope)),
        "product_summary" => product_summary,
    )
end

function final_artifact_for(
    run_id::String,
    input_digest::String,
    validation_digest::String,
    mediated_event_digest::String,
    receipt_digests::Vector{String},
)::Dict{String, Any}
    return Dict(
        "artifact_type" => "verification_pass_v0",
        "run_id" => run_id,
        "status" => "PASS",
        "input_digest" => input_digest,
        "validation_digest" => validation_digest,
        "mediated_event_digest" => mediated_event_digest,
        "receipt_digests" => receipt_digests,
    )
end

function append_unique!(items::Vector{String}, digest::String)
    digest in items || push!(items, digest)
end

function collect_trace_digests(steps::Vector{Dict{String, Any}}, field::String)::Vector{String}
    out = String[]
    for step in steps
        for digest in ensure_string_array(step, field)
            append_unique!(out, digest)
        end
    end
    return out
end

function collect_trace_artifact_digests(steps::Vector{Dict{String, Any}})::Vector{String}
    out = String[]
    fields = ["input_digests", "output_digests", "obligation_digests", "receipt_digests"]
    for step in steps
        for field in fields
            for digest in ensure_string_array(step, field)
                normalized = normalize_artifact_digest(digest)
                normalized === nothing && continue
                append_unique!(out, normalized)
            end
        end
    end
    return out
end

function parse_chain_jsonl(step::Dict{String, Any}, path::String)::Vector{Dict{String, Any}}
    isfile(path) || fail_mismatch(step, "ledger_chain.exists", "chain file present", path)
    entries = Dict{String, Any}[]
    for (line_no, line) in enumerate(eachline(path))
        isempty(strip(line)) && continue
        parsed = try
            to_plain(JSON3.read(line))
        catch err
            fail_mismatch(step, "ledger_chain.row[$(line_no)].json", "valid json", sprint(showerror, err))
        end
        parsed isa Dict || fail_mismatch(step, "ledger_chain.row", "object", typeof(parsed))
        push!(entries, as_dict(parsed))
    end
    isempty(entries) && fail_mismatch(step, "ledger_chain.rows", "non-empty chain", "empty")
    return entries
end

function verify_chain_continuity(step::Dict{String, Any}, entries::Vector{Dict{String, Any}})::Tuple{Dict{String, Int}, String}
    expected_prev = repeat("0", 64)
    expected_sequence = 1
    event_index = Dict{String, Int}()

    for (idx, entry) in enumerate(entries)
        sequence = parse_int_field(step, "ledger_chain[$(idx)].sequence", get(entry, "sequence", nothing))
        assert_equals(step, "ledger_chain[$(idx)].sequence.order", expected_sequence, sequence)

        prev_hash = normalize_hex64(step, "ledger_chain[$(idx)].prev_hash", get(entry, "prev_hash", ""))
        assert_equals(step, "ledger_chain[$(idx)].prev_hash.order", expected_prev, prev_hash)

        event_hash = normalize_hex64(step, "ledger_chain[$(idx)].event_hash", get(entry, "event_hash", ""))
        event_obj = get(entry, "event", nothing)
        event_obj === nothing && fail_mismatch(step, "ledger_chain[$(idx)].event", "present", "missing")

        computed_event_hash = sha256_hex(canon_json(ledger_hash_scope(sequence, prev_hash, event_obj)))
        assert_equals(step, "ledger_chain[$(idx)].event_hash.computed", computed_event_hash, event_hash)

        event_index[event_hash] = idx
        expected_prev = event_hash
        expected_sequence += 1
    end

    return event_index, expected_prev
end

function verify_pii_audit_chain!(
    bundle_path::String,
    manifest::Dict{String, Any},
    state::Dict{String, Any},
)
    pii_receipt_digests = if haskey(manifest, "pii_access_receipt_digests")
        String.(manifest["pii_access_receipt_digests"])
    else
        String[]
    end
    pii_ledger_receipt_digests = if haskey(manifest, "pii_ledger_receipt_digests")
        String.(manifest["pii_ledger_receipt_digests"])
    else
        String[]
    end

    ledger_chain_file = as_string(get(manifest, "ledger_chain_file", ""))
    has_chain = !isempty(ledger_chain_file)
    has_pii_receipts = !isempty(pii_receipt_digests)
    if !has_chain && !has_pii_receipts
        return
    end

    step = pii_audit_step()
    has_chain || fail_mismatch(step, "ledger_chain_file", "present", ledger_chain_file)

    ledger_chain_path = joinpath(bundle_path, ledger_chain_file)
    isfile(ledger_chain_path) || fail_mismatch(step, "ledger_chain.exists", "present", ledger_chain_path)
    chain_bytes = read(ledger_chain_path)
    expected_chain_digest = as_string(get(manifest, "ledger_chain_digest", ""))
    actual_chain_digest = sha256_hex(chain_bytes)
    assert_equals(step, "ledger_chain_digest", expected_chain_digest, actual_chain_digest)

    chain_entries = parse_chain_jsonl(step, ledger_chain_path)
    chain_index, chain_head = verify_chain_continuity(step, chain_entries)

    expected_head_hash = normalize_hex64(step, "manifest.ledger_chain_head_hash", get(manifest, "ledger_chain_head_hash", ""))
    assert_equals(step, "manifest.ledger_chain_head_hash", chain_head, expected_head_hash)

    if haskey(state, "ledger_receipt_digest")
        s4_ledger_receipt = load_artifact_obj(step, "s4.ledger_receipt", bundle_path, String(state["ledger_receipt_digest"]))
        verify_ledger_receipt!(step, s4_ledger_receipt; expect_event_in_chain = chain_index)
    end

    ledger_receipt_by_internal_digest = Dict{String, String}()
    for digest in pii_ledger_receipt_digests
        normalized = normalize_artifact_digest(digest)
        normalized === nothing && fail_mismatch(step, "manifest.pii_ledger_receipt_digests", "sha256 digest list", pii_ledger_receipt_digests)
        pii_ledger_receipt = load_artifact_obj(step, "pii.ledger_receipt.index", bundle_path, normalized)
        verify_ledger_receipt!(step, pii_ledger_receipt; expect_event_in_chain = chain_index)
        internal_digest = normalize_artifact_digest(get(pii_ledger_receipt, "receipt_digest", nothing))
        internal_digest === nothing && fail_mismatch(step, "pii.ledger_receipt.index.receipt_digest", "sha256 digest", get(pii_ledger_receipt, "receipt_digest", nothing))
        ledger_receipt_by_internal_digest[internal_digest] = normalized
    end

    for digest in pii_receipt_digests
        pii_receipt = load_artifact_obj(step, "pii.receipt", bundle_path, digest)
        assert_equals(step, "pii_receipt.receipt_type", "pii.reveal.v0", as_string(get(pii_receipt, "receipt_type", "")))

        pii_receipt_wo_digest = copy(pii_receipt)
        delete!(pii_receipt_wo_digest, "receipt_digest")
        computed_pii_receipt_digest = sha256_hex(canon_json(pii_receipt_wo_digest))
        pii_receipt_digest = normalize_artifact_digest(get(pii_receipt, "receipt_digest", nothing))
        pii_receipt_digest === nothing && fail_mismatch(step, "pii_receipt.receipt_digest", "sha256 digest", get(pii_receipt, "receipt_digest", nothing))
        assert_equals(step, "pii_receipt.receipt_digest.computed", computed_pii_receipt_digest, pii_receipt_digest)

        evidence = as_dict(get(pii_receipt, "evidence", Dict{String, Any}()))
        audit_event_hash = normalize_hex64(step, "pii_receipt.audit_event_hash", get(evidence, "audit_event_hash", ""))
        receipt_head_hash = normalize_hex64(step, "pii_receipt.head_hash", get(evidence, "head_hash", ""))
        haskey(chain_index, audit_event_hash) || fail_mismatch(step, "pii_receipt.audit_event_hash.chain", "hash present in ledger chain", audit_event_hash)
        haskey(chain_index, receipt_head_hash) || fail_mismatch(step, "pii_receipt.head_hash.chain", "hash present in ledger chain", receipt_head_hash)

        # The hash-chain append returns the new event hash as head hash.
        assert_equals(step, "pii_receipt.head_equals_event", audit_event_hash, receipt_head_hash)

        ledger_receipt_internal_digest = normalize_artifact_digest(get(evidence, "ledger_receipt_digest", nothing))
        ledger_receipt_internal_digest === nothing && fail_mismatch(step, "pii_receipt.ledger_receipt_digest", "sha256 digest", get(evidence, "ledger_receipt_digest", nothing))

        ledger_receipt_artifact_digest = get(ledger_receipt_by_internal_digest, ledger_receipt_internal_digest, nothing)
        ledger_receipt_artifact_digest === nothing && fail_mismatch(step, "pii_receipt.ledger_receipt_digest.manifest", collect(keys(ledger_receipt_by_internal_digest)), ledger_receipt_internal_digest)

        pii_ledger_receipt = load_artifact_obj(step, "pii.ledger_receipt", bundle_path, ledger_receipt_artifact_digest)
        verify_ledger_receipt!(step, pii_ledger_receipt; expect_event_in_chain = chain_index)

        ledger_event_hash = normalize_hex64(step, "pii.ledger_receipt.event_hash", get(pii_ledger_receipt, "event_hash", ""))
        ledger_head_hash = normalize_hex64(step, "pii.ledger_receipt.head_hash", get(pii_ledger_receipt, "head_hash", ""))
        assert_equals(step, "pii.ledger_receipt.event_hash.link", audit_event_hash, ledger_event_hash)
        assert_equals(step, "pii.ledger_receipt.head_hash.link", receipt_head_hash, ledger_head_hash)
    end

    println("step_ok step_id=PII-AUDIT step_type=pii_audit_chain_verify")
end

function replay_step!(
    bundle_path::String,
    manifest::Dict{String, Any},
    step::Dict{String, Any},
    idx::Int,
    state::Dict{String, Any},
)
    expected_step_id, expected_step_type = STEP_PLAN[idx]
    assert_equals(step, "step_id", expected_step_id, String(get(step, "step_id", "")))
    assert_equals(step, "step_type", expected_step_type, String(get(step, "step_type", "")))

    schema_keys = sort(collect(keys(step)))
    assert_equals(step, "schema.keys", sort(TRACE_SCHEMA_FIELDS), schema_keys)

    input_digests = ensure_string_array(step, "input_digests")
    output_digests = ensure_string_array(step, "output_digests")
    obligation_digests = ensure_string_array(step, "obligation_digests")
    receipt_digests = ensure_string_array(step, "receipt_digests")

    for digest in input_digests
        load_artifact_obj(step, "input", bundle_path, digest)
    end
    for digest in obligation_digests
        load_artifact_obj(step, "obligation", bundle_path, digest)
    end
    for digest in receipt_digests
        receipt_obj = load_artifact_obj(step, "receipt", bundle_path, digest)
        haskey(receipt_obj, "receipt_type") || fail_mismatch(step, "receipt.shape", "receipt_type present", "receipt_type missing")
    end

    run_id = String(manifest["run_id"])
    input_digest = String(manifest["input_digest"])
    validation_digest = String(manifest["validation_digest"])

    if expected_step_type == "validate"
        assert_equals(step, "input_digests", [input_digest], input_digests)
        assert_equals(step, "obligation_digests", String[], obligation_digests)
        assert_equals(step, "receipt_digests", String[], receipt_digests)

        validation_obj = Dict(
            "artifact_type" => "validation_v0",
            "run_id" => run_id,
            "input_digest" => input_digest,
            "result" => "OK",
        )
        computed_validation_digest = sha256_hex(canon_json(validation_obj))
        assert_equals(step, "output_digests", [computed_validation_digest], output_digests)
        assert_equals(step, "manifest.validation_digest", validation_digest, computed_validation_digest)
        load_artifact_obj(step, "output", bundle_path, computed_validation_digest)
        state["validation_digest"] = computed_validation_digest
    elseif expected_step_type == "mediate_transform"
        assert_equals(step, "input_digests", [input_digest], input_digests)
        assert_equals(step, "obligation_digests", String[], obligation_digests)
        assert_equals(step, "receipt_digests", String[], receipt_digests)

        input_obj = load_artifact_obj(step, "input", bundle_path, input_digest)
        mediated_event = mediated_event_from(input_obj)
        computed_mediated_digest = sha256_hex(canon_json(mediated_event))
        assert_equals(step, "output_digests", [computed_mediated_digest], output_digests)
        load_artifact_obj(step, "output", bundle_path, computed_mediated_digest)
        state["mediated_event_digest"] = computed_mediated_digest
    elseif expected_step_type == "distribute_fanout"
        mediated_event_digest = String(state["mediated_event_digest"])
        assert_equals(step, "input_digests", [mediated_event_digest], input_digests)
        assert_equals(step, "obligation_digests.length", 2, length(obligation_digests))
        assert_equals(step, "receipt_digests.length", 2, length(receipt_digests))

        webhook_obligation = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        assert_equals(step, "webhook_obligation.type", "webhook.delivery.v0", as_string(get(webhook_obligation, "obligation_type", "")))
        assert_equals(step, "webhook_obligation.inputs_digest", mediated_event_digest, as_string(get(webhook_obligation, "mediated_event_digest", "")))
        webhook_receipt = webhook_receipt_for(webhook_obligation)
        computed_webhook_digest = sha256_hex(canon_json(webhook_receipt))
        assert_equals(step, "webhook_receipt.digest", computed_webhook_digest, receipt_digests[1])
        load_artifact_obj(step, "output", bundle_path, computed_webhook_digest)

        file_obligation = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[2])
        assert_equals(step, "file_obligation.type", "file.delivery.v0", as_string(get(file_obligation, "obligation_type", "")))
        assert_equals(step, "file_obligation.inputs_digest", mediated_event_digest, as_string(get(file_obligation, "mediated_event_digest", "")))
        path_hint = as_string(get(file_obligation, "path_hint", ""))
        startswith(path_hint, "egress/files/") || fail_mismatch(step, "file_obligation.path_hint", "egress/files/<digest>.json", path_hint)

        mediated_bytes = load_artifact_bytes(step, "input", bundle_path, mediated_event_digest)
        file_receipt = file_receipt_for(file_obligation, mediated_bytes)
        computed_file_digest = sha256_hex(canon_json(file_receipt))
        assert_equals(step, "file_receipt.digest", computed_file_digest, receipt_digests[2])
        load_artifact_obj(step, "output", bundle_path, computed_file_digest)

        expected_outputs = [computed_webhook_digest, computed_file_digest]
        assert_equals(step, "output_digests", expected_outputs, output_digests)

        state["webhook_receipt_digest"] = computed_webhook_digest
        state["file_receipt_digest"] = computed_file_digest
    elseif expected_step_type == "crm_update"
        mediated_event_digest = String(state["mediated_event_digest"])
        assert_equals(step, "input_digests", [mediated_event_digest], input_digests)
        assert_equals(step, "obligation_digests.length", 1, length(obligation_digests))
        assert_equals(step, "receipt_digests", String[], receipt_digests)

        crm_req = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        assert_equals(step, "obligation.run_id", run_id, String(get(crm_req, "run_id", "")))
        assert_equals(step, "obligation.inputs_digest", mediated_event_digest, String(get(crm_req, "inputs_digest", "")))
        crm_receipt = crm_receipt_for(crm_req)
        computed_crm_digest = sha256_hex(canon_json(crm_receipt))
        assert_equals(step, "output_digests", [computed_crm_digest], output_digests)
        load_artifact_obj(step, "output", bundle_path, computed_crm_digest)
        state["crm_digest"] = computed_crm_digest
    elseif expected_step_type == "audit_append"
        mediated_event_digest = String(state["mediated_event_digest"])
        expected_receipts = [String(state["webhook_receipt_digest"]), String(state["file_receipt_digest"]), String(state["crm_digest"])]

        assert_equals(step, "input_digests", [input_digest, state["validation_digest"], mediated_event_digest], input_digests)
        assert_equals(step, "obligation_digests.length", 1, length(obligation_digests))
        assert_equals(step, "receipt_digests", expected_receipts, receipt_digests)
        assert_equals(step, "output_digests.length", 1, length(output_digests))

        ledger_req = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        assert_equals(step, "obligation.run_id", run_id, String(get(ledger_req, "run_id", "")))
        assert_equals(step, "obligation.artifact_digests", [input_digest, state["validation_digest"], mediated_event_digest], String.(get(ledger_req, "artifact_digests", Any[])))
        assert_equals(step, "obligation.receipt_digests", expected_receipts, String.(get(ledger_req, "receipt_digests", Any[])))

        ledger_receipt_digest = normalize_artifact_digest(output_digests[1])
        ledger_receipt_digest === nothing && fail_mismatch(step, "output_digests[1]", "sha256 digest label", output_digests[1])
        ledger_receipt = load_artifact_obj(step, "output", bundle_path, ledger_receipt_digest)
        verify_ledger_receipt!(step, ledger_receipt)

        evidence = as_dict(get(ledger_receipt, "evidence", Dict{String, Any}()))
        ledger_event = as_dict(get(evidence, "event", Dict{String, Any}()))
        assert_equals(step, "ledger_event.run_id", run_id, as_string(get(ledger_event, "run_id", "")))
        assert_equals(step, "ledger_event.artifact_digests", [input_digest, state["validation_digest"], mediated_event_digest], String.(get(ledger_event, "artifact_digests", Any[])))
        assert_equals(step, "ledger_event.receipt_digests", expected_receipts, String.(get(ledger_event, "receipt_digests", Any[])))

        state["ledger_digest"] = ledger_receipt_digest
        state["ledger_receipt_digest"] = ledger_receipt_digest
        state["ledger_head_hash"] = as_string(get(ledger_receipt, "head_hash", ""))
        state["ledger_event_hash"] = as_string(get(ledger_receipt, "event_hash", ""))
    elseif expected_step_type == "sign_bundle"
        mediated_event_digest = String(state["mediated_event_digest"])
        expected_receipts = [
            String(state["webhook_receipt_digest"]),
            String(state["file_receipt_digest"]),
            String(state["crm_digest"]),
            String(state["ledger_digest"]),
        ]

        assert_equals(step, "input_digests", [input_digest, state["validation_digest"], mediated_event_digest], input_digests)
        assert_equals(step, "obligation_digests.length", 1, length(obligation_digests))
        assert_equals(step, "receipt_digests", expected_receipts, receipt_digests)

        sign_req = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        manifest_obj = get(sign_req, "manifest", Dict{String, Any}())
        manifest_obj isa Dict || fail_mismatch(step, "obligation.manifest", "object", typeof(manifest_obj))
        assert_equals(step, "obligation.manifest.run_id", run_id, String(get(manifest_obj, "run_id", "")))
        assert_equals(step, "obligation.manifest.artifact_digests", [input_digest, state["validation_digest"], mediated_event_digest], String.(get(manifest_obj, "artifact_digests", Any[])))
        assert_equals(step, "obligation.manifest.receipt_digests", expected_receipts, String.(get(manifest_obj, "receipt_digests", Any[])))

        sign_receipt = sign_receipt_for(sign_req)
        computed_sign_digest = sha256_hex(canon_json(sign_receipt))
        assert_equals(step, "output_digests", [computed_sign_digest], output_digests)
        load_artifact_obj(step, "output", bundle_path, computed_sign_digest)
        state["sign_digest"] = computed_sign_digest
    elseif expected_step_type == "signing_links"
        mediated_event_digest = String(state["mediated_event_digest"])
        assert_equals(step, "input_digests", [mediated_event_digest], input_digests)
        assert_equals(step, "output_digests.length", 1, length(output_digests))
        assert_equals(step, "obligation_digests.length", 2, length(obligation_digests))
        assert_equals(step, "receipt_digests", String[], receipt_digests)

        mediated_event = load_artifact_obj(step, "input", bundle_path, mediated_event_digest)
        mediated_payload = as_dict(get(mediated_event, "payload", Dict{String, Any}()))
        signing_package = signing_package_for(run_id, mediated_payload)
        computed_signing_package_digest = sha256_hex(canon_json(signing_package))
        assert_equals(step, "output_digests", [computed_signing_package_digest], output_digests)
        load_artifact_obj(step, "output", bundle_path, computed_signing_package_digest)
        signing_package_label = "sha256:" * computed_signing_package_digest

        parent_link = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        assert_equals(step, "parent_link.type", "signature.link.v0", as_string(get(parent_link, "obligation_type", "")))
        assert_equals(step, "parent_link.run_id", run_id, as_string(get(parent_link, "run_id", "")))
        assert_equals(step, "parent_link.signer_role", "parent", as_string(get(parent_link, "signer_role", "")))
        assert_equals(step, "parent_link.signing_package_digest", signing_package_label, as_string(get(parent_link, "signing_package_digest", "")))
        parent_token = as_string(get(parent_link, "token", ""))
        isempty(parent_token) && fail_mismatch(step, "parent_link.token", "non-empty token", parent_token)
        assert_equals(step, "parent_link.url_path", "/ui/sign/parent/$(parent_token)", as_string(get(parent_link, "url_path", "")))

        child_link = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[2])
        assert_equals(step, "child_link.type", "signature.link.v0", as_string(get(child_link, "obligation_type", "")))
        assert_equals(step, "child_link.run_id", run_id, as_string(get(child_link, "run_id", "")))
        assert_equals(step, "child_link.signer_role", "child", as_string(get(child_link, "signer_role", "")))
        assert_equals(step, "child_link.signing_package_digest", signing_package_label, as_string(get(child_link, "signing_package_digest", "")))
        child_token = as_string(get(child_link, "token", ""))
        isempty(child_token) && fail_mismatch(step, "child_link.token", "non-empty token", child_token)
        assert_equals(step, "child_link.url_path", "/ui/sign/child/$(child_token)", as_string(get(child_link, "url_path", "")))

        state["signing_package_artifact_digest"] = computed_signing_package_digest
        state["signing_package_digest"] = signing_package_label
    elseif expected_step_type == "signature_gate_parent" || expected_step_type == "signature_gate_child"
        role = expected_step_type == "signature_gate_parent" ? "parent" : "child"
        signing_package_artifact_digest = String(state["signing_package_artifact_digest"])

        assert_equals(step, "input_digests", [signing_package_artifact_digest], input_digests)
        assert_equals(step, "obligation_digests.length", 1, length(obligation_digests))
        assert_equals(step, "receipt_digests.length", 1, length(receipt_digests))
        assert_equals(step, "output_digests.length", 1, length(output_digests))

        gate_link = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        assert_equals(step, "gate_link.type", "signature.link.v0", as_string(get(gate_link, "obligation_type", "")))
        assert_equals(step, "gate_link.run_id", run_id, as_string(get(gate_link, "run_id", "")))
        assert_equals(step, "gate_link.signer_role", role, as_string(get(gate_link, "signer_role", "")))
        assert_equals(step, "gate_link.signing_package_digest", String(state["signing_package_digest"]), as_string(get(gate_link, "signing_package_digest", "")))

        receipt_digest_normalized = normalize_artifact_digest(receipt_digests[1])
        receipt_digest_normalized === nothing && fail_mismatch(step, "receipt_digests[1]", "valid digest label", receipt_digests[1])
        assert_equals(step, "signature_gate.digest", receipt_digest_normalized, output_digests[1])
        state["signature_receipt_" * role] = receipt_digest_normalized
    elseif expected_step_type == "mainframe_open_account"
        mediated_event_digest = String(state["mediated_event_digest"])
        signing_package_artifact_digest = String(state["signing_package_artifact_digest"])
        parent_signature_digest = String(state["signature_receipt_parent"])
        child_signature_digest = String(state["signature_receipt_child"])

        assert_equals(step, "input_digests", [mediated_event_digest, signing_package_artifact_digest], input_digests)
        assert_equals(step, "obligation_digests.length", 1, length(obligation_digests))
        assert_equals(step, "receipt_digests.length", 1, length(receipt_digests))
        assert_equals(step, "output_digests.length", 1, length(output_digests))

        mainframe_req = load_artifact_obj(step, "obligation", bundle_path, obligation_digests[1])
        assert_equals(step, "mainframe_obligation.type", "mainframe.open_account.v0", as_string(get(mainframe_req, "obligation_type", "")))
        assert_equals(step, "mainframe_obligation.run_id", run_id, as_string(get(mainframe_req, "run_id", "")))
        assert_equals(step, "mainframe_obligation.mediated_event_digest", mediated_event_digest, as_string(get(mainframe_req, "mediated_event_digest", "")))
        assert_equals(step, "mainframe_obligation.evidence_digests", [parent_signature_digest, child_signature_digest], String.(get(mainframe_req, "evidence_digests", Any[])))

        mainframe_receipt = mainframe_receipt_for(mainframe_req)
        computed_mainframe_digest = sha256_hex(canon_json(mainframe_receipt))
        receipt_digest_normalized = normalize_artifact_digest(receipt_digests[1])
        receipt_digest_normalized === nothing && fail_mismatch(step, "receipt_digests[1]", "valid digest label", receipt_digests[1])
        assert_equals(step, "mainframe_receipt.digest", computed_mainframe_digest, receipt_digest_normalized)
        assert_equals(step, "output_digests", [computed_mainframe_digest], output_digests)
        load_artifact_obj(step, "output", bundle_path, computed_mainframe_digest)
        state["mainframe_digest"] = computed_mainframe_digest
    elseif expected_step_type == "finalize"
        mediated_event_digest = String(state["mediated_event_digest"])
        final_receipts = [
            String(state["webhook_receipt_digest"]),
            String(state["file_receipt_digest"]),
            String(state["crm_digest"]),
            String(state["ledger_digest"]),
            String(state["sign_digest"]),
            String(state["signature_receipt_parent"]),
            String(state["signature_receipt_child"]),
            String(state["mainframe_digest"]),
        ]

        assert_equals(step, "input_digests", [input_digest, state["validation_digest"], mediated_event_digest], input_digests)
        assert_equals(step, "obligation_digests", String[], obligation_digests)
        assert_equals(step, "receipt_digests", final_receipts, receipt_digests)

        final_obj = final_artifact_for(run_id, input_digest, state["validation_digest"], mediated_event_digest, final_receipts)
        computed_final_digest = sha256_hex(canon_json(final_obj))
        assert_equals(step, "output_digests", [computed_final_digest], output_digests)
        load_artifact_obj(step, "output", bundle_path, computed_final_digest)
        state["final_digest"] = computed_final_digest
        state["final_receipts"] = final_receipts
    else
        fail_mismatch(step, "step_type", "known step", expected_step_type)
    end

    println("step_ok step_id=$(expected_step_id) step_type=$(expected_step_type)")
end

function main()
    if length(ARGS) < 1
        println("usage: replay.jl <bundle_path>")
        exit(1)
    end

    bundle_path = ARGS[1]
    manifest_path = joinpath(bundle_path, "manifest.json")
    isfile(manifest_path) || error("manifest not found: $(manifest_path)")
    manifest = to_plain(JSON3.read(read(manifest_path, String)))

    trace_relpath = String(get(manifest, "run_trace_file", "run_trace.jsonl"))
    trace_path = joinpath(bundle_path, trace_relpath)
    expected_trace_digest = String(get(manifest, "run_trace_digest", ""))
    actual_trace_digest = sha256_hex(read(trace_path))
    expected_trace_digest == actual_trace_digest || fail_global("run_trace_digest", expected_trace_digest, actual_trace_digest)

    steps = parse_trace(trace_path)
    length(steps) == length(STEP_PLAN) || fail_global("trace_step_count", length(STEP_PLAN), length(steps))
    haskey(manifest, "trace_step_count") && Int(manifest["trace_step_count"]) == length(steps) || fail_global("manifest.trace_step_count", length(steps), get(manifest, "trace_step_count", "missing"))

    state = Dict{String, Any}()
    for (idx, step) in enumerate(steps)
        replay_step!(bundle_path, manifest, step, idx, state)
    end

    haskey(manifest, "mediated_event_digest") && String(manifest["mediated_event_digest"]) == String(state["mediated_event_digest"]) || fail_global("manifest.mediated_event_digest", String(state["mediated_event_digest"]), get(manifest, "mediated_event_digest", "missing"))

    if haskey(manifest, "receipt_digests")
        expected_manifest_receipts = String.(manifest["receipt_digests"])
        replay_receipts = String.(state["final_receipts"])
        expected_manifest_receipts == replay_receipts || fail_global("manifest.receipt_digests", replay_receipts, expected_manifest_receipts)
    end

    trace_obligations = collect_trace_digests(steps, "obligation_digests")
    haskey(manifest, "obligation_digests") && String.(manifest["obligation_digests"]) == trace_obligations || fail_global("manifest.obligation_digests", trace_obligations, get(manifest, "obligation_digests", "missing"))

    trace_artifacts = collect_trace_artifact_digests(steps)
    expected_artifacts = copy(trace_artifacts)
    if haskey(manifest, "pii_accesses")
        raw_accesses = manifest["pii_accesses"]
        if raw_accesses isa AbstractVector
            for raw_access in raw_accesses
                access = as_dict(raw_access)
                for key in ("receipt_artifact_digest", "ledger_receipt_artifact_digest")
                    normalized = normalize_artifact_digest(get(access, key, nothing))
                    normalized === nothing && continue
                    append_unique!(expected_artifacts, normalized)
                end
            end
        end
    else
        for key in ("pii_access_receipt_digests", "pii_ledger_receipt_digests")
            if haskey(manifest, key)
                for digest in String.(manifest[key])
                    normalized = normalize_artifact_digest(digest)
                    normalized === nothing && continue
                    append_unique!(expected_artifacts, normalized)
                end
            end
        end
    end
    haskey(manifest, "artifact_digests") && String.(manifest["artifact_digests"]) == expected_artifacts || fail_global("manifest.artifact_digests", expected_artifacts, get(manifest, "artifact_digests", "missing"))

    verify_pii_audit_chain!(bundle_path, manifest, state)

    final_digest = String(state["final_digest"])
    expected_final_digest = String(manifest["final_digest"])
    match = final_digest == expected_final_digest
    result = Dict(
        "bundle_path" => bundle_path,
        "run_id" => manifest["run_id"],
        "steps_verified" => length(steps),
        "expected_final_digest" => expected_final_digest,
        "replayed_final_digest" => final_digest,
        "match" => match,
    )
    println(String(canon_json(result)))
    match || exit(2)
end

main()
