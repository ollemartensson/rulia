using Base64
using HTTP
using JSON3
using SHA: hmac_sha256

include("canon.jl")
using .Canon

const HOST = get(ENV, "HOST", "0.0.0.0")
const PORT = parse(Int, get(ENV, "PORT", "8080"))
const ARTIFACT_DIR = get(ENV, "ARTIFACT_DIR", "/app/volumes/artifacts")
const BUNDLE_DIR = get(ENV, "BUNDLE_DIR", "/app/volumes/bundles")
const WORKFLOW_DIR = get(ENV, "WORKFLOW_DIR", "/app/workflows/portable")
const EGRESS_FILES_DIR = get(ENV, "EGRESS_FILES_DIR", "/app/volumes/egress/files")
const CRM_URL = get(ENV, "CRM_URL", "http://crm-mock:8080")
const SIGN_URL = get(ENV, "SIGN_URL", "http://signing-mock:8080")
const LEDGER_URL = get(ENV, "LEDGER_URL", "http://audit-ledger:8080")
const PII_VAULT_URL = get(ENV, "PII_VAULT_URL", "http://pii-vault-mock:8080")
const WEBHOOK_URL = get(ENV, "WEBHOOK_URL", "http://webhook-mock:8080")
const MAINFRAME_URL = get(ENV, "MAINFRAME_URL", "http://mainframe-mock:8080")
const SDK_GATEWAY_URL = get(ENV, "SDK_GATEWAY_URL", "http://sdk-gateway:8080")
const WORKFLOW_SIGNING_TOKEN_SECRET = strip(get(ENV, "WORKFLOW_SIGNING_TOKEN_SECRET", ""))

const RUNS = Dict{String, Dict{String, Any}}()
const HEX64_RE = r"^[0-9a-f]{64}$"
const SHA256_LABEL_RE = r"^sha256:([0-9a-f]{64})$"

function ensure_dirs()
    mkpath(ARTIFACT_DIR)
    mkpath(BUNDLE_DIR)
    mkpath(EGRESS_FILES_DIR)
end

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

function sha256_label(hex_digest::String)::String
    return "sha256:$(hex_digest)"
end

function normalize_signer_role(role)::Union{Nothing, String}
    role_value = lowercase(strip(as_string(role)))
    role_value in ("parent", "child") || return nothing
    return role_value
end

function signing_token_secret()::String
    if isempty(WORKFLOW_SIGNING_TOKEN_SECRET)
        # Keep demo flows operable even when compose env is not wired for this variable.
        return "demo-workflow-signing-token-secret-v0"
    end
    return WORKFLOW_SIGNING_TOKEN_SECRET
end

function json_response(status::Integer, obj)::HTTP.Response
    return HTTP.Response(status, ["Content-Type" => "application/json"], canon_json(obj))
end

function artifact_path(digest)::String
    normalized = normalize_artifact_digest(digest)
    normalized === nothing && error("invalid artifact digest: $(digest)")
    return joinpath(ARTIFACT_DIR, normalized)
end

function store_artifact(obj)::String
    bytes = canon_json(obj)
    digest = sha256_hex(bytes)
    path = artifact_path(digest)
    if !isfile(path)
        open(path, "w") do io
            write(io, bytes)
        end
    end
    return digest
end

function read_artifact(digest)::Vector{UInt8}
    return read(artifact_path(digest))
end

function trace_step(step_id::String, step_type::String;
    input_digests::Vector{String} = String[],
    output_digests::Vector{String} = String[],
    obligation_digests::Vector{String} = String[],
    receipt_digests::Vector{String} = String[])::Dict{String, Any}
    return Dict(
        "step_id" => step_id,
        "step_type" => step_type,
        "input_digests" => input_digests,
        "output_digests" => output_digests,
        "obligation_digests" => obligation_digests,
        "receipt_digests" => receipt_digests,
    )
end

function write_trace_jsonl(path::String, steps)::String
    open(path, "w") do io
        for step in steps
            write(io, canon_json(step))
            write(io, UInt8('\n'))
        end
    end
    return sha256_hex(read(path))
end

function deterministic_run_id(input_digest::String)::String
    return "run-" * input_digest[1:16]
end

function append_unique!(items::Vector{String}, digest::String)
    digest in items || push!(items, digest)
end

function collect_trace_artifact_digests(trace_steps::Vector{Dict{String, Any}})::Vector{String}
    fields = ["input_digests", "output_digests", "obligation_digests", "receipt_digests"]
    digests = String[]

    for step in trace_steps
        for field in fields
            raw = get(step, field, Any[])
            raw isa AbstractVector || continue
            for digest in raw
                digest isa AbstractString || continue
                normalized = normalize_artifact_digest(digest)
                normalized === nothing && continue
                append_unique!(digests, normalized)
            end
        end
    end

    return digests
end

function post_json(url::String, body_obj)::Dict{String, Any}
    body = canon_json(body_obj)
    resp = HTTP.request("POST", url, ["Content-Type" => "application/json"], body)
    if resp.status < 200 || resp.status >= 300
        error("capability call failed: $(url) -> $(resp.status)")
    end
    parsed = JSON3.read(String(resp.body))
    return to_plain(parsed)
end

function get_bytes(url::String)::Vector{UInt8}
    resp = HTTP.request("GET", url)
    if resp.status < 200 || resp.status >= 300
        error("capability call failed: $(url) -> $(resp.status)")
    end
    return Vector{UInt8}(resp.body)
end

function inspect_workflow_with_sdk(file_name::String, workflow_text::String)::Union{Nothing, Dict{String, Any}}
    payload = Dict(
        "file" => file_name,
        "text" => workflow_text,
    )
    try
        return post_json("$(SDK_GATEWAY_URL)/sdk/workflow/inspect", payload)
    catch err
        @warn "sdk workflow inspect failed" file = file_name error = sprint(showerror, err)
        return nothing
    end
end

function mediated_event_from(parsed_event::Dict{String, Any})::Dict{String, Any}
    customer_id = as_string(get(parsed_event, "customer_id", ""))
    change_type = as_string(get(parsed_event, "change_type", ""))
    new_value = as_string(get(parsed_event, "new_value", ""))
    correlation_id = as_string(get(parsed_event, "correlation_id", ""))

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

function webhook_obligation_for(run_id::String, mediated_event_digest::String, mediated_event::Dict{String, Any})::Dict{String, Any}
    request_seed = Dict(
        "run_id" => run_id,
        "inputs_digest" => mediated_event_digest,
        "medium" => "webhook",
    )
    request_id = "webhook-" * sha256_hex(canon_json(request_seed))[1:16]

    return Dict(
        "obligation_type" => "webhook.delivery.v0",
        "request_id" => request_id,
        "target" => "webhook-mock:/webhook/deliver",
        "mediated_event_digest" => mediated_event_digest,
        "mediated_event" => mediated_event,
    )
end

function file_obligation_for(run_id::String, mediated_event_digest::String)::Dict{String, Any}
    request_seed = Dict(
        "run_id" => run_id,
        "inputs_digest" => mediated_event_digest,
        "medium" => "file",
    )
    request_id = "file-" * sha256_hex(canon_json(request_seed))[1:16]

    return Dict(
        "obligation_type" => "file.delivery.v0",
        "request_id" => request_id,
        "mediated_event_digest" => mediated_event_digest,
        "path_hint" => "egress/files/$(mediated_event_digest).json",
    )
end

function file_receipt_for(file_obligation::Dict{String, Any}, mediated_event_digest::String, mediated_bytes::Vector{UInt8})::Dict{String, Any}
    receipt_wo_digest = Dict(
        "receipt_type" => "file.delivery",
        "request_id" => as_string(get(file_obligation, "request_id", "file-unknown")),
        "inputs_digest" => mediated_event_digest,
        "outputs_digest" => sha256_hex(mediated_bytes),
        "evidence" => Dict(
            "path_hint" => as_string(get(file_obligation, "path_hint", "egress/files/$(mediated_event_digest).json")),
        ),
    )

    return merge(receipt_wo_digest, Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))))
end

function signing_nonce_for(run_id::String, signer_role::String, signing_package_digest::String)::String
    seed = Dict(
        "scope" => "signing.link.token.nonce.v0",
        "run_id" => run_id,
        "signer_role" => signer_role,
        "signing_package_digest" => signing_package_digest,
    )
    return sha256_hex(canon_json(seed))[1:24]
end

function signing_hmac_hex(run_id::String, signer_role::String, signing_package_digest::String, nonce::String)::String
    message = "$(run_id)|$(signer_role)|$(signing_package_digest)|$(nonce)"
    key = Vector{UInt8}(codeunits(signing_token_secret()))
    return bytes2hex(hmac_sha256(key, message))
end

function base64url_encode(bytes::Vector{UInt8})::String
    s = base64encode(bytes)
    s = replace(s, '+' => '-', '/' => '_')
    return replace(s, r"=+$" => "")
end

function base64url_decode(value::String)::Union{Nothing, Vector{UInt8}}
    raw = strip(value)
    isempty(raw) && return nothing
    occursin(r"[^A-Za-z0-9_-]", raw) && return nothing

    padded = replace(raw, '-' => '+', '_' => '/')
    remainder = mod(length(padded), 4)
    remainder == 1 && return nothing
    if remainder != 0
        padded *= repeat("=", 4 - remainder)
    end

    try
        return base64decode(padded)
    catch
        return nothing
    end
end

function issue_signing_token(run_id::String, signer_role::String, signing_package_digest::String)::String
    nonce = signing_nonce_for(run_id, signer_role, signing_package_digest)
    hmac_hex = signing_hmac_hex(run_id, signer_role, signing_package_digest, nonce)
    payload = "$(run_id).$(signer_role).$(signing_package_digest).$(nonce).$(hmac_hex)"
    return base64url_encode(Vector{UInt8}(codeunits(payload)))
end

function decode_and_verify_signing_token(token::String)::Union{Nothing, Dict{String, String}}
    decoded_bytes = base64url_decode(token)
    decoded_bytes === nothing && return nothing
    payload = String(decoded_bytes)

    parts = split(payload, ".")
    length(parts) == 5 || return nothing

    run_id = as_string(parts[1])
    signer_role = normalize_signer_role(parts[2])
    signing_package_digest = as_string(parts[3])
    nonce = lowercase(as_string(parts[4]))
    provided_hmac = lowercase(as_string(parts[5]))

    signer_role === nothing && return nothing
    isempty(run_id) && return nothing
    normalize_artifact_digest(signing_package_digest) === nothing && return nothing
    startswith(signing_package_digest, "sha256:") || return nothing
    occursin(r"^[0-9a-f]{24}$", nonce) || return nothing
    occursin(HEX64_RE, provided_hmac) || return nothing

    expected_hmac = signing_hmac_hex(run_id, signer_role, signing_package_digest, nonce)
    provided_hmac == expected_hmac || return nothing

    expected_nonce = signing_nonce_for(run_id, signer_role, signing_package_digest)
    nonce == expected_nonce || return nothing

    return Dict(
        "run_id" => run_id,
        "signer_role" => signer_role,
        "signing_package_digest" => signing_package_digest,
        "nonce" => nonce,
        "hmac" => provided_hmac,
    )
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
        "terms_hash" => sha256_label(sha256_hex(canon_json(terms_scope))),
        "product_summary" => product_summary,
    )
end

function user_visible_text_b64_for(signing_package::Dict{String, Any})::String
    scope = Dict(
        "text_type" => "rulia-signing-request-v0",
        "terms_hash" => as_string(get(signing_package, "terms_hash", "")),
        "product_summary" => as_dict(get(signing_package, "product_summary", Dict{String, Any}())),
    )
    return base64encode(canon_json(scope))
end

function signing_link_obligation_for(
    run_id::String,
    signer_role::String,
    signing_package_digest::String,
    token::String,
)::Dict{String, Any}
    request_seed = Dict(
        "scope" => "signature.link.v0",
        "run_id" => run_id,
        "signer_role" => signer_role,
        "signing_package_digest" => signing_package_digest,
    )
    request_id = "signing-link-" * sha256_hex(canon_json(request_seed))[1:16]

    return Dict(
        "obligation_type" => "signature.link.v0",
        "request_id" => request_id,
        "run_id" => run_id,
        "signer_role" => signer_role,
        "signing_package_digest" => signing_package_digest,
        "token" => token,
        "url_path" => "/ui/sign/$(signer_role)/$(token)",
    )
end

function token_hint(token::String)::String
    length(token) <= 14 && return token
    return string(token[1:8], "...", token[end-3:end])
end

function find_signing_link(run::Dict{String, Any}, signer_role::String)::Union{Nothing, Dict{String, Any}}
    raw_links = get(run, "signing_links", Any[])
    raw_links isa AbstractVector || return nothing

    for raw in raw_links
        link = as_dict(raw)
        as_string(get(link, "role", "")) == signer_role || continue
        return link
    end
    return nothing
end

function find_gate_step(run::Dict{String, Any}, signer_role::String)::Union{Nothing, Dict{String, Any}}
    step_id = signer_role == "parent" ? "S5b" : "S5c"
    raw_steps = get(run, "trace_steps", Any[])
    raw_steps isa AbstractVector || return nothing

    for raw in raw_steps
        step = as_dict(raw)
        as_string(get(step, "step_id", "")) == step_id || continue
        return step
    end
    return nothing
end

function find_trace_step(run::Dict{String, Any}, step_id::String)::Union{Nothing, Dict{String, Any}}
    raw_steps = get(run, "trace_steps", Any[])
    raw_steps isa AbstractVector || return nothing

    for raw in raw_steps
        step = as_dict(raw)
        as_string(get(step, "step_id", "")) == step_id || continue
        return step
    end
    return nothing
end

function find_mainframe_step(run::Dict{String, Any})::Union{Nothing, Dict{String, Any}}
    return find_trace_step(run, "S6")
end

function find_finalize_step(run::Dict{String, Any})::Union{Nothing, Dict{String, Any}}
    return find_trace_step(run, "S7")
end

function gate_output_receipts(run::Dict{String, Any})::Vector{String}
    gate_digests = String[]
    for role in ("parent", "child")
        step = find_gate_step(run, role)
        step === nothing && continue
        output_digests = get(step, "output_digests", Any[])
        output_digests isa AbstractVector || continue
        for digest in output_digests
            normalized = normalize_artifact_digest(digest)
            normalized === nothing && continue
            append_unique!(gate_digests, normalized)
        end
    end
    return gate_digests
end

function gate_receipt_digest(run::Dict{String, Any}, signer_role::String)::Union{Nothing, String}
    step = find_gate_step(run, signer_role)
    step === nothing && return nothing

    raw_receipts = get(step, "receipt_digests", Any[])
    raw_receipts isa AbstractVector || return nothing
    isempty(raw_receipts) && return nothing
    return normalize_artifact_digest(raw_receipts[1])
end

function signature_evidence_digests(run::Dict{String, Any})::Union{Nothing, Vector{String}}
    parent_digest = gate_receipt_digest(run, "parent")
    child_digest = gate_receipt_digest(run, "child")
    parent_digest === nothing && return nothing
    child_digest === nothing && return nothing
    return [parent_digest, child_digest]
end

function mainframe_output_receipt_digest(run::Dict{String, Any})::Union{Nothing, String}
    step = find_mainframe_step(run)
    step === nothing && return nothing

    output_digests = get(step, "output_digests", Any[])
    output_digests isa AbstractVector || return nothing
    isempty(output_digests) && return nothing
    return normalize_artifact_digest(output_digests[1])
end

function run_base_receipts(run::Dict{String, Any})::Vector{String}
    if haskey(run, "base_receipt_digests") && run["base_receipt_digests"] isa AbstractVector
        return String.(run["base_receipt_digests"])
    elseif haskey(run, "receipt_digests") && run["receipt_digests"] isa AbstractVector
        return String.(run["receipt_digests"])
    end
    return String[]
end

function normalize_string_array(raw)::Vector{String}
    raw isa AbstractVector || return String[]
    out = String[]
    for item in raw
        value = strip(as_string(item))
        isempty(value) && continue
        push!(out, value)
    end
    return out
end

function append_run_artifact_digest!(run::Dict{String, Any}, digest::String)
    artifacts = if haskey(run, "artifact_digests") && run["artifact_digests"] isa AbstractVector
        String.(run["artifact_digests"])
    else
        String[]
    end
    append_unique!(artifacts, digest)
    run["artifact_digests"] = artifacts
end

function recompute_receipt_digests!(run::Dict{String, Any})
    run_receipts = run_base_receipts(run)
    for digest in gate_output_receipts(run)
        append_unique!(run_receipts, digest)
    end

    mainframe_digest = mainframe_output_receipt_digest(run)
    mainframe_digest === nothing || append_unique!(run_receipts, mainframe_digest)

    run["receipt_digests"] = run_receipts
end

function mainframe_open_account_obligation_for(run::Dict{String, Any})::Dict{String, Any}
    run_id = as_string(get(run, "run_id", ""))
    mediated_event_digest = as_string(get(run, "mediated_event_digest", ""))
    evidence_digests = signature_evidence_digests(run)
    evidence_digests === nothing && error("signature evidence is incomplete for mainframe open-account")

    request_seed = Dict(
        "scope" => "mainframe.open_account.v0",
        "run_id" => run_id,
        "mediated_event_digest" => mediated_event_digest,
        "evidence_digests" => evidence_digests,
    )
    request_id = "mainframe-open-" * sha256_hex(canon_json(request_seed))[1:16]

    return Dict(
        "obligation_type" => "mainframe.open_account.v0",
        "request_id" => request_id,
        "run_id" => run_id,
        "mediated_event_digest" => mediated_event_digest,
        "evidence_digests" => evidence_digests,
    )
end

function final_artifact_for(run::Dict{String, Any}, receipt_digests::Vector{String})::Dict{String, Any}
    return Dict(
        "artifact_type" => "verification_pass_v0",
        "run_id" => as_string(get(run, "run_id", "")),
        "status" => "PASS",
        "input_digest" => as_string(get(run, "input_digest", "")),
        "validation_digest" => as_string(get(run, "validation_digest", "")),
        "mediated_event_digest" => as_string(get(run, "mediated_event_digest", "")),
        "receipt_digests" => receipt_digests,
    )
end

function finalize_run!(run::Dict{String, Any})
    finalize_step = find_finalize_step(run)
    finalize_step === nothing && error("finalize step not found")

    existing_outputs = get(finalize_step, "output_digests", Any[])
    if existing_outputs isa AbstractVector && !isempty(existing_outputs)
        run["status"] = "PASS"
        return
    end

    mainframe_digest = mainframe_output_receipt_digest(run)
    mainframe_digest === nothing && error("mainframe open-account step not completed")

    receipt_digests = if haskey(run, "receipt_digests") && run["receipt_digests"] isa AbstractVector
        String.(run["receipt_digests"])
    else
        String[]
    end

    final_obj = final_artifact_for(run, receipt_digests)
    final_digest = store_artifact(final_obj)
    finalize_step["receipt_digests"] = receipt_digests
    finalize_step["output_digests"] = [final_digest]
    run["final_digest"] = final_digest
    run["status"] = "PASS"
end

function commit_mainframe_and_finalize!(run::Dict{String, Any})
    mainframe_step = find_mainframe_step(run)
    mainframe_step === nothing && error("mainframe open-account step not found")

    existing_outputs = get(mainframe_step, "output_digests", Any[])
    if existing_outputs isa AbstractVector && !isempty(existing_outputs)
        recompute_receipt_digests!(run)
        finalize_run!(run)
        return
    end

    obligation = mainframe_open_account_obligation_for(run)
    obligation_digest = store_artifact(obligation)
    mainframe_receipt = post_json("$(MAINFRAME_URL)/mainframe/open-account", obligation)
    mainframe_receipt_digest = store_artifact(mainframe_receipt)

    mainframe_step["obligation_digests"] = [obligation_digest]
    mainframe_step["receipt_digests"] = [sha256_label(mainframe_receipt_digest)]
    mainframe_step["output_digests"] = [mainframe_receipt_digest]

    run_obligations = haskey(run, "obligation_digests") && run["obligation_digests"] isa AbstractVector ? String.(run["obligation_digests"]) : String[]
    append_unique!(run_obligations, obligation_digest)
    run["obligation_digests"] = run_obligations
    run["mainframe_obligation_digest"] = obligation_digest
    run["mainframe_receipt_digest"] = sha256_label(mainframe_receipt_digest)

    recompute_receipt_digests!(run)
    finalize_run!(run)
end

function run_customer_id(run::Dict{String, Any})::String
    customer_id = as_string(get(run, "customer_id", ""))
    if !isempty(customer_id)
        return customer_id
    end

    mediated_event_digest = normalize_artifact_digest(get(run, "mediated_event_digest", nothing))
    mediated_event_digest === nothing && return ""

    mediated_event_bytes = try
        read_artifact(mediated_event_digest)
    catch
        return ""
    end
    mediated_event = try
        to_plain(JSON3.read(String(mediated_event_bytes)))
    catch
        return ""
    end
    payload = as_dict(get(as_dict(mediated_event), "payload", Dict{String, Any}()))
    return as_string(get(payload, "customer_id", ""))
end

function run_pii_accesses(run::Dict{String, Any})::Vector{Dict{String, Any}}
    raw = get(run, "pii_accesses", Any[])
    accesses = Dict{String, Any}[]
    if raw isa AbstractVector
        for item in raw
            push!(accesses, as_dict(item))
        end
    end
    run["pii_accesses"] = accesses
    return accesses
end

function run_pii_receipt_labels(run::Dict{String, Any}, key::String)::Vector{String}
    labels = normalize_string_array(get(run, key, Any[]))
    run[key] = labels
    return labels
end

function next_pii_request_id(run::Dict{String, Any}, subject_id::String, fields::Vector{String})::String
    accesses = run_pii_accesses(run)
    ordinal = lpad(string(length(accesses) + 1), 2, '0')
    seed = Dict(
        "scope" => "workflow.pii.reveal.v0",
        "run_id" => as_string(get(run, "run_id", "")),
        "subject_id" => subject_id,
        "fields" => fields,
        "ordinal" => ordinal,
    )
    return "pii-$(as_string(get(run, "run_id", "")))-$(ordinal)-" * sha256_hex(canon_json(seed))[1:8]
end

function reveal_pii_for_run(run::Dict{String, Any}, payload::Dict{String, Any})::Tuple{Int, Dict{String, Any}}
    run_id = as_string(get(run, "run_id", ""))
    status = as_string(get(run, "status", ""))
    if status != "PASS"
        return 409, Dict("error" => "run must be PASS before PII reveal", "status" => status)
    end

    subject_id = as_string(get(payload, "subject_id", ""))
    isempty(subject_id) && (subject_id = run_customer_id(run))
    isempty(subject_id) && return 400, Dict("error" => "missing subject_id for run")

    actor_type = as_string(get(payload, "actor_type", "human"))
    actor_id = as_string(get(payload, "actor_id", "internal-ui-operator"))
    purpose = as_string(get(payload, "purpose", "manual-review"))
    fields = normalize_string_array(get(payload, "fields", Any["full_name", "email", "phone"]))
    isempty(fields) && (fields = ["full_name", "email", "phone"])

    request_id = as_string(get(payload, "request_id", ""))
    isempty(request_id) && (request_id = next_pii_request_id(run, subject_id, fields))

    vault_request = Dict(
        "request_id" => request_id,
        "run_id" => run_id,
        "subject_id" => subject_id,
        "actor_type" => actor_type,
        "actor_id" => actor_id,
        "purpose" => purpose,
        "fields" => fields,
    )

    vault_response = try
        post_json("$(PII_VAULT_URL)/pii/reveal", vault_request)
    catch err
        return 502, Dict("error" => "pii-vault call failed", "detail" => sprint(showerror, err))
    end

    pii_receipt = as_dict(get(vault_response, "receipt", Dict{String, Any}()))
    ledger_receipt = as_dict(get(vault_response, "ledger_receipt", Dict{String, Any}()))
    isempty(pii_receipt) && return 502, Dict("error" => "pii-vault response missing receipt")
    isempty(ledger_receipt) && return 502, Dict("error" => "pii-vault response missing ledger_receipt")

    pii_receipt_artifact_digest = store_artifact(pii_receipt)
    pii_receipt_label = sha256_label(pii_receipt_artifact_digest)
    ledger_receipt_artifact_digest = store_artifact(ledger_receipt)
    ledger_receipt_label = sha256_label(ledger_receipt_artifact_digest)

    append_run_artifact_digest!(run, pii_receipt_artifact_digest)
    append_run_artifact_digest!(run, ledger_receipt_artifact_digest)

    pii_receipt_labels = run_pii_receipt_labels(run, "pii_access_receipt_digests")
    append_unique!(pii_receipt_labels, pii_receipt_label)
    run["pii_access_receipt_digests"] = pii_receipt_labels

    pii_ledger_labels = run_pii_receipt_labels(run, "pii_ledger_receipt_digests")
    append_unique!(pii_ledger_labels, ledger_receipt_label)
    run["pii_ledger_receipt_digests"] = pii_ledger_labels

    evidence = as_dict(get(pii_receipt, "evidence", Dict{String, Any}()))
    audit_event_hash = as_string(get(evidence, "audit_event_hash", get(vault_response, "audit_event_hash", "")))
    head_hash = as_string(get(evidence, "head_hash", get(vault_response, "head_hash", "")))
    ledger_receipt_digest = as_string(get(evidence, "ledger_receipt_digest", get(vault_response, "ledger_receipt_digest", "")))

    if isempty(audit_event_hash) || isempty(head_hash)
        return 502, Dict("error" => "pii-vault response missing audit hashes")
    end

    accesses = run_pii_accesses(run)
    push!(accesses, Dict(
        "request_id" => request_id,
        "subject_id" => subject_id,
        "fields" => fields,
        "actor_type" => actor_type,
        "actor_id" => actor_id,
        "purpose" => purpose,
        "receipt_digest" => pii_receipt_label,
        "receipt_artifact_digest" => pii_receipt_artifact_digest,
        "ledger_receipt_digest" => ledger_receipt_label,
        "ledger_receipt_artifact_digest" => ledger_receipt_artifact_digest,
        "audit_event_hash" => audit_event_hash,
        "head_hash" => head_hash,
    ))
    run["pii_accesses"] = accesses
    run["pii_access_count"] = length(accesses)
    run["pii_last_receipt_digest"] = pii_receipt_label
    run["pii_last_ledger_receipt_digest"] = ledger_receipt_label
    run["pii_last_audit_event_hash"] = audit_event_hash
    run["pii_audit_head_hash"] = head_hash
    run["audit_chain_head_hash"] = head_hash
    run["pii_last_revealed"] = get(vault_response, "revealed", Dict{String, Any}())

    return 200, Dict(
        "status" => "ok",
        "run_id" => run_id,
        "subject_id" => subject_id,
        "receipt_digest" => pii_receipt_label,
        "ledger_receipt_digest" => ledger_receipt_label,
        "audit_event_hash" => audit_event_hash,
        "audit_head_hash" => head_hash,
        "ledger_receipt_ref" => ledger_receipt_digest,
        "pii_access_count" => length(accesses),
    )
end

function find_signing_resolution(token::String)::Union{Nothing, Dict{String, Any}}
    parsed = decode_and_verify_signing_token(token)
    parsed === nothing && return nothing

    run_id = parsed["run_id"]
    signer_role = parsed["signer_role"]
    signing_package_digest = parsed["signing_package_digest"]
    run = get(RUNS, run_id, nothing)
    run === nothing && return nothing

    link = find_signing_link(run, signer_role)
    link === nothing && return nothing
    as_string(get(link, "token", "")) == token || return nothing
    as_string(get(link, "signing_package_digest", "")) == signing_package_digest || return nothing

    signing_package_bytes = try
        read_artifact(signing_package_digest)
    catch
        return nothing
    end

    signing_package = try
        to_plain(JSON3.read(String(signing_package_bytes)))
    catch
        return nothing
    end
    signing_package isa Dict || return nothing
    signing_package_obj = as_dict(signing_package)
    user_visible_text_b64 = user_visible_text_b64_for(signing_package_obj)

    return Dict(
        "token" => token,
        "run_id" => run_id,
        "signer_role" => signer_role,
        "signing_package_digest" => signing_package_digest,
        "user_visible_text_b64" => user_visible_text_b64,
        "user_visible_text" => user_visible_text_b64,
    )
end

function apply_signature_receipt!(
    run::Dict{String, Any},
    signer_role::String,
    receipt_artifact_digest::String,
    receipt_digest_label::String,
)
    gate_step = find_gate_step(run, signer_role)
    gate_step === nothing && error("signature gate step not found for role $(signer_role)")

    existing_gate_receipts = get(gate_step, "receipt_digests", Any[])
    if existing_gate_receipts isa AbstractVector && !isempty(existing_gate_receipts)
        error("signature already submitted for role $(signer_role)")
    end

    gate_step["output_digests"] = [receipt_artifact_digest]
    gate_step["receipt_digests"] = [receipt_digest_label]

    gate_receipts = haskey(run, "signature_receipt_digests") ? as_dict(run["signature_receipt_digests"]) : Dict{String, Any}()
    gate_receipts[signer_role] = receipt_digest_label
    run["signature_receipt_digests"] = gate_receipts

    recompute_receipt_digests!(run)
    evidence_digests = signature_evidence_digests(run)
    if evidence_digests === nothing
        run["status"] = "WAITING_FOR_SIGNATURES"
    else
        run["status"] = "READY_FOR_MAINFRAME"
        commit_mainframe_and_finalize!(run)
    end

    run["artifact_digests"] = collect_trace_artifact_digests(run["trace_steps"])
end

function process_event(event::Dict{String, Any})::Dict{String, Any}
    trace_steps = Dict{String, Any}[]
    obligation_digests = String[]

    input_obj = Dict(
        "artifact_type" => "legacy.parsed_event.v0",
        "source" => "legacy.outbox.v0",
        "event" => event,
    )
    input_digest = store_artifact(input_obj)
    run_id = deterministic_run_id(input_digest)

    validate_obj = Dict(
        "artifact_type" => "validation_v0",
        "run_id" => run_id,
        "input_digest" => input_digest,
        "result" => "OK",
    )
    validation_digest = store_artifact(validate_obj)
    push!(trace_steps, trace_step(
        "S1",
        "validate";
        input_digests = [input_digest],
        output_digests = [validation_digest],
    ))

    mediated_event = mediated_event_from(event)
    mediated_event_digest = store_artifact(mediated_event)
    push!(trace_steps, trace_step(
        "S2a",
        "mediate_transform";
        input_digests = [input_digest],
        output_digests = [mediated_event_digest],
    ))

    mediated_bytes = read_artifact(mediated_event_digest)

    webhook_obligation = webhook_obligation_for(run_id, mediated_event_digest, mediated_event)
    webhook_obligation_digest = store_artifact(webhook_obligation)
    push!(obligation_digests, webhook_obligation_digest)
    webhook_receipt = post_json("$(WEBHOOK_URL)/webhook/deliver", webhook_obligation)
    webhook_receipt_digest = store_artifact(webhook_receipt)

    file_obligation = file_obligation_for(run_id, mediated_event_digest)
    file_obligation_digest = store_artifact(file_obligation)
    push!(obligation_digests, file_obligation_digest)
    egress_path = joinpath(EGRESS_FILES_DIR, "$(mediated_event_digest).json")
    open(egress_path, "w") do io
        write(io, mediated_bytes)
    end
    file_receipt = file_receipt_for(file_obligation, mediated_event_digest, mediated_bytes)
    file_receipt_digest = store_artifact(file_receipt)

    distribution_receipt_digests = [webhook_receipt_digest, file_receipt_digest]
    push!(trace_steps, trace_step(
        "S2b",
        "distribute_fanout";
        input_digests = [mediated_event_digest],
        output_digests = distribution_receipt_digests,
        obligation_digests = [webhook_obligation_digest, file_obligation_digest],
        receipt_digests = distribution_receipt_digests,
    ))

    mediated_payload = get(mediated_event, "payload", Dict{String, Any}())
    mediated_payload isa Dict || error("mediated payload must be object")
    customer_id = as_string(get(mediated_payload, "customer_id", ""))

    crm_req = Dict(
        "request_id" => "$(run_id)-s3-crm",
        "run_id" => run_id,
        "customer_id" => customer_id,
        "change_type" => as_string(get(mediated_payload, "change_type", "")),
        "new_value" => as_string(get(mediated_payload, "new_value", "")),
        "inputs_digest" => mediated_event_digest,
    )
    crm_obligation_digest = store_artifact(crm_req)
    push!(obligation_digests, crm_obligation_digest)
    crm_receipt = post_json("$(CRM_URL)/crm/update", crm_req)
    crm_digest = store_artifact(crm_receipt)
    push!(trace_steps, trace_step(
        "S3",
        "crm_update";
        input_digests = [mediated_event_digest],
        output_digests = [crm_digest],
        obligation_digests = [crm_obligation_digest],
    ))

    pre_ledger_receipts = [webhook_receipt_digest, file_receipt_digest, crm_digest]
    ledger_req = Dict(
        "request_id" => "$(run_id)-s4-ledger",
        "event_type" => "customer.change",
        "run_id" => run_id,
        "artifact_digests" => [input_digest, validation_digest, mediated_event_digest],
        "receipt_digests" => pre_ledger_receipts,
    )
    ledger_obligation_digest = store_artifact(ledger_req)
    push!(obligation_digests, ledger_obligation_digest)
    ledger_receipt = post_json("$(LEDGER_URL)/ledger/append", ledger_req)
    ledger_head_hash = as_string(get(ledger_receipt, "head_hash", ""))
    ledger_event_hash = as_string(get(ledger_receipt, "event_hash", ""))
    ledger_digest = store_artifact(ledger_receipt)
    push!(trace_steps, trace_step(
        "S4",
        "audit_append";
        input_digests = [input_digest, validation_digest, mediated_event_digest],
        output_digests = [ledger_digest],
        obligation_digests = [ledger_obligation_digest],
        receipt_digests = pre_ledger_receipts,
    ))

    pre_sign_receipts = [webhook_receipt_digest, file_receipt_digest, crm_digest, ledger_digest]
    sign_manifest = Dict(
        "run_id" => run_id,
        "artifact_digests" => [input_digest, validation_digest, mediated_event_digest],
        "receipt_digests" => pre_sign_receipts,
    )
    sign_req = Dict(
        "request_id" => "$(run_id)-s5-sign",
        "manifest" => sign_manifest,
    )
    sign_obligation_digest = store_artifact(sign_req)
    push!(obligation_digests, sign_obligation_digest)
    sign_receipt = post_json("$(SIGN_URL)/sign", sign_req)
    sign_digest = store_artifact(sign_receipt)
    push!(trace_steps, trace_step(
        "S5",
        "sign_bundle";
        input_digests = [input_digest, validation_digest, mediated_event_digest],
        output_digests = [sign_digest],
        obligation_digests = [sign_obligation_digest],
        receipt_digests = pre_sign_receipts,
    ))

    signing_package = signing_package_for(run_id, mediated_payload)
    signing_package_artifact_digest = store_artifact(signing_package)
    signing_package_digest = sha256_label(signing_package_artifact_digest)

    parent_token = issue_signing_token(run_id, "parent", signing_package_digest)
    child_token = issue_signing_token(run_id, "child", signing_package_digest)

    parent_link_obligation = signing_link_obligation_for(run_id, "parent", signing_package_digest, parent_token)
    parent_link_obligation_digest = store_artifact(parent_link_obligation)
    push!(obligation_digests, parent_link_obligation_digest)

    child_link_obligation = signing_link_obligation_for(run_id, "child", signing_package_digest, child_token)
    child_link_obligation_digest = store_artifact(child_link_obligation)
    push!(obligation_digests, child_link_obligation_digest)

    signing_link_obligation_digests = [parent_link_obligation_digest, child_link_obligation_digest]
    push!(trace_steps, trace_step(
        "S5a",
        "signing_links";
        input_digests = [mediated_event_digest],
        output_digests = [signing_package_artifact_digest],
        obligation_digests = signing_link_obligation_digests,
    ))

    push!(trace_steps, trace_step(
        "S5b",
        "signature_gate_parent";
        input_digests = [signing_package_artifact_digest],
        obligation_digests = [parent_link_obligation_digest],
    ))

    push!(trace_steps, trace_step(
        "S5c",
        "signature_gate_child";
        input_digests = [signing_package_artifact_digest],
        obligation_digests = [child_link_obligation_digest],
    ))

    push!(trace_steps, trace_step(
        "S6",
        "mainframe_open_account";
        input_digests = [mediated_event_digest, signing_package_artifact_digest],
    ))

    push!(trace_steps, trace_step(
        "S7",
        "finalize";
        input_digests = [input_digest, validation_digest, mediated_event_digest],
    ))

    base_receipts = [webhook_receipt_digest, file_receipt_digest, crm_digest, ledger_digest, sign_digest]

    artifact_digests = collect_trace_artifact_digests(trace_steps)

    run = Dict(
        "run_id" => run_id,
        "customer_id" => customer_id,
        "input_digest" => input_digest,
        "validation_digest" => validation_digest,
        "mediated_event_digest" => mediated_event_digest,
        "signing_package_digest" => signing_package_digest,
        "signing_link_obligation_digests" => signing_link_obligation_digests,
        "signing_links" => [
            Dict(
                "role" => "parent",
                "token" => parent_token,
                "token_hint" => token_hint(parent_token),
                "url_path" => as_string(get(parent_link_obligation, "url_path", "")),
                "signing_package_digest" => signing_package_digest,
                "obligation_digest" => parent_link_obligation_digest,
            ),
            Dict(
                "role" => "child",
                "token" => child_token,
                "token_hint" => token_hint(child_token),
                "url_path" => as_string(get(child_link_obligation, "url_path", "")),
                "signing_package_digest" => signing_package_digest,
                "obligation_digest" => child_link_obligation_digest,
            ),
        ],
        "signature_receipt_digests" => Dict{String, Any}("parent" => nothing, "child" => nothing),
        "obligation_digests" => obligation_digests,
        "base_receipt_digests" => base_receipts,
        "receipt_digests" => copy(base_receipts),
        "mainframe_obligation_digest" => nothing,
        "mainframe_receipt_digest" => nothing,
        "final_digest" => nothing,
        "artifact_digests" => artifact_digests,
        "ledger_head_hash" => ledger_head_hash,
        "ledger_event_hash" => ledger_event_hash,
        "audit_chain_head_hash" => ledger_head_hash,
        "pii_accesses" => Dict{String, Any}[],
        "pii_access_receipt_digests" => String[],
        "pii_ledger_receipt_digests" => String[],
        "pii_access_count" => 0,
        "pii_last_receipt_digest" => nothing,
        "pii_last_ledger_receipt_digest" => nothing,
        "pii_last_audit_event_hash" => nothing,
        "pii_audit_head_hash" => nothing,
        "trace_steps" => trace_steps,
        "status" => "WAITING_FOR_SIGNATURES",
    )
    RUNS[run_id] = run
    return run
end

function export_bundle(run_id::String)::Dict{String, Any}
    run = get(RUNS, run_id, nothing)
    run === nothing && error("run not found: $(run_id)")
    as_string(get(run, "status", "")) == "PASS" || error("run is not finalized: status=$(as_string(get(run, "status", "")))")

    final_digest = normalize_artifact_digest(get(run, "final_digest", nothing))
    final_digest === nothing && error("run final digest is missing")

    bundle_id = "$(run_id)-$(final_digest[1:12])"
    bundle_path = joinpath(BUNDLE_DIR, bundle_id)
    artifacts_path = joinpath(bundle_path, "artifacts")
    workflows_path = joinpath(bundle_path, "workflows")
    mkpath(artifacts_path)
    mkpath(workflows_path)

    digests = if haskey(run, "artifact_digests")
        String.(run["artifact_digests"])
    else
        collect_trace_artifact_digests(run["trace_steps"])
    end

    for digest in digests
        src = artifact_path(digest)
        dst = joinpath(artifacts_path, digest)
        cp(src, dst; force = true)
    end

    workflow_files = Dict{String, Any}[]
    if isdir(WORKFLOW_DIR)
        for file in sort(readdir(WORKFLOW_DIR))
            src = joinpath(WORKFLOW_DIR, file)
            if isfile(src)
                bytes = read(src)
                digest = sha256_hex(bytes)
                dst = joinpath(workflows_path, file)
                cp(src, dst; force = true)
                workflow_entry = Dict{String, Any}(
                    "file" => file,
                    "digest" => digest,
                )
                inspect = inspect_workflow_with_sdk(file, String(bytes))
                if inspect !== nothing
                    workflow_entry["sdk_is_canonical"] = get(inspect, "is_canonical", false)
                    workflow_entry["sdk_canonical_digest"] = as_string(get(inspect, "digest_hex", ""))
                    workflow_entry["sdk_digest_algorithm"] = as_string(get(inspect, "digest_algorithm", ""))
                    workflow_entry["sdk_encoded_size"] = get(inspect, "encoded_size", 0)
                end
                push!(workflow_files, workflow_entry)
            end
        end
    end

    trace_relpath = "run_trace.jsonl"
    trace_abspath = joinpath(bundle_path, trace_relpath)
    trace_digest = write_trace_jsonl(trace_abspath, run["trace_steps"])

    pii_access_receipt_digests = normalize_string_array(get(run, "pii_access_receipt_digests", Any[]))
    pii_ledger_receipt_digests = normalize_string_array(get(run, "pii_ledger_receipt_digests", Any[]))
    pii_accesses = run_pii_accesses(run)
    run["pii_access_receipt_digests"] = pii_access_receipt_digests
    run["pii_ledger_receipt_digests"] = pii_ledger_receipt_digests
    run["pii_accesses"] = pii_accesses

    ledger_chain_relpath::Union{Nothing, String} = nothing
    ledger_chain_digest::Union{Nothing, String} = nothing
    ledger_chain_head_hash::Union{Nothing, String} = nothing
    head_hash = lowercase(strip(as_string(get(run, "audit_chain_head_hash", get(run, "ledger_head_hash", "")))))
    if !isempty(head_hash)
        ledger_chain_bytes = get_bytes("$(LEDGER_URL)/ledger/chain?head_hash=$(head_hash)")
        ledger_chain_relpath = "ledger_chain.jsonl"
        ledger_chain_abspath = joinpath(bundle_path, ledger_chain_relpath)
        open(ledger_chain_abspath, "w") do io
            write(io, ledger_chain_bytes)
        end
        ledger_chain_digest = sha256_hex(ledger_chain_bytes)
        ledger_chain_head_hash = head_hash
    end

    manifest = Dict(
        "bundle_version" => "v0",
        "run_id" => run["run_id"],
        "input_digest" => run["input_digest"],
        "validation_digest" => run["validation_digest"],
        "mediated_event_digest" => run["mediated_event_digest"],
        "obligation_digests" => run["obligation_digests"],
        "receipt_digests" => run["receipt_digests"],
        "final_digest" => final_digest,
        "run_trace_file" => trace_relpath,
        "run_trace_digest" => trace_digest,
        "trace_step_count" => length(run["trace_steps"]),
        "artifact_digests" => digests,
        "workflow_files" => workflow_files,
        "pii_access_receipt_digests" => pii_access_receipt_digests,
        "pii_ledger_receipt_digests" => pii_ledger_receipt_digests,
        "pii_accesses" => pii_accesses,
    )
    if ledger_chain_relpath !== nothing
        manifest["ledger_chain_file"] = ledger_chain_relpath
        manifest["ledger_chain_digest"] = ledger_chain_digest
        manifest["ledger_chain_head_hash"] = ledger_chain_head_hash
    end
    manifest_bytes = canon_json(manifest)
    manifest_digest = sha256_hex(manifest_bytes)
    open(joinpath(bundle_path, "manifest.json"), "w") do io
        write(io, manifest_bytes)
    end

    return Dict(
        "run_id" => run_id,
        "bundle_path" => bundle_path,
        "manifest_digest" => manifest_digest,
        "final_digest" => final_digest,
        "pii_access_receipt_count" => length(pii_access_receipt_digests),
        "ledger_chain_head_hash" => ledger_chain_head_hash,
    )
end

function sorted_runs()
    runs = collect(values(RUNS))
    sort!(runs; by = r -> r["run_id"])
    return runs
end

function parse_json_body(req::HTTP.Request)::Dict{String, Any}
    if isempty(req.body)
        return Dict{String, Any}()
    end
    return to_plain(JSON3.read(String(req.body)))
end

function submit_signature(payload::Dict{String, Any})::Tuple{Int, Dict{String, Any}}
    run_id = as_string(get(payload, "run_id", ""))
    signer_role = normalize_signer_role(get(payload, "signer_role", ""))
    isempty(run_id) && return 400, Dict("error" => "missing required field: run_id")
    signer_role === nothing && return 400, Dict("error" => "signer_role must be one of: parent, child")

    run = get(RUNS, run_id, nothing)
    run === nothing && return 404, Dict("error" => "run not found")

    token = as_string(get(payload, "token", ""))
    isempty(token) && return 400, Dict("error" => "missing required field: token")

    signing_resolution = find_signing_resolution(token)
    signing_resolution === nothing && return 404, Dict("error" => "signing token not found")
    as_string(get(signing_resolution, "run_id", "")) == run_id || return 404, Dict("error" => "signing token not found")
    as_string(get(signing_resolution, "signer_role", "")) == signer_role || return 404, Dict("error" => "signing token not found")

    gate_step = find_gate_step(run, signer_role)
    gate_step === nothing && return 500, Dict("error" => "signature gate step missing")
    existing_gate_receipts = get(gate_step, "receipt_digests", Any[])
    if existing_gate_receipts isa AbstractVector && !isempty(existing_gate_receipts)
        return 409, Dict("error" => "signature already submitted", "run_id" => run_id, "signer_role" => signer_role)
    end

    raw_receipt = get(payload, "receipt", nothing)
    raw_receipt isa Dict || return 400, Dict("error" => "missing required field: receipt")
    receipt_obj = as_dict(raw_receipt)
    receipt_artifact_digest = store_artifact(receipt_obj)

    if haskey(payload, "receipt_digest")
        provided_digest = normalize_artifact_digest(payload["receipt_digest"])
        provided_digest === nothing && return 400, Dict("error" => "receipt_digest must be sha256:<hex> or <hex>")
        provided_digest == receipt_artifact_digest || return 400, Dict(
            "error" => "receipt_digest mismatch",
            "expected" => sha256_label(receipt_artifact_digest),
            "provided" => as_string(payload["receipt_digest"]),
        )
    end

    receipt_digest_label = sha256_label(receipt_artifact_digest)
    apply_signature_receipt!(run, signer_role, receipt_artifact_digest, receipt_digest_label)

    return 200, Dict(
        "status" => "ok",
        "receipt_digest" => receipt_digest_label,
        "run_id" => run_id,
    )
end

function handle(req::HTTP.Request)
    target = String(HTTP.URI(req.target).path)
    method = String(req.method)

    try
        if method == "GET" && target == "/workflow/health"
            sdk_ready = false
            try
                sdk_health = post_json("$(SDK_GATEWAY_URL)/sdk/workflow/inspect", Dict("text" => "(probe = true)"))
                sdk_ready = as_string(get(sdk_health, "digest_hex", "")) != ""
            catch
                sdk_ready = false
            end
            return json_response(200, Dict("status" => "ok", "sdk_ready" => sdk_ready))
        elseif method == "GET" && target == "/workflow/runs"
            return json_response(200, sorted_runs())
        elseif method == "GET"
            m = match(r"^/workflow/signing/token/([^/]+)$", target)
            if m !== nothing
                token = String(m.captures[1])
                resolved = find_signing_resolution(token)
                resolved === nothing && return json_response(404, Dict("error" => "signing token not found"))
                return json_response(200, resolved)
            end

            m = match(r"^/workflow/runs/([^/]+)$", target)
            if m !== nothing
                run_id = String(m.captures[1])
                run = get(RUNS, run_id, nothing)
                run === nothing && return json_response(404, Dict("error" => "run not found"))
                return json_response(200, run)
            end

            m = match(r"^/workflow/artifacts/([^/]+)$", target)
            if m !== nothing
                digest = normalize_artifact_digest(String(m.captures[1]))
                digest === nothing && return json_response(404, Dict("error" => "artifact not found"))
                path = artifact_path(digest)
                isfile(path) || return json_response(404, Dict("error" => "artifact not found"))
                return HTTP.Response(200, ["Content-Type" => "application/json"], read(path))
            end

            m = match(r"^/workflow/bundles/([^/]+)/export$", target)
            if m !== nothing
                run_id = String(m.captures[1])
                exported = export_bundle(run_id)
                return json_response(200, exported)
            end
        elseif method == "POST"
            m = match(r"^/workflow/runs/([^/]+)/pii/reveal$", target)
            if m !== nothing
                run_id = String(m.captures[1])
                run = get(RUNS, run_id, nothing)
                run === nothing && return json_response(404, Dict("error" => "run not found"))
                payload = parse_json_body(req)
                status, response = reveal_pii_for_run(run, payload)
                return json_response(status, response)
            end

            if target == "/workflow/signatures/submit"
                payload = parse_json_body(req)
                status, response = submit_signature(payload)
                return json_response(status, response)
            elseif target == "/workflow/seed" || target == "/workflow/ingest"
                payload = parse_json_body(req)
                event = haskey(payload, "event") && payload["event"] isa Dict ? payload["event"] : payload
                run = process_event(event)
                return json_response(201, run)
            end
        end

        return json_response(404, Dict("error" => "not found", "target" => target))
    catch err
        return json_response(500, Dict("error" => sprint(showerror, err)))
    end
end

ensure_dirs()
@info "workflow-host starting" host = HOST port = PORT
HTTP.serve(handle, HOST, PORT)
