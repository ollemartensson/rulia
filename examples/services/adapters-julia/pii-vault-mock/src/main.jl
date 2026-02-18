using HTTP
using JSON3

include("canon.jl")
using .Canon

const HOST = get(ENV, "HOST", "0.0.0.0")
const PORT = parse(Int, get(ENV, "PORT", "8080"))
const LEDGER_URL = get(ENV, "LEDGER_URL", "http://audit-ledger:8080")

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

function json_response(status::Int, obj)
    HTTP.Response(status, ["Content-Type" => "application/json"], canon_json(obj))
end

function post_json(url::String, body_obj)::Dict{String, Any}
    body = canon_json(body_obj)
    response = HTTP.request("POST", url, ["Content-Type" => "application/json"], body)
    if response.status < 200 || response.status >= 300
        error("capability call failed: $(url) -> $(response.status)")
    end
    return to_plain(JSON3.read(String(response.body)))
end

function stable_profile(subject_id::String)::Dict{String, Any}
    seed = sha256_hex(canon_json(Dict("scope" => "pii.profile.v0", "subject_id" => subject_id)))
    street_no = 10 + parse(Int, seed[1:2]; base = 16) % 90
    postal_code = 10000 + parse(Int, seed[3:6]; base = 16) % 89999

    return Dict(
        "subject_id" => subject_id,
        "full_name" => "Customer " * uppercase(seed[1:6]),
        "email" => "customer+" * seed[1:10] * "@example.test",
        "phone" => "+4670" * seed[11:17],
        "address" => "Demo Street $(street_no), $(postal_code) Stockholm",
        "birth_date" => "1990-01-01",
    )
end

function normalize_fields(raw)::Vector{String}
    default_fields = ["full_name", "email", "phone"]
    raw isa AbstractVector || return default_fields

    out = String[]
    for field in raw
        value = strip(as_string(field))
        isempty(value) && continue
        push!(out, value)
    end
    return isempty(out) ? default_fields : out
end

function audited_reveal(payload::Dict{String, Any})::Dict{String, Any}
    run_id = as_string(get(payload, "run_id", ""))
    subject_id = as_string(get(payload, "subject_id", get(payload, "customer_id", "")))
    actor_type = as_string(get(payload, "actor_type", "human"))
    actor_id = as_string(get(payload, "actor_id", "internal-ui-operator"))
    purpose = as_string(get(payload, "purpose", "manual-review"))
    fields = normalize_fields(get(payload, "fields", Any[]))

    request_id = as_string(get(payload, "request_id", ""))
    if isempty(request_id)
        request_seed = Dict(
            "scope" => "pii.reveal.v0",
            "run_id" => run_id,
            "subject_id" => subject_id,
            "actor_type" => actor_type,
            "actor_id" => actor_id,
            "purpose" => purpose,
            "fields" => fields,
        )
        request_id = "pii-reveal-" * sha256_hex(canon_json(request_seed))[1:16]
    end

    audit_event = Dict(
        "event_type" => "pii.read.v0",
        "request_id" => request_id,
        "run_id" => run_id,
        "subject_id" => subject_id,
        "actor_type" => actor_type,
        "actor_id" => actor_id,
        "purpose" => purpose,
        "fields" => fields,
    )

    ledger_request = Dict(
        "request_id" => request_id * "-ledger",
        "event_type" => "pii.read.v0",
        "run_id" => run_id,
        "event" => audit_event,
    )
    ledger_receipt = post_json("$(LEDGER_URL)/ledger/append", ledger_request)

    audit_event_hash = as_string(get(ledger_receipt, "event_hash", ""))
    head_hash = as_string(get(ledger_receipt, "head_hash", ""))
    ledger_receipt_digest = as_string(get(ledger_receipt, "receipt_digest", ""))

    isempty(audit_event_hash) && error("audit-ledger receipt missing event_hash")
    isempty(head_hash) && error("audit-ledger receipt missing head_hash")
    isempty(ledger_receipt_digest) && error("audit-ledger receipt missing receipt_digest")

    full_profile = stable_profile(subject_id)
    revealed = Dict{String, Any}()
    for field in fields
        if haskey(full_profile, field)
            revealed[field] = full_profile[field]
        end
    end
    haskey(revealed, "subject_id") || (revealed["subject_id"] = subject_id)

    outputs = Dict(
        "subject_id" => subject_id,
        "fields" => fields,
        "pii" => revealed,
    )

    receipt_wo_digest = Dict(
        "receipt_type" => "pii.reveal.v0",
        "request_id" => request_id,
        "inputs_digest" => sha256_hex(canon_json(payload)),
        "outputs_digest" => sha256_hex(canon_json(outputs)),
        "evidence" => Dict(
            "adapter" => "pii-vault-mock-julia",
            "version" => "v0",
            "run_id" => run_id,
            "audit_event_hash" => audit_event_hash,
            "head_hash" => head_hash,
            "ledger_receipt_digest" => ledger_receipt_digest,
            "ledger_sequence" => get(ledger_receipt, "sequence", nothing),
            "ledger_prev_hash" => as_string(get(ledger_receipt, "prev_hash", "")),
        ),
    )
    receipt = merge(
        receipt_wo_digest,
        Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))),
    )

    return Dict(
        "status" => "ok",
        "audit_event_hash" => audit_event_hash,
        "head_hash" => head_hash,
        "ledger_receipt_digest" => ledger_receipt_digest,
        "receipt" => receipt,
        "ledger_receipt" => ledger_receipt,
        "revealed" => revealed,
    )
end

function handle(req::HTTP.Request)
    target = String(HTTP.URI(req.target).path)
    method = String(req.method)

    if method == "GET" && target == "/pii/health"
        return json_response(200, Dict("status" => "ok"))
    elseif method == "POST" && target == "/pii/reveal"
        payload = isempty(req.body) ? Dict{String, Any}() : to_plain(JSON3.read(String(req.body)))
        payload = as_dict(payload)

        run_id = as_string(get(payload, "run_id", ""))
        subject_id = as_string(get(payload, "subject_id", get(payload, "customer_id", "")))

        isempty(run_id) && return json_response(400, Dict("error" => "missing required field: run_id"))
        isempty(subject_id) && return json_response(400, Dict("error" => "missing required field: subject_id"))

        try
            return json_response(200, audited_reveal(payload))
        catch err
            return json_response(502, Dict("error" => sprint(showerror, err)))
        end
    end

    return json_response(404, Dict("error" => "not found", "target" => target))
end

@info "pii-vault-mock starting" host = HOST port = PORT ledger_url = LEDGER_URL
HTTP.serve(handle, HOST, PORT)
