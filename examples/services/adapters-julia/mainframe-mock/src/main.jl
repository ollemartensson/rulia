using HTTP
using JSON3

include("canon.jl")
using .Canon

const HOST = get(ENV, "HOST", "0.0.0.0")
const PORT = parse(Int, get(ENV, "PORT", "8080"))

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

function json_response(status::Int, obj)
    HTTP.Response(status, ["Content-Type" => "application/json"], canon_json(obj))
end

function request_digest_hex(request::Dict{String, Any})::String
    return sha256_hex(canon_json(request))
end

function receipt_for(request::Dict{String, Any})::Dict{String, Any}
    request_digest = request_digest_hex(request)
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

function handle(req::HTTP.Request)
    target = String(HTTP.URI(req.target).path)
    method = String(req.method)

    if method == "GET" && target == "/mainframe/health"
        return json_response(200, Dict("status" => "ok"))
    elseif method == "POST" && target == "/mainframe/open-account"
        payload = isempty(req.body) ? Dict{String, Any}() : to_plain(JSON3.read(String(req.body)))
        return json_response(200, receipt_for(payload))
    end

    return json_response(404, Dict("error" => "not found", "target" => target))
end

@info "mainframe-mock starting" host = HOST port = PORT
HTTP.serve(handle, HOST, PORT)
