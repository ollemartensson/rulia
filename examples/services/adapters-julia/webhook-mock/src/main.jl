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

function receipt_for(request::Dict{String, Any})
    request_id = as_string(get(request, "request_id", "webhook-unknown"))
    inputs_digest = as_string(get(request, "mediated_event_digest", ""))

    outputs = Dict("status" => "DELIVERED")

    receipt_wo_digest = Dict(
        "receipt_type" => "webhook.delivery",
        "request_id" => request_id,
        "inputs_digest" => inputs_digest,
        "outputs_digest" => sha256_hex(canon_json(outputs)),
        "evidence" => Dict(
            "adapter" => "webhook-mock-julia",
            "version" => "v0",
            "outputs" => outputs,
        ),
    )

    return merge(receipt_wo_digest, Dict("receipt_digest" => sha256_hex(canon_json(receipt_wo_digest))))
end

function json_response(status::Int, obj)
    HTTP.Response(status, ["Content-Type" => "application/json"], canon_json(obj))
end

function handle(req::HTTP.Request)
    target = String(HTTP.URI(req.target).path)
    method = String(req.method)

    if method == "GET" && target == "/webhook/health"
        return json_response(200, Dict("status" => "ok"))
    elseif method == "POST" && target == "/webhook/deliver"
        payload = isempty(req.body) ? Dict{String, Any}() : to_plain(JSON3.read(String(req.body)))
        return json_response(200, receipt_for(payload))
    end

    return json_response(404, Dict("error" => "not found", "target" => target))
end

@info "webhook-mock starting" host = HOST port = PORT
HTTP.serve(handle, HOST, PORT)
