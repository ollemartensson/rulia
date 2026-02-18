using Base64
using HTTP
using JSON3

include("canon.jl")
using .Canon

const HOST = get(ENV, "HOST", "0.0.0.0")
const PORT = parse(Int, get(ENV, "PORT", "8080"))
const BANKID_MODE = lowercase(strip(get(ENV, "BANKID_MODE", "mock")))
const BANKID_BASE_URL_DEFAULT = "https://appapi2.test.bankid.com/rp/v6.0"
const ORDER_LOCK = ReentrantLock()
const ORDERS = Dict{String, Dict{String, Any}}()
const SSL_LOCK = ReentrantLock()
const REAL_SSLCONFIG = Ref{Any}(nothing)
const REAL_SSL_TMPDIR = Ref{Union{Nothing, String}}(nothing)

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
    else
        return Dict{String, Any}()
    end
end

function json_response(status::Int, obj)
    return HTTP.Response(status, ["Content-Type" => "application/json"], canon_json(obj))
end

function parse_body(req::HTTP.Request)::Dict{String, Any}
    isempty(req.body) && return Dict{String, Any}()
    return to_plain(JSON3.read(String(req.body)))
end

function bankid_base_url()::String
    raw = strip(get(ENV, "BANKID_BASE_URL", BANKID_BASE_URL_DEFAULT))
    return endswith(raw, "/") ? raw[1:end-1] : raw
end

function store_order!(order_ref::String, meta::Dict{String, Any})
    lock(ORDER_LOCK) do
        ORDERS[order_ref] = meta
    end
end

function fetch_order!(order_ref::String; bump_collect::Bool=false)
    lock(ORDER_LOCK) do
        haskey(ORDERS, order_ref) || return nothing
        meta = ORDERS[order_ref]
        if bump_collect
            count = get(meta, "collect_calls", 0)
            meta["collect_calls"] = (count isa Integer ? Int(count) : 0) + 1
        end
        ORDERS[order_ref] = meta
        return deepcopy(meta)
    end
end

function completion_subset(completion_data::Dict{String, Any})::Dict{String, Any}
    user = as_dict(get(completion_data, "user", Dict{String, Any}()))
    device = as_dict(get(completion_data, "device", Dict{String, Any}()))
    cert = as_dict(get(completion_data, "cert", Dict{String, Any}()))

    return Dict(
        "signature" => as_string(get(completion_data, "signature", "")),
        "ocsp_response" => as_string(get(completion_data, "ocspResponse", "")),
        "user" => Dict(
            "personal_number" => as_string(get(user, "personalNumber", "")),
            "name" => as_string(get(user, "name", "")),
            "given_name" => as_string(get(user, "givenName", "")),
            "surname" => as_string(get(user, "surname", "")),
        ),
        "device" => Dict(
            "ip_address" => as_string(get(device, "ipAddress", "")),
            "uhi" => as_string(get(device, "uhi", "")),
        ),
        "cert" => Dict(
            "not_before" => as_string(get(cert, "notBefore", "")),
            "not_after" => as_string(get(cert, "notAfter", "")),
        ),
    )
end

function build_receipt(meta::Dict{String, Any}, completion_data::Dict{String, Any})
    subset = completion_subset(completion_data)
    completion_data_digest = sha256_hex(canon_json(subset))

    signature_scope = Dict(
        "signature" => get(subset, "signature", ""),
        "ocsp_response" => get(subset, "ocsp_response", ""),
        "cert" => get(subset, "cert", Dict{String, Any}()),
    )
    signature_digest = sha256_hex(canon_json(signature_scope))

    receipt = Dict(
        "receipt_type" => "signature.bankid",
        "bankid_environment" => "test",
        "signer_role" => as_string(get(meta, "signer_role", "")),
        "signing_package_digest" => as_string(get(meta, "signing_package_digest", "")),
        "completion_data_digest" => completion_data_digest,
        "signature_digest" => signature_digest,
        "evidence" => Dict("policy" => "bankid-test-sign-v1"),
    )

    receipt_digest = sha256_hex(canon_json(receipt))
    return receipt, receipt_digest
end

function mock_completion_data(order_ref::String, meta::Dict{String, Any})
    signature_scope = Dict(
        "order_ref" => order_ref,
        "signer_role" => as_string(get(meta, "signer_role", "")),
        "signing_package_digest" => as_string(get(meta, "signing_package_digest", "")),
    )
    ocsp_scope = Dict("order_ref" => order_ref, "status" => "good")

    return Dict(
        "signature" => base64encode(canon_json(signature_scope)),
        "ocspResponse" => base64encode(canon_json(ocsp_scope)),
        "user" => Dict(
            "personalNumber" => "190000000000",
            "name" => "Mock Signer",
            "givenName" => "Mock",
            "surname" => "Signer",
        ),
        "device" => Dict(
            "ipAddress" => as_string(get(meta, "end_user_ip", "")),
            "uhi" => "mock-uhi",
        ),
        "cert" => Dict(
            "notBefore" => "2026-01-01T00:00:00Z",
            "notAfter" => "2031-01-01T00:00:00Z",
        ),
    )
end

function parse_bankid_response(resp::HTTP.Response)::Dict{String, Any}
    isempty(resp.body) && return Dict{String, Any}()
    text = String(resp.body)
    isempty(strip(text)) && return Dict{String, Any}()
    try
        return to_plain(JSON3.read(text))
    catch
        return Dict("raw" => text)
    end
end

function ensure_ca_roots!()
    ca_path = strip(get(ENV, "BANKID_CA_PATH", ""))
    isempty(ca_path) && return
    isfile(ca_path) || error("BANKID_CA_PATH does not exist: $(ca_path)")
    ENV["JULIA_SSL_CA_ROOTS_PATH"] = ca_path
end

function ensure_real_sslconfig()
    lock(SSL_LOCK) do
        REAL_SSLCONFIG[] === nothing || return REAL_SSLCONFIG[]

        pfx_path = strip(get(ENV, "BANKID_PFX_PATH", "/certs/bankid-test.pfx"))
        pfx_password = get(ENV, "BANKID_PFX_PASSWORD", "")
        isempty(pfx_path) && error("BANKID_PFX_PATH is required in real mode")
        isfile(pfx_path) || error("BANKID_PFX_PATH does not exist: $(pfx_path)")

        ensure_ca_roots!()

        tmpdir = mktempdir(prefix="bankid-mtls-")
        cert_pem = joinpath(tmpdir, "client-cert.pem")
        key_pem = joinpath(tmpdir, "client-key.pem")

        cert_cmd = addenv(
            `openssl pkcs12 -in $pfx_path -clcerts -nokeys -passin env:BANKID_PFX_PASSWORD -out $cert_pem`,
            "BANKID_PFX_PASSWORD" => pfx_password,
        )
        key_cmd = addenv(
            `openssl pkcs12 -in $pfx_path -nocerts -nodes -passin env:BANKID_PFX_PASSWORD -out $key_pem`,
            "BANKID_PFX_PASSWORD" => pfx_password,
        )

        run(cert_cmd)
        run(key_cmd)
        chmod(key_pem, 0o600)

        REAL_SSL_TMPDIR[] = tmpdir
        REAL_SSLCONFIG[] = HTTP.SSLConfig(cert_pem, key_pem)
        return REAL_SSLCONFIG[]
    end
end

function bankid_post(path::String, payload::Dict{String, Any})
    url = string(bankid_base_url(), path)
    headers = ["Content-Type" => "application/json", "Accept" => "application/json"]

    return HTTP.request(
        "POST",
        url,
        headers,
        canon_json(payload);
        status_exception=false,
        retry=false,
        readtimeout=30,
        connect_timeout=15,
        require_ssl_verification=true,
        sslconfig=ensure_real_sslconfig(),
    )
end

function validate_start_payload(payload::Dict{String, Any})
    signing_package_digest = as_string(get(payload, "signing_package_digest", ""))
    signer_role = as_string(get(payload, "signer_role", ""))
    end_user_ip = as_string(get(payload, "end_user_ip", ""))
    user_visible_text = as_string(get(payload, "user_visible_text", ""))

    isempty(signing_package_digest) && error("missing required field: signing_package_digest")
    isempty(signer_role) && error("missing required field: signer_role")
    isempty(end_user_ip) && error("missing required field: end_user_ip")
    isempty(user_visible_text) && error("missing required field: user_visible_text")

    startswith(signing_package_digest, "sha256:") || error("signing_package_digest must start with sha256:")
    signer_role in ("parent", "child") || error("signer_role must be one of: parent, child")

    return signing_package_digest, signer_role, end_user_ip, user_visible_text
end

function start_mock(payload::Dict{String, Any})
    signing_package_digest, signer_role, end_user_ip, user_visible_text = validate_start_payload(payload)

    scope = Dict(
        "signing_package_digest" => signing_package_digest,
        "signer_role" => signer_role,
        "end_user_ip" => end_user_ip,
        "user_visible_text" => user_visible_text,
    )
    d = sha256_hex(canon_json(scope))
    order_ref = "mock-order-" * d[1:32]
    auto_start_token = "mock-autostart-" * d[33:64]

    store_order!(order_ref, Dict(
        "signing_package_digest" => signing_package_digest,
        "signer_role" => signer_role,
        "end_user_ip" => end_user_ip,
        "collect_calls" => 0,
    ))

    return json_response(200, Dict(
        "order_ref" => order_ref,
        "auto_start_token" => auto_start_token,
        "status" => "pending",
    ))
end

function start_real(payload::Dict{String, Any})
    signing_package_digest, signer_role, end_user_ip, user_visible_text = validate_start_payload(payload)

    bankid_resp = bankid_post("/sign", Dict(
        "endUserIp" => end_user_ip,
        "userVisibleData" => user_visible_text,
    ))

    body = parse_bankid_response(bankid_resp)
    if bankid_resp.status != 200
        return json_response(502, Dict(
            "error" => "bankid_sign_failed",
            "bankid_status" => bankid_resp.status,
            "bankid_error_code" => as_string(get(body, "errorCode", "")),
            "details" => as_string(get(body, "details", "")),
        ))
    end

    order_ref = as_string(get(body, "orderRef", ""))
    auto_start_token = as_string(get(body, "autoStartToken", ""))
    isempty(order_ref) && return json_response(502, Dict("error" => "bankid_sign_missing_order_ref"))
    isempty(auto_start_token) && return json_response(502, Dict("error" => "bankid_sign_missing_auto_start_token"))

    store_order!(order_ref, Dict(
        "signing_package_digest" => signing_package_digest,
        "signer_role" => signer_role,
        "end_user_ip" => end_user_ip,
        "collect_calls" => 0,
    ))

    return json_response(200, Dict(
        "order_ref" => order_ref,
        "auto_start_token" => auto_start_token,
        "status" => "pending",
    ))
end

function collect_mock(payload::Dict{String, Any})
    order_ref = as_string(get(payload, "order_ref", ""))
    isempty(order_ref) && return json_response(400, Dict("error" => "missing required field: order_ref"))

    meta = fetch_order!(order_ref; bump_collect=true)
    meta === nothing && return json_response(404, Dict("error" => "unknown_order_ref", "order_ref" => order_ref))

    collect_calls = Int(get(meta, "collect_calls", 0))
    if collect_calls <= 1
        return json_response(200, Dict("status" => "pending", "hint_code" => "outstandingTransaction"))
    end

    receipt, receipt_digest = build_receipt(meta, mock_completion_data(order_ref, meta))
    return json_response(200, Dict(
        "status" => "complete",
        "receipt" => receipt,
        "receipt_digest" => "sha256:" * receipt_digest,
    ))
end

function collect_real(payload::Dict{String, Any})
    order_ref = as_string(get(payload, "order_ref", ""))
    isempty(order_ref) && return json_response(400, Dict("error" => "missing required field: order_ref"))

    meta = fetch_order!(order_ref; bump_collect=true)
    meta === nothing && return json_response(404, Dict("error" => "unknown_order_ref", "order_ref" => order_ref))

    bankid_resp = bankid_post("/collect", Dict("orderRef" => order_ref))
    body = parse_bankid_response(bankid_resp)

    if bankid_resp.status != 200
        return json_response(502, Dict(
            "error" => "bankid_collect_failed",
            "bankid_status" => bankid_resp.status,
            "bankid_error_code" => as_string(get(body, "errorCode", "")),
            "details" => as_string(get(body, "details", "")),
        ))
    end

    state = as_string(get(body, "status", ""))
    hint_code = as_string(get(body, "hintCode", ""))

    if state == "pending"
        resp = Dict("status" => "pending")
        isempty(hint_code) || (resp["hint_code"] = hint_code)
        return json_response(200, resp)
    elseif state == "complete"
        completion_data = as_dict(get(body, "completionData", Dict{String, Any}()))
        receipt, receipt_digest = build_receipt(meta, completion_data)
        return json_response(200, Dict(
            "status" => "complete",
            "receipt" => receipt,
            "receipt_digest" => "sha256:" * receipt_digest,
        ))
    elseif state == "failed"
        resp = Dict("status" => "failed")
        isempty(hint_code) || (resp["hint_code"] = hint_code)
        return json_response(200, resp)
    else
        return json_response(502, Dict("error" => "bankid_collect_unexpected_status", "bankid_status" => state))
    end
end

function mode_dispatch(start_or_collect::Symbol, payload::Dict{String, Any})
    if BANKID_MODE == "mock"
        return start_or_collect === :start ? start_mock(payload) : collect_mock(payload)
    elseif BANKID_MODE == "real"
        return start_or_collect === :start ? start_real(payload) : collect_real(payload)
    else
        return json_response(500, Dict("error" => "invalid BANKID_MODE", "mode" => BANKID_MODE))
    end
end

function handle(req::HTTP.Request)
    target = String(HTTP.URI(req.target).path)
    method = String(req.method)

    if method == "GET" && (target == "/bankid/health" || target == "/health")
        return json_response(200, Dict(
            "status" => "ok",
            "service" => "bankid-test",
            "mode" => BANKID_MODE,
            "bankid_base_url" => bankid_base_url(),
            "ca_roots" => isempty(strip(get(ENV, "BANKID_CA_PATH", ""))) ? "system" : "file",
        ))
    elseif method == "POST" && (target == "/bankid/sign/start" || target == "/sign/start")
        try
            payload = parse_body(req)
            return mode_dispatch(:start, payload)
        catch err
            return json_response(400, Dict("error" => "bad_request", "details" => sprint(showerror, err)))
        end
    elseif method == "POST" && (target == "/bankid/sign/collect" || target == "/sign/collect")
        try
            payload = parse_body(req)
            return mode_dispatch(:collect, payload)
        catch err
            return json_response(400, Dict("error" => "bad_request", "details" => sprint(showerror, err)))
        end
    end

    return json_response(404, Dict("error" => "not_found", "target" => target))
end

@info "bankid-test starting" host = HOST port = PORT mode = BANKID_MODE base_url = bankid_base_url()
HTTP.serve(handle, HOST, PORT)
