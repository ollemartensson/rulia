using HTTP
using JSON3

include("canon.jl")
using .Canon

const OUTBOX_DIR = get(ENV, "OUTBOX_DIR", "/app/volumes/tk4/outbox")
const PROCESSED_DIR = get(ENV, "PROCESSED_DIR", "/app/volumes/tk4/processed")
const KAFKA_BROKER = get(ENV, "KAFKA_BROKER", "redpanda:9092")
const KAFKA_TOPIC = get(ENV, "KAFKA_TOPIC", "legacy.outbox.v0")
const WORKFLOW_SEED_URL = get(ENV, "WORKFLOW_SEED_URL", "http://workflow-host-julia:8080/workflow/seed")
const POLL_INTERVAL_SECONDS = parse(Int, get(ENV, "POLL_INTERVAL_SECONDS", "2"))

function parse_record(raw::String)::Dict{String, Any}
    line = replace(raw, r"\r?\n$" => "")
    ncodeunits(line) == 148 || error("record must be 148 bytes, got $(ncodeunits(line))")

    customer_raw = line[1:10]
    change_raw = line[11:12]
    new_value_raw = line[13:52]
    correlation_raw = line[53:84]
    checksum_raw = lowercase(line[85:148])

    canon = string(customer_raw, "|", change_raw, "|", new_value_raw, "|", correlation_raw)
    computed_checksum = sha256_hex(Vector{UInt8}(codeunits(canon)))

    return Dict(
        "customer_id" => strip(customer_raw),
        "change_type" => strip(change_raw),
        "new_value" => rstrip(new_value_raw),
        "correlation_id" => strip(correlation_raw),
        "record_checksum" => checksum_raw,
        "record_checksum_valid" => checksum_raw == computed_checksum,
        "record_checksum_computed" => computed_checksum,
    )
end

function publish_to_kafka(payload::Vector{UInt8})
    cmd = Cmd(["kcat", "-P", "-b", KAFKA_BROKER, "-t", KAFKA_TOPIC])
    open(cmd, "w") do io
        write(io, payload)
    end
end

function post_to_workflow(event_payload::Dict{String, Any})
    body = canon_json(event_payload)
    resp = HTTP.request("POST", WORKFLOW_SEED_URL, ["Content-Type" => "application/json"], body)
    resp.status in (200, 201) || error("workflow seed failed with status $(resp.status)")
end

function process_file(path::String)
    raw_bytes = read(path)
    raw_digest = sha256_hex(raw_bytes)
    raw_string = String(raw_bytes)
    parsed = parse_record(raw_string)

    payload = Dict(
        "event_type" => "legacy.outbox.v0",
        "raw_bytes_digest" => raw_digest,
        "event" => parsed,
    )
    payload_bytes = canon_json(payload)

    publish_to_kafka(payload_bytes)
    post_to_workflow(payload)

    mkpath(PROCESSED_DIR)
    dest = joinpath(PROCESSED_DIR, basename(path) * ".done")
    mv(path, dest; force = true)
    @info "processed outbox record" src = path dest = dest
end

function main()
    mkpath(OUTBOX_DIR)
    mkpath(PROCESSED_DIR)
    @info "mf-outbox-bridge started" outbox = OUTBOX_DIR topic = KAFKA_TOPIC

    while true
        files = filter(f -> endswith(f, ".dat"), readdir(OUTBOX_DIR; join = true))
        sort!(files)
        for file in files
            try
                process_file(file)
            catch err
                @error "failed processing outbox file" file = file err = sprint(showerror, err)
            end
        end
        sleep(POLL_INTERVAL_SECONDS)
    end
end

main()
