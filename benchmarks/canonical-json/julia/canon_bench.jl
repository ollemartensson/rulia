using JSON3
using SHA

include("../../../examples/services/workflow-host-julia/src/canon.jl")
import .Canon

const SHA256_BITCOUNT_IDX = Int(div(SHA.short_blocklen(SHA.SHA2_256_CTX), sizeof(UInt64)) + 1)
const USE_COMMONCRYPTO_SHA256 = Sys.isapple()

struct KernelValues
    owners::Vector{Vector{UInt8}}
    ptrs::Vector{Ptr{UInt8}}
    nbytes_c::Vector{Cuint}
    nbytes_u64::Vector{UInt64}
end

function KernelValues(owners::Vector{Vector{UInt8}})
    n = length(owners)
    ptrs = Vector{Ptr{UInt8}}(undef, n)
    nbytes_c = Vector{Cuint}(undef, n)
    nbytes_u64 = Vector{UInt64}(undef, n)
    @inbounds for i in eachindex(owners)
        b = owners[i]
        ptrs[i] = pointer(b)
        nbytes_c[i] = Cuint(length(b))
        nbytes_u64[i] = UInt64(length(b))
    end
    return KernelValues(owners, ptrs, nbytes_c, nbytes_u64)
end

struct BaseVectorCase
    payload::Any
    canonical::Vector{UInt8}
end

struct HashThreadState
    sha_ctx::SHA.SHA2_256_CTX
    digest::Vector{UInt8}
end

function init_hash_states(n::Int = Threads.nthreads())::Vector{HashThreadState}
    states = Vector{HashThreadState}(undef, n)
    @inbounds for i in 1:n
        states[i] = HashThreadState(SHA.SHA2_256_CTX(), Vector{UInt8}(undef, 32))
    end
    return states
end

function arg_value(flag::String, default::String)::String
    idx = findfirst(==(flag), ARGS)
    idx === nothing && return default
    idx == length(ARGS) && error("$flag requires a value")
    return ARGS[idx + 1]
end

function arg_int(flag::String, default::Int)::Int
    value = arg_value(flag, string(default))
    try
        return parse(Int, value)
    catch
        error("invalid integer for $flag: $value")
    end
end

function to_plain(x)
    if x isa JSON3.Object
        out = Dict{String, Any}()
        for (k, v) in pairs(x)
            out[String(k)] = to_plain(v)
        end
        return out
    elseif x isa JSON3.Array
        return [to_plain(v) for v in x]
    else
        return x
    end
end

function load_base_vectors(vectors_dir::String)
    files = sort(filter(f -> endswith(f, ".json"), readdir(vectors_dir; join = true)))
    isempty(files) && error("no .json vectors found in $vectors_dir")

    base = Vector{BaseVectorCase}()
    for json_path in files
        stem = splitext(basename(json_path))[1]
        expected_hex = lowercase(strip(read(joinpath(vectors_dir, stem * ".canon.hex"), String)))
        expected_sha = lowercase(strip(read(joinpath(vectors_dir, stem * ".sha256"), String)))

        parsed = to_plain(JSON3.read(read(json_path, String)))
        parsed isa Dict{String, Any} || error("vector $stem top-level must be object")
        actual_bytes = Canon.canon_json(parsed)
        actual_hex = bytes2hex(actual_bytes)
        actual_sha = Canon.sha256_hex(actual_bytes)

        actual_hex == expected_hex || error("vector $stem canonical bytes mismatch")
        actual_sha == expected_sha || error("vector $stem sha mismatch")

        push!(base, BaseVectorCase(parsed, actual_bytes))
    end

    return base
end

function build_profile_values(profile::String, base::Vector{BaseVectorCase})::Vector{Vector{UInt8}}
    if profile == "base"
        return [item.canonical for item in base]
    elseif profile == "stress"
        total = length(base) * 20
        out = Vector{Vector{UInt8}}(undef, total)
        out_idx = 1
        for round in 0:19
            for (index1, item) in enumerate(base)
                idx = index1 - 1
                payload = item.payload
                record = Dict(
                    "case" => round,
                    "source_index" => idx,
                    "kind" => "stress",
                    "payload" => payload,
                    "echo" => Any[
                        payload,
                        Dict(
                            "flag" => ((round + idx) % 2) == 0,
                            "seq" => round * 10 + idx,
                            "text" => "café😀",
                        ),
                    ],
                    "metrics" => Dict(
                        "neg" => -(round + idx),
                        "big" => 1234567890123456789,
                        "small" => round,
                    ),
                )
                out[out_idx] = Canon.canon_json(record)
                out_idx += 1
            end
        end
        return out
    else
        error("unsupported profile: $profile (expected base|stress)")
    end
end

function sha256_first_u64!(ctx::SHA.SHA2_256_CTX, data)::UInt64
    ctx.state .= SHA.SHA2_256_initial_hash_value
    ctx.bytecount = 0
    ctx.used = false

    SHA.update!(ctx, data)
    SHA.pad_remainder!(ctx)
    pbuf = Ptr{typeof(ctx.bytecount)}(pointer(ctx.buffer))
    Base.unsafe_store!(pbuf, bswap(ctx.bytecount * 8), SHA256_BITCOUNT_IDX)
    SHA.transform!(ctx)

    return (UInt64(ctx.state[1]) << 32) | UInt64(ctx.state[2])
end

@inline function sha256_first_u64_commoncrypto!(digest::Vector{UInt8}, ptr::Ptr{UInt8}, nbytes::Cuint)::UInt64
    ccall((:CC_SHA256, "/usr/lib/system/libcommonCrypto.dylib"), Ptr{UInt8},
        (Ptr{UInt8}, Cuint, Ptr{UInt8}), ptr, nbytes, pointer(digest))
    return bswap(unsafe_load(Ptr{UInt64}(pointer(digest))))
end

@inline function run_once(values::KernelValues, sha_ctx::SHA.SHA2_256_CTX, digest::Vector{UInt8})::UInt64
    return run_iterations_single(values, 1, sha_ctx, digest)
end

@inline function run_iterations_single(values::KernelValues, iterations::Int, sha_ctx::SHA.SHA2_256_CTX, digest::Vector{UInt8})::UInt64
    ptrs = values.ptrs
    nbytes_c = values.nbytes_c
    nbytes_u64 = values.nbytes_u64
    owners = values.owners
    checksum = UInt64(0)
    @inbounds for _ in 1:iterations
        sink = UInt64(0)
        @simd for i in eachindex(ptrs)
            @static if USE_COMMONCRYPTO_SHA256
                acc = sha256_first_u64_commoncrypto!(digest, ptrs[i], nbytes_c[i])
            else
                acc = sha256_first_u64!(sha_ctx, owners[i])
            end
            sink += xor(acc, nbytes_u64[i])
        end
        checksum += sink
    end
    return checksum
end

function run_iterations(values::KernelValues, iterations::Int, states::Vector{HashThreadState}, partial_sums::Vector{UInt64})::UInt64
    worker_count = length(states)
    worker_count == length(partial_sums) || error("partial_sums length must match hash state count")

    if worker_count == 1
        s = states[1]
        return run_iterations_single(values, iterations, s.sha_ctx, s.digest)
    end

    fill!(partial_sums, 0)
    chunk = cld(iterations, worker_count)
    @sync for worker in 1:worker_count
        start_iter = (worker - 1) * chunk + 1
        end_iter = min(iterations, worker * chunk)
        start_iter > end_iter && continue

        state = states[worker]
        reps = end_iter - start_iter + 1
        Threads.@spawn begin
            partial_sums[worker] = run_iterations_single(values, reps, state.sha_ctx, state.digest)
        end
    end

    total = UInt64(0)
    @inbounds for i in 1:worker_count
        total += partial_sums[i]
    end
    return total
end

function main()
    vectors_dir = arg_value("--vectors-dir", "examples/contracts/canon_vectors")
    profile = arg_value("--profile", "base")
    iterations = arg_int("--iterations", 50_000)
    warmup = arg_int("--warmup", 5_000)

    base = load_base_vectors(vectors_dir)
    values = KernelValues(build_profile_values(profile, base))
    states = init_hash_states()
    partial_sums = zeros(UInt64, length(states))

    warmup_sink = run_iterations(values, warmup, states, partial_sums)

    start_ns = time_ns()
    checksum = warmup_sink + run_iterations(values, iterations, states, partial_sums)
    elapsed_ns = time_ns() - start_ns

    ops = iterations * length(values.owners)
    ops_per_sec = elapsed_ns == 0 ? 0.0 : (ops * 1_000_000_000.0) / elapsed_ns

    result = Dict(
        "language" => "julia",
        "profile" => profile,
        "vectors" => length(values.owners),
        "iterations" => iterations,
        "ops" => ops,
        "elapsed_ns" => elapsed_ns,
        "ops_per_sec" => ops_per_sec,
        "checksum" => string(checksum, base = 16, pad = 16),
    )
    println(JSON3.write(result))
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
