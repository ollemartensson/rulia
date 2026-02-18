module Canon

using JSON3
using SHA
using Printf

export canon_json, sha256_hex

function sha256_hex(bytes::Vector{UInt8})::String
    return bytes2hex(sha256(bytes))
end

function _json_string_bytes(s::AbstractString)::Vector{UInt8}
    return Vector{UInt8}(JSON3.write(String(s)))
end

function _normalize_float(x::AbstractFloat)::String
    isfinite(x) || error("non-finite floats are not allowed in canonical scope")
    if x == 0
        return "0"
    end
    s = @sprintf("%.17g", Float64(x))
    s = replace(s, 'E' => 'e')
    if occursin('e', s)
        parts = split(s, 'e')
        mantissa = parts[1]
        exp = parts[2]
        exp = replace(exp, "+" => "")
        exp = replace(exp, r"^(-?)0+([0-9]+)$" => s"\1\2")
        return string(mantissa, "e", exp)
    end
    return s
end

function _write_canon(io::IO, x)
    if x === nothing
        write(io, "null")
    elseif x isa Bool
        write(io, x ? "true" : "false")
    elseif x isa Integer
        write(io, string(x))
    elseif x isa AbstractFloat
        write(io, _normalize_float(x))
    elseif x isa AbstractString
        write(io, _json_string_bytes(x))
    elseif x isa Symbol
        write(io, _json_string_bytes(String(x)))
    elseif x isa AbstractVector || x isa Tuple
        write(io, UInt8('['))
        first = true
        for v in x
            if !first
                write(io, UInt8(','))
            end
            first = false
            _write_canon(io, v)
        end
        write(io, UInt8(']'))
    elseif x isa Dict || x isa NamedTuple
        pairs_list = Pair{String, Any}[]
        for (k, v) in pairs(x)
            key = k isa String ? k : string(k)
            push!(pairs_list, key => v)
        end
        sort!(pairs_list; by = p -> p.first)
        write(io, UInt8('{'))
        first = true
        for (k, v) in pairs_list
            if !first
                write(io, UInt8(','))
            end
            first = false
            write(io, _json_string_bytes(k))
            write(io, UInt8(':'))
            _write_canon(io, v)
        end
        write(io, UInt8('}'))
    else
        error("unsupported type in canonical json: $(typeof(x))")
    end
end

function canon_json(x)::Vector{UInt8}
    io = IOBuffer()
    _write_canon(io, x)
    return take!(io)
end

end
