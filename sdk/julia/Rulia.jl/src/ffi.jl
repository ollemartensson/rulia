const _lib_handle = Ref{Ptr{Nothing}}(C_NULL)
const _lib_path = Ref{String}("")

@enum RuliaStatus::Int32 begin
    RULIA_STATUS_OK = 0
    RULIA_STATUS_INVALID_ARGUMENT = 1
    RULIA_STATUS_PARSE_ERROR = 2
    RULIA_STATUS_DECODE_ERROR = 3
    RULIA_STATUS_VERIFY_ERROR = 4
    RULIA_STATUS_OUT_OF_MEMORY = 5
    RULIA_STATUS_INTERNAL_ERROR = 6
    RULIA_STATUS_FORMAT_INVALID_SYNTAX = 7
    RULIA_STATUS_FORMAT_NOT_CANONICAL = 8
    RULIA_STATUS_FRAMING_INVALID_LENGTH = 9
    RULIA_STATUS_FRAMING_TRUNCATED_HEADER = 10
    RULIA_STATUS_FRAMING_TRUNCATED_PAYLOAD = 11
    RULIA_STATUS_FRAMING_TOO_LARGE = 12
    RULIA_STATUS_FRAMING_OUTPUT_ERROR = 13
    RULIA_STATUS_FRAMING_NEED_MORE_DATA = 14
end

@enum RuliaDigestAlgorithm::UInt8 begin
    RULIA_DIGEST_SHA256 = 1
    RULIA_DIGEST_BLAKE3 = 2
end

struct RuliaError <: Exception
    status::RuliaStatus
    message::String
end

function Base.showerror(io::IO, err::RuliaError)
    print(io, err.message, " (", Int32(err.status), ": ", err.status, ")")
end

struct RuliaBytes
    ptr::Ptr{UInt8}
    len::UInt
end

struct RuliaHandleResult
    handle::UInt
    status::RuliaStatus
end

struct RuliaBytesResult
    ptr::Ptr{UInt8}
    len::UInt
    status::RuliaStatus
end

struct RuliaStringResult
    ptr::Ptr{Cchar}
    len::UInt
    status::RuliaStatus
end

struct EncodedWithDigest
    bytes::Vector{UInt8}
    digest::Vector{UInt8}
    algorithm::RuliaDigestAlgorithm
end

struct RuliaKeywordValue
    namespace::Union{Nothing,String}
    name::String
end

struct RuliaSymbolValue
    namespace::Union{Nothing,String}
    name::String
end

struct RuliaTaggedValue
    tag::RuliaSymbolValue
    value::Any
end

struct RuliaMapEntry
    key::Any
    value::Any
end

struct RuliaAnnotatedValue
    metadata::Vector{RuliaMapEntry}
    value::Any
end

struct RuliaRawValue
    kind::String
    text::String
end

struct FrameDecoder
    handle::UInt
end

function load_library(path::AbstractString)
    handle = Libdl.dlopen(String(path))
    _lib_handle[] = handle
    _lib_path[] = String(path)
    return handle
end

function lib_ref()
    path = _lib_path[]
    path == "" && error("Rulia shared library not loaded; call install_tools(...) or load_library(path)")
    return path
end

function legacy_symbol_available(symbol::Symbol)
    handle = _lib_handle[]
    handle == C_NULL && return false
    return Libdl.dlsym_e(handle, symbol) != C_NULL
end

function with_bytes(f::Function, text::String)
    data = Vector{UInt8}(codeunits(text))
    return f(pointer(data), Csize_t(length(data)))
end

function bytes_free(bytes::RuliaBytes)
    bytes.ptr == C_NULL && return
    ccall((:rulia_v1_bytes_free, lib_ref()), Cvoid, (Ptr{UInt8}, Csize_t), bytes.ptr, bytes.len)
    return
end

function bytes_to_vec(bytes::RuliaBytes)
    if bytes.ptr == C_NULL
        return UInt8[]
    end
    len = Int(bytes.len)
    vec = Vector{UInt8}(undef, len)
    try
        if len > 0
            unsafe_copyto!(pointer(vec), bytes.ptr, len)
        end
    finally
        bytes_free(bytes)
    end
    return vec
end

bytes_to_string(bytes::RuliaBytes) = String(bytes_to_vec(bytes))

function status_error(status::RuliaStatus, context::String)
    return RuliaError(status, context)
end

function value_free(handle::UInt)
    handle == 0 && return
    ccall((:rulia_v1_value_free, lib_ref()), Cvoid, (UInt,), handle)
    return
end

function parse_handle(text::String)
    result = ccall((:rulia_v1_parse, lib_ref()), RuliaHandleResult, (Cstring,), text)
    if result.status == RULIA_STATUS_OK
        return result.handle
    end
    throw(status_error(result.status, "parse failed"))
end

function decode_handle(bytes::AbstractVector{UInt8})
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    ptr = isempty(data) ? Ptr{UInt8}(C_NULL) : pointer(data)
    result = ccall((:rulia_v1_decode, lib_ref()), RuliaHandleResult,
        (Ptr{UInt8}, Csize_t), ptr, Csize_t(length(data)))
    if result.status == RULIA_STATUS_OK
        return result.handle
    end
    throw(status_error(result.status, "decode failed"))
end

function encode_handle(handle::UInt; canonical::Bool=false)
    result = if canonical
        ccall((:rulia_v1_encode_canonical, lib_ref()), RuliaBytesResult, (UInt,), handle)
    else
        ccall((:rulia_v1_encode, lib_ref()), RuliaBytesResult, (UInt,), handle)
    end
    if result.status == RULIA_STATUS_OK
        return bytes_to_vec(RuliaBytes(result.ptr, result.len))
    end
    bytes_free(RuliaBytes(result.ptr, result.len))
    throw(status_error(result.status, canonical ? "encode_canonical failed" : "encode failed"))
end

function to_text(handle::UInt)
    result = ccall((:rulia_v1_to_string, lib_ref()), RuliaStringResult, (UInt,), handle)
    if result.status == RULIA_STATUS_OK
        text = result.ptr == C_NULL ? "" : unsafe_string(result.ptr, Int(result.len))
        if result.ptr != C_NULL
            ccall((:rulia_v1_string_free, lib_ref()), Cvoid, (Ptr{Cchar},), result.ptr)
        end
        return text
    end
    if result.ptr != C_NULL
        ccall((:rulia_v1_string_free, lib_ref()), Cvoid, (Ptr{Cchar},), result.ptr)
    end
    throw(status_error(result.status, "to_text failed"))
end

function with_parsed_value(text::String, f::Function)
    handle = parse_handle(text)
    try
        return f(handle)
    finally
        value_free(handle)
    end
end

function with_decoded_value(bytes::AbstractVector{UInt8}, f::Function)
    handle = decode_handle(bytes)
    try
        return f(handle)
    finally
        value_free(handle)
    end
end

function parse_legacy_value(text::String)
    value = ccall((:rulia_parse, lib_ref()), Ptr{Nothing}, (Cstring,), text)
    if value == C_NULL
        throw(status_error(RULIA_STATUS_PARSE_ERROR, "parse failed"))
    end
    return value
end

function value_free_legacy(value::Ptr{Nothing})
    value == C_NULL && return
    ccall((:rulia_free, lib_ref()), Cvoid, (Ptr{Nothing},), value)
    return
end

function string_free_legacy(ptr::Ptr{Cchar})
    ptr == C_NULL && return
    ccall((:rulia_string_free, lib_ref()), Cvoid, (Ptr{Cchar},), ptr)
    return
end

function bytes_free_legacy(ptr::Ptr{UInt8}, len::Csize_t)
    ptr == C_NULL && return
    ccall((:rulia_bytes_free, lib_ref()), Cvoid, (Ptr{UInt8}, Csize_t), ptr, len)
    return
end

function take_string_legacy(ptr::Ptr{Cchar})
    ptr == C_NULL && return nothing
    try
        return unsafe_string(ptr)
    finally
        string_free_legacy(ptr)
    end
end

function take_bytes_legacy(ptr::Ptr{UInt8}, len::Csize_t)
    ptr == C_NULL && return UInt8[]
    length = Int(len)
    out = Vector{UInt8}(undef, length)
    try
        if length > 0
            unsafe_copyto!(pointer(out), ptr, length)
        end
    finally
        bytes_free_legacy(ptr, len)
    end
    return out
end

function decode_legacy_value(bytes::AbstractVector{UInt8})
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    ptr = isempty(data) ? Ptr{UInt8}(C_NULL) : pointer(data)
    value = ccall((:rulia_decode, lib_ref()), Ptr{Nothing}, (Ptr{UInt8}, Csize_t), ptr, Csize_t(length(data)))
    if value == C_NULL
        throw(status_error(RULIA_STATUS_DECODE_ERROR, "decode failed"))
    end
    return value
end

function value_kind_legacy(value::Ptr{Nothing})
    kind_ptr = ccall((:rulia_kind, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
    kind_ptr == C_NULL && return "unknown"
    return unsafe_string(kind_ptr)
end

function value_from_legacy_owned(value::Ptr{Nothing})
    value == C_NULL && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "null legacy value"))
    try
        return value_from_legacy(value)
    finally
        value_free_legacy(value)
    end
end

function value_from_legacy(value::Ptr{Nothing})
    kind = value_kind_legacy(value)
    if kind == "nil"
        return nothing
    elseif kind == "bool"
        out = Ref{UInt8}(0)
        ok = ccall((:rulia_get_bool, lib_ref()), UInt8, (Ptr{Nothing}, Ref{UInt8}), value, out)
        ok == 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "bool extraction failed"))
        return out[] != 0
    elseif kind == "int"
        out = Ref{Int64}(0)
        ok = ccall((:rulia_get_int, lib_ref()), UInt8, (Ptr{Nothing}, Ref{Int64}), value, out)
        ok == 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "int extraction failed"))
        return out[]
    elseif kind == "uint"
        out = Ref{UInt64}(0)
        ok = ccall((:rulia_get_uint, lib_ref()), UInt8, (Ptr{Nothing}, Ref{UInt64}), value, out)
        ok == 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "uint extraction failed"))
        return out[]
    elseif kind == "bigint"
        if !legacy_symbol_available(:rulia_get_bigint)
            text_ptr = ccall((:rulia_to_string, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
            text = take_string_legacy(text_ptr)
            text === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "fallback stringify failed"))
            return RuliaRawValue(kind, text)
        end
        ptr = ccall((:rulia_get_bigint, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        text = take_string_legacy(ptr)
        text === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "bigint extraction failed"))
        return parse(BigInt, text)
    elseif kind == "f32"
        out = Ref{Float32}(0)
        ok = ccall((:rulia_get_float32, lib_ref()), UInt8, (Ptr{Nothing}, Ref{Float32}), value, out)
        ok == 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "f32 extraction failed"))
        return out[]
    elseif kind == "f64"
        out = Ref{Float64}(0)
        ok = ccall((:rulia_get_float64, lib_ref()), UInt8, (Ptr{Nothing}, Ref{Float64}), value, out)
        ok == 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "f64 extraction failed"))
        return out[]
    elseif kind == "string"
        ptr = ccall((:rulia_get_string, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        result = take_string_legacy(ptr)
        result === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "string extraction failed"))
        return result
    elseif kind == "bytes"
        len_out = Ref{Csize_t}(0)
        ptr = ccall((:rulia_get_bytes, lib_ref()), Ptr{UInt8}, (Ptr{Nothing}, Ref{Csize_t}), value, len_out)
        ptr == C_NULL && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "bytes extraction failed"))
        return take_bytes_legacy(ptr, len_out[])
    elseif kind == "keyword"
        name_ptr = ccall((:rulia_keyword_name, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        name = take_string_legacy(name_ptr)
        name === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "keyword extraction failed"))
        namespace_ptr = ccall((:rulia_keyword_namespace, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        namespace = take_string_legacy(namespace_ptr)
        return RuliaKeywordValue(namespace, name)
    elseif kind == "symbol"
        name_ptr = ccall((:rulia_symbol_name, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        name = take_string_legacy(name_ptr)
        name === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "symbol extraction failed"))
        namespace_ptr = ccall((:rulia_symbol_namespace, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        namespace = take_string_legacy(namespace_ptr)
        return RuliaSymbolValue(namespace, name)
    elseif kind == "vector"
        len = ccall((:rulia_vector_len, lib_ref()), Clong, (Ptr{Nothing},), value)
        len < 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "vector length failed"))
        items = Any[]
        if len > 0
            for index in 0:(Int(len)-1)
                child = ccall((:rulia_vector_get, lib_ref()), Ptr{Nothing}, (Ptr{Nothing}, Csize_t), value, Csize_t(index))
                push!(items, value_from_legacy_owned(child))
            end
        end
        return items
    elseif kind == "set"
        len = ccall((:rulia_set_len, lib_ref()), Clong, (Ptr{Nothing},), value)
        len < 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "set length failed"))
        items = Any[]
        if len > 0
            for index in 0:(Int(len)-1)
                child = ccall((:rulia_set_get, lib_ref()), Ptr{Nothing}, (Ptr{Nothing}, Csize_t), value, Csize_t(index))
                push!(items, value_from_legacy_owned(child))
            end
        end
        return items
    elseif kind == "map"
        len = ccall((:rulia_map_len, lib_ref()), Clong, (Ptr{Nothing},), value)
        len < 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "map length failed"))
        entries = Vector{RuliaMapEntry}()
        if len > 0
            for index in 0:(Int(len)-1)
                key_ptr = Ref{Ptr{Nothing}}(C_NULL)
                value_ptr = Ref{Ptr{Nothing}}(C_NULL)
                ok = ccall((:rulia_map_entry_at, lib_ref()), UInt8,
                    (Ptr{Nothing}, Csize_t, Ref{Ptr{Nothing}}, Ref{Ptr{Nothing}}),
                    value, Csize_t(index), key_ptr, value_ptr)
                ok == 0 && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "map entry extraction failed"))
                key = value_from_legacy_owned(key_ptr[])
                item = value_from_legacy_owned(value_ptr[])
                push!(entries, RuliaMapEntry(key, item))
            end
        end
        return entries
    elseif kind == "tagged"
        tag_ptr = ccall((:rulia_tagged_tag, lib_ref()), Ptr{Nothing}, (Ptr{Nothing},), value)
        payload_ptr = ccall((:rulia_tagged_value, lib_ref()), Ptr{Nothing}, (Ptr{Nothing},), value)
        tag_value = value_from_legacy_owned(tag_ptr)
        payload = value_from_legacy_owned(payload_ptr)
        tag_value isa RuliaSymbolValue || throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "tagged tag is not symbol"))
        return RuliaTaggedValue(tag_value, payload)
    elseif kind == "annotated"
        if !legacy_symbol_available(:rulia_annotated_metadata) || !legacy_symbol_available(:rulia_annotated_inner)
            text_ptr = ccall((:rulia_to_string, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
            text = take_string_legacy(text_ptr)
            text === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "fallback stringify failed"))
            return RuliaRawValue(kind, text)
        end
        metadata_ptr = ccall((:rulia_annotated_metadata, lib_ref()), Ptr{Nothing}, (Ptr{Nothing},), value)
        payload_ptr = ccall((:rulia_annotated_inner, lib_ref()), Ptr{Nothing}, (Ptr{Nothing},), value)
        metadata_value = value_from_legacy_owned(metadata_ptr)
        payload = value_from_legacy_owned(payload_ptr)
        metadata_value isa Vector{RuliaMapEntry} || throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "annotated metadata is not map"))
        return RuliaAnnotatedValue(metadata_value, payload)
    else
        text_ptr = ccall((:rulia_to_string, lib_ref()), Ptr{Cchar}, (Ptr{Nothing},), value)
        text = take_string_legacy(text_ptr)
        text === nothing && throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "fallback stringify failed"))
        return RuliaRawValue(kind, text)
    end
end

function parse_typed(text::String)
    value = parse_legacy_value(text)
    return value_from_legacy_owned(value)
end

function decode_typed(bytes::AbstractVector{UInt8})
    value = decode_legacy_value(bytes)
    return value_from_legacy_owned(value)
end

function format_text(text::String)
    out = Ref{RuliaBytes}(RuliaBytes(Ptr{UInt8}(C_NULL), 0))
    status = with_bytes(text) do ptr, len
        RuliaStatus(ccall((:rulia_v1_format_text, lib_ref()), Int32,
            (Ptr{UInt8}, Csize_t, Ref{RuliaBytes}), ptr, len, out))
    end

    if status == RULIA_STATUS_OK
        return bytes_to_string(out[])
    end

    bytes_free(out[])
    throw(status_error(status, "format_text failed"))
end

function format_check(text::String)
    status = with_bytes(text) do ptr, len
        RuliaStatus(ccall((:rulia_v1_format_check, lib_ref()), Int32,
            (Ptr{UInt8}, Csize_t), ptr, len))
    end

    if status == RULIA_STATUS_OK
        return true
    elseif status == RULIA_STATUS_FORMAT_NOT_CANONICAL
        return false
    end
    throw(status_error(status, "format_check failed"))
end

function encode(text::String; canonical::Bool=false)
    return with_parsed_value(text) do handle
        encode_handle(handle; canonical=canonical)
    end
end

encode_canonical(text::String) = encode(text; canonical=true)

function decode_text(bytes::AbstractVector{UInt8})
    return with_decoded_value(bytes) do handle
        to_text(handle)
    end
end

function canonicalize_binary(bytes::AbstractVector{UInt8})
    return with_decoded_value(bytes) do handle
        encode_handle(handle; canonical=true)
    end
end

function canonicalize_value_text(text::String)
    return with_parsed_value(text) do handle
        to_text(handle)
    end
end

function encode_with_digest(text::String; algorithm::RuliaDigestAlgorithm=RULIA_DIGEST_SHA256)
    value = parse_legacy_value(text)
    try
        out_len = Ref{Csize_t}(0)
        digest = Vector{UInt8}(undef, 32)
        ptr = ccall((:rulia_encode_with_digest, lib_ref()), Ptr{UInt8},
            (Ptr{Nothing}, UInt8, Ref{Csize_t}, Ptr{UInt8}),
            value, UInt8(algorithm), out_len, pointer(digest))
        if ptr == C_NULL
            throw(status_error(RULIA_STATUS_INTERNAL_ERROR, "encode_with_digest failed"))
        end
        bytes = bytes_to_vec(RuliaBytes(ptr, UInt(out_len[])))
        return EncodedWithDigest(bytes, digest, algorithm)
    finally
        value_free_legacy(value)
    end
end

function verify_digest(bytes::AbstractVector{UInt8})
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    ptr = isempty(data) ? Ptr{UInt8}(C_NULL) : pointer(data)
    algorithm = ccall((:rulia_verify_digest, lib_ref()), UInt8,
        (Ptr{UInt8}, Csize_t), ptr, Csize_t(length(data)))
    if algorithm == UInt8(RULIA_DIGEST_SHA256)
        return RULIA_DIGEST_SHA256
    elseif algorithm == UInt8(RULIA_DIGEST_BLAKE3)
        return RULIA_DIGEST_BLAKE3
    end
    return nothing
end

has_valid_digest(bytes::AbstractVector{UInt8}) = !isnothing(verify_digest(bytes))

function frame_encode(payload::AbstractVector{UInt8})
    payload_vec = payload isa Vector{UInt8} ? payload : Vector{UInt8}(payload)
    out = Ref{RuliaBytes}(RuliaBytes(Ptr{UInt8}(C_NULL), 0))
    ptr = isempty(payload_vec) ? Ptr{UInt8}(C_NULL) : pointer(payload_vec)
    status = RuliaStatus(ccall((:rulia_v1_frame_encode, lib_ref()), Int32,
        (Ptr{UInt8}, Csize_t, Ref{RuliaBytes}), ptr, Csize_t(length(payload_vec)), out))

    if status == RULIA_STATUS_OK
        return bytes_to_vec(out[])
    end

    bytes_free(out[])
    throw(status_error(status, "frame_encode failed"))
end

function frame_decoder_new(max_len::Integer)
    handle = Ref{UInt}(0)
    status = RuliaStatus(ccall((:rulia_v1_frame_decoder_new, lib_ref()), Int32,
        (UInt32, Ref{UInt}), UInt32(max_len), handle))
    if status != RULIA_STATUS_OK
        throw(status_error(status, "frame_decoder_new failed"))
    end
    return FrameDecoder(handle[])
end

function frame_decoder_free(decoder::FrameDecoder)
    if decoder.handle != 0
        ccall((:rulia_v1_frame_decoder_free, lib_ref()), Cvoid, (UInt,), decoder.handle)
    end
    return
end

function frame_decoder_push!(decoder::FrameDecoder, bytes::AbstractVector{UInt8})
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    out = Ref{RuliaBytes}(RuliaBytes(Ptr{UInt8}(C_NULL), 0))
    consumed = Ref{Csize_t}(0)
    ptr = isempty(data) ? Ptr{UInt8}(C_NULL) : pointer(data)
    status = RuliaStatus(ccall((:rulia_v1_frame_decoder_push, lib_ref()), Int32,
        (UInt, Ptr{UInt8}, Csize_t, Ref{RuliaBytes}, Ref{Csize_t}),
        decoder.handle, ptr, Csize_t(length(data)), out, consumed))

    frames = Vector{Vector{UInt8}}()
    if status == RULIA_STATUS_OK
        push!(frames, bytes_to_vec(out[]))
    elseif status == RULIA_STATUS_FRAMING_NEED_MORE_DATA
        # no frame yet
    else
        bytes_free(out[])
        throw(status_error(status, "frame_decoder_push failed"))
    end

    return (frames, Int(consumed[]), status == RULIA_STATUS_FRAMING_NEED_MORE_DATA, isempty(data))
end
