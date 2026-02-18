module Rulia

using CodecZlib
using Downloads
using JSON
using Libdl
using SHA
using Tar

include("artifacts.jl")
include("ffi.jl")

export FrameDecoder
export EncodedWithDigest
export RuliaKeywordValue
export RuliaMapEntry
export RuliaRawValue
export RuliaError
export RuliaDigestAlgorithm
export RuliaSymbolValue
export RuliaStatus
export RuliaTaggedValue
export RuliaAnnotatedValue
export canonicalize_binary
export canonicalize_value_text
export decode_typed
export decode_text
export encode
export encode_canonical
export encode_with_digest
export format_check
export format_text
export frame_decoder_new
export frame_decoder_push!
export frame_encode
export has_valid_digest
export install_tools
export load_library
export parse_typed
export verify_digest

end
