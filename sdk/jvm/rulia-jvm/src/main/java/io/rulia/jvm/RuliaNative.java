package io.rulia.jvm;

import jnr.ffi.Pointer;
import jnr.ffi.Runtime;
import jnr.ffi.Struct;

public interface RuliaNative {
    int rulia_ffi_abi_version();

    Pointer rulia_ffi_version_string();

    int rulia_v1_format_text(Pointer ptr, long len, RuliaBytes out);

    int rulia_v1_format_check(Pointer ptr, long len);

    int rulia_v1_frame_encode(Pointer payloadPtr, long payloadLen, RuliaBytes out);

    int rulia_v1_frame_encode_with_limit(Pointer payloadPtr, long payloadLen, int maxLen, RuliaBytes out);

    int rulia_v1_frame_decoder_new(int maxLen, Pointer outDecoder);

    void rulia_v1_frame_decoder_free(long decoder);

    int rulia_v1_frame_decoder_push(long decoder, Pointer ptr, long len, RuliaBytes outFrame,
                                    Pointer outConsumed);

    Pointer rulia_parse(Pointer input);

    Pointer rulia_parse_file(Pointer path);

    Pointer rulia_decode(Pointer bytes, long len);

    Pointer rulia_encode(Pointer value, Pointer outLen);

    Pointer rulia_encode_canonical(Pointer value, Pointer outLen);

    Pointer rulia_encode_with_digest(Pointer value, byte algorithm, Pointer outLen, Pointer digestOut);

    byte rulia_verify_digest(Pointer bytes, long len);

    Pointer rulia_to_string(Pointer value);

    Pointer rulia_kind(Pointer value);

    Pointer rulia_get_string(Pointer value);

    Pointer rulia_get_bigint(Pointer value);

    Pointer rulia_get_bytes(Pointer value, Pointer lenOut);

    boolean rulia_get_int(Pointer value, Pointer out);

    boolean rulia_get_uint(Pointer value, Pointer out);

    boolean rulia_get_float64(Pointer value, Pointer out);

    boolean rulia_get_float32(Pointer value, Pointer out);

    boolean rulia_get_bool(Pointer value, Pointer out);

    long rulia_vector_len(Pointer value);

    Pointer rulia_vector_get(Pointer value, long index);

    long rulia_set_len(Pointer value);

    Pointer rulia_set_get(Pointer value, long index);

    long rulia_map_len(Pointer value);

    Pointer rulia_map_get(Pointer value, Pointer key);

    Pointer rulia_map_keys(Pointer value);

    boolean rulia_map_entry_at(Pointer value, long index, Pointer outKey, Pointer outValue);

    Pointer rulia_keyword_name(Pointer value);

    Pointer rulia_keyword_namespace(Pointer value);

    Pointer rulia_symbol_name(Pointer value);

    Pointer rulia_symbol_namespace(Pointer value);

    Pointer rulia_tagged_tag(Pointer value);

    Pointer rulia_tagged_value(Pointer value);

    Pointer rulia_annotated_metadata(Pointer value);

    Pointer rulia_annotated_inner(Pointer value);

    void rulia_free(Pointer value);

    void rulia_bytes_free(Pointer ptr, long len);

    void rulia_string_free(Pointer ptr);

    void rulia_v1_bytes_free(Pointer ptr, long len);

    void rulia_v1_string_free(Pointer ptr);

    void rulia_v1_value_free(long handle);

    final class RuliaBytes extends Struct {
        public final Struct.Pointer ptr = new Struct.Pointer();
        public final size_t len = new size_t();

        public RuliaBytes(Runtime runtime) {
            super(runtime);
        }
    }
}
