#ifndef RULIA_FFI_V1_H
#define RULIA_FFI_V1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// ABI Version
// ============================================================================

#define RULIA_FFI_ABI_VERSION 1u
#define RULIA_FFI_VERSION_STRING "rulia-ffi-abi-v1"

// Returns the ABI version supported by this library.
uint32_t rulia_ffi_abi_version(void);

// Returns a static, null-terminated version string for diagnostics.
// The returned pointer is owned by the library and must not be freed.
const char *rulia_ffi_version_string(void);

// ============================================================================
// Status Codes
// ============================================================================

typedef enum rulia_status_t {
  RULIA_STATUS_OK = 0,
  RULIA_STATUS_INVALID_ARGUMENT = 1,
  RULIA_STATUS_PARSE_ERROR = 2,
  RULIA_STATUS_DECODE_ERROR = 3,
  RULIA_STATUS_VERIFY_ERROR = 4,
  RULIA_STATUS_OUT_OF_MEMORY = 5,
  RULIA_STATUS_INTERNAL_ERROR = 6,
  RULIA_STATUS_FORMAT_INVALID_SYNTAX = 7,
  RULIA_STATUS_FORMAT_NOT_CANONICAL = 8,
  RULIA_STATUS_FRAMING_INVALID_LENGTH = 9,
  RULIA_STATUS_FRAMING_TRUNCATED_HEADER = 10,
  RULIA_STATUS_FRAMING_TRUNCATED_PAYLOAD = 11,
  RULIA_STATUS_FRAMING_TOO_LARGE = 12,
  RULIA_STATUS_FRAMING_OUTPUT_ERROR = 13,
  RULIA_STATUS_FRAMING_NEED_MORE_DATA = 14,
} rulia_status_t;

typedef rulia_status_t rulia_v1_status_t;

// ============================================================================
// Result Types
// ============================================================================

typedef uintptr_t rulia_handle_t;

// Owned byte buffer (ptr + len) allocated by the FFI.
typedef struct rulia_v1_bytes_t {
  uint8_t *ptr;
  size_t len;
} rulia_v1_bytes_t;

// Owned byte buffer result. On failure, ptr is NULL and len is 0.
typedef struct rulia_bytes_result_t {
  uint8_t *ptr;
  size_t len;
  rulia_status_t status;
} rulia_bytes_result_t;

// Owned handle result. On failure, handle is 0.
typedef struct rulia_handle_result_t {
  rulia_handle_t handle;
  rulia_status_t status;
} rulia_handle_result_t;

// Owned string result. len excludes the trailing NUL. On failure, ptr is NULL.
typedef struct rulia_string_result_t {
  char *ptr;
  size_t len;
  rulia_status_t status;
} rulia_string_result_t;

// ============================================================================
// Ownership and Lifetime Rules
// ============================================================================
// - Handles are opaque tokens owned by the caller and must be released with
//   rulia_v1_value_free (value handles) or rulia_v1_reader_free (reader handles).
// - Byte buffers returned by the FFI are owned by the caller and must be
//   released with rulia_v1_bytes_free using the returned ptr and len.
// - Strings returned by the FFI are owned by the caller and must be released
//   with rulia_v1_string_free. len excludes the trailing NUL.
// - Input buffers are treated as immutable; the runtime does not mutate them.
// - Reader/value handles created from rulia_v1_reader_new borrow the caller
//   buffer; the caller must keep that buffer alive while any reader/value
//   handles exist. Borrowed slices returned by rulia_v1_value_as_* become
//   invalid after rulia_v1_reader_free.
// - Version strings returned by rulia_ffi_version_string are static and must
//   not be freed.

// ============================================================================
// ABI v1 API
// ============================================================================

// Parse a UTF-8 text buffer into a value handle.
// On success, returns status OK and a non-zero handle.
// On failure, returns a non-OK status and handle 0.
rulia_handle_result_t rulia_v1_parse(const char *input);

// Decode binary bytes into a value handle.
// On success, returns status OK and a non-zero handle.
// On failure, returns a non-OK status and handle 0.
rulia_handle_result_t rulia_v1_decode(const uint8_t *bytes, size_t len);

// Create a zero-copy reader over a caller-owned buffer.
// On success, returns status OK and writes a non-zero handle to out_reader.
// The caller must keep the buffer alive while any reader/value handles exist.
rulia_status_t rulia_v1_reader_new(const uint8_t *ptr, size_t len,
                                   rulia_handle_t *out_reader);

// Free a zero-copy reader handle.
void rulia_v1_reader_free(rulia_handle_t reader);

// Get the root value handle from a reader.
// On success, returns status OK and writes a non-zero handle to out_value.
rulia_status_t rulia_v1_reader_root(rulia_handle_t reader,
                                    rulia_handle_t *out_value);

// Get the kind of a value handle (TypeTag as uint16_t).
rulia_status_t rulia_v1_value_kind(rulia_handle_t value, uint16_t *out_kind);

// Borrow a UTF-8 string slice from a value handle.
// On success, out_ptr/out_len point into the caller buffer and are not NUL-terminated.
rulia_status_t rulia_v1_value_as_string(rulia_handle_t value,
                                        const uint8_t **out_ptr,
                                        size_t *out_len);

// Borrow a bytes slice from a value handle.
// On success, out_ptr/out_len point into the caller buffer.
rulia_status_t rulia_v1_value_as_bytes(rulia_handle_t value,
                                       const uint8_t **out_ptr,
                                       size_t *out_len);

// Encode a value handle to its binary representation.
// On success, returns status OK and an owned byte buffer.
rulia_bytes_result_t rulia_v1_encode(rulia_handle_t handle);

// Encode a value handle to canonical binary representation.
// On success, returns status OK and an owned byte buffer.
rulia_bytes_result_t rulia_v1_encode_canonical(rulia_handle_t handle);

// Convert a value handle to its text representation.
// On success, returns status OK and an owned null-terminated string.
rulia_string_result_t rulia_v1_to_string(rulia_handle_t handle);

// Format UTF-8 text to canonical form.
// On success, returns status OK and an owned byte buffer.
rulia_status_t rulia_v1_format_text(const uint8_t *ptr, size_t len,
                                    rulia_v1_bytes_t *out);

// Check whether UTF-8 text is canonical.
// Returns OK if canonical, FORMAT_NOT_CANONICAL if not, FORMAT_INVALID_SYNTAX
// on parse error.
rulia_status_t rulia_v1_format_check(const uint8_t *ptr, size_t len);

// Encode a payload into a framed stream buffer (u32le length prefix).
// Returns FRAMING_INVALID_LENGTH for len==0 or FRAMING_TOO_LARGE if len exceeds
// the default maximum (64 MiB).
rulia_status_t rulia_v1_frame_encode(const uint8_t *payload_ptr,
                                     size_t payload_len,
                                     rulia_v1_bytes_t *out);

// Encode a payload into a framed stream buffer with a custom length limit.
rulia_status_t rulia_v1_frame_encode_with_limit(const uint8_t *payload_ptr,
                                                size_t payload_len,
                                                uint32_t max_len,
                                                rulia_v1_bytes_t *out);

// Create a frame decoder for incremental stream decoding.
rulia_status_t rulia_v1_frame_decoder_new(uint32_t max_len,
                                          rulia_handle_t *out_decoder);

// Free a frame decoder handle.
void rulia_v1_frame_decoder_free(rulia_handle_t decoder);

// Push bytes into a frame decoder.
// Returns OK with an owned payload buffer when a frame is complete.
// Returns FRAMING_NEED_MORE_DATA if the frame is incomplete.
// Passing len==0 signals end-of-stream and may return truncated status codes.
rulia_status_t rulia_v1_frame_decoder_push(rulia_handle_t decoder,
                                           const uint8_t *ptr, size_t len,
                                           rulia_v1_bytes_t *out_frame,
                                           size_t *out_consumed);

// ADD BELOW: rulia_v1_frame_decoder_push(...) declaration.
// ============================================================================
// Portable Workflow Semantic Kernel (ABI v1 additive)
// ============================================================================
// Common contract for all rulia_v1_pw_* verbs:
// - input_ptr/input_len are borrowed for the duration of the call (immutable).
// - out_result is required and receives owned canonical result bytes on OK.
// - out_error_detail is optional; when non-NULL, it receives owned canonical
//   FfiErrorDetailV0 bytes on non-OK status and empty bytes on OK.
// - Caller frees any returned bytes with rulia_v1_bytes_free(ptr, len).

// Hash canonical subject bytes into HashSubjectResultV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_hash_subject_v0(const uint8_t *input_ptr,
                                           size_t input_len,
                                           rulia_v1_bytes_t *out_result,
                                           rulia_v1_bytes_t *out_error_detail);

// Derive request identity into RequestIdentityOutputV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_request_identity_v0(const uint8_t *input_ptr,
                                               size_t input_len,
                                               rulia_v1_bytes_t *out_result,
                                               rulia_v1_bytes_t *out_error_detail);

// Desugar rules sexpr text to canonical rules in RulesDesugarResultV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_rules_desugar_sexpr_v0(const uint8_t *input_ptr,
                                                  size_t input_len,
                                                  rulia_v1_bytes_t *out_result,
                                                  rulia_v1_bytes_t *out_error_detail);

// Compile canonical artifact subset into CompileEvalIRResultV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_compile_evalir_v0(const uint8_t *input_ptr,
                                             size_t input_len,
                                             rulia_v1_bytes_t *out_result,
                                             rulia_v1_bytes_t *out_error_detail);

// Run EvalIR to boundary and return EvalRunResultV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_evalir_run_v1(const uint8_t *input_ptr,
                                         size_t input_len,
                                         rulia_v1_bytes_t *out_result,
                                         rulia_v1_bytes_t *out_error_detail);

// Verify receipt and return VerifierResultV0(subject=:receipt).
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_verify_receipt_v0(const uint8_t *input_ptr,
                                             size_t input_len,
                                             rulia_v1_bytes_t *out_result,
                                             rulia_v1_bytes_t *out_error_detail);

// Verify obligation and return VerifierResultV0(subject=:obligation).
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_verify_obligation_v0(const uint8_t *input_ptr,
                                                size_t input_len,
                                                rulia_v1_bytes_t *out_result,
                                                rulia_v1_bytes_t *out_error_detail);

// Match capabilities and return MatchCapResultV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_match_capabilities_v0(const uint8_t *input_ptr,
                                                 size_t input_len,
                                                 rulia_v1_bytes_t *out_result,
                                                 rulia_v1_bytes_t *out_error_detail);

// Build receipt bytes-to-sign payload in ReceiptSigningPayloadResultV0.
// Borrowed input bytes; caller owns out_result/out_error_detail buffers.
rulia_status_t rulia_v1_pw_receipt_signing_payload_v0(
    const uint8_t *input_ptr, size_t input_len, rulia_v1_bytes_t *out_result,
    rulia_v1_bytes_t *out_error_detail);
// ADD ABOVE: // Free Functions (ABI v1)

// ============================================================================
// Free Functions (ABI v1)
// ============================================================================

// Free a value handle returned by rulia_v1_parse, rulia_v1_decode, or
// rulia_v1_reader_root.
void rulia_v1_value_free(rulia_handle_t handle);
void rulia_v1_bytes_free(uint8_t *ptr, size_t len);
void rulia_v1_string_free(char *ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // RULIA_FFI_V1_H
