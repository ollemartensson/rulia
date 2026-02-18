use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::Value;
use rulia_ffi::{
    rulia_v1_bytes_free, rulia_v1_decode, rulia_v1_encode_canonical, rulia_v1_pw_compile_evalir_v0,
    rulia_v1_pw_evalir_run_v1, rulia_v1_pw_hash_subject_v0, rulia_v1_pw_match_capabilities_v0,
    rulia_v1_pw_receipt_signing_payload_v0, rulia_v1_pw_request_identity_v0,
    rulia_v1_pw_rules_desugar_sexpr_v0, rulia_v1_pw_verify_obligation_v0,
    rulia_v1_pw_verify_receipt_v0, rulia_v1_value_free, RuliaBytes, RuliaStatus,
};

type PwVerb =
    unsafe extern "C" fn(*const u8, usize, *mut RuliaBytes, *mut RuliaBytes) -> RuliaStatus;

struct FfiBytes {
    ptr: *mut u8,
    len: usize,
}

impl Drop for FfiBytes {
    fn drop(&mut self) {
        unsafe {
            rulia_v1_bytes_free(self.ptr, self.len);
        }
    }
}

fn canonical_nil_bytes() -> Vec<u8> {
    rulia::encode_canonical(&Value::Nil).expect("encode canonical nil")
}

fn take_output(bytes: RuliaBytes) -> Option<FfiBytes> {
    if bytes.ptr.is_null() {
        assert_eq!(bytes.len, 0);
        None
    } else {
        Some(FfiBytes {
            ptr: bytes.ptr,
            len: bytes.len,
        })
    }
}

fn assert_roundtrip_via_ffi_decode(bytes: &FfiBytes) {
    let decode = unsafe { rulia_v1_decode(bytes.ptr.cast_const(), bytes.len) };
    assert_eq!(decode.status, RuliaStatus::Ok);
    assert_ne!(decode.handle, 0);

    let encoded = unsafe { rulia_v1_encode_canonical(decode.handle) };
    assert_eq!(encoded.status, RuliaStatus::Ok);
    assert!(!encoded.ptr.is_null());

    let original_slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    let encoded_slice = unsafe { std::slice::from_raw_parts(encoded.ptr, encoded.len) };
    assert_eq!(encoded_slice, original_slice);

    unsafe {
        rulia_v1_bytes_free(encoded.ptr, encoded.len);
        rulia_v1_value_free(decode.handle);
    }
}

#[test]
fn pw_verbs_emit_canonical_bytes_roundtrippable_via_decode() {
    let input = canonical_nil_bytes();
    let verbs: [(&str, PwVerb); 9] = [
        ("hash_subject_v0", rulia_v1_pw_hash_subject_v0),
        ("request_identity_v0", rulia_v1_pw_request_identity_v0),
        ("rules_desugar_sexpr_v0", rulia_v1_pw_rules_desugar_sexpr_v0),
        ("compile_evalir_v0", rulia_v1_pw_compile_evalir_v0),
        ("evalir_run_v1", rulia_v1_pw_evalir_run_v1),
        ("verify_receipt_v0", rulia_v1_pw_verify_receipt_v0),
        ("verify_obligation_v0", rulia_v1_pw_verify_obligation_v0),
        ("match_capabilities_v0", rulia_v1_pw_match_capabilities_v0),
        (
            "receipt_signing_payload_v0",
            rulia_v1_pw_receipt_signing_payload_v0,
        ),
    ];

    for (name, verb) in verbs {
        let mut out_result = RuliaBytes {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let mut out_error_detail = RuliaBytes {
            ptr: ptr::null_mut(),
            len: 0,
        };

        let _status = unsafe {
            verb(
                input.as_ptr(),
                input.len(),
                &mut out_result,
                &mut out_error_detail,
            )
        };
        let result = take_output(out_result);
        let error_detail = take_output(out_error_detail);

        assert!(
            result.is_some() || error_detail.is_some(),
            "{name} returned neither result bytes nor error detail bytes"
        );

        if let Some(result) = &result {
            assert_roundtrip_via_ffi_decode(result);
        }
        if let Some(error_detail) = &error_detail {
            assert_roundtrip_via_ffi_decode(error_detail);
        }
    }
}
