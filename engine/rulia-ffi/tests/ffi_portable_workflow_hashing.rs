use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::{Keyword, Symbol, TaggedValue, Value};
use rulia_ffi::{
    rulia_v1_bytes_free, rulia_v1_pw_compute_args_hash_v0, rulia_v1_pw_compute_request_key_v0,
    RuliaBytes, RuliaStatus,
};

const EXPECTED_ARGS_HASH_HEX: &str =
    "64d425b5611a981e0b6a95e45749dcec0d0ab47845165ecdf84558553a7232db";
const EXPECTED_REQUEST_KEY_HEX: &str =
    "5b4094beb6739b2dfcf1f60967d475eb1f5e2e0cd296faa61e80e8b2a9101a68";
const FAILURE_CODE_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";

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

fn kw(name: &str) -> Value {
    Value::Keyword(Keyword::simple(name))
}

fn digest_value(hex: &str) -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("digest"),
        Value::Map(vec![
            (kw("alg"), kw("sha256")),
            (kw("hex"), Value::String(hex.to_string())),
        ]),
    ))
}

fn request_args_canonical_v0_value() -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("request_args_canonical_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_request_args_canonical_v0")),
            (kw("capability_id"), kw("approval_service")),
            (kw("capability_version"), Value::String("v1".to_string())),
            (kw("operation"), kw("submit")),
            (
                kw("input"),
                Value::Map(vec![
                    (
                        kw("payload_hash"),
                        digest_value(
                            "1111111111111111111111111111111111111111111111111111111111111111",
                        ),
                    ),
                    (kw("payload_embed"), Value::Nil),
                    (kw("payload_embed_redaction_class"), kw("hash_only")),
                    (kw("payload_bytes"), Value::UInt(0)),
                ]),
            ),
            (kw("expected_receipt_schema_ref"), Value::Nil),
            (
                kw("policy"),
                Value::Map(vec![
                    (
                        kw("capability_allowlist"),
                        Value::Vector(vec![kw("approval_service")]),
                    ),
                    (kw("operation_allowlist"), Value::Vector(vec![kw("submit")])),
                    (kw("redaction_class"), kw("hash_only")),
                    (kw("max_output_bytes"), Value::UInt(1024)),
                    (kw("pii_class"), kw("none")),
                    (kw("allow_embedded_receipt_payload"), Value::Bool(false)),
                ]),
            ),
        ]),
    ))
}

fn request_seed_v0_value(args_hash_hex: &str) -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("request_seed_v0"),
        Value::Map(vec![
            (
                kw("artifact_hash"),
                digest_value("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
            (kw("step_id"), Value::String("S0003".to_string())),
            (kw("request_ordinal"), Value::UInt(1)),
            (kw("args_hash"), digest_value(args_hash_hex)),
            (kw("history_cursor"), Value::Nil),
            (kw("process_id"), Value::Nil),
        ]),
    ))
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let expected_key = kw(key);
    for (entry_key, entry_value) in entries {
        if *entry_key == expected_key {
            return Some(entry_value);
        }
    }
    None
}

fn key_name(value: &Value) -> String {
    match value {
        Value::Keyword(keyword) => keyword.name().to_string(),
        Value::String(raw) => raw.clone(),
        _ => panic!("map key must be keyword/string"),
    }
}

fn assert_exact_keys(entries: &[(Value, Value)], expected: &[&str]) {
    let mut actual = entries
        .iter()
        .map(|(key, _)| key_name(key))
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected_sorted = expected
        .iter()
        .map(|key| key.to_string())
        .collect::<Vec<_>>();
    expected_sorted.sort();
    assert_eq!(actual, expected_sorted);
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    rulia::encode_canonical(value).expect("encode canonical")
}

fn noncanonical_bytes(value: &Value) -> Vec<u8> {
    rulia::encode_value(value).expect("encode non-canonical")
}

fn decode_ffi_bytes(bytes: &FfiBytes) -> Value {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    rulia::decode_value(slice).expect("decode ffi bytes")
}

fn decode_digest_hex(bytes: &FfiBytes) -> String {
    let digest = decode_ffi_bytes(bytes);
    let Value::Tagged(tagged) = digest else {
        panic!("expected tagged digest");
    };
    assert_eq!(tagged.tag.as_str(), "digest");

    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected digest map payload");
    };
    let Some(Value::Keyword(alg)) = map_get(entries, "alg") else {
        panic!("expected digest alg");
    };
    assert_eq!(alg.name(), "sha256");
    let Some(Value::String(hex)) = map_get(entries, "hex") else {
        panic!("expected digest hex");
    };
    hex.clone()
}

fn decode_failure_codes(bytes: &FfiBytes) -> Vec<String> {
    let detail = decode_ffi_bytes(bytes);
    let Value::Tagged(tagged) = detail else {
        panic!("expected tagged FfiErrorDetailV0");
    };
    assert_eq!(tagged.tag.as_str(), "ffi_error_detail_v0");

    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected FfiErrorDetailV0 map payload");
    };

    assert_exact_keys(
        entries,
        &[
            "format",
            "verb",
            "status",
            "primary_failure_code",
            "failure_codes",
            "failure_path",
            "limit",
        ],
    );

    let Some(Value::Vector(failure_codes)) = map_get(entries, "failure_codes") else {
        panic!("expected failure_codes vector");
    };
    failure_codes
        .iter()
        .map(|value| match value {
            Value::String(value) => value.clone(),
            _ => panic!("expected failure_code string"),
        })
        .collect()
}

#[test]
fn compute_args_hash_v0_returns_expected_digest() {
    let input = canonical_bytes(&request_args_canonical_v0_value());

    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_compute_args_hash_v0(
            input.as_ptr(),
            input.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    assert_eq!(status, RuliaStatus::Ok);
    assert!(!out_result.ptr.is_null());
    assert!(out_error_detail.ptr.is_null());
    assert_eq!(out_error_detail.len, 0);

    let result_bytes = FfiBytes {
        ptr: out_result.ptr,
        len: out_result.len,
    };
    let digest_hex = decode_digest_hex(&result_bytes);
    assert_eq!(digest_hex, EXPECTED_ARGS_HASH_HEX);
}

#[test]
fn compute_request_key_v0_returns_expected_digest() {
    let input = canonical_bytes(&request_seed_v0_value(EXPECTED_ARGS_HASH_HEX));

    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_compute_request_key_v0(
            input.as_ptr(),
            input.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    assert_eq!(status, RuliaStatus::Ok);
    assert!(!out_result.ptr.is_null());
    assert!(out_error_detail.ptr.is_null());
    assert_eq!(out_error_detail.len, 0);

    let result_bytes = FfiBytes {
        ptr: out_result.ptr,
        len: out_result.len,
    };
    let digest_hex = decode_digest_hex(&result_bytes);
    assert_eq!(digest_hex, EXPECTED_REQUEST_KEY_HEX);
}

#[test]
fn compute_args_hash_v0_invalid_bytes_report_schema_mismatch() {
    let input = [0xffu8, 0x10, 0x00, 0x01];

    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_compute_args_hash_v0(
            input.as_ptr(),
            input.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(out_result.ptr.is_null());
    assert!(!out_error_detail.ptr.is_null());

    let error_bytes = FfiBytes {
        ptr: out_error_detail.ptr,
        len: out_error_detail.len,
    };
    let failure_codes = decode_failure_codes(&error_bytes);
    assert_eq!(
        failure_codes,
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn compute_request_key_v0_invalid_bytes_report_schema_mismatch() {
    let input = [0x01u8, 0x02, 0x03, 0x04];

    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_compute_request_key_v0(
            input.as_ptr(),
            input.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(out_result.ptr.is_null());
    assert!(!out_error_detail.ptr.is_null());

    let error_bytes = FfiBytes {
        ptr: out_error_detail.ptr,
        len: out_error_detail.len,
    };
    let failure_codes = decode_failure_codes(&error_bytes);
    assert_eq!(
        failure_codes,
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn compute_request_key_v0_rejects_noncanonical_seed_bytes() {
    let noncanonical = noncanonical_bytes(&request_seed_v0_value(EXPECTED_ARGS_HASH_HEX));

    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_compute_request_key_v0(
            noncanonical.as_ptr(),
            noncanonical.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    assert_eq!(status, RuliaStatus::VerifyError);
    assert!(out_result.ptr.is_null());
    assert!(!out_error_detail.ptr.is_null());

    let error_bytes = FfiBytes {
        ptr: out_error_detail.ptr,
        len: out_error_detail.len,
    };
    let failure_codes = decode_failure_codes(&error_bytes);
    assert_eq!(
        failure_codes,
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}
