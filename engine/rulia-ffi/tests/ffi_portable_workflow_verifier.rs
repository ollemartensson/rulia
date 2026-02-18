use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use ed25519_dalek::{Signer, SigningKey};
#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::{HashAlgorithm, Keyword, Symbol, TaggedValue, Value};
use rulia_ffi::{
    rulia_v1_bytes_free, rulia_v1_pw_verify_obligation_v0, rulia_v1_pw_verify_receipt_v0,
    RuliaBytes, RuliaStatus,
};

const FAILURE_CODE_MISSING_RECEIPT: &str = "PROTOCOL.missing_receipt";
const FAILURE_CODE_REQUEST_HASH_MISMATCH: &str = "PROTOCOL.request_hash_mismatch";
const FAILURE_CODE_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const FAILURE_CODE_SIGNATURE_INVALID: &str = "PROTOCOL.signature_invalid";
const FAILURE_CODE_UNTRUSTED_SIGNER: &str = "PROTOCOL.untrusted_signer";
const RECEIPT_SIGNATURE_DOMAIN: &str = "rulia:receipt:v0";
const TRUSTED_SIGNER_KEY_ID: &str = "key:test-signer-1";

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

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rulia-cli")
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    rulia::encode_canonical(value).expect("encode canonical")
}

fn decode_value(bytes: &[u8]) -> Value {
    rulia::decode_value(bytes).expect("decode canonical value")
}

fn decode_ffi_value(bytes: &FfiBytes) -> Value {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    decode_value(slice)
}

fn trust_anchor_key_id_from_path(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("trust anchor path file name must be UTF-8");
    if let Some(prefix) = file_name.strip_suffix(".pub.rulia.bin") {
        return prefix.to_string();
    }
    if let Some(prefix) = file_name.strip_suffix(".pub") {
        return prefix.to_string();
    }
    if let Some(prefix) = file_name.strip_suffix(".rulia.bin") {
        return prefix.to_string();
    }
    file_name.to_string()
}

fn trust_anchors_bytes(trust_dir: PathBuf) -> Vec<u8> {
    let mut files = fs::read_dir(&trust_dir)
        .expect("read trust dir")
        .map(|entry| entry.expect("read trust dir entry").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));

    let mut public_keys_entries = Vec::new();
    for file in files {
        let key_id = trust_anchor_key_id_from_path(&file);
        let key_bytes = fs::read(&file).expect("read trust anchor bytes");
        public_keys_entries.push((Value::String(key_id), Value::Bytes(key_bytes)));
    }

    let trust_value = Value::Tagged(TaggedValue::new(
        Symbol::simple("trust_anchors_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_trust_anchors_v0")),
            (kw("anchors"), Value::Map(public_keys_entries)),
        ]),
    ));
    canonical_bytes(&trust_value)
}

fn trust_anchors_bytes_from_entries(public_keys: Vec<(String, Vec<u8>)>) -> Vec<u8> {
    let public_keys_entries = public_keys
        .into_iter()
        .map(|(key_id, key_bytes)| (Value::String(key_id), Value::Bytes(key_bytes)))
        .collect::<Vec<_>>();
    let trust_value = Value::Tagged(TaggedValue::new(
        Symbol::simple("trust_anchors_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_trust_anchors_v0")),
            (kw("anchors"), Value::Map(public_keys_entries)),
        ]),
    ));
    canonical_bytes(&trust_value)
}

fn history_prefix_bytes(receipts: &[Value]) -> Vec<u8> {
    canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("history_prefix_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_history_prefix_v0")),
            (kw("receipts"), Value::Vector(receipts.to_vec())),
        ]),
    )))
}

fn verify_receipt_input_bytes(request: Vec<u8>, receipt: Vec<u8>, trust: Vec<u8>) -> Vec<u8> {
    canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("verify_receipt_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_verify_receipt_input_v0")),
            (kw("request_bytes"), Value::Bytes(request)),
            (kw("receipt_bytes"), Value::Bytes(receipt)),
            (kw("trust_bytes"), Value::Bytes(trust)),
        ]),
    )))
}

fn verify_obligation_input_bytes(obligation: Vec<u8>, history: Vec<u8>, trust: Vec<u8>) -> Vec<u8> {
    canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("verify_obligation_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_verify_obligation_input_v0")),
            (kw("obligation_bytes"), Value::Bytes(obligation)),
            (kw("history_bytes"), Value::Bytes(history)),
            (kw("trust_bytes"), Value::Bytes(trust)),
        ]),
    )))
}

fn call_verify_receipt(input: &[u8]) -> (RuliaStatus, Option<FfiBytes>, Option<FfiBytes>) {
    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        rulia_v1_pw_verify_receipt_v0(
            input.as_ptr(),
            input.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    let result = if out_result.ptr.is_null() {
        None
    } else {
        Some(FfiBytes {
            ptr: out_result.ptr,
            len: out_result.len,
        })
    };
    let error = if out_error_detail.ptr.is_null() {
        None
    } else {
        Some(FfiBytes {
            ptr: out_error_detail.ptr,
            len: out_error_detail.len,
        })
    };
    (status, result, error)
}

fn call_verify_obligation(input: &[u8]) -> (RuliaStatus, Option<FfiBytes>, Option<FfiBytes>) {
    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        rulia_v1_pw_verify_obligation_v0(
            input.as_ptr(),
            input.len(),
            &mut out_result,
            &mut out_error_detail,
        )
    };
    let result = if out_result.ptr.is_null() {
        None
    } else {
        Some(FfiBytes {
            ptr: out_result.ptr,
            len: out_result.len,
        })
    };
    let error = if out_error_detail.ptr.is_null() {
        None
    } else {
        Some(FfiBytes {
            ptr: out_error_detail.ptr,
            len: out_error_detail.len,
        })
    };
    (status, result, error)
}

fn decode_failure_codes(bytes: &FfiBytes) -> Vec<String> {
    let detail = decode_ffi_value(bytes);
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
        panic!("expected failure_codes");
    };
    failure_codes
        .iter()
        .map(|value| match value {
            Value::String(value) => value.clone(),
            _ => panic!("failure_code must be string"),
        })
        .collect()
}

fn decode_verifier_result(bytes: &FfiBytes) -> (String, bool, Option<String>, Vec<String>) {
    let result = decode_ffi_value(bytes);
    let Value::Tagged(tagged) = result else {
        panic!("expected tagged VerifierResultV0");
    };
    assert_eq!(tagged.tag.as_str(), "verifier_result_v0");
    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected VerifierResultV0 map payload");
    };

    assert_exact_keys(
        entries,
        &[
            "format",
            "subject",
            "passed",
            "primary_failure_code",
            "failure_codes",
        ],
    );
    assert!(map_get(entries, "satisfied").is_none());

    let Some(Value::Keyword(subject)) = map_get(entries, "subject") else {
        panic!("expected subject keyword");
    };
    let Some(Value::Bool(passed)) = map_get(entries, "passed") else {
        panic!("expected passed bool");
    };
    let Some(primary_failure_code_value) = map_get(entries, "primary_failure_code") else {
        panic!("expected primary_failure_code");
    };
    let primary_failure_code = match primary_failure_code_value {
        Value::String(value) => Some(value.clone()),
        Value::Nil => None,
        _ => panic!("expected primary_failure_code string/nil"),
    };
    let Some(Value::Vector(failure_codes)) = map_get(entries, "failure_codes") else {
        panic!("expected failure_codes vector");
    };
    let failure_codes = failure_codes
        .iter()
        .map(|value| match value {
            Value::String(value) => value.clone(),
            _ => panic!("failure_code must be string"),
        })
        .collect::<Vec<_>>();
    (
        subject.name().to_string(),
        *passed,
        primary_failure_code,
        failure_codes,
    )
}

fn request_v0_value() -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("request_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_request_v0")),
            (kw("step_id"), Value::String("S_http".to_string())),
            (kw("request_index"), Value::UInt(0)),
            (kw("capability_id"), kw("http_invoke")),
            (kw("capability_version"), Value::String("v1".to_string())),
            (kw("operation"), kw("post")),
        ]),
    ))
}

fn receipt_v0_value(request_hash_hex: &str, signer_key_id: &str, signature: Vec<u8>) -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("receipt_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_receipt_v0")),
            (kw("request_hash"), digest_value(request_hash_hex)),
            (
                kw("attestation"),
                Value::Map(vec![
                    (
                        kw("signer_key_id"),
                        Value::String(signer_key_id.to_string()),
                    ),
                    (kw("signature_alg"), kw("ed25519")),
                    (kw("scope"), kw("rulia_receipt_v0")),
                    (kw("sig"), Value::Bytes(signature)),
                ]),
            ),
        ]),
    ))
}

fn receipt_with_empty_signature(receipt: &Value) -> Value {
    let mut cloned = receipt.clone();
    let Value::Tagged(tagged) = &mut cloned else {
        panic!("receipt must be tagged");
    };
    let Value::Map(entries) = tagged.value.as_mut() else {
        panic!("receipt payload must be map");
    };
    let (_, attestation_value) = entries
        .iter_mut()
        .find(|(key, _)| matches!(key, Value::Keyword(keyword) if keyword.name() == "attestation"))
        .expect("receipt must include attestation");
    let Value::Map(attestation_entries) = attestation_value else {
        panic!("attestation must be map");
    };
    let (_, signature_value) = attestation_entries
        .iter_mut()
        .find(|(key, _)| matches!(key, Value::Keyword(keyword) if keyword.name() == "sig"))
        .expect("attestation must include sig");
    *signature_value = Value::Bytes(Vec::new());
    cloned
}

fn receipt_signature_input(receipt: &Value) -> Vec<u8> {
    let signing_body = receipt_with_empty_signature(receipt);
    let signing_body_bytes = canonical_bytes(&signing_body);
    let mut input =
        Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + 1 + signing_body_bytes.len());
    input.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN.as_bytes());
    input.push(0);
    input.extend_from_slice(&signing_body_bytes);
    input
}

fn sign_receipt(receipt: &Value, signing_key: &SigningKey) -> Vec<u8> {
    signing_key
        .sign(&receipt_signature_input(receipt))
        .to_bytes()
        .to_vec()
}

fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn canonical_sha256_hex(value: &Value) -> String {
    let bytes = canonical_bytes(value);
    bytes_to_hex_lower(&HashAlgorithm::Sha256.compute(&bytes))
}

fn load_receipt_values(history_dir: PathBuf) -> Vec<Value> {
    let mut files = fs::read_dir(&history_dir)
        .expect("read history dir")
        .map(|entry| entry.expect("read history dir entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".receipt.rulia.bin"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));

    files
        .iter()
        .map(|path| decode_value(&fs::read(path).expect("read receipt fixture bytes")))
        .collect()
}

#[test]
fn verify_receipt_v0_passes_with_trusted_signer() {
    let fixture_root = fixture_path("l3_proof_v0");
    let request_bytes = fs::read(fixture_root.join("request.rulia.bin")).expect("read request");
    let receipt_bytes =
        fs::read(fixture_root.join("receipt.valid.rulia.bin")).expect("read receipt");
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust").join("trusted"));
    let input = verify_receipt_input_bytes(request_bytes, receipt_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_receipt(&input);
    assert_eq!(status, RuliaStatus::Ok);
    let result = out_result.expect("expected verifier result");
    assert!(out_error.is_none());
    let (subject, passed, _, failure_codes) = decode_verifier_result(&result);
    assert_eq!(subject, "receipt");
    assert!(passed);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn verify_receipt_v0_reports_request_hash_mismatch() {
    let request = request_v0_value();
    let request_bytes = canonical_bytes(&request);
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let mut mismatch_receipt =
        receipt_v0_value(&"11".repeat(32), TRUSTED_SIGNER_KEY_ID, Vec::new());
    let mismatch_signature = sign_receipt(&mismatch_receipt, &signing_key);
    mismatch_receipt =
        receipt_v0_value(&"11".repeat(32), TRUSTED_SIGNER_KEY_ID, mismatch_signature);
    let receipt_bytes = canonical_bytes(&mismatch_receipt);
    let trust_bytes = trust_anchors_bytes_from_entries(vec![(
        TRUSTED_SIGNER_KEY_ID.to_string(),
        signing_key.verifying_key().to_bytes().to_vec(),
    )]);
    let input = verify_receipt_input_bytes(request_bytes, receipt_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_receipt(&input);
    assert_eq!(status, RuliaStatus::VerifyError);
    assert!(out_result.is_none());
    let error = out_error.expect("expected error detail");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_REQUEST_HASH_MISMATCH.to_string()]
    );
}

#[test]
fn verify_receipt_v0_reports_untrusted_signer() {
    let fixture_root = fixture_path("l3_proof_v0");
    let request_bytes = fs::read(fixture_root.join("request.rulia.bin")).expect("read request");
    let receipt_bytes =
        fs::read(fixture_root.join("receipt.valid.rulia.bin")).expect("read receipt");
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust").join("untrusted"));
    let input = verify_receipt_input_bytes(request_bytes, receipt_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_receipt(&input);
    assert_eq!(status, RuliaStatus::VerifyError);
    assert!(out_result.is_none());
    let error = out_error.expect("expected error detail");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_UNTRUSTED_SIGNER.to_string()]
    );
}

#[test]
fn verify_receipt_v0_reports_signature_invalid() {
    let request = request_v0_value();
    let request_bytes = canonical_bytes(&request);
    let request_hash_hex = canonical_sha256_hex(&request);
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let mut receipt = receipt_v0_value(&request_hash_hex, TRUSTED_SIGNER_KEY_ID, Vec::new());
    let mut signature = sign_receipt(&receipt, &signing_key);
    signature[0] ^= 0xff;
    receipt = receipt_v0_value(&request_hash_hex, TRUSTED_SIGNER_KEY_ID, signature);
    let receipt_bytes = canonical_bytes(&receipt);
    let trust_bytes = trust_anchors_bytes_from_entries(vec![(
        TRUSTED_SIGNER_KEY_ID.to_string(),
        signing_key.verifying_key().to_bytes().to_vec(),
    )]);
    let input = verify_receipt_input_bytes(request_bytes, receipt_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_receipt(&input);
    assert_eq!(status, RuliaStatus::VerifyError);
    assert!(out_result.is_none());
    let error = out_error.expect("expected error detail");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SIGNATURE_INVALID.to_string()]
    );
}

#[test]
fn verify_obligation_v0_returns_passed_true_when_valid_receipt_present() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let obligation_bytes =
        fs::read(fixture_root.join("obligation.rulia.bin")).expect("read obligation");
    let receipts = load_receipt_values(fixture_root.join("history").join("pass"));
    let history_bytes = history_prefix_bytes(&receipts);
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust"));
    let input = verify_obligation_input_bytes(obligation_bytes, history_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_obligation(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(out_error.is_none());
    let result = out_result.expect("expected verifier result");
    let (subject, passed, primary_failure_code, failure_codes) = decode_verifier_result(&result);
    assert_eq!(subject, "obligation");
    assert!(passed);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn verify_obligation_v0_returns_passed_false_when_receipt_missing() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let obligation_bytes =
        fs::read(fixture_root.join("obligation.rulia.bin")).expect("read obligation");
    let history_bytes = history_prefix_bytes(&[]);
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust"));
    let input = verify_obligation_input_bytes(obligation_bytes, history_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_obligation(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(out_error.is_none());
    let result = out_result.expect("expected verifier result");
    let (subject, passed, primary_failure_code, failure_codes) = decode_verifier_result(&result);
    assert_eq!(subject, "obligation");
    assert!(!passed);
    assert_eq!(
        primary_failure_code,
        Some(FAILURE_CODE_MISSING_RECEIPT.to_string())
    );
    assert_eq!(
        failure_codes,
        vec![FAILURE_CODE_MISSING_RECEIPT.to_string()]
    );
}

#[test]
fn verify_obligation_v0_reports_schema_mismatch_for_invalid_obligation_schema() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let invalid_obligation = Value::Tagged(TaggedValue::new(
        Symbol::simple("obligation_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_obligation_v0")),
            (kw("obligation_type"), kw("not_receipt_valid")),
            (kw("params"), Value::Map(Vec::new())),
        ]),
    ));
    let obligation_bytes = canonical_bytes(&invalid_obligation);
    let receipts = load_receipt_values(fixture_root.join("history").join("pass"));
    let history_bytes = history_prefix_bytes(&receipts);
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust"));
    let input = verify_obligation_input_bytes(obligation_bytes, history_bytes, trust_bytes);

    let (status, out_result, out_error) = call_verify_obligation(&input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(out_result.is_none());
    let error = out_error.expect("expected error detail");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn verify_obligation_v0_rejects_legacy_input_tag_alias() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let obligation_bytes =
        fs::read(fixture_root.join("obligation.rulia.bin")).expect("read obligation");
    let receipts = load_receipt_values(fixture_root.join("history").join("pass"));
    let history_bytes = history_prefix_bytes(&receipts);
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust"));
    let legacy_tag_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("satisfy_obligation_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_verify_obligation_input_v0")),
            (kw("obligation_bytes"), Value::Bytes(obligation_bytes)),
            (kw("history_bytes"), Value::Bytes(history_bytes)),
            (kw("trust_bytes"), Value::Bytes(trust_bytes)),
        ]),
    )));

    let (status, out_result, out_error) = call_verify_obligation(&legacy_tag_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(out_result.is_none());
    let error = out_error.expect("expected error detail");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn verify_obligation_v0_rejects_legacy_input_key_alias() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let obligation_bytes =
        fs::read(fixture_root.join("obligation.rulia.bin")).expect("read obligation");
    let receipts = load_receipt_values(fixture_root.join("history").join("pass"));
    let history_bytes = history_prefix_bytes(&receipts);
    let trust_bytes = trust_anchors_bytes(fixture_root.join("trust"));
    let legacy_key_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("verify_obligation_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_verify_obligation_input_v0")),
            (kw("obligation_bytes"), Value::Bytes(obligation_bytes)),
            (kw("history_bytes"), Value::Bytes(history_bytes)),
            (kw("context_trust"), Value::Bytes(trust_bytes)),
        ]),
    )));

    let (status, out_result, out_error) = call_verify_obligation(&legacy_key_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(out_result.is_none());
    let error = out_error.expect("expected error detail");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}
