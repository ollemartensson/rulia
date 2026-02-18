use std::fs;
use std::path::PathBuf;
use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::{Keyword, Symbol, TaggedValue, Value};
use rulia_ffi::{rulia_v1_bytes_free, rulia_v1_pw_match_capabilities_v0, RuliaBytes, RuliaStatus};

const FAILURE_CODE_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const FAILURE_CODE_MISSING_REQUIRED_CAPABILITY: &str = "CAPABILITY.missing_required_capability";
const FAILURE_CODE_INCOMPATIBLE_VERSION: &str = "CAPABILITY.incompatible_version";
const FAILURE_CODE_CONSTRAINT_VIOLATION: &str = "CAPABILITY.constraint_violation";
const FAILURE_CODE_UNTRUSTED_OR_MISSING_TRUST_ANCHOR: &str =
    "CAPABILITY.untrusted_or_missing_trust_anchor";

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

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let expected_key = kw(key);
    let expected_string = Value::String(key.to_string());
    for (entry_key, entry_value) in entries {
        if *entry_key == expected_key || *entry_key == expected_string {
            return Some(entry_value);
        }
    }
    None
}

fn map_get_mut<'a>(entries: &'a mut [(Value, Value)], key: &str) -> Option<&'a mut Value> {
    let expected_key = kw(key);
    let expected_string = Value::String(key.to_string());
    for (entry_key, entry_value) in entries {
        if *entry_key == expected_key || *entry_key == expected_string {
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

fn keyword_or_string(value: &Value) -> String {
    match value {
        Value::Keyword(keyword) => keyword.name().to_string(),
        Value::String(raw) => raw.clone(),
        _ => panic!("expected keyword/string"),
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rulia-cli")
        .join("tests")
        .join("fixtures")
        .join("match_cap_v0")
        .join(name)
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    rulia::encode_canonical(value).expect("encode canonical")
}

fn decode_value(bytes: &[u8]) -> Value {
    rulia::decode_value(bytes).expect("decode canonical value")
}

fn canonicalize_keyword_keys(value: &Value) -> Value {
    match value {
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(entry_key, entry_value)| {
                    let canonical_key_name = match entry_key {
                        Value::Keyword(keyword) => keyword.as_symbol().as_str().replace('/', "_"),
                        Value::String(raw) => raw.clone(),
                        _ => String::new(),
                    };
                    let key = match entry_key {
                        Value::Keyword(_) => Value::String(canonical_key_name.clone()),
                        _ => entry_key.clone(),
                    };

                    let value = canonicalize_keyword_keys(entry_value);
                    let value = if canonical_key_name == "format" {
                        match value {
                            Value::Keyword(keyword) => Value::Keyword(Keyword::simple(
                                keyword.as_symbol().as_str().replace(['/', '-'], "_"),
                            )),
                            Value::String(raw) => Value::String(raw.replace(['/', '-'], "_")),
                            _ => value,
                        }
                    } else {
                        value
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Tagged(tagged) => Value::Tagged(TaggedValue::new(
            tagged.tag.clone(),
            canonicalize_keyword_keys(tagged.value.as_ref()),
        )),
        Value::Vector(values) => {
            Value::Vector(values.iter().map(canonicalize_keyword_keys).collect())
        }
        Value::Set(values) => Value::Set(values.iter().map(canonicalize_keyword_keys).collect()),
        _ => value.clone(),
    }
}

fn canonical_fixture_bytes(bytes: &[u8]) -> Vec<u8> {
    canonical_bytes(&canonicalize_keyword_keys(&decode_value(bytes)))
}

fn decode_ffi_value(bytes: &FfiBytes) -> Value {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    decode_value(slice)
}

fn match_cap_input_bytes(requirements: Vec<u8>, gamma_cap: Vec<u8>) -> Vec<u8> {
    canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("match_capabilities_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_match_capabilities_input_v0")),
            (kw("requirements_bytes"), Value::Bytes(requirements)),
            (kw("gamma_cap_bytes"), Value::Bytes(gamma_cap)),
        ]),
    )))
}

fn call_match_capabilities(input: &[u8]) -> (RuliaStatus, Option<FfiBytes>, Option<FfiBytes>) {
    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_match_capabilities_v0(
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
        panic!("expected failure_codes vector");
    };

    failure_codes
        .iter()
        .map(|value| match value {
            Value::String(value) => value.clone(),
            _ => panic!("expected failure code string"),
        })
        .collect()
}

fn decode_match_cap_result(bytes: &FfiBytes) -> (String, Option<String>, Vec<String>) {
    let result = decode_ffi_value(bytes);
    let Value::Tagged(tagged) = result else {
        panic!("expected tagged MatchCapResultV0");
    };
    assert_eq!(tagged.tag.as_str(), "match_cap_result_v0");

    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected MatchCapResultV0 map payload");
    };

    assert_exact_keys(
        entries,
        &[
            "format",
            "status",
            "matched",
            "unmet_required",
            "unmet_optional",
            "primary_failure_code",
            "failure_codes",
        ],
    );
    assert!(map_get(entries, "verdict").is_none());
    assert!(map_get(entries, "matched_required").is_none());
    assert!(map_get(entries, "matched_optional").is_none());

    let Some(status_value) = map_get(entries, "status") else {
        panic!("expected status");
    };
    let status = keyword_or_string(status_value);

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
            _ => panic!("expected failure code string"),
        })
        .collect();

    (status, primary_failure_code, failure_codes)
}

fn run_fixture_case(case_name: &str) -> (RuliaStatus, Option<FfiBytes>, Option<FfiBytes>) {
    let fixture = fixture_path(case_name);
    let requirements = canonical_fixture_bytes(
        &fs::read(fixture.join("requirements.rulia.bin")).expect("read requirements"),
    );
    let gamma_cap = canonical_fixture_bytes(
        &fs::read(fixture.join("gamma_cap.rulia.bin")).expect("read gamma_cap"),
    );
    let input = match_cap_input_bytes(requirements, gamma_cap);
    call_match_capabilities(&input)
}

fn assert_failure_case(case_name: &str, expected_code: &str) {
    let (status, result, error) = run_fixture_case(case_name);
    assert_eq!(status, RuliaStatus::VerifyError);

    let result = result.expect("failure case should still return MatchCapResultV0 bytes");
    let (match_status, primary_failure_code, failure_codes) = decode_match_cap_result(&result);
    assert_eq!(match_status, "reject");
    assert_eq!(primary_failure_code, Some(expected_code.to_string()));
    assert_eq!(failure_codes, vec![expected_code.to_string()]);

    let error = error.expect("failure case should return FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![expected_code.to_string()]
    );
}

#[test]
fn match_cap_pass_fixture_returns_ok_and_accepted_status() {
    let (status, result, error) = run_fixture_case("pass");
    assert_eq!(status, RuliaStatus::Ok);

    let result = result.expect("pass fixture should return MatchCapResultV0 bytes");
    let (match_status, primary_failure_code, failure_codes) = decode_match_cap_result(&result);
    assert_eq!(match_status, "accepted");
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());

    assert!(
        error.is_none(),
        "success should not return FfiErrorDetailV0"
    );
}

#[test]
fn match_cap_missing_required_capability_fixture_reports_deterministic_failure() {
    assert_failure_case(
        "missing_required_capability",
        FAILURE_CODE_MISSING_REQUIRED_CAPABILITY,
    );
}

#[test]
fn match_cap_incompatible_version_fixture_reports_deterministic_failure() {
    assert_failure_case("incompatible_version", FAILURE_CODE_INCOMPATIBLE_VERSION);
}

#[test]
fn match_cap_constraint_violation_fixture_reports_deterministic_failure() {
    assert_failure_case("constraint_violation", FAILURE_CODE_CONSTRAINT_VIOLATION);
}

#[test]
fn match_cap_untrusted_trust_anchor_fixture_reports_deterministic_failure() {
    assert_failure_case(
        "untrusted_or_missing_trust_anchor",
        FAILURE_CODE_UNTRUSTED_OR_MISSING_TRUST_ANCHOR,
    );
}

#[test]
fn match_cap_multi_failure_orders_failure_codes_deterministically() {
    let fixture = fixture_path("incompatible_version");
    let requirements_bytes = fs::read(fixture.join("requirements.rulia.bin"))
        .expect("read incompatible-version requirements fixture");
    let gamma_cap = canonical_fixture_bytes(
        &fs::read(fixture.join("gamma_cap.rulia.bin"))
            .expect("read incompatible-version gamma_cap fixture"),
    );

    let mut requirements = canonicalize_keyword_keys(&decode_value(&requirements_bytes));
    let Value::Tagged(requirements_tagged) = &mut requirements else {
        panic!("expected tagged CapabilityRequirementsV0");
    };
    let Value::Map(requirements_entries) = requirements_tagged.value.as_mut() else {
        panic!("expected CapabilityRequirementsV0 map payload");
    };
    let Some(Value::Vector(required)) = map_get_mut(requirements_entries, "required") else {
        panic!("expected required vector");
    };
    required.push(Value::Map(vec![
        (
            kw("requirement_id"),
            Value::String("zzz.missing_capability".to_string()),
        ),
        (
            kw("alternatives"),
            Value::Vector(vec![Value::Map(vec![
                (
                    kw("capability_id"),
                    Value::String("offline.validator".to_string()),
                ),
                (kw("capability_version"), Value::String("1".to_string())),
            ])]),
        ),
    ]));

    let input = match_cap_input_bytes(canonical_bytes(&requirements), gamma_cap);
    let (status, result, error) = call_match_capabilities(&input);
    assert_eq!(status, RuliaStatus::VerifyError);

    let result = result.expect("multi-failure case should return MatchCapResultV0 bytes");
    let (match_status, primary_failure_code, failure_codes) = decode_match_cap_result(&result);
    assert_eq!(match_status, "reject");
    assert_eq!(
        failure_codes,
        vec![
            FAILURE_CODE_MISSING_REQUIRED_CAPABILITY.to_string(),
            FAILURE_CODE_INCOMPATIBLE_VERSION.to_string(),
        ]
    );
    assert_eq!(
        primary_failure_code,
        Some(FAILURE_CODE_MISSING_REQUIRED_CAPABILITY.to_string())
    );

    let error = error.expect("multi-failure case should return FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![
            FAILURE_CODE_MISSING_REQUIRED_CAPABILITY.to_string(),
            FAILURE_CODE_INCOMPATIBLE_VERSION.to_string(),
        ]
    );
}

#[test]
fn match_cap_decode_error_maps_to_protocol_schema_mismatch() {
    let malformed = [0xffu8, 0x10, 0x00, 0x01];
    let (status, result, error) = call_match_capabilities(&malformed);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(result.is_none());

    let error = error.expect("decode failure should return FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn match_cap_shape_error_maps_to_protocol_schema_mismatch() {
    let malformed_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("match_capabilities_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_match_capabilities_input_v0")),
            (kw("requirements_bytes"), Value::Bytes(Vec::new())),
        ]),
    )));

    let (status, result, error) = call_match_capabilities(&malformed_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(result.is_none());

    let error = error.expect("shape failure should return FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn match_cap_rejects_legacy_root_tag_alias() {
    let fixture = fixture_path("pass");
    let requirements = canonical_fixture_bytes(
        &fs::read(fixture.join("requirements.rulia.bin")).expect("read requirements"),
    );
    let gamma_cap = canonical_fixture_bytes(
        &fs::read(fixture.join("gamma_cap.rulia.bin")).expect("read gamma_cap"),
    );
    let legacy_tag_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("match_cap_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_match_capabilities_input_v0")),
            (kw("requirements_bytes"), Value::Bytes(requirements)),
            (kw("gamma_cap_bytes"), Value::Bytes(gamma_cap)),
        ]),
    )));

    let (status, result, error) = call_match_capabilities(&legacy_tag_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(result.is_none());
    let error = error.expect("expected FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn match_cap_rejects_legacy_key_alias() {
    let fixture = fixture_path("pass");
    let requirements = canonical_fixture_bytes(
        &fs::read(fixture.join("requirements.rulia.bin")).expect("read requirements"),
    );
    let gamma_cap = canonical_fixture_bytes(
        &fs::read(fixture.join("gamma_cap.rulia.bin")).expect("read gamma_cap"),
    );
    let legacy_key_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("match_capabilities_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_match_capabilities_input_v0")),
            (kw("requirementsBytes"), Value::Bytes(requirements)),
            (kw("gamma_cap_bytes"), Value::Bytes(gamma_cap)),
        ]),
    )));

    let (status, result, error) = call_match_capabilities(&legacy_key_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(result.is_none());
    let error = error.expect("expected FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}
