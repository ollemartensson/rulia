use std::process::Command;
use std::ptr;
use std::{ffi::CString, path::PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::{Keyword, Value};
use rulia_ffi::{
    rulia_ffi_abi_version, rulia_v1_bytes_free, rulia_v1_pw_request_identity_v0, RuliaBytes,
    RuliaStatus,
};

const STUB_FAILURE_CODE: &str = "EVAL.E_STEP_CONTRACT";
#[cfg(unix)]
const FROZEN_PW_VERBS: &[&str] = &[
    "rulia_v1_pw_hash_subject_v0",
    "rulia_v1_pw_request_identity_v0",
    "rulia_v1_pw_rules_desugar_sexpr_v0",
    "rulia_v1_pw_compile_evalir_v0",
    "rulia_v1_pw_evalir_run_v1",
    "rulia_v1_pw_verify_receipt_v0",
    "rulia_v1_pw_verify_obligation_v0",
    "rulia_v1_pw_match_capabilities_v0",
    "rulia_v1_pw_receipt_signing_payload_v0",
];
#[cfg(unix)]
const REMOVED_PW_EXPORTS: &[&str] = &[
    "rulia_v1_pw_compute_args_hash_v0",
    "rulia_v1_pw_compute_request_key_v0",
    "rulia_v1_pw_eval_evalir_v0",
    "rulia_v1_pw_eval_rules_v0",
];

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

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let expected_key = Value::Keyword(Keyword::simple(key));
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

fn ffi_cdylib_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|parent| parent.parent())
        .expect("workspace root");

    #[cfg(target_os = "macos")]
    let lib_name = "librulia_ffi.dylib";
    #[cfg(target_os = "linux")]
    let lib_name = "librulia_ffi.so";
    #[cfg(target_os = "windows")]
    let lib_name = "rulia_ffi.dll";

    workspace_root.join("target").join("debug").join(lib_name)
}

#[test]
fn v1_portable_workflow_stub_smoke() {
    assert_eq!(rulia_ffi_abi_version(), 1);

    let mut out_result = RuliaBytes {
        ptr: std::ptr::dangling_mut::<u8>(),
        len: usize::MAX,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_request_identity_v0(ptr::null(), 0, &mut out_result, &mut out_error_detail)
    };
    assert_eq!(status, RuliaStatus::InternalError);
    assert!(out_result.ptr.is_null());
    assert_eq!(out_result.len, 0);
    assert!(!out_error_detail.ptr.is_null());
    assert!(out_error_detail.len > 0);

    let detail_bytes = FfiBytes {
        ptr: out_error_detail.ptr,
        len: out_error_detail.len,
    };
    let detail_slice = unsafe { std::slice::from_raw_parts(detail_bytes.ptr, detail_bytes.len) };
    let detail = rulia::decode_value(detail_slice).expect("decode canonical error detail");

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
    let Some(verb) = map_get(entries, "verb") else {
        panic!("expected verb keyword");
    };
    assert_eq!(
        verb,
        &Value::Keyword(Keyword::simple("rulia_v1_pw_request_identity_v0"))
    );
    let Some(Value::Vector(failure_codes)) = map_get(entries, "failure_codes") else {
        panic!("expected failure_codes vector");
    };
    assert_eq!(
        failure_codes,
        &vec![Value::String(STUB_FAILURE_CODE.to_string())]
    );
}

#[test]
#[cfg(unix)]
fn v1_portable_workflow_symbol_surface_matches_frozen_contract() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|parent| parent.parent())
        .expect("workspace root");
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("rulia-ffi")
        .current_dir(workspace_root)
        .status()
        .expect("run cargo build for cdylib");
    assert!(
        status.success(),
        "cargo build -p rulia-ffi failed with status {status}"
    );

    let lib_path = ffi_cdylib_path();
    assert!(
        lib_path.exists(),
        "missing cdylib at {}",
        lib_path.display()
    );

    let lib_cstr = CString::new(lib_path.as_os_str().as_bytes()).expect("path cstring");

    let handle = unsafe { libc::dlopen(lib_cstr.as_ptr(), libc::RTLD_NOW) };
    assert!(
        !handle.is_null(),
        "dlopen failed for {}",
        lib_path.display()
    );

    for symbol in FROZEN_PW_VERBS {
        let symbol_cstr = CString::new(*symbol).expect("symbol cstring");
        let address = unsafe { libc::dlsym(handle, symbol_cstr.as_ptr()) };
        assert!(!address.is_null(), "missing frozen symbol {symbol}");
    }
    for symbol in REMOVED_PW_EXPORTS {
        let symbol_cstr = CString::new(*symbol).expect("symbol cstring");
        let address = unsafe { libc::dlsym(handle, symbol_cstr.as_ptr()) };
        assert!(
            address.is_null(),
            "unexpected legacy symbol export still present: {symbol}"
        );
    }

    let close_status = unsafe { libc::dlclose(handle) };
    assert_eq!(close_status, 0, "dlclose failed for {}", lib_path.display());
}
