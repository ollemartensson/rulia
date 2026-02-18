//! C-compatible FFI for Rulia.
//!
//! This crate provides a C API for using Rulia from languages like Julia,
//! Python, and others that support C FFI.

use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use rulia::binary::{MessageReader, TypeTag, ValueRef};
use rulia::{text, HashAlgorithm, Keyword, RuliaError, Symbol, TaggedValue, Value};
use rulia_fmt::ErrorCode;

const RULIA_FFI_ABI_VERSION: u32 = 1;
const RULIA_FFI_VERSION_STRING: &CStr = c"rulia-ffi-abi-v1";
const DEFAULT_MAX_FRAME_LEN: usize = 64 * 1024 * 1024;
const PW_STUB_FAILURE_CODE: &str = "EVAL.E_STEP_CONTRACT";
const PW_PROTOCOL_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const PW_VERB_HASH_SUBJECT: &str = "rulia_v1_pw_hash_subject_v0";
const PW_VERB_REQUEST_IDENTITY: &str = "rulia_v1_pw_request_identity_v0";
const PW_VERB_RULES_DESUGAR_SEXPR: &str = "rulia_v1_pw_rules_desugar_sexpr_v0";
const PW_VERB_COMPILE_EVALIR: &str = "rulia_v1_pw_compile_evalir_v0";
const PW_VERB_EVALIR_RUN: &str = "rulia_v1_pw_evalir_run_v1";
const PW_VERB_COMPUTE_ARGS_HASH: &str = "rulia_v1_pw_compute_args_hash_v0";
const PW_VERB_COMPUTE_REQUEST_KEY: &str = "rulia_v1_pw_compute_request_key_v0";
const PW_VERB_EVAL_EVALIR: &str = "rulia_v1_pw_eval_evalir_v0";
const PW_VERB_EVAL_RULES: &str = "rulia_v1_pw_eval_rules_v0";
const PW_VERB_VERIFY_RECEIPT: &str = "rulia_v1_pw_verify_receipt_v0";
const PW_VERB_VERIFY_OBLIGATION: &str = "rulia_v1_pw_verify_obligation_v0";
const PW_VERB_MATCH_CAPABILITIES: &str = "rulia_v1_pw_match_capabilities_v0";
const PW_VERB_RECEIPT_SIGNING_PAYLOAD: &str = "rulia_v1_pw_receipt_signing_payload_v0";
const RECEIPT_SIGNATURE_DOMAIN: &str = "rulia:receipt:v0";
const RECEIPT_SIGNATURE_SCOPE: &str = "rulia_receipt_v0";
const PW_PROTOCOL_REQUEST_HASH_MISMATCH: &str = "PROTOCOL.request_hash_mismatch";
const PW_PROTOCOL_UNTRUSTED_SIGNER: &str = "PROTOCOL.untrusted_signer";
const PW_PROTOCOL_SIGNATURE_INVALID: &str = "PROTOCOL.signature_invalid";
const PW_PROTOCOL_MISSING_RECEIPT: &str = "PROTOCOL.missing_receipt";
const PW_PROTOCOL_PAYLOAD_HASH_MISMATCH: &str = "PROTOCOL.payload_hash_mismatch";
const PW_PROTOCOL_UNKNOWN_CAPABILITY: &str = "PROTOCOL.unknown_capability";
const PW_PROTOCOL_OUTCOME_DISALLOWED: &str = "PROTOCOL.outcome_disallowed";
const PW_EVAL_UNBOUND_VAR: &str = "EVAL.unbound_var";
const PW_EVAL_TYPE_MISMATCH: &str = "EVAL.type_mismatch";
const PW_EVAL_FORBIDDEN_FEATURE: &str = "EVAL.forbidden_feature";
const PW_EVAL_NO_MATCH: &str = "EVAL.no_match";
const PW_EVAL_AMBIGUOUS_MATCH: &str = "EVAL.ambiguous_match";
const PW_EVAL_STEP_IDENTITY: &str = "EVAL.E_STEP_IDENTITY";
const PW_EVAL_STATE_INVALID: &str = "EVAL.E_STATE_INVALID";
const PW_EVAL_STEP_CONTRACT: &str = "EVAL.E_STEP_CONTRACT";
const PW_EVAL_REQUEST_CANONICALIZATION: &str = "EVAL.E_REQUEST_CANONICALIZATION";
const PW_CAPABILITY_MISSING_REQUIRED_CAPABILITY: &str = "CAPABILITY.missing_required_capability";
const PW_CAPABILITY_INCOMPATIBLE_VERSION: &str = "CAPABILITY.incompatible_version";
const PW_CAPABILITY_CONSTRAINT_VIOLATION: &str = "CAPABILITY.constraint_violation";
const PW_CAPABILITY_UNTRUSTED_OR_MISSING_TRUST_ANCHOR: &str =
    "CAPABILITY.untrusted_or_missing_trust_anchor";
const PW_MAX_RULES_SEXPR_BYTES: usize = 64 * 1024;
const PW_MAX_RULES_SEXPR_TOKENS: usize = 20_000;
const PW_MAX_RULES_SEXPR_FACTS: usize = 1_000;
const PW_MAX_RULES_SEXPR_RULES: usize = 1_000;
const PW_MAX_RULES_SEXPR_BODY_TERMS_PER_RULE: usize = 100;

/// Opaque handle to a Rulia value.
pub struct RuliaValue(Value);

struct RuliaReaderInner {
    base_ptr: *const u8,
    len: usize,
    reader: MessageReader<'static>,
    closed: AtomicBool,
}

// SAFETY: RuliaReaderInner is immutable after construction except for `closed`,
// which is an atomic flag. The underlying buffer is caller-owned and must be kept
// alive and immutable while any handles exist.
unsafe impl Send for RuliaReaderInner {}
unsafe impl Sync for RuliaReaderInner {}

struct RuliaValueRef {
    reader: Arc<RuliaReaderInner>,
    value: ValueRef<'static>,
}

impl Clone for RuliaValueRef {
    fn clone(&self) -> Self {
        Self {
            reader: Arc::clone(&self.reader),
            value: self.value.clone(),
        }
    }
}

struct RuliaFrameDecoder {
    max_len: usize,
    header: [u8; 4],
    header_filled: usize,
    payload_len: Option<usize>,
    payload: Vec<u8>,
}

impl RuliaFrameDecoder {
    fn new(max_len: usize) -> Self {
        Self {
            max_len,
            header: [0u8; 4],
            header_filled: 0,
            payload_len: None,
            payload: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.header = [0u8; 4];
        self.header_filled = 0;
        self.payload_len = None;
        self.payload.clear();
    }

    fn eof_status(&self) -> RuliaStatus {
        if self.header_filled > 0 && self.payload_len.is_none() {
            RuliaStatus::FramingTruncatedHeader
        } else if self.payload_len.is_some() && self.payload.len() < self.payload_len.unwrap() {
            RuliaStatus::FramingTruncatedPayload
        } else {
            RuliaStatus::FramingNeedMoreData
        }
    }
}

enum RuliaHandleKind {
    OwnedValue(RuliaValue),
    Reader(Arc<RuliaReaderInner>),
    ValueRef(RuliaValueRef),
    FrameDecoder(Arc<Mutex<RuliaFrameDecoder>>),
}

/// Pointer-sized handle type for ABI v1.
type RuliaHandle = usize;

static HANDLE_TABLE: OnceLock<Mutex<HashMap<RuliaHandle, RuliaHandleKind>>> = OnceLock::new();
static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(1);

/// Stable FFI status codes for C ABI v1.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RuliaStatus {
    Ok = 0,
    InvalidArgument = 1,
    ParseError = 2,
    DecodeError = 3,
    VerifyError = 4,
    OutOfMemory = 5,
    InternalError = 6,
    FormatInvalidSyntax = 7,
    FormatNotCanonical = 8,
    FramingInvalidLength = 9,
    FramingTruncatedHeader = 10,
    FramingTruncatedPayload = 11,
    FramingTooLarge = 12,
    FramingOutputError = 13,
    FramingNeedMoreData = 14,
}

/// Byte buffer allocated by the FFI.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RuliaBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

/// Result type for byte buffers allocated by the FFI.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RuliaBytesResult {
    pub ptr: *mut u8,
    pub len: usize,
    pub status: RuliaStatus,
}

/// Result type for opaque handles allocated by the FFI.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RuliaHandleResult {
    pub handle: RuliaHandle,
    pub status: RuliaStatus,
}

/// Result type for owned strings allocated by the FFI.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RuliaStringResult {
    pub ptr: *mut c_char,
    pub len: usize,
    pub status: RuliaStatus,
}

fn handle_table() -> &'static Mutex<HashMap<RuliaHandle, RuliaHandleKind>> {
    HANDLE_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle_id() -> RuliaHandle {
    loop {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle != 0 {
            return handle;
        }
    }
}

fn handle_from_kind(kind: RuliaHandleKind) -> RuliaHandle {
    let handle = next_handle_id();
    let mut table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
    table.insert(handle, kind);
    handle
}

fn handle_get_reader(handle: RuliaHandle) -> Option<Arc<RuliaReaderInner>> {
    let table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
    match table.get(&handle) {
        Some(RuliaHandleKind::Reader(inner)) => Some(Arc::clone(inner)),
        _ => None,
    }
}

fn handle_get_value_ref(handle: RuliaHandle) -> Option<RuliaValueRef> {
    let table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
    match table.get(&handle) {
        Some(RuliaHandleKind::ValueRef(value_ref)) => Some(value_ref.clone()),
        _ => None,
    }
}

fn handle_get_frame_decoder(handle: RuliaHandle) -> Option<Arc<Mutex<RuliaFrameDecoder>>> {
    let table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
    match table.get(&handle) {
        Some(RuliaHandleKind::FrameDecoder(decoder)) => Some(Arc::clone(decoder)),
        _ => None,
    }
}

fn handle_with_owned_value<R>(handle: RuliaHandle, f: impl FnOnce(&RuliaValue) -> R) -> Option<R> {
    let table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
    match table.get(&handle) {
        Some(RuliaHandleKind::OwnedValue(value)) => Some(f(value)),
        _ => None,
    }
}

fn status_from_error(error: &RuliaError) -> RuliaStatus {
    match error {
        RuliaError::HashMismatch { .. } | RuliaError::InvalidHash(_) => RuliaStatus::VerifyError,
        RuliaError::UnexpectedValueKind(_) => RuliaStatus::InvalidArgument,
        _ => RuliaStatus::DecodeError,
    }
}

fn status_from_format_error(error: &rulia_fmt::FormatError) -> RuliaStatus {
    match error.code {
        ErrorCode::NonCanonical => RuliaStatus::FormatNotCanonical,
        _ => RuliaStatus::FormatInvalidSyntax,
    }
}

unsafe fn reader_from_raw_bytes(
    ptr: *const u8,
    len: usize,
) -> Result<MessageReader<'static>, RuliaStatus> {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let reader = MessageReader::new(slice).map_err(|err| status_from_error(&err))?;
    let reader_static =
        unsafe { std::mem::transmute::<MessageReader<'_>, MessageReader<'static>>(reader) };
    Ok(reader_static)
}

fn pointer_in_range(base_ptr: *const u8, len: usize, ptr: *const u8, slice_len: usize) -> bool {
    if base_ptr.is_null() || ptr.is_null() {
        return false;
    }
    let base = base_ptr as usize;
    let start = ptr as usize;
    let end = match base.checked_add(len) {
        Some(end) => end,
        None => return false,
    };
    let slice_end = match start.checked_add(slice_len) {
        Some(end) => end,
        None => return false,
    };
    start >= base && slice_end <= end
}

fn reader_root_value(inner: &RuliaReaderInner) -> Result<ValueRef<'static>, RuliaStatus> {
    let root = inner.reader.root().map_err(|err| status_from_error(&err))?;
    let value = root.as_value();
    let value_static = unsafe { std::mem::transmute::<ValueRef<'_>, ValueRef<'static>>(value) };
    Ok(value_static)
}

fn value_kind(value: &Value) -> TypeTag {
    match value {
        Value::Nil => TypeTag::Nil,
        Value::Bool(_) => TypeTag::Bool,
        Value::Int(_) => TypeTag::Int,
        Value::UInt(_) => TypeTag::UInt,
        Value::BigInt(_) => TypeTag::BigInt,
        Value::Float32(_) => TypeTag::Float32,
        Value::Float64(_) => TypeTag::Float64,
        Value::String(_) => TypeTag::String,
        Value::Bytes(_) => TypeTag::Bytes,
        Value::Symbol(_) => TypeTag::Symbol,
        Value::Keyword(_) => TypeTag::Keyword,
        Value::Vector(_) => TypeTag::Vector,
        Value::Set(_) => TypeTag::Set,
        Value::Map(_) => TypeTag::Map,
        Value::Tagged(_) => TypeTag::Tagged,
        Value::Annotated(_) => TypeTag::Annotated,
    }
}

fn bytes_error(status: RuliaStatus) -> RuliaBytesResult {
    RuliaBytesResult {
        ptr: ptr::null_mut(),
        len: 0,
        status,
    }
}

fn handle_error(status: RuliaStatus) -> RuliaHandleResult {
    RuliaHandleResult { handle: 0, status }
}

fn string_error(status: RuliaStatus) -> RuliaStringResult {
    RuliaStringResult {
        ptr: ptr::null_mut(),
        len: 0,
        status,
    }
}

fn bytes_out_init(out: *mut RuliaBytes) -> Result<(), RuliaStatus> {
    if out.is_null() {
        return Err(RuliaStatus::InvalidArgument);
    }
    unsafe {
        *out = RuliaBytes {
            ptr: ptr::null_mut(),
            len: 0,
        };
    }
    Ok(())
}

fn bytes_out_set(out: *mut RuliaBytes, mut bytes: Vec<u8>) -> RuliaStatus {
    if out.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    let ptr = bytes.as_mut_ptr();
    let len = bytes.len();
    std::mem::forget(bytes);
    unsafe {
        *out = RuliaBytes { ptr, len };
    }
    RuliaStatus::Ok
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

fn split_failure_code(code: &str) -> (&str, &str) {
    if let Some((namespace, leaf)) = code.split_once('.') {
        (namespace, leaf)
    } else {
        ("", code)
    }
}

fn ranked_leaf(leaf: &str, known_order: &[&str]) -> usize {
    known_order
        .iter()
        .position(|candidate| *candidate == leaf)
        .unwrap_or(known_order.len())
}

fn namespace_rank(namespace: &str) -> usize {
    match namespace {
        "KERNEL" => 1,
        "EVAL" => 2,
        "PROTOCOL" => 3,
        "CAPABILITY" => 4,
        _ => usize::MAX,
    }
}

fn namespace_local_rank(namespace: &str, leaf: &str) -> usize {
    match namespace {
        "EVAL" => ranked_leaf(
            leaf,
            &[
                "E_ARTIFACT_IDENTITY",
                "E_STEP_IDENTITY",
                "E_STATE_INVALID",
                "E_HISTORY_CURSOR",
                "E_CONTEXT_SNAPSHOT_MISSING",
                "E_CONTEXT_SNAPSHOT_MISMATCH",
                "E_TRIGGER_ITEM_INVALID",
                "E_STEP_CONTRACT",
                "E_REQUEST_CANONICALIZATION",
            ],
        ),
        "PROTOCOL" => ranked_leaf(
            leaf,
            &[
                "unknown_capability",
                "request_hash_mismatch",
                "untrusted_signer",
                "signature_invalid",
                "schema_mismatch",
                "policy_violation",
                "payload_hash_mismatch",
                "missing_receipt",
                "outcome_disallowed",
                "missing_event_type",
                "correlation_mismatch",
                "invalid_correlation_rule",
                "missing_timer_evidence",
                "timer_untrusted",
                "timer_time_invalid",
                "timer_before_deadline",
            ],
        ),
        "CAPABILITY" => ranked_leaf(
            leaf,
            &[
                "missing_required_capability",
                "incompatible_version",
                "incompatible_config_hash",
                "constraint_violation",
                "untrusted_or_missing_trust_anchor",
            ],
        ),
        _ => usize::MAX,
    }
}

fn compare_failure_codes(left: &str, right: &str) -> CmpOrdering {
    let (left_ns, left_leaf) = split_failure_code(left);
    let (right_ns, right_leaf) = split_failure_code(right);
    namespace_rank(left_ns)
        .cmp(&namespace_rank(right_ns))
        .then_with(|| {
            namespace_local_rank(left_ns, left_leaf)
                .cmp(&namespace_local_rank(right_ns, right_leaf))
        })
        .then_with(|| left.cmp(right))
}

fn order_failure_codes(mut failure_codes: Vec<String>) -> Vec<String> {
    failure_codes.sort_by(|left, right| compare_failure_codes(left, right));
    failure_codes.dedup();
    failure_codes
}

fn status_keyword(status: RuliaStatus) -> &'static str {
    match status {
        RuliaStatus::InvalidArgument => "invalid_argument",
        RuliaStatus::ParseError => "parse_error",
        RuliaStatus::DecodeError => "decode_error",
        RuliaStatus::VerifyError => "verify_error",
        RuliaStatus::OutOfMemory => "out_of_memory",
        _ => "internal_error",
    }
}

fn value_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn digest_v0_value(hex: &str) -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("digest"),
        Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("alg")),
                Value::Keyword(Keyword::simple("sha256")),
            ),
            (
                Value::Keyword(Keyword::simple("hex")),
                Value::String(hex.to_string()),
            ),
        ]),
    ))
}

fn pw_error_detail_bytes(
    verb: &str,
    status: RuliaStatus,
    failure_codes: Vec<String>,
    failure_path: Option<String>,
    limit: Option<(String, u64, u64)>,
) -> Option<Vec<u8>> {
    let ordered_failure_codes = order_failure_codes(failure_codes);
    let primary_failure_code = ordered_failure_codes.first().cloned();
    let failure_codes_value = Value::Vector(
        ordered_failure_codes
            .iter()
            .map(|code| Value::String(code.clone()))
            .collect(),
    );
    let failure_path_value = failure_path.map_or(Value::Nil, Value::String);
    let limit_value = match limit {
        Some((name, observed, max)) => Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("name")),
                Value::String(name.to_string()),
            ),
            (
                Value::Keyword(Keyword::simple("observed")),
                Value::UInt(observed),
            ),
            (Value::Keyword(Keyword::simple("max")), Value::UInt(max)),
        ]),
        None => Value::Nil,
    };
    let detail = Value::Tagged(TaggedValue::new(
        Symbol::simple("ffi_error_detail_v0"),
        Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("format")),
                Value::Keyword(Keyword::simple("rulia_pw_ffi_error_detail_v0")),
            ),
            (
                Value::Keyword(Keyword::simple("verb")),
                Value::Keyword(Keyword::simple(verb)),
            ),
            (
                Value::Keyword(Keyword::simple("status")),
                Value::Keyword(Keyword::simple(status_keyword(status))),
            ),
            (
                Value::Keyword(Keyword::simple("primary_failure_code")),
                primary_failure_code.map_or(Value::Nil, Value::String),
            ),
            (
                Value::Keyword(Keyword::simple("failure_codes")),
                failure_codes_value,
            ),
            (
                Value::Keyword(Keyword::simple("failure_path")),
                failure_path_value,
            ),
            (Value::Keyword(Keyword::simple("limit")), limit_value),
        ]),
    ));
    rulia::encode_canonical(&detail).ok()
}

fn pw_stub_error_detail_bytes(verb: &str) -> Option<Vec<u8>> {
    pw_error_detail_bytes(
        verb,
        RuliaStatus::InternalError,
        vec![PW_STUB_FAILURE_CODE.to_string()],
        None,
        None,
    )
}

fn pw_init_outputs(out_result: *mut RuliaBytes, out_error_detail: *mut RuliaBytes) -> RuliaStatus {
    if let Err(status) = bytes_out_init(out_result) {
        return status;
    }
    if !out_error_detail.is_null() {
        unsafe {
            *out_error_detail = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
    }
    RuliaStatus::Ok
}

fn pw_fail(
    verb: &str,
    status: RuliaStatus,
    failure_codes: Vec<String>,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    if !out_result.is_null() {
        unsafe {
            *out_result = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
    }
    if !out_error_detail.is_null() {
        unsafe {
            *out_error_detail = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
        if let Some(bytes) = pw_error_detail_bytes(verb, status, failure_codes, None, None) {
            let _ = bytes_out_set(out_error_detail, bytes);
        }
    }
    status
}

fn map_has_only_allowed_keyword_keys(entries: &[(Value, Value)], allowed_keys: &[&str]) -> bool {
    for (key, _) in entries {
        let Value::Keyword(keyword) = key else {
            return false;
        };
        if !allowed_keys
            .iter()
            .any(|allowed| *allowed == keyword.name())
        {
            return false;
        }
    }
    true
}

fn is_lower_hex(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

fn is_digest_v0(value: &Value) -> bool {
    let Value::Tagged(tagged) = value else {
        return false;
    };
    if tagged.tag.as_str() != "digest" {
        return false;
    }
    let Value::Map(entries) = tagged.value.as_ref() else {
        return false;
    };
    if !map_has_only_allowed_keyword_keys(entries, &["alg", "hex"]) {
        return false;
    }
    let Some(alg_value) = map_get(entries, "alg") else {
        return false;
    };
    let alg = match alg_value {
        Value::Keyword(keyword) => keyword.name(),
        Value::String(value) => value.as_str(),
        _ => return false,
    };
    if alg != "sha256" {
        return false;
    }
    let Some(Value::String(hex)) = map_get(entries, "hex") else {
        return false;
    };
    hex.len() == 64 && is_lower_hex(hex)
}

fn request_args_payload_entries(value: &Value) -> Option<&[(Value, Value)]> {
    match value {
        Value::Tagged(tagged) if tagged.tag.as_str() == "request_args_canonical_v0" => {
            match tagged.value.as_ref() {
                Value::Map(entries) => Some(entries),
                _ => None,
            }
        }
        Value::Map(entries) => Some(entries),
        _ => None,
    }
}

fn request_seed_payload_entries(value: &Value) -> Option<&[(Value, Value)]> {
    match value {
        Value::Tagged(tagged) if tagged.tag.as_str() == "request_seed_v0" => {
            match tagged.value.as_ref() {
                Value::Map(entries) => Some(entries),
                _ => None,
            }
        }
        Value::Map(entries) => Some(entries),
        _ => None,
    }
}

fn is_request_args_canonical_v0(value: &Value) -> bool {
    let Some(entries) = request_args_payload_entries(value) else {
        return false;
    };
    let allowed_keys = [
        "format",
        "capability_id",
        "capability_version",
        "operation",
        "input",
        "expected_receipt_schema_ref",
        "policy",
    ];
    if !map_has_only_allowed_keyword_keys(entries, &allowed_keys) {
        return false;
    }
    let Some(Value::Keyword(_)) = map_get(entries, "capability_id") else {
        return false;
    };
    if let Some(format_value) = map_get(entries, "format") {
        if !matches!(format_value, Value::Keyword(_)) {
            return false;
        }
    }
    let Some(Value::String(_)) = map_get(entries, "capability_version") else {
        return false;
    };
    let Some(Value::Keyword(_)) = map_get(entries, "operation") else {
        return false;
    };
    let Some(input_value) = map_get(entries, "input") else {
        return false;
    };
    let Value::Map(input_entries) = input_value else {
        return false;
    };
    let input_allowed_keys = [
        "payload_hash",
        "payload_embed",
        "payload_embed_redaction_class",
        "payload_bytes",
    ];
    if !map_has_only_allowed_keyword_keys(input_entries, &input_allowed_keys) {
        return false;
    }
    let Some(payload_hash) = map_get(input_entries, "payload_hash") else {
        return false;
    };
    if !is_digest_v0(payload_hash) {
        return false;
    }
    if map_get(input_entries, "payload_embed").is_none() {
        return false;
    }
    let Some(Value::Keyword(payload_embed_redaction_class)) =
        map_get(input_entries, "payload_embed_redaction_class")
    else {
        return false;
    };
    if !matches!(
        payload_embed_redaction_class.name(),
        "hash_only" | "rc_public" | "rc_internal" | "rc_restricted"
    ) {
        return false;
    }
    let Some(Value::UInt(_)) = map_get(input_entries, "payload_bytes") else {
        return false;
    };
    let Some(expected_receipt_schema_ref) = map_get(entries, "expected_receipt_schema_ref") else {
        return false;
    };
    if !matches!(expected_receipt_schema_ref, Value::Nil)
        && !is_digest_v0(expected_receipt_schema_ref)
    {
        return false;
    }
    let Some(Value::Map(_)) = map_get(entries, "policy") else {
        return false;
    };
    true
}

fn is_request_seed_v0(value: &Value) -> bool {
    let Some(entries) = request_seed_payload_entries(value) else {
        return false;
    };
    let allowed_keys = [
        "format",
        "artifact_hash",
        "step_id",
        "request_ordinal",
        "args_hash",
        "history_cursor",
        "process_id",
    ];
    if !map_has_only_allowed_keyword_keys(entries, &allowed_keys) {
        return false;
    }
    let Some(artifact_hash) = map_get(entries, "artifact_hash") else {
        return false;
    };
    if !is_digest_v0(artifact_hash) {
        return false;
    }
    if let Some(format_value) = map_get(entries, "format") {
        if !matches!(format_value, Value::Keyword(_)) {
            return false;
        }
    }
    let Some(Value::String(_)) = map_get(entries, "step_id") else {
        return false;
    };
    let Some(Value::UInt(request_ordinal)) = map_get(entries, "request_ordinal") else {
        return false;
    };
    if *request_ordinal == 0 {
        return false;
    }
    let Some(args_hash) = map_get(entries, "args_hash") else {
        return false;
    };
    if !is_digest_v0(args_hash) {
        return false;
    }
    if let Some(history_cursor) = map_get(entries, "history_cursor") {
        if !matches!(history_cursor, Value::Nil | Value::UInt(_)) {
            return false;
        }
    }
    if let Some(process_id) = map_get(entries, "process_id") {
        if !matches!(process_id, Value::Nil | Value::String(_)) {
            return false;
        }
    }
    true
}

fn decode_canonical_input(input: &[u8]) -> Result<Value, RuliaStatus> {
    let decoded = rulia::decode_value(input).map_err(|_| RuliaStatus::DecodeError)?;
    let canonical = rulia::encode_canonical(&decoded).map_err(|_| RuliaStatus::InternalError)?;
    if canonical != input {
        return Err(RuliaStatus::VerifyError);
    }
    Ok(decoded)
}

fn encode_digest_v0_result(digest_bytes: &[u8]) -> Result<Vec<u8>, RuliaStatus> {
    let digest_hex = value_to_hex_lower(digest_bytes);
    rulia::encode_canonical(&digest_v0_value(&digest_hex)).map_err(|_| RuliaStatus::InternalError)
}

#[derive(Clone, Debug)]
struct ParsedDigestValue {
    algorithm: HashAlgorithm,
    hex: String,
}

impl ParsedDigestValue {
    fn prefixed(&self) -> String {
        format!("{}:{}", self.algorithm.as_str(), self.hex)
    }

    fn same_value(&self, other: &ParsedDigestValue) -> bool {
        self.algorithm.as_str() == other.algorithm.as_str() && self.hex == other.hex
    }
}

#[derive(Clone, Debug, Default)]
struct ParsedRequestV0 {
    expected_receipt_schema_ref: Option<ParsedDigestValue>,
    capability_id: Option<String>,
    capability_version: Option<String>,
    operation: Option<String>,
    payload_hash_valid: bool,
}

#[derive(Clone, Debug)]
struct ParsedReceiptV0 {
    request_hash: ParsedDigestValue,
    request_id: Option<ParsedDigestValue>,
    capability_id: Option<String>,
    capability_version: Option<String>,
    operation: Option<String>,
    outcome: Option<String>,
    schema_ref: Option<ParsedDigestValue>,
    payload_hash_valid: bool,
    signer_key_id: String,
    signature_alg: String,
    scope: String,
    signature: Vec<u8>,
    signing_body_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RequiredCapabilityTuple {
    capability_id: String,
    capability_version: String,
    operation: String,
}

#[derive(Clone, Debug)]
struct ParsedReceiptValidObligationV0 {
    request_hash: ParsedDigestValue,
    allowed_outcomes: Option<Vec<String>>,
    required_capability: Option<RequiredCapabilityTuple>,
}

#[derive(Clone, Debug, Default)]
struct TrustAnchorSet {
    public_keys: HashMap<String, Vec<u8>>,
}

#[derive(Clone, Debug)]
struct HistoryReceiptCandidateV0 {
    history_index: u64,
    canonical_receipt_hash: String,
    parsed_receipt: ParsedReceiptV0,
}

#[derive(Clone, Debug)]
struct VerifyReceiptInputBytesV0 {
    request_bytes: Vec<u8>,
    receipt_bytes: Vec<u8>,
    trust_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct VerifyObligationInputBytesV0 {
    obligation_bytes: Vec<u8>,
    history_bytes: Vec<u8>,
    trust_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct MatchCapabilitiesInputBytesV0 {
    requirements_bytes: Vec<u8>,
    gamma_cap_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct EvalEvalIrInputBytesV0 {
    eval_ir_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    history_bytes: Option<Vec<u8>>,
    gamma_core_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct EvalIrStepV0 {
    step_id: String,
    op: String,
    path: Option<String>,
    value: Option<Value>,
    emission: Option<Value>,
    capability_id: Option<String>,
    operation: Option<String>,
    args: Option<Value>,
    next_step_id: Option<String>,
    obligations: Option<Vec<Value>>,
    policy: Option<String>,
    on_timeout: Option<Value>,
    rules: Option<Value>,
    rules_sexpr: Option<String>,
    routes: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug)]
struct EvalIrPlanV0 {
    format_id: String,
    ir_version: String,
    artifact_hash: Option<String>,
    entry_step_id: String,
    steps: Vec<EvalIrStepV0>,
}

#[derive(Clone, Debug)]
struct EvalRunResultV0 {
    control: EvalControlV0,
    state_out: Value,
    emissions: Vec<Value>,
    errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvalControlV0 {
    Continue,
    Suspend,
    End,
    Error,
}

#[derive(Clone, Debug)]
struct EvalIrHistoryReceiptV0 {
    history_index: u64,
    source_path: String,
    canonical_receipt_hash: String,
    request_hash: String,
    signer_key_id: Option<String>,
    signature_valid: Option<bool>,
}

#[derive(Clone, Debug, Default)]
struct EvalIrTrustContextV0 {
    trusted_signer_keys: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug)]
struct EvalIrObligationSatisfactionV0 {
    satisfied: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JoinPolicyV0 {
    AllOf,
    AnyOf,
}

#[derive(Clone, Debug)]
struct ParsedJoinStepV0 {
    obligations: Vec<String>,
    policy: JoinPolicyV0,
    next_step_id: String,
}

#[derive(Clone, Debug)]
enum RulesSExprNode {
    List(Vec<RulesSExprNode>),
    Token(String),
    String(String),
    Number(String),
    Bool(bool),
    Variable(String),
}

struct RulesSExprParser<'a> {
    input: &'a [u8],
    cursor: usize,
    token_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequiredAbsencePolicyV0 {
    Reject,
    Suspend,
}

#[derive(Clone, Debug)]
struct CapabilityRequirementsV0 {
    required_absence_policy: RequiredAbsencePolicyV0,
    required: Vec<CapabilityRequirementV0>,
    optional: Vec<CapabilityRequirementV0>,
}

#[derive(Clone, Debug)]
struct CapabilityRequirementV0 {
    requirement_id: String,
    alternatives: Vec<CapabilityAlternativeV0>,
    required_operations: Vec<RequiredOperationV0>,
    required_constraints: ConstraintPolicyV0,
    required_trust_anchors: RequiredTrustAnchorsV0,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CapabilityAlternativeV0 {
    capability_id: String,
    capability_version: String,
    capability_config_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct RequiredOperationV0 {
    operation: String,
    semantics_ref: String,
}

#[derive(Clone, Debug)]
struct GammaCapSnapshotV0 {
    capabilities: Vec<CapabilityEntryV0>,
}

#[derive(Clone, Debug)]
struct CapabilityEntryV0 {
    capability_id: String,
    capability_version: String,
    capability_config_hash: String,
    operations: Vec<CapabilityOperationV0>,
    constraints: ConstraintPolicyV0,
    trust_anchors: CapabilityTrustAnchorsV0,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CapabilityOperationV0 {
    operation: String,
    semantics_ref: String,
}

#[derive(Clone, Debug, Default)]
struct ConstraintPolicyV0 {
    fields: BTreeMap<String, ConstraintFieldValueV0>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConstraintFieldValueV0 {
    Set(BTreeSet<String>),
    Max(u64),
    Bool(bool),
    Raw(Value),
}

#[derive(Clone, Debug, Default)]
struct RequiredTrustAnchorsV0 {
    signer_keys_any_of: BTreeSet<String>,
    signer_keys_all_of: BTreeSet<String>,
    allowed_signature_algs: BTreeSet<String>,
    required_cert_roots: BTreeSet<String>,
    cert_roots_any_of: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
struct CapabilityTrustAnchorsV0 {
    trusted_signer_keys: BTreeSet<String>,
    trusted_cert_roots: BTreeSet<String>,
    allowed_signature_algs: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityFailureCategoryV0 {
    MissingRequiredCapability,
    IncompatibleVersion,
    ConstraintViolation,
    UntrustedOrMissingTrustAnchor,
}

impl CapabilityFailureCategoryV0 {
    fn rank(self) -> usize {
        match self {
            CapabilityFailureCategoryV0::MissingRequiredCapability => 1,
            CapabilityFailureCategoryV0::IncompatibleVersion => 2,
            CapabilityFailureCategoryV0::ConstraintViolation => 4,
            CapabilityFailureCategoryV0::UntrustedOrMissingTrustAnchor => 5,
        }
    }

    fn code(self) -> &'static str {
        match self {
            CapabilityFailureCategoryV0::MissingRequiredCapability => {
                PW_CAPABILITY_MISSING_REQUIRED_CAPABILITY
            }
            CapabilityFailureCategoryV0::IncompatibleVersion => PW_CAPABILITY_INCOMPATIBLE_VERSION,
            CapabilityFailureCategoryV0::ConstraintViolation => PW_CAPABILITY_CONSTRAINT_VIOLATION,
            CapabilityFailureCategoryV0::UntrustedOrMissingTrustAnchor => {
                PW_CAPABILITY_UNTRUSTED_OR_MISSING_TRUST_ANCHOR
            }
        }
    }
}

#[derive(Clone, Debug)]
struct RequirementMatchV0 {
    requirement_id: String,
    alternative: CapabilityAlternativeV0,
}

#[derive(Clone, Debug)]
struct RequirementUnmetV0 {
    requirement_id: String,
    failure_category: CapabilityFailureCategoryV0,
    alternative: CapabilityAlternativeV0,
}

enum RequirementOutcomeV0 {
    Matched(RequirementMatchV0),
    Unmet(RequirementUnmetV0),
}

#[derive(Clone, Debug)]
struct MatchCapEvaluationResultV0 {
    status: &'static str,
    matched_required: Vec<RequirementMatchV0>,
    matched_optional: Vec<RequirementMatchV0>,
    unmet_required: Vec<RequirementUnmetV0>,
    unmet_optional: Vec<RequirementUnmetV0>,
    failure_codes: Vec<String>,
}

#[derive(Clone, Debug)]
struct ObligationSatisfactionResultV0 {
    satisfied: bool,
    failure_codes: Vec<String>,
}

fn normalized_lookup_key(value: &str) -> String {
    value.replace(['/', '-'], "_")
}

fn value_key_name(value: &Value) -> Option<String> {
    match value {
        Value::Keyword(keyword) => Some(keyword.as_symbol().as_str().to_string()),
        Value::String(raw) => Some(raw.clone()),
        _ => None,
    }
}

fn map_get_exact_any<'a>(
    entries: &'a [(Value, Value)],
    candidate_keys: &[&str],
) -> Option<&'a Value> {
    entries.iter().find_map(|(key, value)| {
        let key_name = value_key_name(key)?;
        if candidate_keys
            .iter()
            .any(|candidate| *candidate == key_name)
        {
            Some(value)
        } else {
            None
        }
    })
}

fn map_has_only_allowed_keys(entries: &[(Value, Value)], allowed_keys: &[&str]) -> bool {
    entries.iter().all(|(key, _)| {
        let Some(key_name) = value_key_name(key) else {
            return false;
        };
        allowed_keys.iter().any(|allowed| *allowed == key_name)
    })
}

fn require_canonical_keys(
    entries: &[(Value, Value)],
    required_keys: &[&str],
    allowed_keys: &[&str],
    container_name: &str,
) -> Result<(), String> {
    if !map_has_only_allowed_keys(entries, allowed_keys) {
        return Err(format!("{container_name} contains unknown key"));
    }
    for required in required_keys {
        if map_get_exact_any(entries, &[*required]).is_none() {
            return Err(format!("{container_name} missing {required}"));
        }
    }
    Ok(())
}

fn map_get_any<'a>(entries: &'a [(Value, Value)], candidate_keys: &[&str]) -> Option<&'a Value> {
    let normalized_candidates = candidate_keys
        .iter()
        .map(|candidate| normalized_lookup_key(candidate))
        .collect::<Vec<_>>();
    entries.iter().find_map(|(key, value)| {
        let key_name = value_key_name(key)?;
        let normalized_key = normalized_lookup_key(&key_name);
        if normalized_candidates
            .iter()
            .any(|candidate| candidate == &normalized_key)
        {
            Some(value)
        } else {
            None
        }
    })
}

fn map_get_mut_any<'a>(
    entries: &'a mut [(Value, Value)],
    candidate_keys: &[&str],
) -> Option<&'a mut Value> {
    let normalized_candidates = candidate_keys
        .iter()
        .map(|candidate| normalized_lookup_key(candidate))
        .collect::<Vec<_>>();
    entries.iter_mut().find_map(|(key, value)| {
        let key_name = value_key_name(key)?;
        let normalized_key = normalized_lookup_key(&key_name);
        if normalized_candidates
            .iter()
            .any(|candidate| candidate == &normalized_key)
        {
            Some(value)
        } else {
            None
        }
    })
}

fn expect_map_entries<'a>(value: &'a Value, message: &str) -> Result<&'a [(Value, Value)], String> {
    let Value::Map(entries) = value else {
        return Err(message.to_string());
    };
    Ok(entries.as_slice())
}

fn tagged_entries<'a>(
    value: &'a Value,
    expected_tag: &str,
    message: &str,
) -> Result<&'a [(Value, Value)], String> {
    let Value::Tagged(tagged) = value else {
        return Err(message.to_string());
    };
    if tagged.tag.as_str() != expected_tag {
        return Err(message.to_string());
    }
    expect_map_entries(tagged.value.as_ref(), message)
}

fn verify_input_entries<'a>(
    value: &'a Value,
    expected_tags: &[&str],
) -> Result<&'a [(Value, Value)], String> {
    match value {
        Value::Tagged(tagged) if expected_tags.iter().any(|tag| *tag == tagged.tag.as_str()) => {
            expect_map_entries(
                tagged.value.as_ref(),
                "portable workflow input must be a map",
            )
        }
        _ => Err("portable workflow input root tag mismatch".to_string()),
    }
}

fn keyword_or_string(value: &Value) -> Option<String> {
    match value {
        Value::Keyword(keyword) => Some(keyword.as_symbol().as_str().to_string()),
        Value::String(raw) => Some(raw.clone()),
        _ => None,
    }
}

fn expect_string<'a>(value: &'a Value, message: &str) -> Result<&'a str, String> {
    match value {
        Value::String(raw) => Ok(raw.as_str()),
        _ => Err(message.to_string()),
    }
}

fn validate_format_field(
    entries: &[(Value, Value)],
    expected_format: &str,
    message: &str,
) -> Result<(), String> {
    let format_value =
        map_get_exact_any(entries, &["format"]).ok_or_else(|| message.to_string())?;
    let actual = keyword_or_string(format_value).ok_or_else(|| message.to_string())?;
    if actual != expected_format {
        return Err(message.to_string());
    }
    Ok(())
}

fn parse_hash_algorithm(value: &str) -> Option<HashAlgorithm> {
    match value {
        "sha256" => Some(HashAlgorithm::Sha256),
        "blake3" => Some(HashAlgorithm::Blake3),
        _ => None,
    }
}

fn is_valid_digest_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_prefixed_digest(value: &str) -> Option<ParsedDigestValue> {
    let (algorithm_name, hex) = value.split_once(':')?;
    let algorithm = parse_hash_algorithm(algorithm_name)?;
    if !is_valid_digest_hex(hex) {
        return None;
    }
    Some(ParsedDigestValue {
        algorithm,
        hex: hex.to_ascii_lowercase(),
    })
}

fn parse_digest_value(value: &Value) -> Result<ParsedDigestValue, String> {
    match value {
        Value::Tagged(tagged) => {
            if tagged.tag.as_str() != "digest" {
                return Err("digest value must use Digest(...) shape".to_string());
            }
            let digest_entries = expect_map_entries(
                tagged.value.as_ref(),
                "digest value must be map with alg and hex",
            )?;
            let alg_value = map_get_any(digest_entries, &["alg"])
                .ok_or_else(|| "digest missing alg".to_string())?;
            let algorithm_name = keyword_or_string(alg_value)
                .ok_or_else(|| "digest alg must be keyword/string".to_string())?;
            let algorithm = parse_hash_algorithm(&algorithm_name)
                .ok_or_else(|| format!("unsupported digest algorithm '{algorithm_name}'"))?;

            let hex_value = map_get_any(digest_entries, &["hex"])
                .ok_or_else(|| "digest missing hex".to_string())?;
            let hex = expect_string(hex_value, "digest hex must be a string")?;
            if !is_valid_digest_hex(hex) {
                return Err("digest hex must be 64 hexadecimal characters".to_string());
            }
            Ok(ParsedDigestValue {
                algorithm,
                hex: hex.to_ascii_lowercase(),
            })
        }
        Value::String(raw) => parse_prefixed_digest(raw)
            .ok_or_else(|| "digest string must use '<alg>:<64-hex>' format".to_string()),
        _ => Err("digest value must be Digest(...) or '<alg>:<hex>' string".to_string()),
    }
}

fn parse_optional_digest_value(value: &Value) -> Result<Option<ParsedDigestValue>, String> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        parse_digest_value(value).map(Some)
    }
}

fn digest_from_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> ParsedDigestValue {
    ParsedDigestValue {
        algorithm,
        hex: value_to_hex_lower(&algorithm.compute(bytes)),
    }
}

fn extract_required_bytes_field(
    entries: &[(Value, Value)],
    key: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let value = map_get_exact_any(entries, &[key]).ok_or_else(|| format!("missing {label}"))?;
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(format!("{label} must be bytes")),
    }
}

fn extract_optional_bytes_field(
    entries: &[(Value, Value)],
    key: &str,
    label: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = map_get_exact_any(entries, &[key]) else {
        return Ok(None);
    };
    match value {
        Value::Bytes(bytes) => Ok(Some(bytes.clone())),
        _ => Err(format!("{label} must be bytes")),
    }
}

fn parse_verify_receipt_input_bytes_v0(value: &Value) -> Result<VerifyReceiptInputBytesV0, String> {
    let entries = verify_input_entries(value, &["verify_receipt_input_v0"])?;
    require_canonical_keys(
        entries,
        &["format", "request_bytes", "receipt_bytes", "trust_bytes"],
        &["format", "request_bytes", "receipt_bytes", "trust_bytes"],
        "verify_receipt_input_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_verify_receipt_input_v0",
        "verify_receipt input format must be :rulia_verify_receipt_input_v0",
    )?;
    let request_bytes = extract_required_bytes_field(entries, "request_bytes", "request_bytes")?;
    let receipt_bytes = extract_required_bytes_field(entries, "receipt_bytes", "receipt_bytes")?;
    let trust_bytes = extract_required_bytes_field(entries, "trust_bytes", "trust_bytes")?;
    Ok(VerifyReceiptInputBytesV0 {
        request_bytes,
        receipt_bytes,
        trust_bytes,
    })
}

fn parse_verify_obligation_input_bytes_v0(
    value: &Value,
) -> Result<VerifyObligationInputBytesV0, String> {
    let entries = verify_input_entries(value, &["verify_obligation_input_v0"])?;
    require_canonical_keys(
        entries,
        &["format", "obligation_bytes", "history_bytes", "trust_bytes"],
        &["format", "obligation_bytes", "history_bytes", "trust_bytes"],
        "verify_obligation_input_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_verify_obligation_input_v0",
        "verify_obligation input format must be :rulia_verify_obligation_input_v0",
    )?;
    let obligation_bytes =
        extract_required_bytes_field(entries, "obligation_bytes", "obligation_bytes")?;
    let history_bytes = extract_required_bytes_field(entries, "history_bytes", "history_bytes")?;
    let trust_bytes = extract_required_bytes_field(entries, "trust_bytes", "trust_bytes")?;
    Ok(VerifyObligationInputBytesV0 {
        obligation_bytes,
        history_bytes,
        trust_bytes,
    })
}

fn parse_match_capabilities_input_bytes_v0(
    value: &Value,
) -> Result<MatchCapabilitiesInputBytesV0, String> {
    let entries = verify_input_entries(value, &["match_capabilities_input_v0"])?;
    require_canonical_keys(
        entries,
        &["format", "requirements_bytes", "gamma_cap_bytes"],
        &["format", "requirements_bytes", "gamma_cap_bytes"],
        "match_capabilities_input_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_match_capabilities_input_v0",
        "match_capabilities input format must be :rulia_match_capabilities_input_v0",
    )?;
    let requirements_bytes =
        extract_required_bytes_field(entries, "requirements_bytes", "requirements_bytes")?;
    let gamma_cap_bytes =
        extract_required_bytes_field(entries, "gamma_cap_bytes", "gamma_cap_bytes")?;
    Ok(MatchCapabilitiesInputBytesV0 {
        requirements_bytes,
        gamma_cap_bytes,
    })
}

fn parse_eval_evalir_input_bytes_v0(value: &Value) -> Result<EvalEvalIrInputBytesV0, String> {
    let entries = verify_input_entries(value, &["eval_evalir_input_v0"])?;
    require_canonical_keys(
        entries,
        &["format", "eval_ir_bytes", "state_bytes"],
        &[
            "format",
            "eval_ir_bytes",
            "state_bytes",
            "history_bytes",
            "gamma_core_bytes",
        ],
        "eval_evalir_input_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_eval_evalir_input_v0",
        "eval_evalir input format must be :rulia_eval_evalir_input_v0",
    )?;
    let eval_ir_bytes = extract_required_bytes_field(entries, "eval_ir_bytes", "eval_ir_bytes")?;
    let state_bytes = extract_required_bytes_field(entries, "state_bytes", "state_bytes")?;
    let history_bytes = extract_optional_bytes_field(entries, "history_bytes", "history_bytes")?;
    let gamma_core_bytes =
        extract_optional_bytes_field(entries, "gamma_core_bytes", "gamma_core_bytes")?;
    Ok(EvalEvalIrInputBytesV0 {
        eval_ir_bytes,
        state_bytes,
        history_bytes,
        gamma_core_bytes,
    })
}

fn eval_ir_entries_v0(value: &Value) -> Result<&[(Value, Value)], &'static str> {
    match value {
        Value::Map(entries) => Ok(entries.as_slice()),
        Value::Tagged(tagged) => {
            let tag = tagged.tag.as_str();
            if tag == "eval_ir_v0" {
                return expect_map_entries(tagged.value.as_ref(), "eval_ir payload must be map")
                    .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH);
            }
            Err(PW_PROTOCOL_SCHEMA_MISMATCH)
        }
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn eval_ir_step_entries_v0(value: &Value) -> Result<&[(Value, Value)], &'static str> {
    match value {
        Value::Map(entries) => Ok(entries.as_slice()),
        Value::Tagged(tagged) => {
            let tag = tagged.tag.as_str();
            if tag == "eval_step_v0" {
                return expect_map_entries(
                    tagged.value.as_ref(),
                    "eval_ir step payload must be map",
                )
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH);
            }
            Err(PW_PROTOCOL_SCHEMA_MISMATCH)
        }
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_required_string_field_v0(
    entries: &[(Value, Value)],
    keys: &[&str],
) -> Result<String, &'static str> {
    let value = map_get_exact_any(entries, keys).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    match value {
        Value::String(raw) if !raw.trim().is_empty() => Ok(raw.clone()),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_optional_string_field_v0(
    entries: &[(Value, Value)],
    keys: &[&str],
) -> Result<Option<String>, &'static str> {
    let Some(value) = map_get_exact_any(entries, keys) else {
        return Ok(None);
    };
    match value {
        Value::String(raw) if !raw.trim().is_empty() => Ok(Some(raw.clone())),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_step_op_v0(entries: &[(Value, Value)]) -> Result<String, &'static str> {
    let op = map_get_exact_any(entries, &["op"])
        .and_then(keyword_or_string)
        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if op.trim().is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    Ok(op)
}

fn parse_step_routes_v0(
    routes_value: Option<&Value>,
) -> Result<Option<BTreeMap<String, String>>, &'static str> {
    let Some(routes_value) = routes_value else {
        return Ok(None);
    };
    let routes_entries = expect_map_entries(routes_value, "routes must be map")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let mut routes = BTreeMap::new();
    for (route_key, route_target) in routes_entries {
        let route_atom =
            parse_route_atom_value_v0(route_key).map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
        let target = match route_target {
            Value::String(raw) if !raw.trim().is_empty() => raw.clone(),
            _ => return Err(PW_PROTOCOL_SCHEMA_MISMATCH),
        };
        routes.insert(route_atom, target);
    }
    Ok(Some(routes))
}

fn parse_eval_ir_step_v0(value: &Value) -> Result<EvalIrStepV0, &'static str> {
    let entries = eval_ir_step_entries_v0(value)?;
    let step_id = parse_required_string_field_v0(entries, &["step_id"])?;
    let op = parse_step_op_v0(entries)?;
    let path = parse_optional_string_field_v0(entries, &["path"])?;
    let value = map_get_exact_any(entries, &["value"]).cloned();
    let emission = map_get_exact_any(entries, &["emission"]).cloned();
    let capability_id = map_get_exact_any(entries, &["capability_id"])
        .and_then(keyword_or_string)
        .filter(|value| !value.trim().is_empty());
    let operation = map_get_exact_any(entries, &["operation"])
        .and_then(keyword_or_string)
        .filter(|value| !value.trim().is_empty());
    let args = map_get_exact_any(entries, &["args"]).cloned();
    let next_step_id = parse_optional_string_field_v0(entries, &["next_step_id"])?;
    let obligations = match map_get_exact_any(entries, &["obligations"]) {
        Some(value) => Some(
            expect_sequence_values(value, "join obligations must be sequence")
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
                .to_vec(),
        ),
        None => None,
    };
    let policy = map_get_exact_any(entries, &["policy"])
        .and_then(keyword_or_string)
        .filter(|value| !value.trim().is_empty());
    let on_timeout = map_get_exact_any(entries, &["on_timeout"]).cloned();
    let rules = map_get_exact_any(entries, &["rules"]).cloned();
    let rules_sexpr = map_get_exact_any(entries, &["rules_sexpr"])
        .and_then(keyword_or_string)
        .filter(|value| !value.trim().is_empty());
    let routes = parse_step_routes_v0(map_get_exact_any(entries, &["routes"]))?;

    Ok(EvalIrStepV0 {
        step_id,
        op,
        path,
        value,
        emission,
        capability_id,
        operation,
        args,
        next_step_id,
        obligations,
        policy,
        on_timeout,
        rules,
        rules_sexpr,
        routes,
    })
}

fn parse_eval_ir_plan_v0(value: &Value) -> Result<EvalIrPlanV0, &'static str> {
    let entries = eval_ir_entries_v0(value)?;
    let format_id = parse_required_string_field_v0(entries, &["format_id"])?;
    let ir_version = parse_required_string_field_v0(entries, &["ir_version"])?;
    let artifact_hash = match map_get_exact_any(entries, &["artifact_hash"]) {
        Some(value) => Some(
            parse_digest_value(value)
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
                .prefixed(),
        ),
        None => None,
    };
    let entry_step_id = parse_required_string_field_v0(entries, &["entry_step_id"])?;
    let steps_value = map_get_exact_any(entries, &["steps"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let steps_values = expect_sequence_values(steps_value, "eval_ir steps must be sequence")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let mut steps = Vec::with_capacity(steps_values.len());
    for step_value in steps_values {
        steps.push(parse_eval_ir_step_v0(step_value)?);
    }

    Ok(EvalIrPlanV0 {
        format_id,
        ir_version,
        artifact_hash,
        entry_step_id,
        steps,
    })
}

fn is_valid_eval_step_id_v0(step_id: &str) -> bool {
    step_id.len() == 5
        && step_id.as_bytes()[0] == b'S'
        && step_id.as_bytes()[1..]
            .iter()
            .all(|byte| byte.is_ascii_digit())
}

fn collect_successor_step_ids_v0(step: &EvalIrStepV0) -> Result<Vec<String>, &'static str> {
    match step.op.as_str() {
        "assign" | "emit" | "request" => step
            .next_step_id
            .as_ref()
            .map(|next| vec![next.clone()])
            .ok_or(PW_EVAL_STEP_CONTRACT),
        "join_obligations_v0" => step
            .next_step_id
            .as_ref()
            .map(|next| vec![next.clone()])
            .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH),
        "choose_rules_v0" => {
            let routes = step.routes.as_ref().ok_or(PW_EVAL_STEP_CONTRACT)?;
            if routes.is_empty() {
                return Err(PW_EVAL_STEP_CONTRACT);
            }
            Ok(routes.values().cloned().collect())
        }
        "end" => Ok(Vec::new()),
        _ => Err(PW_EVAL_STEP_CONTRACT),
    }
}

fn validate_eval_ir_plan_v0(plan: &EvalIrPlanV0) -> Vec<String> {
    let mut errors = Vec::new();
    if plan.format_id != "portable_workflow.eval_ir.v0" {
        errors.push(PW_EVAL_STATE_INVALID.to_string());
    }
    if plan.ir_version != "v0" {
        errors.push(PW_EVAL_STATE_INVALID.to_string());
    }
    if plan.steps.is_empty() {
        errors.push(PW_EVAL_STEP_IDENTITY.to_string());
        return order_failure_codes(errors);
    }

    let mut step_ids = Vec::with_capacity(plan.steps.len());
    let mut seen_step_ids = BTreeSet::new();
    let mut end_count = 0usize;

    for step in &plan.steps {
        step_ids.push(step.step_id.as_str());
        if !is_valid_eval_step_id_v0(&step.step_id) {
            errors.push(PW_EVAL_STEP_IDENTITY.to_string());
        }
        if !seen_step_ids.insert(step.step_id.clone()) {
            errors.push(PW_EVAL_STEP_IDENTITY.to_string());
        }
        if step.op == "end" {
            end_count += 1;
        }

        match step.op.as_str() {
            "assign" => {
                if step.path.as_deref().is_none()
                    || step.value.is_none()
                    || step.next_step_id.is_none()
                {
                    errors.push(PW_EVAL_STEP_CONTRACT.to_string());
                }
            }
            "emit" => {
                if step.emission.is_none() || step.next_step_id.is_none() {
                    errors.push(PW_EVAL_STEP_CONTRACT.to_string());
                }
            }
            "request" => {
                if step.capability_id.is_none()
                    || step.operation.is_none()
                    || step.args.is_none()
                    || step.next_step_id.is_none()
                {
                    errors.push(PW_EVAL_STEP_CONTRACT.to_string());
                }
            }
            "choose_rules_v0" => {
                if step.next_step_id.is_some() {
                    errors.push(PW_EVAL_STEP_CONTRACT.to_string());
                }
                if step.routes.as_ref().is_none_or(|routes| routes.is_empty()) {
                    errors.push(PW_EVAL_STEP_CONTRACT.to_string());
                }
                if let Err(code) = compile_rules_program_from_eval_step_v0(step) {
                    errors.push(code.to_string());
                }
            }
            "join_obligations_v0" => {
                if let Err(code) = parse_join_step_v0(step) {
                    errors.push(code.to_string());
                }
            }
            "end" => {
                if step.next_step_id.is_some() {
                    errors.push(PW_EVAL_STEP_CONTRACT.to_string());
                }
            }
            _ => errors.push(PW_EVAL_STEP_CONTRACT.to_string()),
        }
    }

    if !step_ids.windows(2).all(|window| window[0] < window[1]) {
        errors.push(PW_EVAL_STEP_IDENTITY.to_string());
    }
    if let Some(first_step_id) = step_ids.first() {
        if plan.entry_step_id != *first_step_id {
            errors.push(PW_EVAL_STEP_IDENTITY.to_string());
        }
    }
    if !seen_step_ids.contains(&plan.entry_step_id) {
        errors.push(PW_EVAL_STEP_IDENTITY.to_string());
    }
    if end_count != 1 {
        errors.push(PW_EVAL_STEP_CONTRACT.to_string());
    }

    for step in &plan.steps {
        match collect_successor_step_ids_v0(step) {
            Ok(successors) => {
                for successor in successors {
                    if !seen_step_ids.contains(&successor) || successor <= step.step_id {
                        errors.push(PW_EVAL_STEP_IDENTITY.to_string());
                    }
                }
            }
            Err(code) => errors.push(code.to_string()),
        }
    }

    let step_index = plan
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let mut visited = BTreeSet::new();
    let mut frontier = vec![plan.entry_step_id.clone()];
    while let Some(step_id) = frontier.pop() {
        if !visited.insert(step_id.clone()) {
            continue;
        }
        let Some(step) = step_index.get(step_id.as_str()) else {
            errors.push(PW_EVAL_STEP_IDENTITY.to_string());
            continue;
        };
        let mut successors = match collect_successor_step_ids_v0(step) {
            Ok(successors) => successors,
            Err(code) => {
                errors.push(code.to_string());
                continue;
            }
        };
        successors.reverse();
        for successor in successors {
            if !visited.contains(&successor) {
                frontier.push(successor);
            }
        }
    }
    if visited.len() != plan.steps.len() {
        errors.push(PW_EVAL_STEP_IDENTITY.to_string());
    }

    order_failure_codes(errors)
}

fn mark_eval_error_v0(result: &mut EvalRunResultV0, code: &'static str) {
    result.control = EvalControlV0::Error;
    result.errors.push(code.to_string());
    result.errors = order_failure_codes(std::mem::take(&mut result.errors));
}

fn sha256_prefixed_v0(bytes: &[u8]) -> String {
    format!(
        "{}:{}",
        HashAlgorithm::Sha256.as_str(),
        value_to_hex_lower(&HashAlgorithm::Sha256.compute(bytes))
    )
}

fn compute_eval_request_identity_v0(
    artifact_hash: &str,
    step_id: &str,
    args: &Value,
) -> Result<String, &'static str> {
    let args_bytes = rulia::encode_canonical(args).map_err(|_| PW_EVAL_REQUEST_CANONICALIZATION)?;
    let args_hash = sha256_prefixed_v0(&args_bytes);
    let request_seed = Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("artifact_hash")),
            Value::String(artifact_hash.to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("step_id")),
            Value::String(step_id.to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("request_ordinal")),
            Value::UInt(1),
        ),
        (
            Value::Keyword(Keyword::simple("args_hash")),
            Value::String(args_hash),
        ),
    ]);
    let seed_bytes =
        rulia::encode_canonical(&request_seed).map_err(|_| PW_EVAL_REQUEST_CANONICALIZATION)?;
    Ok(sha256_prefixed_v0(&seed_bytes))
}

fn compute_eval_obligation_id_v0(
    artifact_hash: &str,
    step_id: &str,
    request_id: &str,
) -> Result<String, &'static str> {
    let seed = Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("artifact_id")),
            Value::String(artifact_hash.to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("step_id")),
            Value::String(step_id.to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("request_id")),
            Value::String(request_id.to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("obligation_type")),
            Value::String("receipt_valid".to_string()),
        ),
    ]);
    let seed_bytes =
        rulia::encode_canonical(&seed).map_err(|_| PW_EVAL_REQUEST_CANONICALIZATION)?;
    Ok(sha256_prefixed_v0(&seed_bytes))
}

fn map_entries_from_value_v0(value: &Value) -> Option<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Some(entries.as_slice()),
        Value::Tagged(tagged) => match tagged.value.as_ref() {
            Value::Map(entries) => Some(entries.as_slice()),
            _ => None,
        },
        _ => None,
    }
}

fn max_steps_from_gamma_core_v0(gamma_core: Option<&Value>) -> usize {
    let Some(gamma_core) = gamma_core else {
        return 10;
    };
    let Some(entries) = map_entries_from_value_v0(gamma_core) else {
        return 10;
    };
    let from_gamma = map_get_any(entries, &["max_steps"]).and_then(|value| match value {
        Value::UInt(value) if *value > 0 => Some(*value as usize),
        Value::Int(value) if *value > 0 => Some(*value as usize),
        _ => None,
    });
    from_gamma.unwrap_or(10)
}

fn parse_join_policy_v0(policy: Option<&str>) -> Result<JoinPolicyV0, &'static str> {
    let Some(policy) = policy else {
        return Ok(JoinPolicyV0::AllOf);
    };
    match policy.trim().trim_start_matches(':') {
        "all_of" => Ok(JoinPolicyV0::AllOf),
        "any_of" => Ok(JoinPolicyV0::AnyOf),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_join_obligation_request_hash_v0(obligation: &Value) -> Result<String, &'static str> {
    let obligation_entries =
        map_entries_from_value_v0(obligation).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let format = map_get_any(obligation_entries, &["format"])
        .and_then(keyword_or_string)
        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let normalized_format = normalized_lookup_key(format.trim()).to_ascii_lowercase();
    if normalized_format != "rulia_obligation_v0" {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let obligation_type = map_get_any(obligation_entries, &["obligation_type"])
        .and_then(keyword_or_string)
        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if obligation_type.trim().trim_start_matches(':') != "receipt_valid" {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let params_value =
        map_get_any(obligation_entries, &["params"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let params_entries =
        map_entries_from_value_v0(params_value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let request_hash_value =
        map_get_any(params_entries, &["request_hash"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let request_hash =
        parse_digest_value(request_hash_value).map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    Ok(request_hash.prefixed())
}

fn parse_join_step_v0(step: &EvalIrStepV0) -> Result<ParsedJoinStepV0, &'static str> {
    let obligations_value = step
        .obligations
        .as_ref()
        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if obligations_value.is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let mut obligations = Vec::with_capacity(obligations_value.len());
    for obligation in obligations_value {
        obligations.push(parse_join_obligation_request_hash_v0(obligation)?);
    }
    let policy = parse_join_policy_v0(step.policy.as_deref())?;
    if step
        .on_timeout
        .as_ref()
        .is_some_and(|value| !matches!(value, Value::Nil))
    {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let next_step_id = step
        .next_step_id
        .clone()
        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    Ok(ParsedJoinStepV0 {
        obligations,
        policy,
        next_step_id,
    })
}

fn parse_evalir_history_receipt_v0(
    item: &Value,
    index: usize,
) -> Result<Option<EvalIrHistoryReceiptV0>, &'static str> {
    let item_entries = map_entries_from_value_v0(item).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let receipt_value = if let Some(receipt_value) = map_get_any(item_entries, &["receipt"]) {
        receipt_value
    } else if map_get_any(item_entries, &["request_hash"]).is_some() {
        item
    } else {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    };
    let receipt_entries =
        map_entries_from_value_v0(receipt_value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let request_hash = parse_digest_value(
        map_get_any(receipt_entries, &["request_hash"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?,
    )
    .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
    .prefixed();

    let signer_key_id = map_get_any(receipt_entries, &["signer_key_id"])
        .and_then(keyword_or_string)
        .or_else(|| {
            map_get_any(receipt_entries, &["attestation"])
                .and_then(map_entries_from_value_v0)
                .and_then(|attestation| map_get_any(attestation, &["signer_key_id"]))
                .and_then(keyword_or_string)
        })
        .filter(|value| !value.trim().is_empty());
    let signature_valid = map_get_any(receipt_entries, &["signature_valid"])
        .and_then(|value| match value {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        })
        .or_else(|| {
            map_get_any(receipt_entries, &["attestation"])
                .and_then(map_entries_from_value_v0)
                .and_then(|attestation| map_get_any(attestation, &["signature_valid"]))
                .and_then(|value| match value {
                    Value::Bool(flag) => Some(*flag),
                    _ => None,
                })
        });
    let history_index = map_get_exact_any(item_entries, &["history_index"])
        .and_then(|value| match value {
            Value::UInt(value) => Some(*value),
            Value::Int(value) if *value >= 0 => Some(*value as u64),
            _ => None,
        })
        .unwrap_or(index as u64);

    let receipt_bytes =
        rulia::encode_canonical(receipt_value).map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    Ok(Some(EvalIrHistoryReceiptV0 {
        history_index,
        source_path: format!("history_prefix.items[{index}]"),
        canonical_receipt_hash: sha256_prefixed_v0(&receipt_bytes),
        request_hash,
        signer_key_id,
        signature_valid,
    }))
}

fn parse_evalir_history_receipts_v0(
    history_prefix: Option<&Value>,
) -> Result<Vec<EvalIrHistoryReceiptV0>, &'static str> {
    let Some(history_prefix) = history_prefix else {
        return Ok(Vec::new());
    };
    let history_entries = match history_prefix {
        Value::Nil => Vec::new(),
        Value::Vector(entries) | Value::Set(entries) => entries.clone(),
        _ => {
            let Some(entries) = map_entries_from_value_v0(history_prefix) else {
                return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
            };
            if let Some(items_value) = map_get_exact_any(entries, &["receipts"]) {
                expect_sequence_values(items_value, "history items must be sequence")
                    .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
                    .to_vec()
            } else if map_get_any(entries, &["request_hash"]).is_some() {
                vec![history_prefix.clone()]
            } else {
                return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
            }
        }
    };

    let mut receipts = Vec::new();
    for (index, item) in history_entries.iter().enumerate() {
        if let Some(receipt) = parse_evalir_history_receipt_v0(item, index)? {
            receipts.push(receipt);
        }
    }
    receipts.sort_by(|left, right| {
        left.history_index.cmp(&right.history_index).then_with(|| {
            left.canonical_receipt_hash
                .cmp(&right.canonical_receipt_hash)
        })
    });
    Ok(receipts)
}

fn parse_evalir_join_trust_context_v0(
    gamma_core: Option<&Value>,
) -> Result<EvalIrTrustContextV0, &'static str> {
    let Some(gamma_core) = gamma_core else {
        return Ok(EvalIrTrustContextV0 {
            trusted_signer_keys: None,
        });
    };
    let Some(entries) = map_entries_from_value_v0(gamma_core) else {
        return Ok(EvalIrTrustContextV0 {
            trusted_signer_keys: None,
        });
    };
    let signer_keys =
        map_get_any(entries, &["trusted_signer_keys", "trust_signer_keys"]).or_else(|| {
            map_get_any(entries, &["trust"])
                .and_then(map_entries_from_value_v0)
                .and_then(|trust_entries| {
                    map_get_any(trust_entries, &["trusted_signer_keys", "signer_keys"])
                })
        });
    let Some(signer_keys) = signer_keys else {
        return Ok(EvalIrTrustContextV0 {
            trusted_signer_keys: None,
        });
    };
    let parsed = parse_string_set(signer_keys, "trusted_signer_keys must be sequence")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    Ok(EvalIrTrustContextV0 {
        trusted_signer_keys: Some(parsed),
    })
}

fn obligation_is_satisfied_evalir_v0(
    request_hash: &str,
    history_receipts: &[EvalIrHistoryReceiptV0],
    trust_context: &EvalIrTrustContextV0,
) -> EvalIrObligationSatisfactionV0 {
    let mut matching_receipts = history_receipts
        .iter()
        .filter(|candidate| candidate.request_hash == request_hash)
        .collect::<Vec<_>>();
    matching_receipts.sort_by(|left, right| {
        left.history_index
            .cmp(&right.history_index)
            .then_with(|| {
                left.canonical_receipt_hash
                    .cmp(&right.canonical_receipt_hash)
            })
            .then_with(|| left.source_path.cmp(&right.source_path))
    });

    if matching_receipts.is_empty() {
        return EvalIrObligationSatisfactionV0 { satisfied: false };
    }
    if trust_context.trusted_signer_keys.is_none() {
        return EvalIrObligationSatisfactionV0 { satisfied: true };
    }

    let trusted_signer_keys = trust_context
        .trusted_signer_keys
        .as_ref()
        .expect("checked is_some above");
    for candidate in matching_receipts {
        let signer_trusted = candidate
            .signer_key_id
            .as_ref()
            .is_some_and(|signer_key_id| trusted_signer_keys.contains(signer_key_id));
        if signer_trusted && candidate.signature_valid == Some(true) {
            return EvalIrObligationSatisfactionV0 { satisfied: true };
        }
    }

    EvalIrObligationSatisfactionV0 { satisfied: false }
}

fn map_key_matches_segment_v0(key: &Value, segment: &str) -> bool {
    value_key_name(key)
        .map(|key_name| normalized_lookup_key(&key_name) == normalized_lookup_key(segment))
        .unwrap_or(false)
}

fn assign_segments_v0(state: &mut Value, segments: &[&str], value: Value) {
    if segments.len() == 1 {
        if !matches!(state, Value::Map(_)) {
            *state = Value::Map(Vec::new());
        }
        let entries = match state {
            Value::Map(entries) => entries,
            _ => unreachable!(),
        };
        if let Some((_, current)) = entries
            .iter_mut()
            .find(|(key, _)| map_key_matches_segment_v0(key, segments[0]))
        {
            *current = value;
        } else {
            entries.push((Value::String(segments[0].to_string()), value));
        }
        return;
    }

    if !matches!(state, Value::Map(_)) {
        *state = Value::Map(Vec::new());
    }
    let entries = match state {
        Value::Map(entries) => entries,
        _ => unreachable!(),
    };
    let index = if let Some(index) = entries
        .iter()
        .position(|(key, _)| map_key_matches_segment_v0(key, segments[0]))
    {
        index
    } else {
        entries.push((
            Value::String(segments[0].to_string()),
            Value::Map(Vec::new()),
        ));
        entries.len() - 1
    };
    if !matches!(entries[index].1, Value::Map(_)) {
        entries[index].1 = Value::Map(Vec::new());
    }
    assign_segments_v0(&mut entries[index].1, &segments[1..], value);
}

fn apply_assign_v0(state: &mut Value, path: &str, value: Value) -> Result<(), ()> {
    let segments = path.split('.').map(str::trim).collect::<Vec<_>>();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(());
    }
    assign_segments_v0(state, &segments, value);
    Ok(())
}

fn parse_rules_program_from_eval_step_v0(step: &EvalIrStepV0) -> Result<Value, &'static str> {
    match (step.rules.as_ref(), step.rules_sexpr.as_ref()) {
        (Some(_), Some(_)) | (None, None) => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
        (Some(rules), None) => Ok(rules.clone()),
        (None, Some(rules_sexpr)) => parse_rules_sexpr_program_v0(rules_sexpr.as_str()),
    }
}

fn compile_rules_program_from_eval_step_v0(
    step: &EvalIrStepV0,
) -> Result<CompiledRulesProgramV0, &'static str> {
    let rules_program = parse_rules_program_from_eval_step_v0(step)?;
    parse_rules_program_v0(&rules_program, &[])
}

fn evaluate_choose_rules_step_v0(step: &EvalIrStepV0) -> Result<String, &'static str> {
    let routes = step.routes.as_ref().ok_or(PW_EVAL_STEP_CONTRACT)?;
    if routes.is_empty() {
        return Err(PW_EVAL_STEP_CONTRACT);
    }
    let program = compile_rules_program_from_eval_step_v0(step)?;
    let selected_route = evaluate_rules_program_v0(&program)?.selected_route;
    routes.get(&selected_route).cloned().ok_or(PW_EVAL_NO_MATCH)
}

fn evaluate_eval_ir_v0(
    plan: &EvalIrPlanV0,
    eval_ir_bytes: &[u8],
    initial_state: Value,
    history_prefix: Option<&Value>,
    gamma_core: Option<&Value>,
) -> EvalRunResultV0 {
    let mut result = EvalRunResultV0 {
        control: EvalControlV0::Continue,
        state_out: initial_state,
        emissions: Vec::new(),
        errors: Vec::new(),
    };
    let validation_errors = validate_eval_ir_plan_v0(plan);
    if !validation_errors.is_empty() {
        result.control = EvalControlV0::Error;
        result.errors = validation_errors;
        return result;
    }

    let step_index = plan
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let artifact_hash = plan
        .artifact_hash
        .clone()
        .unwrap_or_else(|| sha256_prefixed_v0(eval_ir_bytes));
    let max_steps = max_steps_from_gamma_core_v0(gamma_core);
    let mut current_step_id = plan.entry_step_id.clone();

    for _ in 0..max_steps {
        let Some(step) = step_index.get(current_step_id.as_str()) else {
            mark_eval_error_v0(&mut result, PW_EVAL_STEP_IDENTITY);
            return result;
        };
        match step.op.as_str() {
            "assign" => {
                let Some(path) = step.path.as_deref() else {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                };
                let Some(value) = step.value.clone() else {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                };
                if apply_assign_v0(&mut result.state_out, path, value).is_err() {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                }
                let Some(next_step_id) = step.next_step_id.as_ref() else {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_IDENTITY);
                    return result;
                };
                current_step_id = next_step_id.clone();
            }
            "emit" => {
                let Some(emission) = step.emission.clone() else {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                };
                result.emissions.push(emission);
                let Some(next_step_id) = step.next_step_id.as_ref() else {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_IDENTITY);
                    return result;
                };
                current_step_id = next_step_id.clone();
            }
            "request" => {
                if step.capability_id.as_ref().is_none() {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                }
                if step.operation.as_ref().is_none() {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                }
                let Some(args) = step.args.clone() else {
                    mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                    return result;
                };
                let request_id = match compute_eval_request_identity_v0(
                    artifact_hash.as_str(),
                    step.step_id.as_str(),
                    &args,
                ) {
                    Ok(request_id) => request_id,
                    Err(code) => {
                        mark_eval_error_v0(&mut result, code);
                        return result;
                    }
                };
                if let Err(code) = compute_eval_obligation_id_v0(
                    artifact_hash.as_str(),
                    step.step_id.as_str(),
                    request_id.as_str(),
                ) {
                    mark_eval_error_v0(&mut result, code);
                    return result;
                }
                result.control = EvalControlV0::Suspend;
                return result;
            }
            "choose_rules_v0" => {
                let next_step_id = match evaluate_choose_rules_step_v0(step) {
                    Ok(next_step_id) => next_step_id,
                    Err(code) => {
                        mark_eval_error_v0(&mut result, code);
                        return result;
                    }
                };
                current_step_id = next_step_id;
            }
            "join_obligations_v0" => {
                let join_step = match parse_join_step_v0(step) {
                    Ok(join_step) => join_step,
                    Err(code) => {
                        mark_eval_error_v0(&mut result, code);
                        return result;
                    }
                };
                let history_receipts = match parse_evalir_history_receipts_v0(history_prefix) {
                    Ok(history_receipts) => history_receipts,
                    Err(code) => {
                        mark_eval_error_v0(&mut result, code);
                        return result;
                    }
                };
                let trust_context = match parse_evalir_join_trust_context_v0(gamma_core) {
                    Ok(trust_context) => trust_context,
                    Err(code) => {
                        mark_eval_error_v0(&mut result, code);
                        return result;
                    }
                };
                let aggregate_satisfied = match join_step.policy {
                    JoinPolicyV0::AllOf => join_step.obligations.iter().all(|request_hash| {
                        obligation_is_satisfied_evalir_v0(
                            request_hash,
                            history_receipts.as_slice(),
                            &trust_context,
                        )
                        .satisfied
                    }),
                    JoinPolicyV0::AnyOf => join_step.obligations.iter().any(|request_hash| {
                        obligation_is_satisfied_evalir_v0(
                            request_hash,
                            history_receipts.as_slice(),
                            &trust_context,
                        )
                        .satisfied
                    }),
                };
                if !aggregate_satisfied {
                    result.control = EvalControlV0::Suspend;
                    return result;
                }
                current_step_id = join_step.next_step_id;
            }
            "end" => {
                result.control = EvalControlV0::End;
                return result;
            }
            _ => {
                mark_eval_error_v0(&mut result, PW_EVAL_STEP_CONTRACT);
                return result;
            }
        }
    }

    result
}

fn eval_control_keyword_v0(control: EvalControlV0) -> &'static str {
    match control {
        EvalControlV0::Continue => "continue",
        EvalControlV0::Suspend => "suspend",
        EvalControlV0::End => "end",
        EvalControlV0::Error => "error",
    }
}

fn pw_eval_evalir_result_bytes(result: &EvalRunResultV0) -> Option<Vec<u8>> {
    let ordered_failure_codes = order_failure_codes(result.errors.clone());
    let primary_failure_code = ordered_failure_codes.first().cloned();
    let failure_codes_value = Value::Vector(
        ordered_failure_codes
            .iter()
            .map(|code| Value::String(code.clone()))
            .collect::<Vec<_>>(),
    );

    let eval_result = Value::Tagged(TaggedValue::new(
        Symbol::simple("eval_run_result_v0"),
        Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("format")),
                Value::Keyword(Keyword::simple("rulia_pw_eval_run_result_v0")),
            ),
            (
                Value::Keyword(Keyword::simple("terminal_control")),
                Value::Keyword(Keyword::simple(eval_control_keyword_v0(result.control))),
            ),
            (
                Value::Keyword(Keyword::simple("step_results")),
                Value::Vector(Vec::new()),
            ),
            (
                Value::Keyword(Keyword::simple("primary_failure_code")),
                primary_failure_code.map_or(Value::Nil, Value::String),
            ),
            (
                Value::Keyword(Keyword::simple("failure_codes")),
                failure_codes_value,
            ),
        ]),
    ));
    rulia::encode_canonical(&eval_result).ok()
}

impl<'a> RulesSExprParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            cursor: 0,
            token_count: 0,
        }
    }

    fn parse_program(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.skip_insignificant();
        let node = self.parse_expr()?;
        self.skip_insignificant();
        if self.cursor != self.input.len() {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        }
        Ok(node)
    }

    fn parse_expr(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.skip_insignificant();
        let Some(byte) = self.peek() else {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        };
        match byte {
            b'(' => self.parse_list(),
            b'"' => self.parse_string(),
            b')' => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
            _ => self.parse_atom(),
        }
    }

    fn parse_list(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.consume(b'(')?;
        self.record_token()?;
        let mut items = Vec::new();
        loop {
            self.skip_insignificant();
            let Some(byte) = self.peek() else {
                return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
            };
            if byte == b')' {
                self.cursor += 1;
                self.record_token()?;
                break;
            }
            items.push(self.parse_expr()?);
        }
        Ok(RulesSExprNode::List(items))
    }

    fn parse_string(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.consume(b'"')?;
        self.record_token()?;
        let mut parsed = String::new();

        loop {
            if self.cursor >= self.input.len() {
                return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
            }
            let remaining = std::str::from_utf8(&self.input[self.cursor..])
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
            let mut chars = remaining.chars();
            let current = chars.next().ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
            self.cursor += current.len_utf8();
            match current {
                '"' => break,
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
                    };
                    self.cursor += 1;
                    let translated = match escaped {
                        b'\\' => '\\',
                        b'"' => '"',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => return Err(PW_PROTOCOL_SCHEMA_MISMATCH),
                    };
                    parsed.push(translated);
                }
                _ => parsed.push(current),
            }
        }

        Ok(RulesSExprNode::String(parsed))
    }

    fn parse_atom(&mut self) -> Result<RulesSExprNode, &'static str> {
        let start = self.cursor;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'#') {
                break;
            }
            self.cursor += 1;
        }
        if self.cursor == start {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        }
        let token = std::str::from_utf8(&self.input[start..self.cursor])
            .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
        self.record_token()?;
        if token == "true" {
            return Ok(RulesSExprNode::Bool(true));
        }
        if token == "false" {
            return Ok(RulesSExprNode::Bool(false));
        }
        if let Some(variable_name) = parse_rules_sexpr_variable_token_v0(token) {
            return Ok(RulesSExprNode::Variable(variable_name));
        }
        if is_rules_sexpr_number_token_v0(token) {
            return Ok(RulesSExprNode::Number(token.to_string()));
        }
        Ok(RulesSExprNode::Token(token.to_string()))
    }

    fn skip_insignificant(&mut self) {
        loop {
            while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                self.cursor += 1;
            }
            if self.peek() == Some(b'#') {
                while let Some(byte) = self.peek() {
                    self.cursor += 1;
                    if byte == b'\n' {
                        break;
                    }
                }
                continue;
            }
            break;
        }
    }

    fn consume(&mut self, expected: u8) -> Result<(), &'static str> {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            Ok(())
        } else {
            Err(PW_PROTOCOL_SCHEMA_MISMATCH)
        }
    }

    fn record_token(&mut self) -> Result<(), &'static str> {
        self.token_count = self
            .token_count
            .checked_add(1)
            .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
        if self.token_count > PW_MAX_RULES_SEXPR_TOKENS {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }
}

fn parse_rules_sexpr_variable_token_v0(token: &str) -> Option<String> {
    let name = token.strip_prefix('?')?;
    if !is_rules_sexpr_identifier_v0(name) {
        return None;
    }
    Some(name.to_string())
}

fn is_rules_sexpr_identifier_v0(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_rules_sexpr_number_token_v0(token: &str) -> bool {
    token.bytes().any(|byte| byte.is_ascii_digit())
        && (token.parse::<i64>().is_ok()
            || token.parse::<u64>().is_ok()
            || token.parse::<f64>().is_ok())
}

fn parse_rules_sexpr_program_v0(source: &str) -> Result<Value, &'static str> {
    if source.len() > PW_MAX_RULES_SEXPR_BYTES {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let mut parser = RulesSExprParser::new(source);
    let root = parser.parse_program()?;
    let root_items = rules_sexpr_expect_list_v0(&root)?;
    if root_items.len() < 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token_v0(&root_items[0], "rules-sexpr-v0")?;

    let mut facts = None;
    let mut rules = None;
    let mut query = None;
    let mut routing_policy = None;
    for clause in &root_items[1..] {
        let clause_items = rules_sexpr_expect_list_v0(clause)?;
        if clause_items.is_empty() {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        }
        let clause_name = rules_sexpr_expect_token_v0(&clause_items[0])?;
        match clause_name {
            "facts" => {
                if facts.is_some() {
                    return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
                }
                facts = Some(parse_rules_sexpr_facts_clause_v0(clause_items)?);
            }
            "rules" => {
                if rules.is_some() {
                    return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
                }
                rules = Some(parse_rules_sexpr_rules_clause_v0(clause_items)?);
            }
            "query" => {
                if query.is_some() {
                    return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
                }
                query = Some(parse_rules_sexpr_query_clause_v0(clause_items)?);
            }
            "routing_policy" => {
                if routing_policy.is_some() {
                    return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
                }
                routing_policy = Some(parse_rules_sexpr_routing_clause_v0(clause_items)?);
            }
            _ => return Err(PW_PROTOCOL_SCHEMA_MISMATCH),
        }
    }

    let program = Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("facts")),
            Value::Vector(facts.ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?),
        ),
        (
            Value::Keyword(Keyword::simple("rules")),
            Value::Vector(rules.ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?),
        ),
        (
            Value::Keyword(Keyword::simple("query")),
            query.ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?,
        ),
        (
            Value::Keyword(Keyword::simple("routing_policy")),
            routing_policy.ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?,
        ),
    ]);
    normalize_rules_sexpr_program_v0(&program)
}

fn rules_sexpr_expect_list_v0(node: &RulesSExprNode) -> Result<&[RulesSExprNode], &'static str> {
    match node {
        RulesSExprNode::List(items) => Ok(items),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn rules_sexpr_expect_token_v0(node: &RulesSExprNode) -> Result<&str, &'static str> {
    match node {
        RulesSExprNode::Token(token) => Ok(token.as_str()),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn rules_sexpr_expect_exact_token_v0(
    node: &RulesSExprNode,
    expected: &str,
) -> Result<(), &'static str> {
    if rules_sexpr_expect_token_v0(node)? == expected {
        Ok(())
    } else {
        Err(PW_PROTOCOL_SCHEMA_MISMATCH)
    }
}

fn parse_rules_sexpr_facts_clause_v0(items: &[RulesSExprNode]) -> Result<Vec<Value>, &'static str> {
    let fact_count = items.len().saturating_sub(1);
    if fact_count > PW_MAX_RULES_SEXPR_FACTS {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let mut facts = Vec::with_capacity(fact_count);
    for fact in &items[1..] {
        facts.push(parse_rules_sexpr_pattern_v0(fact, false)?);
    }
    Ok(facts)
}

fn parse_rules_sexpr_rules_clause_v0(items: &[RulesSExprNode]) -> Result<Vec<Value>, &'static str> {
    let rule_count = items.len().saturating_sub(1);
    if rule_count > PW_MAX_RULES_SEXPR_RULES {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let mut rules = Vec::with_capacity(rule_count);
    for rule in &items[1..] {
        rules.push(parse_rules_sexpr_rule_v0(rule)?);
    }
    Ok(rules)
}

fn parse_rules_sexpr_rule_v0(node: &RulesSExprNode) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list_v0(node)?;
    if items.len() < 3 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let body_term_count = items.len().saturating_sub(2);
    if body_term_count > PW_MAX_RULES_SEXPR_BODY_TERMS_PER_RULE {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token_v0(&items[0], ":-")?;
    let head = parse_rules_sexpr_pattern_v0(&items[1], true)?;
    let mut body = Vec::with_capacity(body_term_count);
    for item in &items[2..] {
        body.push(parse_rules_sexpr_body_item_v0(item)?);
    }
    Ok(Value::Map(vec![
        (Value::Keyword(Keyword::simple("head")), head),
        (Value::Keyword(Keyword::simple("body")), Value::Vector(body)),
    ]))
}

fn parse_rules_sexpr_body_item_v0(node: &RulesSExprNode) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list_v0(node)?;
    if items.is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    if let Ok(op) = rules_sexpr_expect_token_v0(&items[0]) {
        if is_builtin_operator_v0(op) {
            return parse_rules_sexpr_builtin_v0(op, items);
        }
    }
    parse_rules_sexpr_pattern_v0(node, true)
}

fn parse_rules_sexpr_builtin_v0(op: &str, items: &[RulesSExprNode]) -> Result<Value, &'static str> {
    if items.len() != 3 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let left = parse_rules_sexpr_term_v0(&items[1], true, PW_EVAL_FORBIDDEN_FEATURE)?;
    let right = if op == "in" {
        let set_items = rules_sexpr_expect_list_v0(&items[2]).map_err(|_| PW_EVAL_TYPE_MISMATCH)?;
        if set_items.is_empty() {
            return Err(PW_EVAL_TYPE_MISMATCH);
        }
        rules_sexpr_expect_exact_token_v0(&set_items[0], "set")
            .map_err(|_| PW_EVAL_TYPE_MISMATCH)?;
        let mut values = Vec::with_capacity(set_items.len().saturating_sub(1));
        for member in &set_items[1..] {
            values.push(parse_rules_sexpr_literal_set_member_v0(member)?);
        }
        Value::Vector(values)
    } else {
        parse_rules_sexpr_term_v0(&items[2], true, PW_EVAL_FORBIDDEN_FEATURE)?
    };
    Ok(Value::Vector(vec![
        Value::String(op.to_string()),
        left,
        right,
    ]))
}

fn parse_rules_sexpr_literal_set_member_v0(node: &RulesSExprNode) -> Result<Value, &'static str> {
    match node {
        RulesSExprNode::Variable(_) | RulesSExprNode::List(_) => Err(PW_EVAL_TYPE_MISMATCH),
        _ => parse_rules_sexpr_term_v0(node, false, PW_EVAL_TYPE_MISMATCH),
    }
}

fn parse_rules_sexpr_query_clause_v0(items: &[RulesSExprNode]) -> Result<Value, &'static str> {
    if items.len() != 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    parse_rules_sexpr_pattern_v0(&items[1], true)
}

fn parse_rules_sexpr_routing_clause_v0(items: &[RulesSExprNode]) -> Result<Value, &'static str> {
    if items.len() != 4 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    parse_rules_sexpr_route_predicate_v0(&items[1])?;
    let no_match_policy = parse_rules_sexpr_no_match_policy_v0(&items[2])?;
    let ambiguous_policy = parse_rules_sexpr_ambiguous_policy_v0(&items[3])?;
    Ok(Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("route_predicate")),
            Value::String("route".to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("no_match_policy")),
            no_match_policy,
        ),
        (
            Value::Keyword(Keyword::simple("ambiguous_policy")),
            Value::String(ambiguous_policy),
        ),
    ]))
}

fn parse_rules_sexpr_route_predicate_v0(node: &RulesSExprNode) -> Result<(), &'static str> {
    let items = rules_sexpr_expect_list_v0(node)?;
    if items.len() != 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token_v0(&items[0], "route_predicate")?;
    rules_sexpr_expect_exact_token_v0(&items[1], "route")?;
    Ok(())
}

fn parse_rules_sexpr_no_match_policy_v0(node: &RulesSExprNode) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list_v0(node)?;
    if items.len() != 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token_v0(&items[0], "no_match_policy")?;
    if let Ok(token) = rules_sexpr_expect_token_v0(&items[1]) {
        if token == "error" {
            return Ok(Value::String("error".to_string()));
        }
    }
    let default_items = rules_sexpr_expect_list_v0(&items[1])?;
    if default_items.len() != 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token_v0(&default_items[0], "default")?;
    let route_token = rules_sexpr_expect_token_v0(&default_items[1])?;
    if !is_rules_sexpr_identifier_v0(route_token) {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    Ok(Value::Map(vec![(
        Value::Keyword(Keyword::simple("default")),
        Value::String(format!(":{route_token}")),
    )]))
}

fn parse_rules_sexpr_ambiguous_policy_v0(node: &RulesSExprNode) -> Result<String, &'static str> {
    let items = rules_sexpr_expect_list_v0(node)?;
    if items.len() != 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token_v0(&items[0], "ambiguous_policy")?;
    match rules_sexpr_expect_token_v0(&items[1])? {
        "allow_multiple" => Ok("choose-first".to_string()),
        "error" => Ok("error".to_string()),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_rules_sexpr_pattern_v0(
    node: &RulesSExprNode,
    allow_variables: bool,
) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list_v0(node)?;
    if items.is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let predicate = rules_sexpr_expect_token_v0(&items[0])?;
    if !is_rules_sexpr_identifier_v0(predicate) {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let mut pattern = Vec::with_capacity(items.len());
    pattern.push(Value::String(predicate.to_string()));
    for term in &items[1..] {
        pattern.push(parse_rules_sexpr_term_v0(
            term,
            allow_variables,
            PW_EVAL_FORBIDDEN_FEATURE,
        )?);
    }
    Ok(Value::Vector(pattern))
}

fn parse_rules_sexpr_number_value_v0(raw: &str) -> Result<Value, &'static str> {
    if raw.contains('.') || raw.contains('e') || raw.contains('E') {
        return raw
            .parse::<f64>()
            .map(|value| Value::Float64(value.into()))
            .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(Value::Int(value));
    }
    if let Ok(value) = raw.parse::<u64>() {
        return Ok(Value::UInt(value));
    }
    Err(PW_PROTOCOL_SCHEMA_MISMATCH)
}

fn parse_rules_sexpr_term_v0(
    node: &RulesSExprNode,
    allow_variables: bool,
    nested_term_error: &'static str,
) -> Result<Value, &'static str> {
    match node {
        RulesSExprNode::Variable(name) => {
            if allow_variables {
                Ok(Value::String(format!("?{name}")))
            } else {
                Err(PW_PROTOCOL_SCHEMA_MISMATCH)
            }
        }
        RulesSExprNode::String(value) => Ok(Value::String(value.clone())),
        RulesSExprNode::Number(number) => parse_rules_sexpr_number_value_v0(number),
        RulesSExprNode::Bool(value) => Ok(Value::Bool(*value)),
        RulesSExprNode::Token(token) => {
            if !is_rules_sexpr_identifier_v0(token) {
                return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
            }
            Ok(Value::String(format!(":{token}")))
        }
        RulesSExprNode::List(_) => Err(nested_term_error),
    }
}

fn normalize_rules_sexpr_program_v0(program: &Value) -> Result<Value, &'static str> {
    let program_entries = map_entries_from_value_v0(program).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let facts_value =
        map_get_any(program_entries, &["facts"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let rules_value =
        map_get_any(program_entries, &["rules"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let query = map_get_any(program_entries, &["query"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let routing_policy =
        map_get_any(program_entries, &["routing_policy"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let routing_entries =
        map_entries_from_value_v0(routing_policy).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;

    let mut facts = expect_sequence_values(facts_value, "rules sexpr facts must be sequence")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
        .iter()
        .cloned()
        .map(|value| {
            let sort_key =
                rulia::encode_canonical(&value).map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
            Ok((sort_key, value))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    facts.sort_by(|left, right| left.0.cmp(&right.0));
    facts.dedup_by(|left, right| left.0 == right.0);

    let mut rules = expect_sequence_values(rules_value, "rules sexpr rules must be sequence")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
        .iter()
        .cloned()
        .map(|value| {
            let sort_key =
                rulia::encode_canonical(&value).map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
            Ok((sort_key, value))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    rules.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("facts")),
            Value::Vector(facts.into_iter().map(|(_, value)| value).collect()),
        ),
        (
            Value::Keyword(Keyword::simple("rules")),
            Value::Vector(rules.into_iter().map(|(_, value)| value).collect()),
        ),
        (Value::Keyword(Keyword::simple("query")), query.clone()),
        (
            Value::Keyword(Keyword::simple("routing_policy")),
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("route_predicate")),
                    map_get_any(routing_entries, &["route_predicate"])
                        .cloned()
                        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?,
                ),
                (
                    Value::Keyword(Keyword::simple("no_match_policy")),
                    map_get_any(routing_entries, &["no_match_policy"])
                        .cloned()
                        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?,
                ),
                (
                    Value::Keyword(Keyword::simple("ambiguous_policy")),
                    map_get_any(routing_entries, &["ambiguous_policy"])
                        .cloned()
                        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?,
                ),
            ]),
        ),
    ]))
}

#[derive(Clone, Debug)]
struct EvalRulesInputBytesV0 {
    rules_program_bytes: Vec<u8>,
    facts_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct RulesEvaluationResultV0 {
    selected_route: String,
    route_candidates: Vec<String>,
}

#[derive(Clone, Debug)]
struct RulesPolicyV0 {
    route_predicate: String,
    no_match: NoMatchPolicyV0,
    ambiguous: AmbiguousPolicyV0,
}

#[derive(Clone, Debug)]
struct PredicatePatternV0 {
    predicate: String,
    args: Vec<RulesTermV0>,
}

#[derive(Clone, Debug)]
enum RuleBodyItemV0 {
    Predicate(PredicatePatternV0),
    Builtin(BuiltinCallV0),
}

#[derive(Clone, Debug)]
struct BuiltinCallV0 {
    op: BuiltinOpV0,
    left: RulesTermV0,
    right: BuiltinRhsV0,
}

#[derive(Clone, Debug)]
enum BuiltinRhsV0 {
    Term(RulesTermV0),
    LiteralSet(Vec<RulesLiteralV0>),
}

#[derive(Clone, Debug, Copy)]
enum BuiltinOpV0 {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    In,
}

#[derive(Clone, Debug)]
struct CompiledRuleV0 {
    head: PredicatePatternV0,
    body: Vec<RuleBodyItemV0>,
    sort_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GroundFactV0 {
    predicate: String,
    args: Vec<RulesLiteralV0>,
}

#[derive(Clone, Debug, Copy)]
enum SelectionPolicyV0 {
    CanonicalFirst,
}

#[derive(Clone, Debug)]
enum NoMatchPolicyV0 {
    Error,
    DefaultRoute(String),
}

#[derive(Clone, Debug, Copy)]
enum AmbiguousPolicyV0 {
    Error,
    ChooseFirst,
}

#[derive(Clone, Debug)]
struct CompiledRulesProgramV0 {
    facts: BTreeSet<GroundFactV0>,
    rules: Vec<CompiledRuleV0>,
    query: PredicatePatternV0,
    selection: SelectionPolicyV0,
    no_match: NoMatchPolicyV0,
    ambiguous: AmbiguousPolicyV0,
}

#[derive(Clone, Debug)]
enum RulesTermV0 {
    Var(String),
    Lit(RulesLiteralV0),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RulesLiteralV0 {
    Atom(String),
    String(String),
    Number(String),
    Bool(bool),
}

type RuleBindingsV0 = BTreeMap<String, RulesLiteralV0>;

fn parse_eval_rules_input_bytes_v0(
    value: &Value,
    _input_bytes: &[u8],
) -> Result<EvalRulesInputBytesV0, String> {
    let entries = eval_rules_input_entries(value)?;
    require_canonical_keys(
        entries,
        &["format", "rules_program_bytes"],
        &["format", "rules_program_bytes", "facts_bytes"],
        "eval_rules_input_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_eval_rules_input_v0",
        "eval_rules input format must be :rulia_eval_rules_input_v0",
    )?;
    let rules_program_bytes =
        extract_required_bytes_field(entries, "rules_program_bytes", "rules_program_bytes")?;
    let facts_bytes = extract_optional_bytes_field(entries, "facts_bytes", "facts_bytes")?;
    Ok(EvalRulesInputBytesV0 {
        rules_program_bytes,
        facts_bytes,
    })
}

fn eval_rules_input_entries(value: &Value) -> Result<&[(Value, Value)], String> {
    match value {
        Value::Tagged(tagged) if tagged.tag.as_str() == "eval_rules_input_v0" => {
            expect_map_entries(
                tagged.value.as_ref(),
                "eval rules input payload must be a map",
            )
        }
        _ => Err("eval rules input root tag must be eval_rules_input_v0".to_string()),
    }
}

fn rules_program_entries_v0(value: &Value) -> Result<&[(Value, Value)], &'static str> {
    match value {
        Value::Map(entries) => Ok(entries.as_slice()),
        Value::Tagged(tagged) => {
            let tag = tagged.tag.as_str();
            if tag == "rules_program_v0" {
                return expect_map_entries(
                    tagged.value.as_ref(),
                    "rules program payload must be a map",
                )
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH);
            }
            Err(PW_PROTOCOL_SCHEMA_MISMATCH)
        }
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_rules_program_v0(
    program: &Value,
    additional_facts: &[GroundFactV0],
) -> Result<CompiledRulesProgramV0, &'static str> {
    let entries = rules_program_entries_v0(program)?;

    if let Some(format_id_value) = map_get_any(entries, &["format_id"]) {
        let format_id = keyword_or_string(format_id_value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
        if format_id != "portable_workflow.rules.v0" {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        }
    }
    if let Some(version_value) = map_get_any(entries, &["version"]) {
        let version = keyword_or_string(version_value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
        if version != "v0" {
            return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
        }
    }

    let policy = parse_rules_policy_v0(entries)?;

    let facts_value = map_get_any(entries, &["facts"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let facts_values =
        expect_sequence_values(facts_value, "rules program facts must be a vector/set")
            .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let mut facts = BTreeSet::new();
    let mut arities = BTreeMap::new();
    for fact_value in facts_values {
        let fact = parse_ground_fact_v0(fact_value)?;
        register_predicate_arity_v0(&mut arities, &fact.predicate, fact.args.len())?;
        facts.insert(fact);
    }
    for fact in additional_facts {
        register_predicate_arity_v0(&mut arities, &fact.predicate, fact.args.len())?;
        facts.insert(fact.clone());
    }

    let rules_value = map_get_any(entries, &["rules"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let rules_values =
        expect_sequence_values(rules_value, "rules program rules must be a vector/set")
            .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let mut rules = Vec::with_capacity(rules_values.len());
    for rule_value in rules_values {
        let compiled_rule = parse_rule_v0(rule_value)?;
        register_predicate_arity_v0(
            &mut arities,
            &compiled_rule.head.predicate,
            compiled_rule.head.args.len(),
        )?;
        for item in &compiled_rule.body {
            if let RuleBodyItemV0::Predicate(pattern) = item {
                register_predicate_arity_v0(&mut arities, &pattern.predicate, pattern.args.len())?;
            }
        }
        validate_rule_variable_safety_v0(&compiled_rule)?;
        rules.push(compiled_rule);
    }

    let query_value = map_get_any(entries, &["query"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let query = parse_predicate_pattern_v0(query_value)?;
    register_predicate_arity_v0(&mut arities, &query.predicate, query.args.len())?;
    if query.args.len() != 1 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    if query.predicate != policy.route_predicate {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }

    let topo_rank = rule_topo_ranks_v0(&rules)?;
    rules.sort_by(|left, right| {
        let left_rank = *topo_rank
            .get(left.head.predicate.as_str())
            .expect("head predicate rank must exist");
        let right_rank = *topo_rank
            .get(right.head.predicate.as_str())
            .expect("head predicate rank must exist");
        left_rank
            .cmp(&right_rank)
            .then_with(|| left.sort_key.cmp(&right.sort_key))
    });

    Ok(CompiledRulesProgramV0 {
        facts,
        rules,
        query,
        selection: SelectionPolicyV0::CanonicalFirst,
        no_match: policy.no_match,
        ambiguous: policy.ambiguous,
    })
}

fn parse_rules_policy_v0(entries: &[(Value, Value)]) -> Result<RulesPolicyV0, &'static str> {
    let routing_policy_entries = parse_routing_policy_entries_v0(entries)?;
    let route_predicate = if let Some(routing_entries) = routing_policy_entries {
        let route_predicate_value = map_get_any(routing_entries, &["route_predicate"])
            .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
        parse_route_predicate_v0(route_predicate_value)?
    } else {
        "route".to_string()
    };
    if route_predicate != "route" {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }

    let no_match_value = if let Some(routing_entries) = routing_policy_entries {
        map_get_any(routing_entries, &["no_match_policy"])
            .or_else(|| map_get_any(entries, &["on_no_match"]))
    } else {
        map_get_any(entries, &["on_no_match", "no_match_policy"])
    }
    .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let no_match = parse_no_match_policy_v0(no_match_value)?;

    let ambiguous_value = if let Some(routing_entries) = routing_policy_entries {
        map_get_any(routing_entries, &["ambiguous_policy"])
            .or_else(|| map_get_any(entries, &["on_ambiguous"]))
    } else {
        map_get_any(entries, &["on_ambiguous", "ambiguous_policy"])
    }
    .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let ambiguous = parse_ambiguous_policy_v0(ambiguous_value)?;

    Ok(RulesPolicyV0 {
        route_predicate,
        no_match,
        ambiguous,
    })
}

fn parse_routing_policy_entries_v0(
    entries: &[(Value, Value)],
) -> Result<Option<&[(Value, Value)]>, &'static str> {
    let Some(routing_policy_value) = map_get_any(entries, &["routing_policy"]) else {
        return Ok(None);
    };
    match routing_policy_value {
        Value::Map(routing_entries) => Ok(Some(routing_entries.as_slice())),
        Value::Tagged(tagged) => {
            let tag = tagged.tag.as_str();
            if tag == "routing_policy_v0" {
                return expect_map_entries(
                    tagged.value.as_ref(),
                    "routing_policy must be a map payload",
                )
                .map(Some)
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH);
            }
            Err(PW_PROTOCOL_SCHEMA_MISMATCH)
        }
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_route_predicate_v0(value: &Value) -> Result<String, &'static str> {
    let predicate = keyword_string_or_symbol(value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if predicate.trim() == "route" {
        Ok("route".to_string())
    } else {
        Err(PW_PROTOCOL_SCHEMA_MISMATCH)
    }
}

fn parse_no_match_policy_v0(value: &Value) -> Result<NoMatchPolicyV0, &'static str> {
    if let Some(raw_policy) = keyword_or_string(value) {
        let trimmed = raw_policy.trim();
        if trimmed == "error" {
            return Ok(NoMatchPolicyV0::Error);
        }
        return parse_route_atom_value_v0(value).map(NoMatchPolicyV0::DefaultRoute);
    }

    let Value::Map(entries) = value else {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    };

    if map_get_any(entries, &["kind"])
        .and_then(keyword_or_string)
        .is_some_and(|kind| kind == "error")
    {
        return Ok(NoMatchPolicyV0::Error);
    }

    let default_value = map_get_any(entries, &["default", "route", "default_route"])
        .ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    parse_route_atom_value_v0(default_value).map(NoMatchPolicyV0::DefaultRoute)
}

fn parse_ambiguous_policy_v0(value: &Value) -> Result<AmbiguousPolicyV0, &'static str> {
    let policy = keyword_or_string(value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    match policy.trim() {
        "error" => Ok(AmbiguousPolicyV0::Error),
        "choose_first" | "choose-first" | "allow_multiple" => Ok(AmbiguousPolicyV0::ChooseFirst),
        _ => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_ground_fact_v0(value: &Value) -> Result<GroundFactV0, &'static str> {
    let items = expect_sequence_values(value, "fact must be vector/set")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if items.is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }

    let predicate = parse_predicate_name_v0(&items[0])?;
    let mut args = Vec::with_capacity(items.len().saturating_sub(1));
    for item in &items[1..] {
        let term = parse_term_v0(item)?;
        match term {
            RulesTermV0::Var(_) => return Err(PW_PROTOCOL_SCHEMA_MISMATCH),
            RulesTermV0::Lit(literal) => args.push(literal),
        }
    }

    Ok(GroundFactV0 { predicate, args })
}

fn parse_rule_v0(value: &Value) -> Result<CompiledRuleV0, &'static str> {
    if contains_negation_token_v0(value) {
        return Err(PW_EVAL_FORBIDDEN_FEATURE);
    }

    if let Value::Map(entries) = value {
        let head_value = map_get_any(entries, &["head"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
        let body_value = map_get_any(entries, &["body"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
        let head = parse_predicate_pattern_v0(head_value)?;
        let body_values = expect_sequence_values(body_value, "rule body must be vector/set")
            .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
        let mut body = Vec::with_capacity(body_values.len());
        for body_value in body_values {
            body.push(parse_rule_body_item_v0(body_value)?);
        }
        let sort_key = format_rule_sort_key_v0(&head, &body);
        return Ok(CompiledRuleV0 {
            head,
            body,
            sort_key,
        });
    }

    let items = expect_sequence_values(value, "rule must be map or sexpr vector")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if items.len() < 2 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let operator = keyword_string_or_symbol(&items[0]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if operator != ":-" {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    let head = parse_predicate_pattern_v0(&items[1])?;
    let mut body = Vec::with_capacity(items.len().saturating_sub(2));
    for item in &items[2..] {
        body.push(parse_rule_body_item_v0(item)?);
    }
    let sort_key = format_rule_sort_key_v0(&head, &body);
    Ok(CompiledRuleV0 {
        head,
        body,
        sort_key,
    })
}

fn parse_rule_body_item_v0(value: &Value) -> Result<RuleBodyItemV0, &'static str> {
    if contains_negation_token_v0(value) {
        return Err(PW_EVAL_FORBIDDEN_FEATURE);
    }

    let items = expect_sequence_values(value, "rule body item must be vector/set")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if items.is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }

    let token = keyword_string_or_symbol(&items[0]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if is_builtin_operator_v0(&token) {
        return parse_builtin_call_v0(items).map(RuleBodyItemV0::Builtin);
    }
    Ok(RuleBodyItemV0::Predicate(parse_predicate_pattern_v0(
        value,
    )?))
}

fn parse_builtin_call_v0(items: &[Value]) -> Result<BuiltinCallV0, &'static str> {
    if items.len() != 3 {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }

    let op_token = keyword_string_or_symbol(&items[0]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let op = parse_builtin_operator_v0(&op_token)?;
    let left = parse_term_v0(&items[1])?;

    let right = match op {
        BuiltinOpV0::In => {
            let rhs_items = expect_sequence_values(&items[2], "in rhs must be vector/set")
                .map_err(|_| PW_EVAL_TYPE_MISMATCH)?;
            let mut literals = Vec::with_capacity(rhs_items.len());
            for rhs_item in rhs_items {
                match parse_term_v0(rhs_item)? {
                    RulesTermV0::Var(_) => return Err(PW_EVAL_TYPE_MISMATCH),
                    RulesTermV0::Lit(literal) => literals.push(literal),
                }
            }
            BuiltinRhsV0::LiteralSet(literals)
        }
        _ => BuiltinRhsV0::Term(parse_term_v0(&items[2])?),
    };

    Ok(BuiltinCallV0 { op, left, right })
}

fn parse_predicate_pattern_v0(value: &Value) -> Result<PredicatePatternV0, &'static str> {
    let items = expect_sequence_values(value, "predicate pattern must be vector/set")
        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
    if items.is_empty() {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }

    let predicate = parse_predicate_name_v0(&items[0])?;
    let mut args = Vec::with_capacity(items.len().saturating_sub(1));
    for item in &items[1..] {
        args.push(parse_term_v0(item)?);
    }
    Ok(PredicatePatternV0 { predicate, args })
}

fn parse_predicate_name_v0(value: &Value) -> Result<String, &'static str> {
    let token = keyword_string_or_symbol(value).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
    let trimmed = token.trim();
    if trimmed.is_empty() || trimmed.starts_with('?') || trimmed.starts_with(':') {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
    }
    if is_builtin_operator_v0(trimmed)
        || is_negation_operator_v0(trimmed)
        || looks_like_function_symbol_v0(trimmed)
    {
        return Err(PW_EVAL_FORBIDDEN_FEATURE);
    }
    Ok(trimmed.to_string())
}

fn parse_term_v0(value: &Value) -> Result<RulesTermV0, &'static str> {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if let Some(variable) = parse_variable_name_v0(trimmed) {
                return Ok(RulesTermV0::Var(variable));
            }
            if looks_like_function_symbol_v0(trimmed) {
                return Err(PW_EVAL_FORBIDDEN_FEATURE);
            }
            if is_route_atom_format_v0(trimmed) {
                return Ok(RulesTermV0::Lit(RulesLiteralV0::Atom(trimmed.to_string())));
            }
            Ok(RulesTermV0::Lit(RulesLiteralV0::String(raw.clone())))
        }
        Value::Keyword(keyword) => Ok(RulesTermV0::Lit(RulesLiteralV0::Atom(
            parse_route_atom_from_keyword_v0(keyword),
        ))),
        Value::Symbol(symbol) => {
            let symbol_name = symbol.as_str();
            let raw = symbol_name.trim();
            if let Some(variable) = parse_variable_name_v0(raw) {
                return Ok(RulesTermV0::Var(variable));
            }
            if looks_like_function_symbol_v0(raw) {
                return Err(PW_EVAL_FORBIDDEN_FEATURE);
            }
            Ok(RulesTermV0::Lit(RulesLiteralV0::Atom(raw.to_string())))
        }
        Value::Bool(value) => Ok(RulesTermV0::Lit(RulesLiteralV0::Bool(*value))),
        Value::Int(value) => Ok(RulesTermV0::Lit(RulesLiteralV0::Number(value.to_string()))),
        Value::UInt(value) => Ok(RulesTermV0::Lit(RulesLiteralV0::Number(value.to_string()))),
        Value::BigInt(value) => Ok(RulesTermV0::Lit(RulesLiteralV0::Number(value.to_string()))),
        Value::Float32(value) => Ok(RulesTermV0::Lit(RulesLiteralV0::Number(value.to_string()))),
        Value::Float64(value) => Ok(RulesTermV0::Lit(RulesLiteralV0::Number(value.to_string()))),
        Value::Nil => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
        Value::Bytes(_) | Value::Vector(_) | Value::Set(_) | Value::Map(_) | Value::Tagged(_) => {
            Err(PW_EVAL_FORBIDDEN_FEATURE)
        }
        Value::Annotated(_) => Err(PW_EVAL_FORBIDDEN_FEATURE),
    }
}

fn parse_variable_name_v0(raw: &str) -> Option<String> {
    let name = raw.strip_prefix('?')?;
    if name.is_empty() {
        return None;
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(name.to_string())
}

fn parse_route_atom_from_keyword_v0(keyword: &Keyword) -> String {
    format!(":{}", keyword.as_symbol().as_str())
}

fn parse_route_atom_value_v0(value: &Value) -> Result<String, &'static str> {
    match value {
        Value::Keyword(keyword) => {
            let route_atom = parse_route_atom_from_keyword_v0(keyword);
            if is_route_atom_format_v0(&route_atom) {
                Ok(route_atom)
            } else {
                Err(PW_EVAL_TYPE_MISMATCH)
            }
        }
        Value::String(raw) => {
            let trimmed = raw.trim();
            if is_route_atom_format_v0(trimmed) {
                Ok(trimmed.to_string())
            } else {
                Err(PW_EVAL_TYPE_MISMATCH)
            }
        }
        _ => Err(PW_EVAL_TYPE_MISMATCH),
    }
}

fn is_route_atom_format_v0(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() > 1
        && trimmed.starts_with(':')
        && !trimmed.chars().any(char::is_whitespace)
        && !looks_like_function_symbol_v0(trimmed)
}

fn is_negation_operator_v0(token: &str) -> bool {
    let normalized = token.trim().to_ascii_lowercase();
    normalized == "not" || normalized.starts_with("not(")
}

fn contains_negation_token_v0(value: &Value) -> bool {
    match value {
        Value::String(token) => is_negation_operator_v0(token),
        Value::Keyword(token) => {
            let token_name = token.as_symbol().as_str();
            is_negation_operator_v0(&token_name)
        }
        Value::Symbol(token) => {
            let token_name = token.as_str();
            is_negation_operator_v0(&token_name)
        }
        Value::Vector(items) => items
            .first()
            .and_then(keyword_string_or_symbol)
            .is_some_and(|token| is_negation_operator_v0(&token)),
        Value::Set(items) => items
            .first()
            .and_then(keyword_string_or_symbol)
            .is_some_and(|token| is_negation_operator_v0(&token)),
        Value::Map(entries) => {
            map_get_any(entries, &["not"]).is_some()
                || map_get_any(entries, &["negated"])
                    .and_then(|value| match value {
                        Value::Bool(flag) => Some(*flag),
                        _ => None,
                    })
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn looks_like_function_symbol_v0(token: &str) -> bool {
    let trimmed = token.trim();
    let Some(open_index) = trimmed.find('(') else {
        return false;
    };
    if !trimmed.ends_with(')') || open_index == 0 {
        return false;
    }
    trimmed[..open_index]
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_builtin_operator_v0(token: &str) -> bool {
    matches!(token, "=" | "!=" | "<" | "<=" | ">" | ">=" | "in")
}

fn parse_builtin_operator_v0(token: &str) -> Result<BuiltinOpV0, &'static str> {
    match token.trim() {
        "=" => Ok(BuiltinOpV0::Eq),
        "!=" => Ok(BuiltinOpV0::NotEq),
        "<" => Ok(BuiltinOpV0::Lt),
        "<=" => Ok(BuiltinOpV0::LtEq),
        ">" => Ok(BuiltinOpV0::Gt),
        ">=" => Ok(BuiltinOpV0::GtEq),
        "in" => Ok(BuiltinOpV0::In),
        _ => Err(PW_EVAL_FORBIDDEN_FEATURE),
    }
}

fn register_predicate_arity_v0(
    arities: &mut BTreeMap<String, usize>,
    predicate: &str,
    arity: usize,
) -> Result<(), &'static str> {
    match arities.get(predicate) {
        Some(existing) if *existing != arity => Err(PW_PROTOCOL_SCHEMA_MISMATCH),
        Some(_) => Ok(()),
        None => {
            arities.insert(predicate.to_string(), arity);
            Ok(())
        }
    }
}

fn validate_rule_variable_safety_v0(rule: &CompiledRuleV0) -> Result<(), &'static str> {
    let mut vars_in_predicates = BTreeSet::new();
    for item in &rule.body {
        if let RuleBodyItemV0::Predicate(pattern) = item {
            collect_variables_from_pattern_v0(pattern, &mut vars_in_predicates);
        }
    }
    for variable in variables_in_terms_v0(&rule.head.args) {
        if !vars_in_predicates.contains(&variable) {
            return Err(PW_EVAL_UNBOUND_VAR);
        }
    }

    let mut bound_before_builtin = BTreeSet::new();
    for item in &rule.body {
        match item {
            RuleBodyItemV0::Predicate(pattern) => {
                collect_variables_from_pattern_v0(pattern, &mut bound_before_builtin);
            }
            RuleBodyItemV0::Builtin(builtin) => {
                let mut builtin_vars = BTreeSet::new();
                collect_variables_from_builtin_v0(builtin, &mut builtin_vars);
                for variable in builtin_vars {
                    if !bound_before_builtin.contains(&variable) {
                        return Err(PW_EVAL_UNBOUND_VAR);
                    }
                }
            }
        }
    }

    Ok(())
}

fn collect_variables_from_pattern_v0(
    pattern: &PredicatePatternV0,
    variables: &mut BTreeSet<String>,
) {
    for term in &pattern.args {
        if let RulesTermV0::Var(name) = term {
            variables.insert(name.clone());
        }
    }
}

fn collect_variables_from_builtin_v0(builtin: &BuiltinCallV0, variables: &mut BTreeSet<String>) {
    collect_variables_from_term_v0(&builtin.left, variables);
    match &builtin.right {
        BuiltinRhsV0::Term(term) => collect_variables_from_term_v0(term, variables),
        BuiltinRhsV0::LiteralSet(_) => {}
    }
}

fn collect_variables_from_term_v0(term: &RulesTermV0, variables: &mut BTreeSet<String>) {
    if let RulesTermV0::Var(name) = term {
        variables.insert(name.clone());
    }
}

fn variables_in_terms_v0(terms: &[RulesTermV0]) -> BTreeSet<String> {
    let mut variables = BTreeSet::new();
    for term in terms {
        collect_variables_from_term_v0(term, &mut variables);
    }
    variables
}

fn rule_topo_ranks_v0(rules: &[CompiledRuleV0]) -> Result<BTreeMap<String, usize>, &'static str> {
    let mut head_predicates = BTreeSet::new();
    for rule in rules {
        head_predicates.insert(rule.head.predicate.clone());
    }

    let mut adjacency: BTreeMap<String, BTreeSet<String>> = head_predicates
        .iter()
        .cloned()
        .map(|predicate| (predicate, BTreeSet::new()))
        .collect();
    let mut indegree: BTreeMap<String, usize> = head_predicates
        .iter()
        .cloned()
        .map(|predicate| (predicate, 0usize))
        .collect();

    for rule in rules {
        let head = rule.head.predicate.clone();
        for item in &rule.body {
            if let RuleBodyItemV0::Predicate(pattern) = item {
                if head_predicates.contains(&pattern.predicate)
                    && adjacency
                        .get_mut(&head)
                        .expect("head predicate adjacency must exist")
                        .insert(pattern.predicate.clone())
                {
                    *indegree
                        .get_mut(&pattern.predicate)
                        .expect("body predicate indegree must exist") += 1;
                }
            }
        }
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(predicate, degree)| (*degree == 0).then_some(predicate.clone()))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(head_predicates.len());

    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        order.push(next.clone());
        if let Some(children) = adjacency.get(&next) {
            for child in children {
                let degree = indegree
                    .get_mut(child)
                    .expect("child predicate indegree must exist");
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }

    if order.len() != head_predicates.len() {
        return Err(PW_EVAL_FORBIDDEN_FEATURE);
    }

    Ok(order
        .into_iter()
        .enumerate()
        .map(|(rank, predicate)| (predicate, rank))
        .collect())
}

fn format_rule_sort_key_v0(head: &PredicatePatternV0, body: &[RuleBodyItemV0]) -> String {
    let mut key = String::new();
    key.push_str("head:");
    key.push_str(&format_pattern_v0(head));
    key.push_str("|body:");
    for (index, item) in body.iter().enumerate() {
        if index > 0 {
            key.push(',');
        }
        key.push_str(&format_body_item_v0(item));
    }
    key
}

fn format_pattern_v0(pattern: &PredicatePatternV0) -> String {
    let args = pattern
        .args
        .iter()
        .map(format_term_v0)
        .collect::<Vec<_>>()
        .join(",");
    format!("{}({args})", pattern.predicate)
}

fn format_body_item_v0(item: &RuleBodyItemV0) -> String {
    match item {
        RuleBodyItemV0::Predicate(pattern) => format!("pred:{}", format_pattern_v0(pattern)),
        RuleBodyItemV0::Builtin(call) => {
            let right = match &call.right {
                BuiltinRhsV0::Term(term) => format_term_v0(term),
                BuiltinRhsV0::LiteralSet(set) => format!(
                    "{{{}}}",
                    set.iter()
                        .map(format_literal_v0)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            };
            format!(
                "builtin:{}({},{right})",
                format_builtin_op_v0(call.op),
                format_term_v0(&call.left)
            )
        }
    }
}

fn format_term_v0(term: &RulesTermV0) -> String {
    match term {
        RulesTermV0::Var(name) => format!("?{name}"),
        RulesTermV0::Lit(literal) => format_literal_v0(literal),
    }
}

fn format_literal_v0(literal: &RulesLiteralV0) -> String {
    match literal {
        RulesLiteralV0::Atom(atom) => format!("atom:{atom}"),
        RulesLiteralV0::String(string) => format!("str:{string:?}"),
        RulesLiteralV0::Number(number) => format!("num:{number}"),
        RulesLiteralV0::Bool(flag) => format!("bool:{flag}"),
    }
}

fn format_builtin_op_v0(op: BuiltinOpV0) -> &'static str {
    match op {
        BuiltinOpV0::Eq => "=",
        BuiltinOpV0::NotEq => "!=",
        BuiltinOpV0::Lt => "<",
        BuiltinOpV0::LtEq => "<=",
        BuiltinOpV0::Gt => ">",
        BuiltinOpV0::GtEq => ">=",
        BuiltinOpV0::In => "in",
    }
}

fn evaluate_rules_program_v0(
    program: &CompiledRulesProgramV0,
) -> Result<RulesEvaluationResultV0, &'static str> {
    let mut idb = BTreeSet::new();
    for rule in &program.rules {
        let derived = evaluate_rule_once_v0(rule, &program.facts, &idb)?;
        idb.extend(derived);
    }

    let mut route_candidates = evaluate_query_routes_v0(&program.query, &program.facts, &idb)?;
    if route_candidates.is_empty() {
        return match &program.no_match {
            NoMatchPolicyV0::Error => Err(PW_EVAL_NO_MATCH),
            NoMatchPolicyV0::DefaultRoute(route) => Ok(RulesEvaluationResultV0 {
                selected_route: route.clone(),
                route_candidates: Vec::new(),
            }),
        };
    }

    if route_candidates.len() > 1 && matches!(program.ambiguous, AmbiguousPolicyV0::Error) {
        return Err(PW_EVAL_AMBIGUOUS_MATCH);
    }

    match program.selection {
        SelectionPolicyV0::CanonicalFirst => {
            route_candidates.sort_by(|left, right| compare_route_atoms_v0(left, right));
            let selected_route = route_candidates.first().cloned().ok_or(PW_EVAL_NO_MATCH)?;
            Ok(RulesEvaluationResultV0 {
                selected_route,
                route_candidates,
            })
        }
    }
}

fn evaluate_rule_once_v0(
    rule: &CompiledRuleV0,
    edb: &BTreeSet<GroundFactV0>,
    idb: &BTreeSet<GroundFactV0>,
) -> Result<BTreeSet<GroundFactV0>, &'static str> {
    let mut bindings = vec![RuleBindingsV0::new()];
    for item in &rule.body {
        bindings = match item {
            RuleBodyItemV0::Predicate(pattern) => {
                evaluate_predicate_body_item_v0(pattern, &bindings, edb, idb)
            }
            RuleBodyItemV0::Builtin(call) => evaluate_builtin_body_item_v0(call, &bindings)?,
        };
        if bindings.is_empty() {
            break;
        }
    }

    let mut derived = BTreeSet::new();
    for binding in &bindings {
        derived.insert(instantiate_head_fact_v0(&rule.head, binding)?);
    }
    Ok(derived)
}

fn evaluate_predicate_body_item_v0(
    pattern: &PredicatePatternV0,
    bindings: &[RuleBindingsV0],
    edb: &BTreeSet<GroundFactV0>,
    idb: &BTreeSet<GroundFactV0>,
) -> Vec<RuleBindingsV0> {
    let mut next_bindings = Vec::new();
    for binding in bindings {
        for fact in edb.iter().chain(idb.iter()) {
            if let Some(merged) = unify_pattern_with_fact_v0(pattern, fact, binding) {
                next_bindings.push(merged);
            }
        }
    }
    next_bindings
}

fn unify_pattern_with_fact_v0(
    pattern: &PredicatePatternV0,
    fact: &GroundFactV0,
    bindings: &RuleBindingsV0,
) -> Option<RuleBindingsV0> {
    if pattern.predicate != fact.predicate || pattern.args.len() != fact.args.len() {
        return None;
    }

    let mut merged = bindings.clone();
    for (term, literal) in pattern.args.iter().zip(&fact.args) {
        match term {
            RulesTermV0::Var(name) => {
                if let Some(bound) = merged.get(name) {
                    if bound != literal {
                        return None;
                    }
                } else {
                    merged.insert(name.clone(), literal.clone());
                }
            }
            RulesTermV0::Lit(expected) => {
                if expected != literal {
                    return None;
                }
            }
        }
    }

    Some(merged)
}

fn evaluate_builtin_body_item_v0(
    builtin: &BuiltinCallV0,
    bindings: &[RuleBindingsV0],
) -> Result<Vec<RuleBindingsV0>, &'static str> {
    let mut next_bindings = Vec::new();
    for binding in bindings {
        if evaluate_builtin_call_v0(builtin, binding)? {
            next_bindings.push(binding.clone());
        }
    }
    Ok(next_bindings)
}

fn evaluate_builtin_call_v0(
    builtin: &BuiltinCallV0,
    bindings: &RuleBindingsV0,
) -> Result<bool, &'static str> {
    let left = resolve_term_v0(&builtin.left, bindings)?;
    match builtin.op {
        BuiltinOpV0::Eq => {
            let right = resolve_builtin_rhs_term_v0(&builtin.right, bindings)?;
            comparable_equals_v0(&left, &right)
        }
        BuiltinOpV0::NotEq => {
            let right = resolve_builtin_rhs_term_v0(&builtin.right, bindings)?;
            comparable_equals_v0(&left, &right).map(|matches| !matches)
        }
        BuiltinOpV0::Lt | BuiltinOpV0::LtEq | BuiltinOpV0::Gt | BuiltinOpV0::GtEq => {
            let right = resolve_builtin_rhs_term_v0(&builtin.right, bindings)?;
            let ordering = compare_numeric_literals_v0(&left, &right)?;
            Ok(match builtin.op {
                BuiltinOpV0::Lt => ordering == CmpOrdering::Less,
                BuiltinOpV0::LtEq => {
                    ordering == CmpOrdering::Less || ordering == CmpOrdering::Equal
                }
                BuiltinOpV0::Gt => ordering == CmpOrdering::Greater,
                BuiltinOpV0::GtEq => {
                    ordering == CmpOrdering::Greater || ordering == CmpOrdering::Equal
                }
                BuiltinOpV0::Eq | BuiltinOpV0::NotEq | BuiltinOpV0::In => unreachable!(),
            })
        }
        BuiltinOpV0::In => {
            let BuiltinRhsV0::LiteralSet(set_members) = &builtin.right else {
                return Err(PW_EVAL_TYPE_MISMATCH);
            };
            for member in set_members {
                if comparable_equals_v0(&left, member)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn resolve_builtin_rhs_term_v0(
    right: &BuiltinRhsV0,
    bindings: &RuleBindingsV0,
) -> Result<RulesLiteralV0, &'static str> {
    match right {
        BuiltinRhsV0::Term(term) => resolve_term_v0(term, bindings),
        BuiltinRhsV0::LiteralSet(_) => Err(PW_EVAL_TYPE_MISMATCH),
    }
}

fn resolve_term_v0(
    term: &RulesTermV0,
    bindings: &RuleBindingsV0,
) -> Result<RulesLiteralV0, &'static str> {
    match term {
        RulesTermV0::Var(name) => bindings.get(name).cloned().ok_or(PW_EVAL_UNBOUND_VAR),
        RulesTermV0::Lit(literal) => Ok(literal.clone()),
    }
}

fn comparable_equals_v0(
    left: &RulesLiteralV0,
    right: &RulesLiteralV0,
) -> Result<bool, &'static str> {
    match (left, right) {
        (RulesLiteralV0::Bool(left), RulesLiteralV0::Bool(right)) => Ok(left == right),
        (RulesLiteralV0::String(left), RulesLiteralV0::String(right)) => Ok(left == right),
        (RulesLiteralV0::Atom(left), RulesLiteralV0::Atom(right)) => Ok(left == right),
        (RulesLiteralV0::Number(_), RulesLiteralV0::Number(_)) => {
            Ok(compare_numeric_literals_v0(left, right)? == CmpOrdering::Equal)
        }
        _ => Err(PW_EVAL_TYPE_MISMATCH),
    }
}

fn compare_numeric_literals_v0(
    left: &RulesLiteralV0,
    right: &RulesLiteralV0,
) -> Result<CmpOrdering, &'static str> {
    let RulesLiteralV0::Number(left_number) = left else {
        return Err(PW_EVAL_TYPE_MISMATCH);
    };
    let RulesLiteralV0::Number(right_number) = right else {
        return Err(PW_EVAL_TYPE_MISMATCH);
    };

    let left_value = parse_number_for_builtin_v0(left_number)?;
    let right_value = parse_number_for_builtin_v0(right_number)?;
    left_value
        .partial_cmp(&right_value)
        .ok_or(PW_EVAL_TYPE_MISMATCH)
}

fn parse_number_for_builtin_v0(raw: &str) -> Result<f64, &'static str> {
    raw.parse::<f64>().map_err(|_| PW_EVAL_TYPE_MISMATCH)
}

fn instantiate_head_fact_v0(
    head: &PredicatePatternV0,
    bindings: &RuleBindingsV0,
) -> Result<GroundFactV0, &'static str> {
    let mut args = Vec::with_capacity(head.args.len());
    for term in &head.args {
        args.push(match term {
            RulesTermV0::Var(name) => bindings.get(name).cloned().ok_or(PW_EVAL_UNBOUND_VAR)?,
            RulesTermV0::Lit(literal) => literal.clone(),
        });
    }
    Ok(GroundFactV0 {
        predicate: head.predicate.clone(),
        args,
    })
}

fn evaluate_query_routes_v0(
    query: &PredicatePatternV0,
    edb: &BTreeSet<GroundFactV0>,
    idb: &BTreeSet<GroundFactV0>,
) -> Result<Vec<String>, &'static str> {
    let mut route_candidates = BTreeSet::new();
    for fact in edb.iter().chain(idb.iter()) {
        if let Some(bindings) = unify_pattern_with_fact_v0(query, fact, &RuleBindingsV0::new()) {
            let route_term = query.args.first().expect("query arity validated as one");
            let literal = resolve_term_v0(route_term, &bindings)?;
            let RulesLiteralV0::Atom(route_atom) = literal else {
                return Err(PW_EVAL_TYPE_MISMATCH);
            };
            route_candidates.insert(route_atom);
        }
    }
    Ok(route_candidates.into_iter().collect())
}

fn compare_route_atoms_v0(left: &str, right: &str) -> CmpOrdering {
    let left_canonical = canonical_route_atom_bytes_v0(left);
    let right_canonical = canonical_route_atom_bytes_v0(right);
    match (left_canonical, right_canonical) {
        (Some(left_bytes), Some(right_bytes)) => {
            left_bytes.cmp(&right_bytes).then_with(|| left.cmp(right))
        }
        _ => left.cmp(right),
    }
}

fn canonical_route_atom_bytes_v0(route_atom: &str) -> Option<Vec<u8>> {
    if !is_route_atom_format_v0(route_atom) {
        return None;
    }
    let canonical_value = Value::Keyword(Keyword::parse(route_atom));
    rulia::encode_canonical(&canonical_value).ok()
}

fn route_atom_value_v0(route_atom: &str) -> Value {
    if is_route_atom_format_v0(route_atom) {
        Value::Keyword(Keyword::parse(route_atom))
    } else {
        Value::String(route_atom.to_string())
    }
}

fn parse_additional_facts_v0(value: &Value) -> Result<Vec<GroundFactV0>, &'static str> {
    let facts_values = match value {
        Value::Vector(values) => values.as_slice(),
        Value::Set(values) => values.as_slice(),
        Value::Map(entries) => {
            let facts_value =
                map_get_any(entries, &["facts"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
            expect_sequence_values(facts_value, "facts payload must be vector/set")
                .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
        }
        Value::Tagged(tagged) => {
            let tag = tagged.tag.as_str();
            if tag == "rules_facts_v0" {
                let entries =
                    expect_map_entries(tagged.value.as_ref(), "facts payload must be map")
                        .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?;
                let facts_value =
                    map_get_any(entries, &["facts"]).ok_or(PW_PROTOCOL_SCHEMA_MISMATCH)?;
                expect_sequence_values(facts_value, "facts payload must be vector/set")
                    .map_err(|_| PW_PROTOCOL_SCHEMA_MISMATCH)?
            } else {
                return Err(PW_PROTOCOL_SCHEMA_MISMATCH);
            }
        }
        _ => return Err(PW_PROTOCOL_SCHEMA_MISMATCH),
    };

    let mut facts = Vec::with_capacity(facts_values.len());
    for fact_value in facts_values {
        facts.push(parse_ground_fact_v0(fact_value)?);
    }
    Ok(facts)
}

fn pw_eval_rules_result_bytes(result: &RulesEvaluationResultV0) -> Option<Vec<u8>> {
    let route_candidates_value = Value::Vector(
        result
            .route_candidates
            .iter()
            .map(|route| route_atom_value_v0(route))
            .collect(),
    );

    let eval_result = Value::Tagged(TaggedValue::new(
        Symbol::simple("eval_rules_result_v0"),
        Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("format")),
                Value::Keyword(Keyword::simple("rulia_pw_eval_rules_result_v0")),
            ),
            (
                Value::Keyword(Keyword::simple("selected_route")),
                route_atom_value_v0(&result.selected_route),
            ),
            (
                Value::Keyword(Keyword::simple("route_candidates")),
                route_candidates_value,
            ),
        ]),
    ));
    rulia::encode_canonical(&eval_result).ok()
}

fn keyword_string_or_symbol(value: &Value) -> Option<String> {
    match value {
        Value::Keyword(keyword) => Some(keyword.as_symbol().as_str().to_string()),
        Value::String(raw) => Some(raw.clone()),
        Value::Symbol(symbol) => Some(symbol.as_str().to_string()),
        _ => None,
    }
}

fn parse_u64_value(value: &Value, message: &str) -> Result<u64, String> {
    match value {
        Value::UInt(value) => Ok(*value),
        Value::Int(value) if *value >= 0 => Ok(*value as u64),
        _ => Err(message.to_string()),
    }
}

fn expect_sequence_values<'a>(value: &'a Value, message: &str) -> Result<&'a [Value], String> {
    match value {
        Value::Vector(items) => Ok(items.as_slice()),
        Value::Set(items) => Ok(items.as_slice()),
        _ => Err(message.to_string()),
    }
}

fn parse_string_set(value: &Value, message: &str) -> Result<BTreeSet<String>, String> {
    let items = expect_sequence_values(value, message)?;
    let mut set = BTreeSet::new();
    for item in items {
        set.insert(
            keyword_string_or_symbol(item)
                .ok_or_else(|| format!("{message}: entries must be keyword/string/symbol"))?,
        );
    }
    Ok(set)
}

fn parse_digest_set(value: &Value, message: &str) -> Result<BTreeSet<String>, String> {
    let items = expect_sequence_values(value, message)?;
    let mut set = BTreeSet::new();
    for item in items {
        set.insert(parse_digest_value(item)?.prefixed());
    }
    Ok(set)
}

fn parse_capability_requirements_v0(value: &Value) -> Result<CapabilityRequirementsV0, String> {
    let entries = tagged_entries(
        value,
        "capability_requirements_v0",
        "requirements root must be CapabilityRequirementsV0 tagged value",
    )?;
    require_canonical_keys(
        entries,
        &["format", "required_absence_policy", "required", "optional"],
        &["format", "required_absence_policy", "required", "optional"],
        "capability_requirements_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_capability_requirements_v0",
        "requirements format must be :rulia_capability_requirements_v0",
    )?;

    let required_absence_policy_value = map_get_exact_any(entries, &["required_absence_policy"])
        .ok_or_else(|| "requirements missing required_absence_policy".to_string())?;
    let required_absence_policy = keyword_or_string(required_absence_policy_value)
        .ok_or_else(|| "requirements required_absence_policy must be keyword/string".to_string())
        .and_then(|value| match value.as_str() {
            "reject" => Ok(RequiredAbsencePolicyV0::Reject),
            "suspend" => Ok(RequiredAbsencePolicyV0::Suspend),
            _ => {
                Err("requirements required_absence_policy must be :reject or :suspend".to_string())
            }
        })?;

    let required_value = map_get_exact_any(entries, &["required"])
        .ok_or_else(|| "requirements missing required list".to_string())?;
    let mut required = parse_requirement_list(required_value, "required")?;
    required.sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));

    let optional_value = map_get_exact_any(entries, &["optional"])
        .ok_or_else(|| "requirements missing optional list".to_string())?;
    let mut optional = parse_requirement_list(optional_value, "optional")?;
    optional.sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));

    let mut seen_requirement_ids = BTreeSet::new();
    for requirement in required.iter().chain(optional.iter()) {
        if !seen_requirement_ids.insert(requirement.requirement_id.clone()) {
            return Err(format!(
                "requirements include duplicate requirement_id '{}'",
                requirement.requirement_id
            ));
        }
    }

    Ok(CapabilityRequirementsV0 {
        required_absence_policy,
        required,
        optional,
    })
}

fn parse_requirement_list(
    value: &Value,
    scope_name: &str,
) -> Result<Vec<CapabilityRequirementV0>, String> {
    let items = expect_sequence_values(value, "requirements list must be vector/set")?;
    let mut requirements = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        requirements.push(parse_capability_requirement_v0(
            item,
            &format!("{scope_name}[{index}]"),
        )?);
    }
    Ok(requirements)
}

fn parse_capability_requirement_v0(
    value: &Value,
    context: &str,
) -> Result<CapabilityRequirementV0, String> {
    let entries = expect_map_entries(value, "requirement must be map value")?;
    require_canonical_keys(
        entries,
        &["requirement_id", "alternatives"],
        &[
            "requirement_id",
            "alternatives",
            "required_operations",
            "required_constraints",
            "required_trust_anchors",
        ],
        "capability requirement",
    )?;
    let requirement_id_value = map_get_exact_any(entries, &["requirement_id"])
        .ok_or_else(|| format!("{context} missing requirement_id"))?;
    let requirement_id = expect_string(
        requirement_id_value,
        format!("{context} requirement_id must be string").as_str(),
    )?
    .to_string();

    let alternatives_value = map_get_exact_any(entries, &["alternatives"])
        .ok_or_else(|| format!("{context} missing alternatives"))?;
    let alternatives_values = expect_sequence_values(
        alternatives_value,
        "requirement alternatives must be vector/set",
    )?;
    if alternatives_values.is_empty() {
        return Err(format!("{context} alternatives must be non-empty"));
    }
    let mut alternatives = Vec::with_capacity(alternatives_values.len());
    for (index, alternative_value) in alternatives_values.iter().enumerate() {
        alternatives.push(parse_capability_alternative_v0(
            alternative_value,
            &format!("{context}.alternatives[{index}]"),
        )?);
    }
    alternatives.sort_by(compare_alternative_tuple);
    alternatives.dedup();

    let required_operations = parse_required_operations_v0(
        map_get_exact_any(entries, &["required_operations"]),
        context,
    )?;
    let required_constraints = parse_constraint_policy_v0(
        map_get_exact_any(entries, &["required_constraints"]),
        context,
    )?;
    let required_trust_anchors = parse_required_trust_anchors_v0(
        map_get_exact_any(entries, &["required_trust_anchors"]),
        context,
    )?;

    Ok(CapabilityRequirementV0 {
        requirement_id,
        alternatives,
        required_operations,
        required_constraints,
        required_trust_anchors,
    })
}

fn parse_capability_alternative_v0(
    value: &Value,
    context: &str,
) -> Result<CapabilityAlternativeV0, String> {
    let entries = expect_map_entries(value, "capability alternative must be map value")?;
    require_canonical_keys(
        entries,
        &["capability_id", "capability_version"],
        &[
            "capability_id",
            "capability_version",
            "capability_config_hash",
        ],
        "capability alternative",
    )?;
    let capability_id = expect_string(
        map_get_exact_any(entries, &["capability_id"])
            .ok_or_else(|| format!("{context} missing capability_id"))?,
        format!("{context} capability_id must be string").as_str(),
    )?
    .to_string();
    let capability_version = expect_string(
        map_get_exact_any(entries, &["capability_version"])
            .ok_or_else(|| format!("{context} missing capability_version"))?,
        format!("{context} capability_version must be string").as_str(),
    )?
    .to_string();
    let capability_config_hash = match map_get_exact_any(entries, &["capability_config_hash"]) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(parse_digest_value(value)?.prefixed()),
    };

    Ok(CapabilityAlternativeV0 {
        capability_id,
        capability_version,
        capability_config_hash,
    })
}

fn parse_required_operations_v0(
    value: Option<&Value>,
    context: &str,
) -> Result<Vec<RequiredOperationV0>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if matches!(value, Value::Nil) {
        return Ok(Vec::new());
    }
    let items = expect_sequence_values(value, "required_operations must be vector/set")?;
    let mut required_operations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let entries = expect_map_entries(item, "required operation entry must be map")?;
        require_canonical_keys(
            entries,
            &["operation", "semantics_ref"],
            &[
                "operation",
                "semantics_ref",
                "request_schema_ref",
                "receipt_schema_ref",
            ],
            "required operation entry",
        )?;
        let operation_value = map_get_exact_any(entries, &["operation"])
            .ok_or_else(|| format!("{context} required_operations[{index}] missing operation"))?;
        let operation = keyword_string_or_symbol(operation_value).ok_or_else(|| {
            format!("{context} required_operations[{index}] operation must be keyword/string")
        })?;
        let semantics_ref_value =
            map_get_exact_any(entries, &["semantics_ref"]).ok_or_else(|| {
                format!("{context} required_operations[{index}] missing semantics_ref")
            })?;
        let semantics_ref = parse_digest_value(semantics_ref_value)?.prefixed();
        required_operations.push(RequiredOperationV0 {
            operation,
            semantics_ref,
        });
    }
    required_operations.sort();
    required_operations.dedup();
    Ok(required_operations)
}

fn parse_gamma_cap_snapshot_v0(value: &Value) -> Result<GammaCapSnapshotV0, String> {
    let entries = tagged_entries(
        value,
        "gamma_cap_snapshot_v0",
        "gamma_cap root must be GammaCapSnapshotV0 tagged value",
    )?;
    require_canonical_keys(
        entries,
        &["format", "schema_version", "capabilities"],
        &[
            "format",
            "schema_version",
            "capabilities",
            "snapshot_metadata",
        ],
        "gamma_cap_snapshot_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_gamma_cap_snapshot_v0",
        "gamma_cap format must be :rulia_gamma_cap_snapshot_v0",
    )?;
    let schema_version_value = map_get_exact_any(entries, &["schema_version"])
        .ok_or_else(|| "gamma_cap missing schema_version".to_string())?;
    let schema_version = expect_string(
        schema_version_value,
        "gamma_cap schema_version must be string",
    )?;
    if schema_version != "v0" {
        return Err("gamma_cap schema_version must be 'v0'".to_string());
    }

    let capabilities_value = map_get_exact_any(entries, &["capabilities"])
        .ok_or_else(|| "gamma_cap missing capabilities".to_string())?;
    let capability_values = expect_sequence_values(
        capabilities_value,
        "gamma_cap capabilities must be vector/set",
    )?;
    let mut capabilities = Vec::with_capacity(capability_values.len());
    for (index, capability_value) in capability_values.iter().enumerate() {
        capabilities.push(parse_capability_entry_v0(
            capability_value,
            &format!("capabilities[{index}]"),
        )?);
    }
    capabilities.sort_by(|left, right| {
        left.capability_id
            .cmp(&right.capability_id)
            .then_with(|| left.capability_version.cmp(&right.capability_version))
            .then_with(|| {
                left.capability_config_hash
                    .cmp(&right.capability_config_hash)
            })
    });

    let mut seen_tuples = BTreeSet::new();
    for capability in &capabilities {
        let tuple = (
            capability.capability_id.clone(),
            capability.capability_version.clone(),
            capability.capability_config_hash.clone(),
        );
        if !seen_tuples.insert(tuple) {
            return Err(format!(
                "gamma_cap includes duplicate capability tuple '{}@{}#{}'",
                capability.capability_id,
                capability.capability_version,
                capability.capability_config_hash
            ));
        }
    }

    Ok(GammaCapSnapshotV0 { capabilities })
}

fn parse_capability_entry_v0(value: &Value, context: &str) -> Result<CapabilityEntryV0, String> {
    let entries = tagged_entries(
        value,
        "capability_entry_v0",
        "capability entry must be CapabilityEntryV0 tagged value",
    )?;
    require_canonical_keys(
        entries,
        &[
            "capability_id",
            "capability_version",
            "capability_config_hash",
            "operations",
            "constraints",
            "trust_anchors",
        ],
        &[
            "capability_id",
            "capability_version",
            "capability_config_hash",
            "operations",
            "constraints",
            "trust_anchors",
            "observability_metadata",
        ],
        "capability_entry_v0",
    )?;
    let capability_id = expect_string(
        map_get_exact_any(entries, &["capability_id"])
            .ok_or_else(|| format!("{context} missing capability_id"))?,
        format!("{context} capability_id must be string").as_str(),
    )?
    .to_string();
    let capability_version = expect_string(
        map_get_exact_any(entries, &["capability_version"])
            .ok_or_else(|| format!("{context} missing capability_version"))?,
        format!("{context} capability_version must be string").as_str(),
    )?
    .to_string();
    let capability_config_hash = parse_digest_value(
        map_get_exact_any(entries, &["capability_config_hash"])
            .ok_or_else(|| format!("{context} missing capability_config_hash"))?,
    )?
    .prefixed();

    let operations = parse_capability_operations_v0(
        map_get_exact_any(entries, &["operations"])
            .ok_or_else(|| format!("{context} missing operations"))?,
        context,
    )?;
    let constraints =
        parse_constraint_policy_v0(map_get_exact_any(entries, &["constraints"]), context)?;
    let trust_anchors =
        parse_capability_trust_anchors_v0(map_get_exact_any(entries, &["trust_anchors"]), context)?;

    Ok(CapabilityEntryV0 {
        capability_id,
        capability_version,
        capability_config_hash,
        operations,
        constraints,
        trust_anchors,
    })
}

fn parse_capability_operations_v0(
    value: &Value,
    context: &str,
) -> Result<Vec<CapabilityOperationV0>, String> {
    let items = expect_sequence_values(value, "capability operations must be vector/set")?;
    let mut operations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let entries = expect_map_entries(item, "capability operation entry must be map")?;
        require_canonical_keys(
            entries,
            &["operation", "semantics_ref"],
            &[
                "operation",
                "semantics_ref",
                "request_schema_ref",
                "receipt_schema_ref",
            ],
            "capability operation entry",
        )?;
        let operation = keyword_string_or_symbol(
            map_get_exact_any(entries, &["operation"])
                .ok_or_else(|| format!("{context} operations[{index}] missing operation"))?,
        )
        .ok_or_else(|| format!("{context} operations[{index}] operation must be keyword/string"))?;
        let semantics_ref = parse_digest_value(
            map_get_exact_any(entries, &["semantics_ref"])
                .ok_or_else(|| format!("{context} operations[{index}] missing semantics_ref"))?,
        )?
        .prefixed();
        operations.push(CapabilityOperationV0 {
            operation,
            semantics_ref,
        });
    }
    operations.sort();
    operations.dedup();
    Ok(operations)
}

fn parse_constraint_policy_v0(
    value: Option<&Value>,
    context: &str,
) -> Result<ConstraintPolicyV0, String> {
    let Some(value) = value else {
        return Ok(ConstraintPolicyV0::default());
    };
    if matches!(value, Value::Nil) {
        return Ok(ConstraintPolicyV0::default());
    }
    let entries = expect_map_entries(value, "constraints must be map value")?;
    let mut fields = BTreeMap::new();
    for (key, field_value) in entries {
        let key_name = value_key_name(key)
            .ok_or_else(|| format!("{context} constraints keys must be keyword/string"))?;
        let parsed_field = parse_constraint_field_value(&key_name, field_value)?;
        if fields.insert(key_name.clone(), parsed_field).is_some() {
            return Err(format!(
                "{context} constraints include duplicate key '{key_name}'"
            ));
        }
    }
    Ok(ConstraintPolicyV0 { fields })
}

fn parse_constraint_field_value(
    field_name: &str,
    value: &Value,
) -> Result<ConstraintFieldValueV0, String> {
    if field_name.ends_with("allowlist") || field_name.ends_with("allow/list") {
        return Ok(ConstraintFieldValueV0::Set(parse_string_set(
            value,
            "constraint allowlist field must be vector/set",
        )?));
    }
    if field_name.starts_with("max_") || field_name.starts_with("max/") {
        return Ok(ConstraintFieldValueV0::Max(parse_u64_value(
            value,
            "constraint max field must be unsigned integer",
        )?));
    }
    if field_name.starts_with("allow_") || field_name.starts_with("allow/") {
        return match value {
            Value::Bool(boolean_value) => Ok(ConstraintFieldValueV0::Bool(*boolean_value)),
            _ => Err("constraint allow_* field must be bool".to_string()),
        };
    }

    match value {
        Value::Vector(_) | Value::Set(_) => Ok(ConstraintFieldValueV0::Set(parse_string_set(
            value,
            "constraint vector/set field must contain scalar values",
        )?)),
        Value::Bool(boolean_value) => Ok(ConstraintFieldValueV0::Bool(*boolean_value)),
        Value::UInt(_) | Value::Int(_) => Ok(ConstraintFieldValueV0::Max(parse_u64_value(
            value,
            "constraint numeric field must be non-negative integer",
        )?)),
        _ => Ok(ConstraintFieldValueV0::Raw(value.clone())),
    }
}

fn parse_required_trust_anchors_v0(
    value: Option<&Value>,
    context: &str,
) -> Result<RequiredTrustAnchorsV0, String> {
    let Some(value) = value else {
        return Ok(RequiredTrustAnchorsV0::default());
    };
    if matches!(value, Value::Nil) {
        return Ok(RequiredTrustAnchorsV0::default());
    }
    let entries = expect_map_entries(value, "required_trust_anchors must be map value")?;
    require_canonical_keys(
        entries,
        &[],
        &[
            "signer_keys_any_of",
            "signer_keys_all_of",
            "allowed_signature_algs",
            "required_cert_roots",
            "cert_roots_any_of",
        ],
        "required_trust_anchors",
    )?;

    let signer_keys_any_of = map_get_exact_any(entries, &["signer_keys_any_of"])
        .map(|value| {
            parse_string_set(
                value,
                "required_trust_anchors signer_keys_any_of must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();
    let signer_keys_all_of = map_get_exact_any(entries, &["signer_keys_all_of"])
        .map(|value| {
            parse_string_set(
                value,
                "required_trust_anchors signer_keys_all_of must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();
    let allowed_signature_algs = map_get_exact_any(entries, &["allowed_signature_algs"])
        .map(|value| {
            parse_string_set(
                value,
                "required_trust_anchors allowed_signature_algs must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();
    let required_cert_roots = map_get_exact_any(entries, &["required_cert_roots"])
        .map(|value| {
            parse_digest_set(
                value,
                "required_trust_anchors required_cert_roots must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();
    let cert_roots_any_of = map_get_exact_any(entries, &["cert_roots_any_of"])
        .map(|value| {
            parse_digest_set(
                value,
                "required_trust_anchors cert_roots_any_of must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();

    if signer_keys_any_of.is_empty()
        && signer_keys_all_of.is_empty()
        && allowed_signature_algs.is_empty()
        && required_cert_roots.is_empty()
        && cert_roots_any_of.is_empty()
        && !entries.is_empty()
    {
        let _ = context;
    }

    Ok(RequiredTrustAnchorsV0 {
        signer_keys_any_of,
        signer_keys_all_of,
        allowed_signature_algs,
        required_cert_roots,
        cert_roots_any_of,
    })
}

fn parse_capability_trust_anchors_v0(
    value: Option<&Value>,
    _context: &str,
) -> Result<CapabilityTrustAnchorsV0, String> {
    let Some(value) = value else {
        return Ok(CapabilityTrustAnchorsV0::default());
    };
    if matches!(value, Value::Nil) {
        return Ok(CapabilityTrustAnchorsV0::default());
    }
    let entries = expect_map_entries(value, "trust_anchors must be map value")?;
    require_canonical_keys(
        entries,
        &[],
        &[
            "trusted_signer_keys",
            "trusted_cert_roots",
            "allowed_signature_algs",
            "min_signatures",
        ],
        "trust_anchors",
    )?;

    let trusted_signer_keys = map_get_exact_any(entries, &["trusted_signer_keys"])
        .map(|value| {
            parse_string_set(
                value,
                "trust_anchors trusted_signer_keys must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();
    let trusted_cert_roots = map_get_exact_any(entries, &["trusted_cert_roots"])
        .map(|value| parse_digest_set(value, "trust_anchors trusted_cert_roots must be vector/set"))
        .transpose()?
        .unwrap_or_default();
    let allowed_signature_algs = map_get_exact_any(entries, &["allowed_signature_algs"])
        .map(|value| {
            parse_string_set(
                value,
                "trust_anchors allowed_signature_algs must be vector/set",
            )
        })
        .transpose()?
        .unwrap_or_default();

    Ok(CapabilityTrustAnchorsV0 {
        trusted_signer_keys,
        trusted_cert_roots,
        allowed_signature_algs,
    })
}

fn evaluate_match_capability(
    requirements: &CapabilityRequirementsV0,
    gamma_cap_snapshot: &GammaCapSnapshotV0,
) -> MatchCapEvaluationResultV0 {
    let mut matched_required = Vec::new();
    let mut matched_optional = Vec::new();
    let mut unmet_required = Vec::new();
    let mut unmet_optional = Vec::new();

    for requirement in &requirements.required {
        match evaluate_requirement(requirement, gamma_cap_snapshot) {
            RequirementOutcomeV0::Matched(matched) => matched_required.push(matched),
            RequirementOutcomeV0::Unmet(unmet) => unmet_required.push(unmet),
        }
    }
    for requirement in &requirements.optional {
        match evaluate_requirement(requirement, gamma_cap_snapshot) {
            RequirementOutcomeV0::Matched(matched) => matched_optional.push(matched),
            RequirementOutcomeV0::Unmet(unmet) => unmet_optional.push(unmet),
        }
    }

    unmet_required.sort_by(compare_requirement_unmet);
    unmet_optional.sort_by(compare_requirement_unmet);
    matched_required.sort_by(compare_requirement_match);
    matched_optional.sort_by(compare_requirement_match);

    let status = if unmet_required.is_empty() {
        if unmet_optional.is_empty() {
            "accepted"
        } else {
            "accepted_with_soft_gaps"
        }
    } else if requirements.required_absence_policy == RequiredAbsencePolicyV0::Suspend {
        "suspend"
    } else {
        "reject"
    };
    let failure_codes = if status == "reject" || status == "suspend" {
        unmet_required
            .iter()
            .map(|unmet| unmet.failure_category.code().to_string())
            .collect()
    } else {
        Vec::new()
    };

    MatchCapEvaluationResultV0 {
        status,
        matched_required,
        matched_optional,
        unmet_required,
        unmet_optional,
        failure_codes,
    }
}

fn evaluate_requirement(
    requirement: &CapabilityRequirementV0,
    gamma_cap_snapshot: &GammaCapSnapshotV0,
) -> RequirementOutcomeV0 {
    let mut alternative_failures = Vec::new();
    for alternative in &requirement.alternatives {
        match evaluate_alternative(requirement, alternative, gamma_cap_snapshot) {
            Ok(()) => {
                return RequirementOutcomeV0::Matched(RequirementMatchV0 {
                    requirement_id: requirement.requirement_id.clone(),
                    alternative: alternative.clone(),
                });
            }
            Err(failure_category) => alternative_failures.push((failure_category, alternative)),
        }
    }

    let (failure_category, alternative) = alternative_failures
        .into_iter()
        .min_by(
            |(left_failure, left_alternative), (right_failure, right_alternative)| {
                left_failure
                    .rank()
                    .cmp(&right_failure.rank())
                    .then_with(|| compare_alternative_tuple(left_alternative, right_alternative))
            },
        )
        .expect("requirement alternatives must be non-empty");

    RequirementOutcomeV0::Unmet(RequirementUnmetV0 {
        requirement_id: requirement.requirement_id.clone(),
        failure_category,
        alternative: alternative.clone(),
    })
}

fn compare_requirement_unmet(left: &RequirementUnmetV0, right: &RequirementUnmetV0) -> CmpOrdering {
    left.requirement_id
        .cmp(&right.requirement_id)
        .then_with(|| {
            left.failure_category
                .rank()
                .cmp(&right.failure_category.rank())
        })
        .then_with(|| compare_alternative_tuple(&left.alternative, &right.alternative))
}

fn compare_requirement_match(left: &RequirementMatchV0, right: &RequirementMatchV0) -> CmpOrdering {
    left.requirement_id
        .cmp(&right.requirement_id)
        .then_with(|| compare_alternative_tuple(&left.alternative, &right.alternative))
}

fn evaluate_alternative(
    requirement: &CapabilityRequirementV0,
    alternative: &CapabilityAlternativeV0,
    gamma_cap_snapshot: &GammaCapSnapshotV0,
) -> Result<(), CapabilityFailureCategoryV0> {
    let id_matches: Vec<&CapabilityEntryV0> = gamma_cap_snapshot
        .capabilities
        .iter()
        .filter(|entry| entry.capability_id == alternative.capability_id)
        .collect();
    if id_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::MissingRequiredCapability);
    }

    let version_matches: Vec<&CapabilityEntryV0> = id_matches
        .into_iter()
        .filter(|entry| entry.capability_version == alternative.capability_version)
        .collect();
    if version_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::IncompatibleVersion);
    }

    let mut config_matches: Vec<&CapabilityEntryV0> =
        if let Some(required_hash) = &alternative.capability_config_hash {
            version_matches
                .into_iter()
                .filter(|entry| &entry.capability_config_hash == required_hash)
                .collect()
        } else {
            version_matches
        };
    if config_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::IncompatibleVersion);
    }

    config_matches.sort_by(|left, right| {
        left.capability_id
            .cmp(&right.capability_id)
            .then_with(|| left.capability_version.cmp(&right.capability_version))
            .then_with(|| {
                left.capability_config_hash
                    .cmp(&right.capability_config_hash)
            })
    });

    let operation_matches: Vec<&CapabilityEntryV0> = config_matches
        .iter()
        .copied()
        .filter(|entry| operations_compatible(&requirement.required_operations, &entry.operations))
        .collect();
    if operation_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::ConstraintViolation);
    }

    let constraint_matches: Vec<&CapabilityEntryV0> = operation_matches
        .iter()
        .copied()
        .filter(|entry| {
            constraints_compatible(&requirement.required_constraints, &entry.constraints)
        })
        .collect();
    if constraint_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::ConstraintViolation);
    }

    let trusted = constraint_matches.iter().any(|entry| {
        trust_anchors_compatible(&requirement.required_trust_anchors, &entry.trust_anchors)
    });
    if !trusted {
        return Err(CapabilityFailureCategoryV0::UntrustedOrMissingTrustAnchor);
    }

    Ok(())
}

fn compare_alternative_tuple(
    left: &CapabilityAlternativeV0,
    right: &CapabilityAlternativeV0,
) -> CmpOrdering {
    left.capability_id
        .cmp(&right.capability_id)
        .then_with(|| left.capability_version.cmp(&right.capability_version))
        .then_with(|| {
            left.capability_config_hash
                .cmp(&right.capability_config_hash)
        })
}

fn operations_compatible(
    required_operations: &[RequiredOperationV0],
    environment_operations: &[CapabilityOperationV0],
) -> bool {
    required_operations.iter().all(|required_operation| {
        environment_operations.iter().any(|environment_operation| {
            required_operation.operation == environment_operation.operation
                && required_operation.semantics_ref == environment_operation.semantics_ref
        })
    })
}

fn constraints_compatible(
    required_constraints: &ConstraintPolicyV0,
    environment_constraints: &ConstraintPolicyV0,
) -> bool {
    required_constraints
        .fields
        .iter()
        .all(|(field_name, required_value)| {
            let Some(environment_value) = environment_constraints.fields.get(field_name) else {
                return false;
            };
            constraint_field_compatible(required_value, environment_value)
        })
}

fn constraint_field_compatible(
    required_value: &ConstraintFieldValueV0,
    environment_value: &ConstraintFieldValueV0,
) -> bool {
    match (required_value, environment_value) {
        (
            ConstraintFieldValueV0::Set(required_set),
            ConstraintFieldValueV0::Set(environment_set),
        ) => required_set.is_subset(environment_set),
        (
            ConstraintFieldValueV0::Max(required_max),
            ConstraintFieldValueV0::Max(environment_max),
        ) => required_max <= environment_max,
        (ConstraintFieldValueV0::Bool(required), ConstraintFieldValueV0::Bool(environment)) => {
            !required || *environment
        }
        (ConstraintFieldValueV0::Raw(required), ConstraintFieldValueV0::Raw(environment)) => {
            required == environment
        }
        _ => false,
    }
}

fn trust_anchors_compatible(
    required_trust_anchors: &RequiredTrustAnchorsV0,
    environment_trust_anchors: &CapabilityTrustAnchorsV0,
) -> bool {
    if !required_trust_anchors
        .signer_keys_all_of
        .is_subset(&environment_trust_anchors.trusted_signer_keys)
    {
        return false;
    }
    if !required_trust_anchors.signer_keys_any_of.is_empty()
        && required_trust_anchors
            .signer_keys_any_of
            .is_disjoint(&environment_trust_anchors.trusted_signer_keys)
    {
        return false;
    }
    if !required_trust_anchors
        .allowed_signature_algs
        .is_subset(&environment_trust_anchors.allowed_signature_algs)
    {
        return false;
    }
    if !required_trust_anchors
        .required_cert_roots
        .is_subset(&environment_trust_anchors.trusted_cert_roots)
    {
        return false;
    }
    if !required_trust_anchors.cert_roots_any_of.is_empty()
        && required_trust_anchors
            .cert_roots_any_of
            .is_disjoint(&environment_trust_anchors.trusted_cert_roots)
    {
        return false;
    }
    true
}

fn alternative_value(alternative: &CapabilityAlternativeV0) -> Value {
    Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("capability_id")),
            Value::String(alternative.capability_id.clone()),
        ),
        (
            Value::Keyword(Keyword::simple("capability_version")),
            Value::String(alternative.capability_version.clone()),
        ),
        (
            Value::Keyword(Keyword::simple("capability_config_hash")),
            alternative
                .capability_config_hash
                .as_ref()
                .map_or(Value::Nil, |value| Value::String(value.clone())),
        ),
    ])
}

fn requirement_match_value(matched: &RequirementMatchV0, scope: &str) -> Value {
    Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("requirement_id")),
            Value::String(matched.requirement_id.clone()),
        ),
        (
            Value::Keyword(Keyword::simple("scope")),
            Value::Keyword(Keyword::simple(scope)),
        ),
        (
            Value::Keyword(Keyword::simple("selected_alternative")),
            alternative_value(&matched.alternative),
        ),
    ])
}

fn requirement_unmet_value(unmet: &RequirementUnmetV0, scope: &str) -> Value {
    Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("requirement_id")),
            Value::String(unmet.requirement_id.clone()),
        ),
        (
            Value::Keyword(Keyword::simple("scope")),
            Value::Keyword(Keyword::simple(scope)),
        ),
        (
            Value::Keyword(Keyword::simple("failure_category")),
            Value::String(unmet.failure_category.code().to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("selected_alternative")),
            alternative_value(&unmet.alternative),
        ),
    ])
}

fn pw_match_cap_result_bytes(result: &MatchCapEvaluationResultV0) -> Option<Vec<u8>> {
    let ordered_failure_codes = order_failure_codes(result.failure_codes.clone());
    let primary_failure_code = ordered_failure_codes.first().cloned();
    let failure_codes_value = Value::Vector(
        ordered_failure_codes
            .iter()
            .map(|code| Value::String(code.clone()))
            .collect(),
    );
    let mut matched = result
        .matched_required
        .iter()
        .map(|entry| requirement_match_value(entry, "required"))
        .collect::<Vec<_>>();
    matched.extend(
        result
            .matched_optional
            .iter()
            .map(|entry| requirement_match_value(entry, "optional")),
    );
    let unmet_required = Value::Vector(
        result
            .unmet_required
            .iter()
            .map(|entry| requirement_unmet_value(entry, "required"))
            .collect(),
    );
    let unmet_optional = Value::Vector(
        result
            .unmet_optional
            .iter()
            .map(|entry| requirement_unmet_value(entry, "optional"))
            .collect(),
    );
    let match_result = Value::Tagged(TaggedValue::new(
        Symbol::simple("match_cap_result_v0"),
        Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("format")),
                Value::Keyword(Keyword::simple("rulia_pw_match_cap_result_v0")),
            ),
            (
                Value::Keyword(Keyword::simple("status")),
                Value::Keyword(Keyword::simple(result.status)),
            ),
            (
                Value::Keyword(Keyword::simple("matched")),
                Value::Vector(matched),
            ),
            (
                Value::Keyword(Keyword::simple("unmet_required")),
                unmet_required,
            ),
            (
                Value::Keyword(Keyword::simple("unmet_optional")),
                unmet_optional,
            ),
            (
                Value::Keyword(Keyword::simple("primary_failure_code")),
                primary_failure_code.map_or(Value::Nil, Value::String),
            ),
            (
                Value::Keyword(Keyword::simple("failure_codes")),
                failure_codes_value,
            ),
        ]),
    ));
    rulia::encode_canonical(&match_result).ok()
}

fn pw_fail_with_result(
    verb: &str,
    status: RuliaStatus,
    failure_codes: Vec<String>,
    result_bytes: Vec<u8>,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    if !out_result.is_null() {
        unsafe {
            *out_result = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
    }
    let set_status = bytes_out_set(out_result, result_bytes);
    if set_status != RuliaStatus::Ok {
        return set_status;
    }

    if !out_error_detail.is_null() {
        unsafe {
            *out_error_detail = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
        if let Some(bytes) = pw_error_detail_bytes(verb, status, failure_codes, None, None) {
            let _ = bytes_out_set(out_error_detail, bytes);
        }
    }
    status
}

fn validate_request_payload_hash(entries: &[(Value, Value)]) -> Result<bool, String> {
    let Some(input_value) = map_get_any(entries, &["input"]) else {
        return Ok(true);
    };
    let input_entries = expect_map_entries(input_value, "request input must be a map")?;
    let payload_embed = map_get_any(input_entries, &["payload_embed"]);
    let payload_bytes_value = map_get_any(input_entries, &["payload_bytes"]);
    let Some(payload_embed_value) = payload_embed else {
        return Ok(true);
    };
    if matches!(payload_embed_value, Value::Nil) {
        if let Some(payload_bytes_value) = payload_bytes_value {
            let Value::UInt(payload_bytes) = payload_bytes_value else {
                return Err("request input payload_bytes must be uint".to_string());
            };
            if *payload_bytes != 0 {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    let payload_hash_value = map_get_any(input_entries, &["payload_hash"])
        .ok_or_else(|| "request input missing payload_hash".to_string())?;
    let payload_hash = parse_digest_value(payload_hash_value)?;
    let payload_bytes = rulia::encode_canonical(payload_embed_value)
        .map_err(|err| format!("failed to canonicalize request payload_embed: {err}"))?;
    let computed_hash = digest_from_bytes(payload_hash.algorithm, &payload_bytes);
    if !computed_hash.same_value(&payload_hash) {
        return Ok(false);
    }
    if let Some(payload_bytes_value) = payload_bytes_value {
        let Value::UInt(reported_payload_bytes) = payload_bytes_value else {
            return Err("request input payload_bytes must be uint".to_string());
        };
        if *reported_payload_bytes as usize != payload_bytes.len() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn parse_request_v0(value: &Value) -> Result<ParsedRequestV0, String> {
    let request_entries = tagged_entries(
        value,
        "request_v0",
        "request root must be RequestV0 tagged value",
    )?;
    validate_format_field(
        request_entries,
        "rulia_request_v0",
        "request format must be :rulia_request_v0",
    )?;

    let expected_receipt_schema_ref =
        match map_get_any(request_entries, &["expected_receipt_schema_ref"]) {
            Some(schema_ref_value) => parse_optional_digest_value(schema_ref_value)?,
            None => None,
        };

    let capability_id =
        map_get_any(request_entries, &["capability_id"]).and_then(keyword_or_string);
    let capability_version =
        map_get_any(request_entries, &["capability_version"]).and_then(|value| {
            if let Value::String(raw) = value {
                Some(raw.clone())
            } else {
                keyword_or_string(value)
            }
        });
    let operation = map_get_any(request_entries, &["operation"]).and_then(keyword_or_string);
    let payload_hash_valid = validate_request_payload_hash(request_entries)?;

    Ok(ParsedRequestV0 {
        expected_receipt_schema_ref,
        capability_id,
        capability_version,
        operation,
        payload_hash_valid,
    })
}

fn validate_receipt_output_payload_hash(entries: &[(Value, Value)]) -> Result<bool, String> {
    let Some(output_value) = map_get_any(entries, &["output"]) else {
        return Ok(true);
    };
    let output_entries = expect_map_entries(output_value, "receipt output must be map")?;
    let output_embed = map_get_any(output_entries, &["output_embed"]);
    let output_bytes_value = map_get_any(output_entries, &["output_bytes"]);
    let Some(output_embed_value) = output_embed else {
        return Ok(true);
    };
    if matches!(output_embed_value, Value::Nil) {
        if let Some(output_bytes_value) = output_bytes_value {
            let Value::UInt(output_bytes) = output_bytes_value else {
                return Err("receipt output output_bytes must be uint".to_string());
            };
            if *output_bytes != 0 {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    let output_hash_value = map_get_any(output_entries, &["output_hash"])
        .ok_or_else(|| "receipt output missing output_hash".to_string())?;
    let output_hash = parse_digest_value(output_hash_value)?;
    let output_embed_bytes = rulia::encode_canonical(output_embed_value)
        .map_err(|err| format!("failed to canonicalize receipt output_embed: {err}"))?;
    let computed_hash = digest_from_bytes(output_hash.algorithm, &output_embed_bytes);
    if !computed_hash.same_value(&output_hash) {
        return Ok(false);
    }
    if let Some(output_bytes_value) = output_bytes_value {
        let Value::UInt(reported_output_bytes) = output_bytes_value else {
            return Err("receipt output output_bytes must be uint".to_string());
        };
        if *reported_output_bytes as usize != output_embed_bytes.len() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn canonical_receipt_signing_body(receipt: &Value) -> Result<Vec<u8>, String> {
    let mut signing_body = receipt.clone();
    let Value::Tagged(tagged) = &mut signing_body else {
        return Err("receipt root must be tagged value".to_string());
    };
    if tagged.tag.as_str() != "receipt_v0" {
        return Err("receipt root tag must be receipt_v0".to_string());
    }
    let Value::Map(receipt_entries) = tagged.value.as_mut() else {
        return Err("receipt payload must be map".to_string());
    };
    let attestation_value = map_get_mut_any(receipt_entries, &["attestation"])
        .ok_or_else(|| "receipt missing attestation".to_string())?;
    let Value::Map(attestation_entries) = attestation_value else {
        return Err("receipt attestation must be map".to_string());
    };
    let signature_value = map_get_mut_any(attestation_entries, &["sig"])
        .ok_or_else(|| "receipt attestation missing sig".to_string())?;
    *signature_value = Value::Bytes(Vec::new());

    rulia::encode_canonical(&signing_body)
        .map_err(|err| format!("failed to canonicalize receipt signing body: {err}"))
}

fn parse_receipt_v0(value: &Value) -> Result<ParsedReceiptV0, String> {
    let receipt_entries = tagged_entries(
        value,
        "receipt_v0",
        "receipt root must be ReceiptV0 tagged value",
    )?;
    validate_format_field(
        receipt_entries,
        "rulia_receipt_v0",
        "receipt format must be :rulia_receipt_v0",
    )?;

    let request_hash_value = map_get_any(receipt_entries, &["request_hash"])
        .ok_or_else(|| "receipt missing request_hash".to_string())?;
    let request_hash = parse_digest_value(request_hash_value)?;
    let request_id = match map_get_any(receipt_entries, &["request_id"]) {
        Some(request_id) => parse_optional_digest_value(request_id)?,
        None => None,
    };

    let capability_id =
        map_get_any(receipt_entries, &["capability_id"]).and_then(keyword_or_string);
    let capability_version =
        map_get_any(receipt_entries, &["capability_version"]).and_then(|value| {
            if let Value::String(raw) = value {
                Some(raw.clone())
            } else {
                keyword_or_string(value)
            }
        });
    let operation = map_get_any(receipt_entries, &["operation"]).and_then(keyword_or_string);
    let outcome = map_get_any(receipt_entries, &["outcome"]).and_then(keyword_or_string);
    let schema_ref = match map_get_exact_any(receipt_entries, &["schema_ref"]) {
        Some(value) => parse_optional_digest_value(value)?,
        None => None,
    };
    let payload_hash_valid = validate_receipt_output_payload_hash(receipt_entries)?;

    let attestation_value = map_get_any(receipt_entries, &["attestation"])
        .ok_or_else(|| "receipt missing attestation".to_string())?;
    let attestation_entries =
        expect_map_entries(attestation_value, "receipt attestation must be map")?;

    let signer_key_id_value = map_get_any(attestation_entries, &["signer_key_id"])
        .ok_or_else(|| "receipt attestation missing signer_key_id".to_string())?;
    let signer_key_id = expect_string(
        signer_key_id_value,
        "receipt attestation signer_key_id must be string",
    )?
    .to_string();

    let signature_alg_value = map_get_any(attestation_entries, &["signature_alg"])
        .ok_or_else(|| "receipt attestation missing signature_alg".to_string())?;
    let signature_alg = keyword_or_string(signature_alg_value)
        .ok_or_else(|| "receipt attestation signature_alg must be keyword/string".to_string())?;

    let scope_value = map_get_any(attestation_entries, &["scope"])
        .ok_or_else(|| "receipt attestation missing scope".to_string())?;
    let scope = keyword_or_string(scope_value)
        .ok_or_else(|| "receipt attestation scope must be keyword/string".to_string())?;

    let signature_value = map_get_any(attestation_entries, &["sig"])
        .ok_or_else(|| "receipt attestation missing sig".to_string())?;
    let signature = match signature_value {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err("receipt attestation sig must be bytes".to_string()),
    };

    let signing_body_bytes = canonical_receipt_signing_body(value)?;

    Ok(ParsedReceiptV0 {
        request_hash,
        request_id,
        capability_id,
        capability_version,
        operation,
        outcome,
        schema_ref,
        payload_hash_valid,
        signer_key_id,
        signature_alg,
        scope,
        signature,
        signing_body_bytes,
    })
}

fn parse_receipt_valid_obligation_v0(
    value: &Value,
) -> Result<ParsedReceiptValidObligationV0, String> {
    let obligation_entries = tagged_entries(
        value,
        "obligation_v0",
        "obligation root must be ObligationV0 tagged value",
    )?;
    validate_format_field(
        obligation_entries,
        "rulia_obligation_v0",
        "obligation format must be :rulia_obligation_v0",
    )?;

    let obligation_type_value = map_get_any(obligation_entries, &["obligation_type"])
        .ok_or_else(|| "obligation missing obligation_type".to_string())?;
    let obligation_type = keyword_or_string(obligation_type_value)
        .ok_or_else(|| "obligation obligation_type must be keyword/string".to_string())?;
    if obligation_type != "receipt_valid" {
        return Err("obligation obligation_type must be :receipt_valid".to_string());
    }

    let params_value = map_get_any(obligation_entries, &["params"])
        .ok_or_else(|| "obligation missing params".to_string())?;
    let params_entries = expect_map_entries(params_value, "obligation params must be map")?;
    let request_hash_value = map_get_any(params_entries, &["request_hash"])
        .ok_or_else(|| "obligation params missing request_hash".to_string())?;
    let request_hash = parse_digest_value(request_hash_value)?;

    let allowed_outcomes = match map_get_any(params_entries, &["allowed_outcomes"]) {
        Some(Value::Vector(values)) | Some(Value::Set(values)) => {
            let mut outcomes = Vec::with_capacity(values.len());
            for value in values {
                outcomes.push(keyword_or_string(value).ok_or_else(|| {
                    "obligation params allowed_outcomes values must be keyword/string".to_string()
                })?);
            }
            Some(outcomes)
        }
        Some(_) => {
            return Err(
                "obligation params allowed_outcomes must be vector/set of keyword/string"
                    .to_string(),
            );
        }
        None => None,
    };

    let required_capability = match map_get_any(params_entries, &["require_capability"]) {
        Some(Value::Nil) => None,
        Some(value) => {
            let capability_entries =
                expect_map_entries(value, "obligation params require_capability must be map")?;
            let capability_id = map_get_any(capability_entries, &["capability_id"])
                .and_then(keyword_or_string)
                .ok_or_else(|| {
                    "obligation require_capability capability_id must be keyword/string".to_string()
                })?;
            let capability_version = map_get_any(capability_entries, &["capability_version"])
                .and_then(keyword_or_string)
                .ok_or_else(|| {
                    "obligation require_capability capability_version must be keyword/string"
                        .to_string()
                })?;
            let operation = map_get_any(capability_entries, &["operation"])
                .and_then(keyword_or_string)
                .ok_or_else(|| {
                    "obligation require_capability operation must be keyword/string".to_string()
                })?;
            Some(RequiredCapabilityTuple {
                capability_id,
                capability_version,
                operation,
            })
        }
        None => None,
    };

    Ok(ParsedReceiptValidObligationV0 {
        request_hash,
        allowed_outcomes,
        required_capability,
    })
}

fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0usize;
    while index < bytes.len() {
        let high = nibble(bytes[index])?;
        let low = nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn parse_public_key_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => {
            if bytes.len() == 32 {
                Some(bytes.clone())
            } else {
                None
            }
        }
        Value::String(hex_value) => {
            let decoded = decode_hex_bytes(hex_value)?;
            if decoded.len() == 32 {
                Some(decoded)
            } else {
                None
            }
        }
        Value::Map(entries) => {
            map_get_exact_any(entries, &["public_key"]).and_then(parse_public_key_bytes)
        }
        Value::Tagged(tagged) => match tagged.value.as_ref() {
            Value::Map(entries) => {
                map_get_exact_any(entries, &["public_key"]).and_then(parse_public_key_bytes)
            }
            _ => None,
        },
        _ => None,
    }
}

fn parse_single_trust_anchor_entries(
    entries: &[(Value, Value)],
    public_keys: &mut HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    require_canonical_keys(
        entries,
        &["key_id", "public_key"],
        &["key_id", "public_key"],
        "trust anchor entry",
    )?;
    let key_id = map_get_exact_any(entries, &["key_id"])
        .and_then(keyword_or_string)
        .ok_or_else(|| "trust anchor key_id must be keyword/string".to_string())?;
    let key_value = map_get_exact_any(entries, &["public_key"])
        .ok_or_else(|| "trust anchor missing public key field".to_string())?;
    let public_key = parse_public_key_bytes(key_value)
        .ok_or_else(|| "trust anchor public key must be 32-byte value".to_string())?;
    if public_keys.insert(key_id.clone(), public_key).is_some() {
        return Err(format!("duplicate trust anchor key id '{key_id}'"));
    }
    Ok(())
}

fn parse_trust_anchor_collection(
    value: &Value,
    public_keys: &mut HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    match value {
        Value::Nil => Ok(()),
        Value::Vector(values) | Value::Set(values) => {
            for value in values {
                match value {
                    Value::Map(entries) => parse_single_trust_anchor_entries(entries, public_keys)?,
                    Value::Tagged(tagged) => {
                        let entries = expect_map_entries(
                            tagged.value.as_ref(),
                            "trust anchor entry payload must be map",
                        )?;
                        parse_single_trust_anchor_entries(entries, public_keys)?;
                    }
                    _ => return Err("trust anchor entries must be map/tagged-map".to_string()),
                }
            }
            Ok(())
        }
        Value::Map(entries) => {
            if map_get_exact_any(entries, &["key_id"]).is_some() {
                return parse_single_trust_anchor_entries(entries, public_keys);
            }
            for (key, value) in entries {
                let key_id = value_key_name(key).ok_or_else(|| {
                    "trust anchor map keys must be string or keyword key IDs".to_string()
                })?;
                let public_key = parse_public_key_bytes(value)
                    .ok_or_else(|| "trust anchor public key must be 32-byte value".to_string())?;
                if public_keys.insert(key_id.clone(), public_key).is_some() {
                    return Err(format!("duplicate trust anchor key id '{key_id}'"));
                }
            }
            Ok(())
        }
        Value::Tagged(tagged) => parse_trust_anchor_collection(tagged.value.as_ref(), public_keys),
        _ => Err("trust anchors must be map/vector/set".to_string()),
    }
}

fn parse_trust_anchors_v0(value: &Value) -> Result<TrustAnchorSet, String> {
    let entries = tagged_entries(
        value,
        "trust_anchors_v0",
        "trust anchors root must be TrustAnchorsV0 tagged value",
    )?;
    require_canonical_keys(
        entries,
        &["format", "anchors"],
        &["format", "anchors"],
        "trust_anchors_v0",
    )?;
    validate_format_field(
        entries,
        "rulia_trust_anchors_v0",
        "trust anchors format must be :rulia_trust_anchors_v0",
    )?;
    let anchors_value = map_get_exact_any(entries, &["anchors"])
        .ok_or_else(|| "trust anchors missing anchors".to_string())?;
    let mut public_keys = HashMap::new();
    parse_trust_anchor_collection(anchors_value, &mut public_keys)?;
    Ok(TrustAnchorSet { public_keys })
}

fn looks_like_receipt_map(entries: &[(Value, Value)]) -> bool {
    map_get_any(entries, &["request_hash"]).is_some()
        && map_get_any(entries, &["attestation"]).is_some()
}

fn parse_history_receipt_entry(value: &Value, fallback_index: u64) -> Result<(u64, Value), String> {
    if matches!(value, Value::Tagged(tagged) if tagged.tag.as_str() == "receipt_v0") {
        return Ok((fallback_index, value.clone()));
    }

    let (entry_index, entry_payload) = match value {
        Value::Map(entries) => {
            let index = match map_get_exact_any(entries, &["history_index"]) {
                Some(Value::UInt(index)) => *index,
                Some(_) => {
                    return Err("history entry history_index must be uint".to_string());
                }
                None => fallback_index,
            };
            if let Some(receipt_value) = map_get_exact_any(entries, &["receipt"]) {
                (index, receipt_value.clone())
            } else if looks_like_receipt_map(entries) {
                (index, value.clone())
            } else {
                return Err("history entry missing receipt payload".to_string());
            }
        }
        Value::Tagged(tagged) => {
            let entries = expect_map_entries(
                tagged.value.as_ref(),
                "history entry tagged payload must be map",
            )?;
            let index = match map_get_exact_any(entries, &["history_index"]) {
                Some(Value::UInt(index)) => *index,
                Some(_) => {
                    return Err("history entry history_index must be uint".to_string());
                }
                None => fallback_index,
            };
            if let Some(receipt_value) = map_get_exact_any(entries, &["receipt"]) {
                (index, receipt_value.clone())
            } else if looks_like_receipt_map(entries) {
                (index, Value::Map(entries.to_vec()))
            } else {
                return Err("history entry missing receipt payload".to_string());
            }
        }
        _ => {
            return Err("history entry must be receipt or map with receipt payload".to_string());
        }
    };

    Ok((entry_index, entry_payload))
}

fn parse_history_prefix_v0(value: &Value) -> Result<Vec<HistoryReceiptCandidateV0>, String> {
    let history_entries = match value {
        Value::Vector(entries) | Value::Set(entries) => entries.clone(),
        Value::Map(entries) => {
            if looks_like_receipt_map(entries) {
                vec![value.clone()]
            } else if let Some(history_value) = map_get_exact_any(entries, &["receipts"]) {
                match history_value {
                    Value::Vector(history_entries) | Value::Set(history_entries) => {
                        history_entries.clone()
                    }
                    _ => return Err("history prefix entries must be vector/set".to_string()),
                }
            } else {
                return Err("history prefix missing receipts".to_string());
            }
        }
        Value::Tagged(tagged) => {
            if tagged.tag.as_str() == "receipt_v0" {
                vec![value.clone()]
            } else {
                match tagged.value.as_ref() {
                    Value::Map(entries) => {
                        if let Some(history_value) = map_get_exact_any(entries, &["receipts"]) {
                            match history_value {
                                Value::Vector(history_entries) | Value::Set(history_entries) => {
                                    history_entries.clone()
                                }
                                _ => {
                                    return Err(
                                        "history prefix entries must be vector/set".to_string()
                                    )
                                }
                            }
                        } else if looks_like_receipt_map(entries) {
                            vec![Value::Map(entries.to_vec())]
                        } else {
                            return Err("history prefix missing receipts".to_string());
                        }
                    }
                    Value::Vector(history_entries) | Value::Set(history_entries) => {
                        history_entries.clone()
                    }
                    _ => {
                        return Err(
                            "history prefix tagged payload must be map/vector/set".to_string()
                        )
                    }
                }
            }
        }
        Value::Nil => Vec::new(),
        _ => {
            return Err("history prefix must be vector/set/map/tagged-map".to_string());
        }
    };

    let mut candidates = Vec::with_capacity(history_entries.len());
    for (entry_index, history_entry) in history_entries.iter().enumerate() {
        let (history_index, receipt_value) =
            parse_history_receipt_entry(history_entry, entry_index as u64)?;
        let parsed_receipt = parse_receipt_v0(&receipt_value)?;
        let canonical_receipt_bytes = rulia::encode_canonical(&receipt_value)
            .map_err(|err| format!("failed to canonicalize history receipt: {err}"))?;
        let canonical_receipt_hash = format!(
            "{}:{}",
            HashAlgorithm::Sha256.as_str(),
            value_to_hex_lower(&HashAlgorithm::Sha256.compute(&canonical_receipt_bytes))
        );
        candidates.push(HistoryReceiptCandidateV0 {
            history_index,
            canonical_receipt_hash,
            parsed_receipt,
        });
    }

    candidates.sort_by(|left, right| {
        left.history_index.cmp(&right.history_index).then_with(|| {
            left.canonical_receipt_hash
                .cmp(&right.canonical_receipt_hash)
        })
    });
    Ok(candidates)
}

fn verify_ed25519_signature(public_key: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let public_key_bytes: [u8; 32] = match public_key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = match Ed25519Signature::from_slice(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    verifying_key.verify_strict(message, &signature).is_ok()
}

fn receipt_signature_input(signing_body_bytes: &[u8]) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + 1 + signing_body_bytes.len());
    input.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN.as_bytes());
    input.push(0);
    input.extend_from_slice(signing_body_bytes);
    input
}

fn verify_receipt_signature(parsed_receipt: &ParsedReceiptV0, public_key: &[u8]) -> bool {
    if parsed_receipt.scope != RECEIPT_SIGNATURE_SCOPE {
        return false;
    }
    if parsed_receipt.signature_alg != "ed25519" {
        return false;
    }
    verify_ed25519_signature(
        public_key,
        &receipt_signature_input(&parsed_receipt.signing_body_bytes),
        &parsed_receipt.signature,
    )
}

fn verify_receipt_failures(
    parsed_receipt: &ParsedReceiptV0,
    expected_request_hash: &ParsedDigestValue,
    trust_anchors: &TrustAnchorSet,
) -> Vec<String> {
    let mut failure_codes = Vec::new();
    if !parsed_receipt
        .request_hash
        .same_value(expected_request_hash)
    {
        failure_codes.push(PW_PROTOCOL_REQUEST_HASH_MISMATCH.to_string());
    }
    if let Some(request_id) = &parsed_receipt.request_id {
        if !request_id.same_value(&parsed_receipt.request_hash) {
            failure_codes.push(PW_PROTOCOL_REQUEST_HASH_MISMATCH.to_string());
        }
    }

    let trusted_public_key = trust_anchors.public_keys.get(&parsed_receipt.signer_key_id);
    if trusted_public_key.is_none() {
        failure_codes.push(PW_PROTOCOL_UNTRUSTED_SIGNER.to_string());
    }

    let signature_valid = trusted_public_key
        .map(|public_key| verify_receipt_signature(parsed_receipt, public_key))
        .unwrap_or(false);
    if trusted_public_key.is_some() && !signature_valid {
        failure_codes.push(PW_PROTOCOL_SIGNATURE_INVALID.to_string());
    }

    order_failure_codes(failure_codes)
}

fn receipt_capability_matches(
    parsed_receipt: &ParsedReceiptV0,
    required_capability: &RequiredCapabilityTuple,
) -> bool {
    parsed_receipt.capability_id.as_deref() == Some(required_capability.capability_id.as_str())
        && parsed_receipt.capability_version.as_deref()
            == Some(required_capability.capability_version.as_str())
        && parsed_receipt.operation.as_deref() == Some(required_capability.operation.as_str())
}

fn evaluate_receipt_valid_obligation(
    obligation: &ParsedReceiptValidObligationV0,
    history_candidates: &[HistoryReceiptCandidateV0],
    trust_anchors: &TrustAnchorSet,
) -> ObligationSatisfactionResultV0 {
    let mut matching_candidates = history_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .parsed_receipt
                .request_hash
                .same_value(&obligation.request_hash)
        })
        .collect::<Vec<_>>();
    matching_candidates.sort_by(|left, right| {
        left.history_index.cmp(&right.history_index).then_with(|| {
            left.canonical_receipt_hash
                .cmp(&right.canonical_receipt_hash)
        })
    });

    if matching_candidates.is_empty() {
        return ObligationSatisfactionResultV0 {
            satisfied: false,
            failure_codes: vec![PW_PROTOCOL_MISSING_RECEIPT.to_string()],
        };
    }

    let mut aggregated_failure_codes = Vec::new();
    for candidate in matching_candidates {
        let mut candidate_failures = verify_receipt_failures(
            &candidate.parsed_receipt,
            &obligation.request_hash,
            trust_anchors,
        );
        if !candidate.parsed_receipt.payload_hash_valid {
            candidate_failures.push(PW_PROTOCOL_PAYLOAD_HASH_MISMATCH.to_string());
        }

        if let Some(required_capability) = &obligation.required_capability {
            if !receipt_capability_matches(&candidate.parsed_receipt, required_capability) {
                candidate_failures.push(PW_PROTOCOL_UNKNOWN_CAPABILITY.to_string());
            }
        }

        if let Some(allowed_outcomes) = &obligation.allowed_outcomes {
            let outcome_allowed = candidate
                .parsed_receipt
                .outcome
                .as_deref()
                .map(|outcome| allowed_outcomes.iter().any(|allowed| allowed == outcome))
                .unwrap_or(false);
            if !outcome_allowed {
                candidate_failures.push(PW_PROTOCOL_OUTCOME_DISALLOWED.to_string());
            }
        }

        let candidate_failures = order_failure_codes(candidate_failures);
        if candidate_failures.is_empty() {
            return ObligationSatisfactionResultV0 {
                satisfied: true,
                failure_codes: Vec::new(),
            };
        }
        aggregated_failure_codes.extend(candidate_failures);
    }

    ObligationSatisfactionResultV0 {
        satisfied: false,
        failure_codes: order_failure_codes(aggregated_failure_codes),
    }
}

fn pw_verifier_result_bytes(
    subject: &str,
    passed: bool,
    failure_codes: Vec<String>,
) -> Option<Vec<u8>> {
    let ordered_failure_codes = order_failure_codes(failure_codes);
    let primary_failure_code = ordered_failure_codes.first().cloned();
    let failure_codes_value = Value::Vector(
        ordered_failure_codes
            .iter()
            .map(|code| Value::String(code.clone()))
            .collect(),
    );

    let result_entries = vec![
        (
            Value::Keyword(Keyword::simple("format")),
            Value::Keyword(Keyword::simple("rulia_pw_verifier_result_v0")),
        ),
        (
            Value::Keyword(Keyword::simple("subject")),
            Value::Keyword(Keyword::simple(subject)),
        ),
        (
            Value::Keyword(Keyword::simple("passed")),
            Value::Bool(passed),
        ),
        (
            Value::Keyword(Keyword::simple("primary_failure_code")),
            primary_failure_code.map_or(Value::Nil, Value::String),
        ),
        (
            Value::Keyword(Keyword::simple("failure_codes")),
            failure_codes_value,
        ),
    ];
    let verifier_result = Value::Tagged(TaggedValue::new(
        Symbol::simple("verifier_result_v0"),
        Value::Map(result_entries),
    ));
    rulia::encode_canonical(&verifier_result).ok()
}

fn pw_stub_internal_error(
    verb: &str,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    if !out_result.is_null() {
        unsafe {
            *out_result = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
    }
    if !out_error_detail.is_null() {
        unsafe {
            *out_error_detail = RuliaBytes {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
        if let Some(bytes) = pw_stub_error_detail_bytes(verb) {
            let _ = bytes_out_set(out_error_detail, bytes);
        }
    }
    RuliaStatus::InternalError
}

/// Return the C ABI version supported by this library.
#[no_mangle]
pub extern "C" fn rulia_ffi_abi_version() -> u32 {
    RULIA_FFI_ABI_VERSION
}

/// Return a static version string for diagnostics.
#[no_mangle]
pub extern "C" fn rulia_ffi_version_string() -> *const c_char {
    RULIA_FFI_VERSION_STRING.as_ptr()
}

/// Parse a Rulia text string into a value (ABI v1).
///
/// Returns a handle result with status codes instead of null pointers.
///
/// # Safety
/// `input` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_parse(input: *const c_char) -> RuliaHandleResult {
    if input.is_null() {
        return handle_error(RuliaStatus::InvalidArgument);
    }

    let c_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return handle_error(RuliaStatus::InvalidArgument),
    };

    match text::parse(c_str) {
        Ok(value) => RuliaHandleResult {
            handle: handle_from_kind(RuliaHandleKind::OwnedValue(RuliaValue(value))),
            status: RuliaStatus::Ok,
        },
        Err(_) => handle_error(RuliaStatus::ParseError),
    }
}

/// Decode binary bytes into a Rulia value (ABI v1).
///
/// # Safety
/// `bytes` must be a valid pointer to a byte array of length `len`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_decode(bytes: *const u8, len: usize) -> RuliaHandleResult {
    if bytes.is_null() {
        return handle_error(RuliaStatus::InvalidArgument);
    }

    let slice = std::slice::from_raw_parts(bytes, len);
    match rulia::decode_value(slice) {
        Ok(value) => RuliaHandleResult {
            handle: handle_from_kind(RuliaHandleKind::OwnedValue(RuliaValue(value))),
            status: RuliaStatus::Ok,
        },
        Err(_) => handle_error(RuliaStatus::DecodeError),
    }
}

/// Create a zero-copy reader over a caller-owned buffer (ABI v1).
///
/// # Safety
/// `ptr` must be a valid pointer to a byte array of length `len` that remains
/// alive and immutable for the lifetime of any reader/value handles.
/// `out_reader` must be a valid pointer to a RuliaHandle storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_reader_new(
    ptr: *const u8,
    len: usize,
    out_reader: *mut RuliaHandle,
) -> RuliaStatus {
    if out_reader.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_reader = 0;
    if ptr.is_null() {
        return RuliaStatus::InvalidArgument;
    }

    let reader = match reader_from_raw_bytes(ptr, len) {
        Ok(reader) => reader,
        Err(status) => return status,
    };
    let inner = Arc::new(RuliaReaderInner {
        base_ptr: ptr,
        len,
        reader,
        closed: AtomicBool::new(false),
    });
    *out_reader = handle_from_kind(RuliaHandleKind::Reader(inner));
    RuliaStatus::Ok
}

/// Free a zero-copy reader handle (ABI v1).
///
/// # Safety
/// `reader` must be a handle returned by `rulia_v1_reader_new`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_reader_free(reader: RuliaHandle) {
    let removed = {
        let mut table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
        if matches!(table.get(&reader), Some(RuliaHandleKind::Reader(_))) {
            table.remove(&reader)
        } else {
            None
        }
    };
    if let Some(RuliaHandleKind::Reader(inner)) = removed {
        inner.closed.store(true, Ordering::Release);
    }
}

/// Get the root value handle from a reader (ABI v1).
///
/// # Safety
/// `reader` must be a valid reader handle.
/// `out_value` must be a valid pointer to a RuliaHandle storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_reader_root(
    reader: RuliaHandle,
    out_value: *mut RuliaHandle,
) -> RuliaStatus {
    if out_value.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_value = 0;
    let inner = match handle_get_reader(reader) {
        Some(inner) => inner,
        None => return RuliaStatus::InvalidArgument,
    };
    if inner.closed.load(Ordering::Acquire) {
        return RuliaStatus::InvalidArgument;
    }
    let root = match reader_root_value(&inner) {
        Ok(root) => root,
        Err(status) => return status,
    };
    let value_ref = RuliaValueRef {
        reader: Arc::clone(&inner),
        value: root,
    };
    *out_value = handle_from_kind(RuliaHandleKind::ValueRef(value_ref));
    RuliaStatus::Ok
}

/// Get the kind of a value handle (ABI v1).
///
/// # Safety
/// `value` must be a valid value handle.
/// `out_kind` must be a valid pointer to a u16 storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_value_kind(
    value: RuliaHandle,
    out_kind: *mut u16,
) -> RuliaStatus {
    if out_kind.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_kind = 0;
    if let Some(value_ref) = handle_get_value_ref(value) {
        if value_ref.reader.closed.load(Ordering::Acquire) {
            return RuliaStatus::InvalidArgument;
        }
        *out_kind = value_ref.value.kind() as u16;
        return RuliaStatus::Ok;
    }
    if let Some(kind) = handle_with_owned_value(value, |value| value_kind(&value.0)) {
        *out_kind = kind as u16;
        return RuliaStatus::Ok;
    }
    RuliaStatus::InvalidArgument
}

/// Get a borrowed string slice from a value handle (ABI v1).
///
/// # Safety
/// `value` must be a valid value handle returned by `rulia_v1_reader_root`.
/// `out_ptr` and `out_len` must be valid pointers to storage locations.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_value_as_string(
    value: RuliaHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> RuliaStatus {
    if out_ptr.is_null() || out_len.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_ptr = ptr::null();
    *out_len = 0;
    let value_ref = match handle_get_value_ref(value) {
        Some(value_ref) => value_ref,
        None => return RuliaStatus::InvalidArgument,
    };
    if value_ref.reader.closed.load(Ordering::Acquire) {
        return RuliaStatus::InvalidArgument;
    }
    match value_ref.value.as_string() {
        Ok(s) => {
            let ptr = s.as_ptr();
            let len = s.len();
            if !pointer_in_range(value_ref.reader.base_ptr, value_ref.reader.len, ptr, len) {
                return RuliaStatus::InternalError;
            }
            *out_ptr = ptr;
            *out_len = len;
            RuliaStatus::Ok
        }
        Err(err) => status_from_error(&err),
    }
}

/// Get a borrowed bytes slice from a value handle (ABI v1).
///
/// # Safety
/// `value` must be a valid value handle returned by `rulia_v1_reader_root`.
/// `out_ptr` and `out_len` must be valid pointers to storage locations.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_value_as_bytes(
    value: RuliaHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> RuliaStatus {
    if out_ptr.is_null() || out_len.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_ptr = ptr::null();
    *out_len = 0;
    let value_ref = match handle_get_value_ref(value) {
        Some(value_ref) => value_ref,
        None => return RuliaStatus::InvalidArgument,
    };
    if value_ref.reader.closed.load(Ordering::Acquire) {
        return RuliaStatus::InvalidArgument;
    }
    match value_ref.value.as_bytes() {
        Ok(bytes) => {
            let ptr = bytes.as_ptr();
            let len = bytes.len();
            if !pointer_in_range(value_ref.reader.base_ptr, value_ref.reader.len, ptr, len) {
                return RuliaStatus::InternalError;
            }
            *out_ptr = ptr;
            *out_len = len;
            RuliaStatus::Ok
        }
        Err(err) => status_from_error(&err),
    }
}

/// Encode a Rulia value to its binary representation (ABI v1).
///
/// # Safety
/// `handle` must be a handle returned by `rulia_v1_parse` or `rulia_v1_decode`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_encode(handle: RuliaHandle) -> RuliaBytesResult {
    let encoded = match handle_with_owned_value(handle, |value| rulia::encode_value(&value.0)) {
        Some(Ok(bytes)) => bytes,
        Some(Err(_)) => return bytes_error(RuliaStatus::InternalError),
        None => return bytes_error(RuliaStatus::InvalidArgument),
    };

    let len = encoded.len();
    let ptr = encoded.as_ptr() as *mut u8;
    std::mem::forget(encoded);
    RuliaBytesResult {
        ptr,
        len,
        status: RuliaStatus::Ok,
    }
}

/// Encode a value in canonical form (ABI v1).
///
/// # Safety
/// `handle` must be a handle returned by `rulia_v1_parse` or `rulia_v1_decode`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_encode_canonical(handle: RuliaHandle) -> RuliaBytesResult {
    let encoded = match handle_with_owned_value(handle, |value| rulia::encode_canonical(&value.0)) {
        Some(Ok(bytes)) => bytes,
        Some(Err(_)) => return bytes_error(RuliaStatus::InternalError),
        None => return bytes_error(RuliaStatus::InvalidArgument),
    };

    let len = encoded.len();
    let ptr = encoded.as_ptr() as *mut u8;
    std::mem::forget(encoded);
    RuliaBytesResult {
        ptr,
        len,
        status: RuliaStatus::Ok,
    }
}

/// Convert a Rulia value to its text representation (ABI v1).
///
/// Returns a newly allocated null-terminated string.
///
/// # Safety
/// `handle` must be a handle returned by `rulia_v1_parse` or `rulia_v1_decode`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_to_string(handle: RuliaHandle) -> RuliaStringResult {
    let text_value = match handle_with_owned_value(handle, |value| text::to_string(&value.0)) {
        Some(s) => s,
        None => return string_error(RuliaStatus::InvalidArgument),
    };

    match CString::new(text_value) {
        Ok(c_string) => RuliaStringResult {
            len: c_string.as_bytes().len(),
            ptr: c_string.into_raw(),
            status: RuliaStatus::Ok,
        },
        Err(_) => string_error(RuliaStatus::InternalError),
    }
}

/// Format Rulia text into canonical form (ABI v1.1).
///
/// # Safety
/// `ptr` must be a valid pointer to a byte array of length `len` (UTF-8).
/// `out` must be a valid pointer to a RuliaBytes storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_format_text(
    ptr: *const u8,
    len: usize,
    out: *mut RuliaBytes,
) -> RuliaStatus {
    if let Err(status) = bytes_out_init(out) {
        return status;
    }
    if ptr.is_null() && len > 0 {
        return RuliaStatus::InvalidArgument;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    };
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return RuliaStatus::FormatInvalidSyntax,
    };

    match rulia_fmt::format(text) {
        Ok(formatted) => bytes_out_set(out, formatted.into_bytes()),
        Err(_) => RuliaStatus::FormatInvalidSyntax,
    }
}

/// Check whether Rulia text is canonical (ABI v1.1).
///
/// # Safety
/// `ptr` must be a valid pointer to a byte array of length `len` (UTF-8).
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_format_check(ptr: *const u8, len: usize) -> RuliaStatus {
    if ptr.is_null() && len > 0 {
        return RuliaStatus::InvalidArgument;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    };
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return RuliaStatus::FormatInvalidSyntax,
    };

    match rulia_fmt::check(text) {
        Ok(()) => RuliaStatus::Ok,
        Err(err) => status_from_format_error(&err),
    }
}

fn frame_encode_with_limit(
    payload_ptr: *const u8,
    payload_len: usize,
    max_len: usize,
    out: *mut RuliaBytes,
) -> RuliaStatus {
    if let Err(status) = bytes_out_init(out) {
        return status;
    }
    if payload_ptr.is_null() && payload_len > 0 {
        return RuliaStatus::InvalidArgument;
    }
    if payload_len == 0 {
        return RuliaStatus::FramingInvalidLength;
    }
    if payload_len > max_len || payload_len > u32::MAX as usize {
        return RuliaStatus::FramingTooLarge;
    }

    let payload = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };
    let total_len = match 4usize.checked_add(payload_len) {
        Some(total_len) => total_len,
        None => return RuliaStatus::FramingOutputError,
    };
    let mut buffer = Vec::new();
    if buffer.try_reserve_exact(total_len).is_err() {
        return RuliaStatus::FramingOutputError;
    }
    buffer.extend_from_slice(&(payload_len as u32).to_le_bytes());
    buffer.extend_from_slice(payload);
    bytes_out_set(out, buffer)
}

/// Encode a payload into a framed stream buffer (ABI v1.1).
///
/// # Safety
/// `payload_ptr` must be a valid pointer to a byte array of length `payload_len`.
/// `out` must be a valid pointer to a RuliaBytes storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_frame_encode(
    payload_ptr: *const u8,
    payload_len: usize,
    out: *mut RuliaBytes,
) -> RuliaStatus {
    frame_encode_with_limit(payload_ptr, payload_len, DEFAULT_MAX_FRAME_LEN, out)
}

/// Encode a payload into a framed stream buffer with a custom length limit (ABI v1.1).
///
/// # Safety
/// `payload_ptr` must be a valid pointer to a byte array of length `payload_len`.
/// `out` must be a valid pointer to a RuliaBytes storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_frame_encode_with_limit(
    payload_ptr: *const u8,
    payload_len: usize,
    max_len: u32,
    out: *mut RuliaBytes,
) -> RuliaStatus {
    frame_encode_with_limit(payload_ptr, payload_len, max_len as usize, out)
}

/// Create a frame decoder for incremental stream decoding (ABI v1.1).
///
/// # Safety
/// `out_decoder` must be a valid pointer to a RuliaHandle storage location.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_frame_decoder_new(
    max_len: u32,
    out_decoder: *mut RuliaHandle,
) -> RuliaStatus {
    if out_decoder.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_decoder = 0;
    if max_len == 0 {
        return RuliaStatus::InvalidArgument;
    }
    let decoder = RuliaFrameDecoder::new(max_len as usize);
    *out_decoder = handle_from_kind(RuliaHandleKind::FrameDecoder(Arc::new(Mutex::new(decoder))));
    RuliaStatus::Ok
}

/// Free a frame decoder handle (ABI v1.1).
///
/// # Safety
/// `decoder` must be a handle returned by `rulia_v1_frame_decoder_new`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_frame_decoder_free(decoder: RuliaHandle) {
    let mut table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
    if matches!(table.get(&decoder), Some(RuliaHandleKind::FrameDecoder(_))) {
        table.remove(&decoder);
    }
}

/// Push bytes into a frame decoder (ABI v1.1).
///
/// # Safety
/// `decoder` must be a valid decoder handle.
/// `ptr` must be a valid pointer to a byte array of length `len` unless `len` is 0.
/// Passing `len == 0` signals end-of-stream and may return truncated status codes.
/// `out_frame` and `out_consumed` must be valid pointers to storage locations.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_frame_decoder_push(
    decoder: RuliaHandle,
    ptr: *const u8,
    len: usize,
    out_frame: *mut RuliaBytes,
    out_consumed: *mut usize,
) -> RuliaStatus {
    if out_consumed.is_null() {
        return RuliaStatus::InvalidArgument;
    }
    *out_consumed = 0;
    if let Err(status) = bytes_out_init(out_frame) {
        return status;
    }
    let decoder = match handle_get_frame_decoder(decoder) {
        Some(decoder) => decoder,
        None => return RuliaStatus::InvalidArgument,
    };

    let mut decoder = decoder.lock().unwrap_or_else(|err| err.into_inner());
    if len == 0 {
        let status = decoder.eof_status();
        if status != RuliaStatus::FramingNeedMoreData {
            decoder.reset();
        }
        return status;
    }
    if ptr.is_null() {
        return RuliaStatus::InvalidArgument;
    }

    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    let mut consumed = 0usize;

    if decoder.payload_len.is_none() {
        let needed = 4usize.saturating_sub(decoder.header_filled);
        let available = len - consumed;
        let take = needed.min(available);
        if take > 0 {
            let start = decoder.header_filled;
            let end = start + take;
            decoder.header[start..end].copy_from_slice(&input[consumed..consumed + take]);
            decoder.header_filled = end;
            consumed += take;
        }

        if decoder.header_filled < 4 {
            *out_consumed = consumed;
            return RuliaStatus::FramingNeedMoreData;
        }

        let frame_len = u32::from_le_bytes(decoder.header) as usize;
        if frame_len == 0 {
            decoder.reset();
            *out_consumed = consumed;
            return RuliaStatus::FramingInvalidLength;
        }
        if frame_len > decoder.max_len {
            decoder.reset();
            *out_consumed = consumed;
            return RuliaStatus::FramingTooLarge;
        }
        decoder.payload.clear();
        if decoder.payload.try_reserve_exact(frame_len).is_err() {
            decoder.reset();
            *out_consumed = consumed;
            return RuliaStatus::FramingOutputError;
        }
        decoder.payload_len = Some(frame_len);
    }

    let expected = match decoder.payload_len {
        Some(expected) => expected,
        None => {
            decoder.reset();
            *out_consumed = consumed;
            return RuliaStatus::InternalError;
        }
    };
    let remaining = expected.saturating_sub(decoder.payload.len());
    let available = len - consumed;
    let take = remaining.min(available);
    if take > 0 {
        decoder
            .payload
            .extend_from_slice(&input[consumed..consumed + take]);
        consumed += take;
    }

    if decoder.payload.len() < expected {
        *out_consumed = consumed;
        return RuliaStatus::FramingNeedMoreData;
    }

    let payload = std::mem::take(&mut decoder.payload);
    decoder.reset();
    *out_consumed = consumed;
    bytes_out_set(out_frame, payload)
}

/// Portable workflow compute-args-hash helper.
///
/// # Safety
/// Input pointers must follow ABI pointer/length rules and out pointers must be writable.
pub unsafe extern "C" fn rulia_v1_pw_compute_args_hash_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            PW_VERB_COMPUTE_ARGS_HASH,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }
    let input = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input_ptr, input_len)
    };
    let decoded = match decode_canonical_input(input) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                PW_VERB_COMPUTE_ARGS_HASH,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_COMPUTE_ARGS_HASH,
                RuliaStatus::VerifyError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_COMPUTE_ARGS_HASH,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    if !is_request_args_canonical_v0(&decoded) {
        return pw_fail(
            PW_VERB_COMPUTE_ARGS_HASH,
            RuliaStatus::VerifyError,
            vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
            out_result,
            out_error_detail,
        );
    }
    let digest_bytes = rulia::HashAlgorithm::Sha256.compute(input);
    let result_bytes = match encode_digest_v0_result(&digest_bytes) {
        Ok(bytes) => bytes,
        Err(status) => {
            return pw_fail(
                PW_VERB_COMPUTE_ARGS_HASH,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    bytes_out_set(out_result, result_bytes)
}

/// Portable workflow compute-request-key helper.
///
/// # Safety
/// Input pointers must follow ABI pointer/length rules and out pointers must be writable.
pub unsafe extern "C" fn rulia_v1_pw_compute_request_key_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            PW_VERB_COMPUTE_REQUEST_KEY,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }
    let input = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input_ptr, input_len)
    };
    let decoded = match decode_canonical_input(input) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                PW_VERB_COMPUTE_REQUEST_KEY,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_COMPUTE_REQUEST_KEY,
                RuliaStatus::VerifyError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_COMPUTE_REQUEST_KEY,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    if !is_request_seed_v0(&decoded) {
        return pw_fail(
            PW_VERB_COMPUTE_REQUEST_KEY,
            RuliaStatus::VerifyError,
            vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
            out_result,
            out_error_detail,
        );
    }
    let digest_bytes = rulia::HashAlgorithm::Sha256.compute(input);
    let result_bytes = match encode_digest_v0_result(&digest_bytes) {
        Ok(bytes) => bytes,
        Err(status) => {
            return pw_fail(
                PW_VERB_COMPUTE_REQUEST_KEY,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    bytes_out_set(out_result, result_bytes)
}

/// Portable workflow hash-subject stub (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_hash_subject_v0(
    _input_ptr: *const u8,
    _input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_stub_internal_error(PW_VERB_HASH_SUBJECT, out_result, out_error_detail)
}

/// Portable workflow request-identity stub (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_request_identity_v0(
    _input_ptr: *const u8,
    _input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_stub_internal_error(PW_VERB_REQUEST_IDENTITY, out_result, out_error_detail)
}

/// Portable workflow rules-desugar stub (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_rules_desugar_sexpr_v0(
    _input_ptr: *const u8,
    _input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_stub_internal_error(PW_VERB_RULES_DESUGAR_SEXPR, out_result, out_error_detail)
}

/// Portable workflow compile-evalir stub (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_compile_evalir_v0(
    _input_ptr: *const u8,
    _input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_stub_internal_error(PW_VERB_COMPILE_EVALIR, out_result, out_error_detail)
}

/// Portable workflow evalir-run stub (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_evalir_run_v1(
    _input_ptr: *const u8,
    _input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_stub_internal_error(PW_VERB_EVALIR_RUN, out_result, out_error_detail)
}

/// Portable workflow eval-evalir implementation.
///
/// # Safety
/// Out pointers must be writable when non-null.
pub unsafe extern "C" fn rulia_v1_pw_eval_evalir_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            PW_VERB_EVAL_EVALIR,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }

    let input_bytes = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input_ptr, input_len)
    };
    let decoded_input = match decode_canonical_input(input_bytes) {
        Ok(decoded) => decoded,
        Err(_) => {
            return pw_fail(
                PW_VERB_EVAL_EVALIR,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let eval_input = match parse_eval_evalir_input_bytes_v0(&decoded_input) {
        Ok(eval_input) => eval_input,
        Err(_) => {
            return pw_fail(
                PW_VERB_EVAL_EVALIR,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let eval_ir_value = match decode_canonical_input(&eval_input.eval_ir_bytes) {
        Ok(eval_ir_value) => eval_ir_value,
        Err(_) => {
            return pw_fail(
                PW_VERB_EVAL_EVALIR,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let state_value = match decode_canonical_input(&eval_input.state_bytes) {
        Ok(state_value) => state_value,
        Err(_) => {
            return pw_fail(
                PW_VERB_EVAL_EVALIR,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let history_value = match eval_input.history_bytes.as_ref() {
        Some(history_bytes) => match decode_canonical_input(history_bytes) {
            Ok(history_value) => Some(history_value),
            Err(_) => {
                return pw_fail(
                    PW_VERB_EVAL_EVALIR,
                    RuliaStatus::DecodeError,
                    vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                    out_result,
                    out_error_detail,
                );
            }
        },
        None => None,
    };
    let gamma_core_value = match eval_input.gamma_core_bytes.as_ref() {
        Some(gamma_core_bytes) => match decode_canonical_input(gamma_core_bytes) {
            Ok(gamma_core_value) => Some(gamma_core_value),
            Err(_) => {
                return pw_fail(
                    PW_VERB_EVAL_EVALIR,
                    RuliaStatus::DecodeError,
                    vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                    out_result,
                    out_error_detail,
                );
            }
        },
        None => None,
    };

    let eval_ir_plan = match parse_eval_ir_plan_v0(&eval_ir_value) {
        Ok(eval_ir_plan) => eval_ir_plan,
        Err(_) => {
            return pw_fail(
                PW_VERB_EVAL_EVALIR,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    if parse_evalir_history_receipts_v0(history_value.as_ref()).is_err()
        || parse_evalir_join_trust_context_v0(gamma_core_value.as_ref()).is_err()
    {
        return pw_fail(
            PW_VERB_EVAL_EVALIR,
            RuliaStatus::DecodeError,
            vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
            out_result,
            out_error_detail,
        );
    }

    let eval_result = evaluate_eval_ir_v0(
        &eval_ir_plan,
        &eval_input.eval_ir_bytes,
        state_value,
        history_value.as_ref(),
        gamma_core_value.as_ref(),
    );
    if eval_result.control == EvalControlV0::Error {
        let failure_codes = if eval_result.errors.is_empty() {
            vec![PW_EVAL_STEP_CONTRACT.to_string()]
        } else {
            eval_result.errors
        };
        return pw_fail(
            PW_VERB_EVAL_EVALIR,
            RuliaStatus::VerifyError,
            failure_codes,
            out_result,
            out_error_detail,
        );
    }

    let result_bytes = match pw_eval_evalir_result_bytes(&eval_result) {
        Some(result_bytes) => result_bytes,
        None => {
            return pw_fail(
                PW_VERB_EVAL_EVALIR,
                RuliaStatus::InternalError,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    bytes_out_set(out_result, result_bytes)
}

/// Portable workflow eval-rules implementation.
///
/// # Safety
/// Out pointers must be writable when non-null.
pub unsafe extern "C" fn rulia_v1_pw_eval_rules_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            PW_VERB_EVAL_RULES,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }

    let input_bytes = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input_ptr, input_len)
    };

    let decoded_input = match decode_canonical_input(input_bytes) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    let eval_input = match parse_eval_rules_input_bytes_v0(&decoded_input, input_bytes) {
        Ok(input) => input,
        Err(_) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let rules_program = match decode_canonical_input(&eval_input.rules_program_bytes) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    let additional_facts = if let Some(facts_bytes) = eval_input.facts_bytes {
        let facts_value = match decode_canonical_input(&facts_bytes) {
            Ok(decoded) => decoded,
            Err(RuliaStatus::DecodeError) => {
                return pw_fail(
                    PW_VERB_EVAL_RULES,
                    RuliaStatus::DecodeError,
                    vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                    out_result,
                    out_error_detail,
                );
            }
            Err(RuliaStatus::VerifyError) => {
                return pw_fail(
                    PW_VERB_EVAL_RULES,
                    RuliaStatus::DecodeError,
                    vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                    out_result,
                    out_error_detail,
                );
            }
            Err(status) => {
                return pw_fail(
                    PW_VERB_EVAL_RULES,
                    status,
                    Vec::new(),
                    out_result,
                    out_error_detail,
                );
            }
        };
        match parse_additional_facts_v0(&facts_value) {
            Ok(facts) => facts,
            Err(code) => {
                return pw_fail(
                    PW_VERB_EVAL_RULES,
                    RuliaStatus::DecodeError,
                    vec![code.to_string()],
                    out_result,
                    out_error_detail,
                );
            }
        }
    } else {
        Vec::new()
    };

    let compiled_program = match parse_rules_program_v0(&rules_program, &additional_facts) {
        Ok(program) => program,
        Err(code) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::VerifyError,
                vec![code.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let evaluation = match evaluate_rules_program_v0(&compiled_program) {
        Ok(result) => result,
        Err(code) => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::VerifyError,
                vec![code.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let result_bytes = match pw_eval_rules_result_bytes(&evaluation) {
        Some(bytes) => bytes,
        None => {
            return pw_fail(
                PW_VERB_EVAL_RULES,
                RuliaStatus::InternalError,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    bytes_out_set(out_result, result_bytes)
}

/// Portable workflow verify-receipt implementation (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_verify_receipt_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            PW_VERB_VERIFY_RECEIPT,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }
    let input_bytes = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input_ptr, input_len)
    };
    let decoded_input = match decode_canonical_input(input_bytes) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    let verify_input = match parse_verify_receipt_input_bytes_v0(&decoded_input) {
        Ok(input) => input,
        Err(_) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let request_value = match decode_canonical_input(&verify_input.request_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    let receipt_value = match decode_canonical_input(&verify_input.receipt_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    let trust_value = match decode_canonical_input(&verify_input.trust_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    let parsed_request = match parse_request_v0(&request_value) {
        Ok(parsed) => parsed,
        Err(_) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let parsed_receipt = match parse_receipt_v0(&receipt_value) {
        Ok(parsed) => parsed,
        Err(_) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let trust_anchors = match parse_trust_anchors_v0(&trust_value) {
        Ok(parsed) => parsed,
        Err(_) => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let expected_request_hash = digest_from_bytes(
        parsed_receipt.request_hash.algorithm,
        &verify_input.request_bytes,
    );
    let mut failure_codes =
        verify_receipt_failures(&parsed_receipt, &expected_request_hash, &trust_anchors);

    if !parsed_request.payload_hash_valid || !parsed_receipt.payload_hash_valid {
        failure_codes.push(PW_PROTOCOL_PAYLOAD_HASH_MISMATCH.to_string());
    }
    if let Some(expected_schema_ref) = &parsed_request.expected_receipt_schema_ref {
        let schema_matches = parsed_receipt
            .schema_ref
            .as_ref()
            .map(|schema_ref| schema_ref.same_value(expected_schema_ref))
            .unwrap_or(false);
        if !schema_matches {
            failure_codes.push(PW_PROTOCOL_SCHEMA_MISMATCH.to_string());
        }
    }
    if let (Some(request_capability), Some(receipt_capability)) = (
        parsed_request.capability_id.as_deref(),
        parsed_receipt.capability_id.as_deref(),
    ) {
        if request_capability != receipt_capability {
            failure_codes.push(PW_PROTOCOL_SCHEMA_MISMATCH.to_string());
        }
    }
    if let (Some(request_capability_version), Some(receipt_capability_version)) = (
        parsed_request.capability_version.as_deref(),
        parsed_receipt.capability_version.as_deref(),
    ) {
        if request_capability_version != receipt_capability_version {
            failure_codes.push(PW_PROTOCOL_SCHEMA_MISMATCH.to_string());
        }
    }
    if let (Some(request_operation), Some(receipt_operation)) = (
        parsed_request.operation.as_deref(),
        parsed_receipt.operation.as_deref(),
    ) {
        if request_operation != receipt_operation {
            failure_codes.push(PW_PROTOCOL_SCHEMA_MISMATCH.to_string());
        }
    }
    let failure_codes = order_failure_codes(failure_codes);
    if !failure_codes.is_empty() {
        return pw_fail(
            PW_VERB_VERIFY_RECEIPT,
            RuliaStatus::VerifyError,
            failure_codes,
            out_result,
            out_error_detail,
        );
    }

    let result_bytes = match pw_verifier_result_bytes("receipt", true, Vec::new()) {
        Some(bytes) => bytes,
        None => {
            return pw_fail(
                PW_VERB_VERIFY_RECEIPT,
                RuliaStatus::InternalError,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    bytes_out_set(out_result, result_bytes)
}

fn pw_run_verify_obligation_v0(
    verb: &str,
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            verb,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }
    let input_bytes = if input_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(input_ptr, input_len) }
    };
    let decoded_input = match decode_canonical_input(input_bytes) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(verb, status, Vec::new(), out_result, out_error_detail);
        }
    };

    let verify_input = match parse_verify_obligation_input_bytes_v0(&decoded_input) {
        Ok(input) => input,
        Err(_) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let obligation_value = match decode_canonical_input(&verify_input.obligation_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => return pw_fail(verb, status, Vec::new(), out_result, out_error_detail),
    };
    let history_value = match decode_canonical_input(&verify_input.history_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => return pw_fail(verb, status, Vec::new(), out_result, out_error_detail),
    };
    let trust_value = match decode_canonical_input(&verify_input.trust_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => return pw_fail(verb, status, Vec::new(), out_result, out_error_detail),
    };

    let obligation = match parse_receipt_valid_obligation_v0(&obligation_value) {
        Ok(parsed) => parsed,
        Err(_) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let history_candidates = match parse_history_prefix_v0(&history_value) {
        Ok(parsed) => parsed,
        Err(_) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let trust_anchors = match parse_trust_anchors_v0(&trust_value) {
        Ok(parsed) => parsed,
        Err(_) => {
            return pw_fail(
                verb,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let satisfaction =
        evaluate_receipt_valid_obligation(&obligation, &history_candidates, &trust_anchors);
    let result_bytes = match pw_verifier_result_bytes(
        "obligation",
        satisfaction.satisfied,
        satisfaction.failure_codes,
    ) {
        Some(bytes) => bytes,
        None => {
            return pw_fail(
                verb,
                RuliaStatus::InternalError,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    bytes_out_set(out_result, result_bytes)
}

/// Portable workflow verify-obligation implementation (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_verify_obligation_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_run_verify_obligation_v0(
        PW_VERB_VERIFY_OBLIGATION,
        input_ptr,
        input_len,
        out_result,
        out_error_detail,
    )
}

/// Portable workflow match-capabilities implementation (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_match_capabilities_v0(
    input_ptr: *const u8,
    input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    let init_status = pw_init_outputs(out_result, out_error_detail);
    if init_status != RuliaStatus::Ok {
        return init_status;
    }
    if input_ptr.is_null() && input_len > 0 {
        return pw_fail(
            PW_VERB_MATCH_CAPABILITIES,
            RuliaStatus::InvalidArgument,
            Vec::new(),
            out_result,
            out_error_detail,
        );
    }
    let input_bytes = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input_ptr, input_len)
    };
    let decoded_input = match decode_canonical_input(input_bytes) {
        Ok(decoded) => decoded,
        Err(RuliaStatus::DecodeError) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    let match_input = match parse_match_capabilities_input_bytes_v0(&decoded_input) {
        Ok(input) => input,
        Err(_) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let requirements_value = match decode_canonical_input(&match_input.requirements_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };
    let gamma_cap_value = match decode_canonical_input(&match_input.gamma_cap_bytes) {
        Ok(value) => value,
        Err(RuliaStatus::DecodeError | RuliaStatus::VerifyError) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
        Err(status) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                status,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    let requirements = match parse_capability_requirements_v0(&requirements_value) {
        Ok(requirements) => requirements,
        Err(_) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };
    let gamma_cap_snapshot = match parse_gamma_cap_snapshot_v0(&gamma_cap_value) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::DecodeError,
                vec![PW_PROTOCOL_SCHEMA_MISMATCH.to_string()],
                out_result,
                out_error_detail,
            );
        }
    };

    let result = evaluate_match_capability(&requirements, &gamma_cap_snapshot);
    let result_bytes = match pw_match_cap_result_bytes(&result) {
        Some(bytes) => bytes,
        None => {
            return pw_fail(
                PW_VERB_MATCH_CAPABILITIES,
                RuliaStatus::InternalError,
                Vec::new(),
                out_result,
                out_error_detail,
            );
        }
    };

    if result.status == "reject" || result.status == "suspend" {
        return pw_fail_with_result(
            PW_VERB_MATCH_CAPABILITIES,
            RuliaStatus::VerifyError,
            result.failure_codes.clone(),
            result_bytes,
            out_result,
            out_error_detail,
        );
    }

    bytes_out_set(out_result, result_bytes)
}

/// Portable workflow receipt-signing-payload stub (ABI v1 additive).
///
/// # Safety
/// Out pointers must be writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_pw_receipt_signing_payload_v0(
    _input_ptr: *const u8,
    _input_len: usize,
    out_result: *mut RuliaBytes,
    out_error_detail: *mut RuliaBytes,
) -> RuliaStatus {
    pw_stub_internal_error(
        PW_VERB_RECEIPT_SIGNING_PAYLOAD,
        out_result,
        out_error_detail,
    )
}

/// Free bytes allocated by ABI v1 functions.
///
/// # Safety
/// `ptr` and `len` must be from a previous ABI v1 bytes result or null/zero.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_bytes_free(ptr: *mut u8, len: usize) {
    rulia_bytes_free(ptr, len);
}

/// Free a string allocated by ABI v1 functions.
///
/// # Safety
/// `ptr` must be a pointer returned by `rulia_v1_to_string` or null.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_string_free(ptr: *mut c_char) {
    rulia_string_free(ptr);
}

/// Free a value handle allocated by ABI v1 functions.
///
/// # Safety
/// `handle` must be returned by `rulia_v1_parse`, `rulia_v1_decode`, or
/// `rulia_v1_reader_root`.
#[no_mangle]
pub unsafe extern "C" fn rulia_v1_value_free(handle: RuliaHandle) {
    let removed = {
        let mut table = handle_table().lock().unwrap_or_else(|err| err.into_inner());
        if matches!(
            table.get(&handle),
            Some(RuliaHandleKind::OwnedValue(_) | RuliaHandleKind::ValueRef(_))
        ) {
            table.remove(&handle)
        } else {
            None
        }
    };
    drop(removed);
}

/// Parse a Rulia text string into a value.
///
/// Returns a pointer to a RuliaValue on success, or null on error.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `input` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn rulia_parse(input: *const c_char) -> *mut RuliaValue {
    if input.is_null() {
        return ptr::null_mut();
    }

    let c_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match text::parse(c_str) {
        Ok(value) => Box::into_raw(Box::new(RuliaValue(value))),
        Err(_) => ptr::null_mut(),
    }
}

/// Parse a Rulia file.
///
/// Returns a pointer to a RuliaValue on success, or null on error.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `path` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn rulia_parse_file(path: *const c_char) -> *mut RuliaValue {
    if path.is_null() {
        return ptr::null_mut();
    }

    let c_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match text::parse_file(c_str) {
        Ok(value) => Box::into_raw(Box::new(RuliaValue(value))),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a RuliaValue allocated by this library.
///
/// # Safety
/// `value` must be a pointer returned by `rulia_parse` or null.
#[no_mangle]
pub unsafe extern "C" fn rulia_free(value: *mut RuliaValue) {
    if !value.is_null() {
        drop(Box::from_raw(value));
    }
}

/// Get the kind of a Rulia value as a string.
///
/// Returns a static null-terminated string like "map", "vector", "string", etc.
/// Returns null if the value pointer is null.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue or null.
#[no_mangle]
pub unsafe extern "C" fn rulia_kind(value: *const RuliaValue) -> *const c_char {
    if value.is_null() {
        return ptr::null();
    }

    // Return static null-terminated strings for each kind
    match &(*value).0 {
        Value::Nil => c"nil".as_ptr(),
        Value::Bool(_) => c"bool".as_ptr(),
        Value::Int(_) => c"int".as_ptr(),
        Value::UInt(_) => c"uint".as_ptr(),
        Value::BigInt(_) => c"bigint".as_ptr(),
        Value::Float32(_) => c"f32".as_ptr(),
        Value::Float64(_) => c"f64".as_ptr(),
        Value::String(_) => c"string".as_ptr(),
        Value::Bytes(_) => c"bytes".as_ptr(),
        Value::Symbol(_) => c"symbol".as_ptr(),
        Value::Keyword(_) => c"keyword".as_ptr(),
        Value::Vector(_) => c"vector".as_ptr(),
        Value::Set(_) => c"set".as_ptr(),
        Value::Map(_) => c"map".as_ptr(),
        Value::Tagged(_) => c"tagged".as_ptr(),
        Value::Annotated(_) => c"annotated".as_ptr(),
    }
}

/// Encode a Rulia value to its binary representation.
///
/// Returns a pointer to the encoded bytes and sets `len` to the length.
/// The caller is responsible for freeing the bytes with `rulia_bytes_free`.
/// Returns null on error.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `len` must be a valid pointer to a usize.
#[no_mangle]
pub unsafe extern "C" fn rulia_encode(value: *const RuliaValue, len: *mut usize) -> *mut u8 {
    if value.is_null() || len.is_null() {
        return ptr::null_mut();
    }

    match rulia::encode_value(&(*value).0) {
        Ok(bytes) => {
            *len = bytes.len();
            let ptr = bytes.as_ptr() as *mut u8;
            std::mem::forget(bytes);
            ptr
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Decode binary bytes into a RuliaValue.
///
/// Returns a pointer to a RuliaValue on success, or null on error.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `bytes` must be a valid pointer to a byte array of length `len`.
#[no_mangle]
pub unsafe extern "C" fn rulia_decode(bytes: *const u8, len: usize) -> *mut RuliaValue {
    if bytes.is_null() {
        return ptr::null_mut();
    }

    let slice = std::slice::from_raw_parts(bytes, len);
    match rulia::decode_value(slice) {
        Ok(value) => Box::into_raw(Box::new(RuliaValue(value))),
        Err(_) => ptr::null_mut(),
    }
}

/// Encode a value in canonical form.
///
/// Returns a pointer to the encoded bytes and sets `len` to the length.
/// The caller is responsible for freeing the bytes with `rulia_bytes_free`.
/// Returns null on error.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `len` must be a valid pointer to a usize.
#[no_mangle]
pub unsafe extern "C" fn rulia_encode_canonical(
    value: *const RuliaValue,
    len: *mut usize,
) -> *mut u8 {
    if value.is_null() || len.is_null() {
        return ptr::null_mut();
    }

    match rulia::encode_canonical(&(*value).0) {
        Ok(bytes) => {
            *len = bytes.len();
            let ptr = bytes.as_ptr() as *mut u8;
            std::mem::forget(bytes);
            ptr
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Encode a value with an embedded digest.
///
/// Returns a pointer to the encoded bytes and sets `len` to the length.
/// Writes the 32-byte digest to `digest_out`.
/// The caller is responsible for freeing the bytes with `rulia_bytes_free`.
/// Returns null on error.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `algorithm` must be 1 (SHA256) or 2 (Blake3).
/// `len` must be a valid pointer to a usize.
/// `digest_out` must be a valid pointer to a 32-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn rulia_encode_with_digest(
    value: *const RuliaValue,
    algorithm: u8,
    len: *mut usize,
    digest_out: *mut u8,
) -> *mut u8 {
    if value.is_null() || len.is_null() || digest_out.is_null() {
        return ptr::null_mut();
    }

    let hash_algorithm = match algorithm {
        1 => rulia::HashAlgorithm::Sha256,
        2 => rulia::HashAlgorithm::Blake3,
        _ => return ptr::null_mut(),
    };

    match rulia::encode_with_digest_using(&(*value).0, hash_algorithm) {
        Ok(encoded) => {
            let digest_slice = std::slice::from_raw_parts_mut(digest_out, 32);
            digest_slice.copy_from_slice(&encoded.digest);

            *len = encoded.bytes.len();
            let ptr = encoded.bytes.as_ptr() as *mut u8;
            std::mem::forget(encoded.bytes);
            ptr
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Verify digest in bytes.
///
/// Returns the algorithm ID (1=SHA256, 2=Blake3) on success, or 0 on failure.
///
/// # Safety
/// `bytes` must be a valid pointer to a byte array of length `len`.
#[no_mangle]
pub unsafe extern "C" fn rulia_verify_digest(bytes: *const u8, len: usize) -> u8 {
    if bytes.is_null() {
        return 0;
    }

    let slice = std::slice::from_raw_parts(bytes, len);
    match rulia::verify_digest(slice) {
        Ok((algorithm, _digest)) => match algorithm {
            rulia::HashAlgorithm::Sha256 => 1,
            rulia::HashAlgorithm::Blake3 => 2,
        },
        Err(_) => 0,
    }
}

/// Free bytes allocated by `rulia_encode`.
///
/// # Safety
/// `ptr` and `len` must be from a previous call to `rulia_encode`.
#[no_mangle]
pub unsafe extern "C" fn rulia_bytes_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

/// Convert a Rulia value to its text representation.
///
/// Returns a newly allocated null-terminated string.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_to_string(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    let s = text::to_string(&(*value).0);
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string allocated by `rulia_to_string`.
///
/// # Safety
/// `s` must be a pointer returned by `rulia_to_string` or null.
#[no_mangle]
pub unsafe extern "C" fn rulia_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// ============================================================================
// Primitive Value Extraction
// ============================================================================

/// Get string value from a RuliaValue.
///
/// Returns a newly allocated null-terminated string, or null if the value is not a string.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_string(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::String(s) => match CString::new(s.as_str()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Get bigint value from a RuliaValue as decimal text.
///
/// Returns a newly allocated null-terminated string, or null if the value is not bigint.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_bigint(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::BigInt(bigint) => match CString::new(bigint.to_string()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Get bytes value from a RuliaValue.
///
/// Returns a newly allocated byte buffer and writes its length to `len_out`,
/// or null if the value is not bytes.
/// The caller is responsible for freeing it with `rulia_bytes_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `len_out` must be a valid pointer to a usize.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_bytes(
    value: *const RuliaValue,
    len_out: *mut usize,
) -> *mut u8 {
    if value.is_null() || len_out.is_null() {
        return ptr::null_mut();
    }

    *len_out = 0;
    match &(*value).0 {
        Value::Bytes(bytes) => {
            let mut out = Vec::with_capacity(bytes.len());
            out.extend_from_slice(bytes);
            *len_out = out.len();
            let ptr = out.as_mut_ptr();
            std::mem::forget(out);
            ptr
        }
        _ => ptr::null_mut(),
    }
}

/// Get integer value from a RuliaValue.
///
/// Returns true and writes the value to `out` if successful, false otherwise.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `out` must be a valid pointer to an i64.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_int(value: *const RuliaValue, out: *mut i64) -> bool {
    if value.is_null() || out.is_null() {
        return false;
    }

    match &(*value).0 {
        Value::Int(i) => {
            *out = *i;
            true
        }
        _ => false,
    }
}

/// Get unsigned integer value from a RuliaValue.
///
/// Returns true and writes the value to `out` if successful, false otherwise.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `out` must be a valid pointer to a u64.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_uint(value: *const RuliaValue, out: *mut u64) -> bool {
    if value.is_null() || out.is_null() {
        return false;
    }

    match &(*value).0 {
        Value::UInt(u) => {
            *out = *u;
            true
        }
        _ => false,
    }
}

/// Get float64 value from a RuliaValue.
///
/// Returns true and writes the value to `out` if successful, false otherwise.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `out` must be a valid pointer to an f64.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_float64(value: *const RuliaValue, out: *mut f64) -> bool {
    if value.is_null() || out.is_null() {
        return false;
    }

    match &(*value).0 {
        Value::Float64(f) => {
            *out = f.into_inner();
            true
        }
        _ => false,
    }
}

/// Get float32 value from a RuliaValue.
///
/// Returns true and writes the value to `out` if successful, false otherwise.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `out` must be a valid pointer to an f32.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_float32(value: *const RuliaValue, out: *mut f32) -> bool {
    if value.is_null() || out.is_null() {
        return false;
    }

    match &(*value).0 {
        Value::Float32(f) => {
            *out = f.into_inner();
            true
        }
        _ => false,
    }
}

/// Get bool value from a RuliaValue.
///
/// Returns true and writes the value to `out` if successful, false otherwise.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `out` must be a valid pointer to a bool.
#[no_mangle]
pub unsafe extern "C" fn rulia_get_bool(value: *const RuliaValue, out: *mut bool) -> bool {
    if value.is_null() || out.is_null() {
        return false;
    }

    match &(*value).0 {
        Value::Bool(b) => {
            *out = *b;
            true
        }
        _ => false,
    }
}

// ============================================================================
// Collection Access
// ============================================================================

/// Get vector length.
///
/// Returns the length of the vector, or -1 if the value is not a vector.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_vector_len(value: *const RuliaValue) -> isize {
    if value.is_null() {
        return -1;
    }

    match &(*value).0 {
        Value::Vector(vec) => vec.len() as isize,
        _ => -1,
    }
}

/// Get vector element at index.
///
/// Returns a pointer to a new RuliaValue containing the element, or null on error.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_vector_get(
    value: *const RuliaValue,
    index: usize,
) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Vector(vec) => {
            if index < vec.len() {
                Box::into_raw(Box::new(RuliaValue(vec[index].clone())))
            } else {
                ptr::null_mut()
            }
        }
        _ => ptr::null_mut(),
    }
}

/// Get set length.
///
/// Returns the length of the set, or -1 if the value is not a set.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_set_len(value: *const RuliaValue) -> isize {
    if value.is_null() {
        return -1;
    }

    match &(*value).0 {
        Value::Set(items) => items.len() as isize,
        _ => -1,
    }
}

/// Get set element at index.
///
/// Returns a pointer to a new RuliaValue containing the element, or null on error.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_set_get(value: *const RuliaValue, index: usize) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Set(items) => {
            if index < items.len() {
                Box::into_raw(Box::new(RuliaValue(items[index].clone())))
            } else {
                ptr::null_mut()
            }
        }
        _ => ptr::null_mut(),
    }
}

/// Get map length.
///
/// Returns the number of entries in the map, or -1 if the value is not a map.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_map_len(value: *const RuliaValue) -> isize {
    if value.is_null() {
        return -1;
    }

    match &(*value).0 {
        Value::Map(entries) => entries.len() as isize,
        _ => -1,
    }
}

/// Get map value by keyword name.
///
/// Returns a pointer to a new RuliaValue containing the value, or null if key not found.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `key` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn rulia_map_get(
    value: *const RuliaValue,
    key: *const c_char,
) -> *mut RuliaValue {
    if value.is_null() || key.is_null() {
        return ptr::null_mut();
    }

    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match &(*value).0 {
        Value::Map(entries) => {
            let search_key = Value::Keyword(rulia::Keyword::parse(key_str));
            for (k, v) in entries {
                if k == &search_key {
                    return Box::into_raw(Box::new(RuliaValue(v.clone())));
                }
            }
            ptr::null_mut()
        }
        _ => ptr::null_mut(),
    }
}

/// Get map keys as a vector.
///
/// Returns a pointer to a new RuliaValue containing a vector of keys, or null on error.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_map_keys(value: *const RuliaValue) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Map(entries) => {
            let keys: Vec<Value> = entries.iter().map(|(k, _)| k.clone()).collect();
            Box::into_raw(Box::new(RuliaValue(Value::Vector(keys))))
        }
        _ => ptr::null_mut(),
    }
}

/// Get map key/value entry at index.
///
/// Returns true and writes newly allocated key/value pointers when successful.
/// Caller owns both outputs and must free them with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
/// `out_key` and `out_value` must be valid pointers to pointer storage.
#[no_mangle]
pub unsafe extern "C" fn rulia_map_entry_at(
    value: *const RuliaValue,
    index: usize,
    out_key: *mut *mut RuliaValue,
    out_value: *mut *mut RuliaValue,
) -> bool {
    if value.is_null() || out_key.is_null() || out_value.is_null() {
        return false;
    }

    *out_key = ptr::null_mut();
    *out_value = ptr::null_mut();

    match &(*value).0 {
        Value::Map(entries) => {
            if let Some((key, map_value)) = entries.get(index) {
                *out_key = Box::into_raw(Box::new(RuliaValue(key.clone())));
                *out_value = Box::into_raw(Box::new(RuliaValue(map_value.clone())));
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

// ============================================================================
// Keyword/Symbol Access
// ============================================================================

/// Get keyword name.
///
/// Returns a newly allocated null-terminated string, or null if the value is not a keyword.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_keyword_name(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Keyword(kw) => match CString::new(kw.name()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Get keyword namespace.
///
/// Returns a newly allocated null-terminated string, or null if the keyword has no namespace
/// or the value is not a keyword.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_keyword_namespace(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Keyword(kw) => match kw.namespace() {
            Some(ns) => match CString::new(ns) {
                Ok(c_string) => c_string.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            None => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Get symbol name.
///
/// Returns a newly allocated null-terminated string, or null if the value is not a symbol.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_symbol_name(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Symbol(sym) => match CString::new(sym.name()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Get symbol namespace.
///
/// Returns a newly allocated null-terminated string, or null if the symbol has no namespace
/// or the value is not a symbol.
/// The caller is responsible for freeing it with `rulia_string_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_symbol_namespace(value: *const RuliaValue) -> *mut c_char {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Symbol(sym) => match sym.namespace() {
            Some(ns) => match CString::new(ns) {
                Ok(c_string) => c_string.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            None => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Get tagged value tag as a new symbol value.
///
/// Returns a pointer to a new `RuliaValue::Symbol`, or null if value is not tagged.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_tagged_tag(value: *const RuliaValue) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Tagged(tagged) => Box::into_raw(Box::new(RuliaValue(Value::Symbol(tagged.tag.clone())))),
        _ => ptr::null_mut(),
    }
}

/// Get tagged value payload.
///
/// Returns a pointer to a new `RuliaValue` containing the tagged payload,
/// or null if value is not tagged.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_tagged_value(value: *const RuliaValue) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Tagged(tagged) => Box::into_raw(Box::new(RuliaValue((*tagged.value).clone()))),
        _ => ptr::null_mut(),
    }
}

/// Get annotated metadata as a map value.
///
/// Returns a pointer to a new `RuliaValue::Map` containing metadata entries,
/// or null if value is not annotated.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_annotated_metadata(value: *const RuliaValue) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Annotated(annotation) => {
            Box::into_raw(Box::new(RuliaValue(Value::Map(annotation.metadata.clone()))))
        }
        _ => ptr::null_mut(),
    }
}

/// Get annotated inner value.
///
/// Returns a pointer to a new `RuliaValue` containing the annotated payload,
/// or null if value is not annotated.
/// The caller is responsible for freeing the returned value with `rulia_free`.
///
/// # Safety
/// `value` must be a valid pointer to a RuliaValue.
#[no_mangle]
pub unsafe extern "C" fn rulia_annotated_inner(value: *const RuliaValue) -> *mut RuliaValue {
    if value.is_null() {
        return ptr::null_mut();
    }

    match &(*value).0 {
        Value::Annotated(annotation) => Box::into_raw(Box::new(RuliaValue((*annotation.value).clone()))),
        _ => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulia::Keyword;

    #[test]
    fn abi_version_is_v1() {
        assert_eq!(rulia_ffi_abi_version(), 1);
    }

    #[test]
    fn handle_is_pointer_sized() {
        assert_eq!(
            std::mem::size_of::<RuliaHandle>(),
            std::mem::size_of::<*mut RuliaValue>()
        );
    }

    #[test]
    fn v1_zero_copy_string_and_bytes_are_in_buffer() {
        let value = Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("name")),
                Value::String("hello".into()),
            ),
            (
                Value::Keyword(Keyword::simple("data")),
                Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            ),
        ]);
        let bytes = rulia::encode_value(&value).expect("encode");

        let mut reader_handle: RuliaHandle = 0;
        let status =
            unsafe { rulia_v1_reader_new(bytes.as_ptr(), bytes.len(), &mut reader_handle) };
        assert_eq!(status, RuliaStatus::Ok);
        assert_ne!(reader_handle, 0);

        let mut root_handle: RuliaHandle = 0;
        let status = unsafe { rulia_v1_reader_root(reader_handle, &mut root_handle) };
        assert_eq!(status, RuliaStatus::Ok);
        assert_ne!(root_handle, 0);

        let mut kind: u16 = 0;
        let status = unsafe { rulia_v1_value_kind(root_handle, &mut kind) };
        assert_eq!(status, RuliaStatus::Ok);
        assert_eq!(kind, TypeTag::Map as u16);

        let root_ref = match handle_get_value_ref(root_handle) {
            Some(value_ref) => value_ref,
            None => panic!("expected value_ref handle"),
        };

        let mut string_ref = None;
        let mut bytes_ref = None;
        for entry in root_ref.value.map_iter().expect("map iter") {
            let (_key, value_ref) = entry.expect("entry");
            match value_ref.kind() {
                TypeTag::String => string_ref = Some(value_ref.clone()),
                TypeTag::Bytes => bytes_ref = Some(value_ref.clone()),
                _ => {}
            }
        }

        let string_ref = string_ref.expect("string value");
        let bytes_ref = bytes_ref.expect("bytes value");

        let string_handle = handle_from_kind(RuliaHandleKind::ValueRef(RuliaValueRef {
            reader: Arc::clone(&root_ref.reader),
            value: string_ref,
        }));
        let bytes_handle = handle_from_kind(RuliaHandleKind::ValueRef(RuliaValueRef {
            reader: Arc::clone(&root_ref.reader),
            value: bytes_ref,
        }));

        let mut string_ptr: *const u8 = ptr::null();
        let mut string_len: usize = 0;
        let status =
            unsafe { rulia_v1_value_as_string(string_handle, &mut string_ptr, &mut string_len) };
        assert_eq!(status, RuliaStatus::Ok);
        assert!(pointer_in_range(
            bytes.as_ptr(),
            bytes.len(),
            string_ptr,
            string_len
        ));

        let mut bytes_ptr: *const u8 = ptr::null();
        let mut bytes_len: usize = 0;
        let status =
            unsafe { rulia_v1_value_as_bytes(bytes_handle, &mut bytes_ptr, &mut bytes_len) };
        assert_eq!(status, RuliaStatus::Ok);
        assert!(pointer_in_range(
            bytes.as_ptr(),
            bytes.len(),
            bytes_ptr,
            bytes_len
        ));

        unsafe {
            rulia_v1_value_free(string_handle);
            rulia_v1_value_free(bytes_handle);
            rulia_v1_value_free(root_handle);
            rulia_v1_reader_free(reader_handle);
        }
    }
}
