use std::fs;
use std::path::PathBuf;
use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::{Keyword, Symbol, TaggedValue, Value};
use rulia_ffi::{rulia_v1_bytes_free, rulia_v1_pw_eval_evalir_v0, RuliaBytes, RuliaStatus};

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
    for (entry_key, entry_value) in entries {
        let matches_key = match entry_key {
            Value::Keyword(keyword) => keyword.name() == key,
            Value::String(raw) => raw == key,
            _ => false,
        };
        if matches_key {
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

fn decode_value(bytes: &[u8]) -> Value {
    rulia::decode_value(bytes).expect("decode canonical")
}

fn decode_ffi_value(bytes: &FfiBytes) -> Value {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    let decoded = decode_value(slice);
    let reencoded = canonical_bytes(&decoded);
    assert_eq!(reencoded, slice, "ffi bytes must be canonical");
    decoded
}

fn ffi_bytes_to_vec(bytes: &FfiBytes) -> Vec<u8> {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    slice.to_vec()
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rulia-cli")
        .join("tests")
        .join("fixtures")
        .join("l2_evalir_v0")
        .join(name)
}

fn fixture_value(name: &str) -> Value {
    let raw = fs::read_to_string(fixture_path(name)).expect("read fixture");
    parse_json_value(raw.as_str()).expect("parse fixture JSON")
}

fn eval_evalir_input_bytes(
    eval_ir: &Value,
    state: &Value,
    history: Option<&Value>,
    gamma_core: Option<&Value>,
) -> Vec<u8> {
    let mut entries = vec![
        (kw("format"), kw("rulia_eval_evalir_input_v0")),
        (
            kw("eval_ir_bytes"),
            Value::Bytes(canonical_bytes(&canonical_eval_ir_value(eval_ir))),
        ),
        (kw("state_bytes"), Value::Bytes(canonical_bytes(state))),
    ];
    if let Some(history) = history {
        entries.push((
            kw("history_bytes"),
            Value::Bytes(canonical_bytes(&canonical_history_prefix_value(history))),
        ));
    }
    if let Some(gamma_core) = gamma_core {
        entries.push((
            kw("gamma_core_bytes"),
            Value::Bytes(canonical_bytes(gamma_core)),
        ));
    }
    canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("eval_evalir_input_v0"),
        Value::Map(entries),
    )))
}

fn canonical_eval_ir_value(value: &Value) -> Value {
    match value {
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, entry_value)| {
                    let canonical_key = match key {
                        Value::String(raw) if raw == "kind" => Value::String("op".to_string()),
                        Value::Keyword(keyword) if keyword.name() == "kind" => kw("op"),
                        _ => key.clone(),
                    };
                    (canonical_key, canonical_eval_ir_value(entry_value))
                })
                .collect(),
        ),
        Value::Vector(values) => {
            Value::Vector(values.iter().map(canonical_eval_ir_value).collect())
        }
        Value::Set(values) => Value::Set(values.iter().map(canonical_eval_ir_value).collect()),
        Value::Tagged(tagged) => Value::Tagged(TaggedValue::new(
            tagged.tag.clone(),
            canonical_eval_ir_value(tagged.value.as_ref()),
        )),
        _ => value.clone(),
    }
}

fn canonical_history_prefix_value(value: &Value) -> Value {
    let Value::Map(entries) = value else {
        return value.clone();
    };
    let receipts = entries.iter().find_map(|(key, value)| match key {
        Value::String(raw) if raw == "receipts" || raw == "items" => Some(value.clone()),
        Value::Keyword(keyword) if keyword.name() == "receipts" || keyword.name() == "items" => {
            Some(value.clone())
        }
        _ => None,
    });
    match receipts {
        Some(receipts) => Value::Map(vec![(Value::String("receipts".to_string()), receipts)]),
        None => value.clone(),
    }
}

fn call_eval_evalir(input: &[u8]) -> (RuliaStatus, Option<FfiBytes>, Option<FfiBytes>) {
    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        rulia_v1_pw_eval_evalir_v0(
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

fn decode_eval_result(bytes: &FfiBytes) -> (String, usize, Option<String>, Vec<String>) {
    let value = decode_ffi_value(bytes);
    let Value::Tagged(tagged) = value else {
        panic!("expected tagged EvalRunResultV0");
    };
    assert_eq!(tagged.tag.as_str(), "eval_run_result_v0");
    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected EvalRunResultV0 map payload");
    };

    assert_exact_keys(
        entries,
        &[
            "format",
            "terminal_control",
            "step_results",
            "primary_failure_code",
            "failure_codes",
        ],
    );
    assert!(map_get(entries, "control").is_none());
    assert!(map_get(entries, "state_out").is_none());
    assert!(map_get(entries, "emissions").is_none());
    assert!(map_get(entries, "requests").is_none());
    assert!(map_get(entries, "obligations").is_none());
    assert!(map_get(entries, "errors").is_none());

    let Some(control) = map_get(entries, "terminal_control") else {
        panic!("expected terminal_control");
    };
    let terminal_control = match control {
        Value::Keyword(keyword) => keyword.name().to_string(),
        Value::String(raw) => raw.clone(),
        _ => panic!("terminal_control must be keyword/string"),
    };
    let Some(Value::Vector(step_results)) = map_get(entries, "step_results") else {
        panic!("expected step_results vector");
    };
    let Some(primary_failure_code_value) = map_get(entries, "primary_failure_code") else {
        panic!("expected primary_failure_code");
    };
    let primary_failure_code = match primary_failure_code_value {
        Value::String(value) => Some(value.clone()),
        Value::Nil => None,
        _ => panic!("primary_failure_code must be string/nil"),
    };

    let Some(Value::Vector(failure_codes)) = map_get(entries, "failure_codes") else {
        panic!("expected failure_codes vector");
    };
    let failure_codes = failure_codes
        .iter()
        .map(|value| match value {
            Value::String(value) => value.clone(),
            _ => panic!("failure code must be string"),
        })
        .collect::<Vec<_>>();

    (
        terminal_control,
        step_results.len(),
        primary_failure_code,
        failure_codes,
    )
}

fn decode_failure_codes(bytes: &FfiBytes) -> Vec<String> {
    let detail = decode_ffi_value(bytes);
    let Value::Tagged(tagged) = detail else {
        panic!("expected tagged FfiErrorDetailV0");
    };
    assert_eq!(tagged.tag.as_str(), "ffi_error_detail_v0");
    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected FfiErrorDetailV0 payload");
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
            _ => panic!("failure code must be string"),
        })
        .collect()
}

#[derive(Clone)]
struct JsonParser<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            cursor: 0,
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        let Some(byte) = self.peek() else {
            return Err("unexpected end of JSON input".to_string());
        };
        match byte {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(Value::String),
            b'-' | b'0'..=b'9' => self.parse_number(),
            b't' => self.parse_true(),
            b'f' => self.parse_false(),
            b'n' => self.parse_null(),
            _ => Err(format!("unexpected JSON token byte: {byte}")),
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.consume(b'{')?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.cursor += 1;
            return Ok(Value::Map(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.consume(b':')?;
            let value = self.parse_value()?;
            entries.push((Value::String(key), value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.cursor += 1;
                }
                Some(b'}') => {
                    self.cursor += 1;
                    break;
                }
                _ => return Err("object must end with ',' or '}'".to_string()),
            }
        }
        Ok(Value::Map(entries))
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.consume(b'[')?;
        self.skip_ws();
        let mut values = Vec::new();
        if self.peek() == Some(b']') {
            self.cursor += 1;
            return Ok(Value::Vector(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.cursor += 1;
                }
                Some(b']') => {
                    self.cursor += 1;
                    break;
                }
                _ => return Err("array must end with ',' or ']'".to_string()),
            }
        }
        Ok(Value::Vector(values))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.consume(b'"')?;
        let mut output = String::new();
        loop {
            if self.cursor >= self.input.len() {
                return Err("unterminated JSON string".to_string());
            }
            let remaining = std::str::from_utf8(&self.input[self.cursor..])
                .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
            let mut chars = remaining.chars();
            let current = chars
                .next()
                .ok_or_else(|| "unterminated JSON string".to_string())?;
            self.cursor += current.len_utf8();
            match current {
                '"' => break,
                '\\' => {
                    let escaped = self.peek().ok_or_else(|| "invalid escape".to_string())?;
                    self.cursor += 1;
                    let translated = match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => return Err("unsupported JSON escape sequence".to_string()),
                    };
                    output.push(translated);
                }
                _ => output.push(current),
            }
        }
        Ok(output)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.cursor;
        if self.peek() == Some(b'-') {
            self.cursor += 1;
        }
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.cursor += 1;
        }
        if self.peek() == Some(b'.') {
            self.cursor += 1;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.cursor += 1;
            }
        }
        if self.peek().is_some_and(|byte| byte == b'e' || byte == b'E') {
            self.cursor += 1;
            if self.peek().is_some_and(|byte| byte == b'+' || byte == b'-') {
                self.cursor += 1;
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.cursor += 1;
            }
        }

        let raw = std::str::from_utf8(&self.input[start..self.cursor])
            .map_err(|_| "invalid UTF-8 in number".to_string())?;
        if raw.contains('.') || raw.contains('e') || raw.contains('E') {
            return raw
                .parse::<f64>()
                .map(|value| Value::Float64(value.into()))
                .map_err(|_| "invalid JSON float".to_string());
        }
        if raw.starts_with('-') {
            return raw
                .parse::<i64>()
                .map(Value::Int)
                .map_err(|_| "invalid JSON integer".to_string());
        }
        if let Ok(value) = raw.parse::<i64>() {
            return Ok(Value::Int(value));
        }
        raw.parse::<u64>()
            .map(Value::UInt)
            .map_err(|_| "invalid JSON unsigned integer".to_string())
    }

    fn parse_true(&mut self) -> Result<Value, String> {
        self.consume_keyword("true")?;
        Ok(Value::Bool(true))
    }

    fn parse_false(&mut self) -> Result<Value, String> {
        self.consume_keyword("false")?;
        Ok(Value::Bool(false))
    }

    fn parse_null(&mut self) -> Result<Value, String> {
        self.consume_keyword("null")?;
        Ok(Value::Nil)
    }

    fn consume_keyword(&mut self, keyword: &str) -> Result<(), String> {
        for byte in keyword.bytes() {
            self.consume(byte)?;
        }
        Ok(())
    }

    fn consume(&mut self, expected: u8) -> Result<(), String> {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            Ok(())
        } else {
            Err(format!("expected byte '{}'", expected as char))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.cursor += 1;
        }
    }
}

fn parse_json_value(input: &str) -> Result<Value, String> {
    let mut parser = JsonParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.cursor != parser.input.len() {
        return Err("trailing JSON content".to_string());
    }
    Ok(value)
}

#[test]
fn eval_evalir_assign_emit_end_fixture_reaches_end() {
    let eval_ir = fixture_value("evalir_assign_emit_end.json");
    let state = fixture_value("initial_state_base.json");
    let input = eval_evalir_input_bytes(&eval_ir, &state, None, None);

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none(), "success should not return error detail");

    let result = result.expect("success should return EvalRunResultV0 bytes");
    let (terminal_control, step_results_len, primary_failure_code, failure_codes) =
        decode_eval_result(&result);
    assert_eq!(terminal_control, "end");
    assert_eq!(step_results_len, 0);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());

    let bytes_first = ffi_bytes_to_vec(&result);
    let (status_again, result_again, error_again) = call_eval_evalir(&input);
    assert_eq!(status_again, RuliaStatus::Ok);
    assert!(error_again.is_none());
    let result_again = result_again.expect("second run should return result bytes");
    assert_eq!(bytes_first, ffi_bytes_to_vec(&result_again));
}

#[test]
fn eval_evalir_request_suspend_fixture_emits_receipt_valid_obligation() {
    let eval_ir = fixture_value("evalir_request_suspend.json");
    let state = fixture_value("initial_state_base.json");
    let history = fixture_value("history_prefix_empty.json");
    let gamma_core = fixture_value("gamma_core_main.json");
    let input = eval_evalir_input_bytes(&eval_ir, &state, Some(&history), Some(&gamma_core));

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none());

    let result = result.expect("success should return EvalRunResultV0 bytes");
    let (terminal_control, step_results_len, primary_failure_code, failure_codes) =
        decode_eval_result(&result);
    assert_eq!(terminal_control, "suspend");
    assert_eq!(step_results_len, 0);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn eval_evalir_branch_fixture_sets_open_case_and_ends() {
    let eval_ir = fixture_value("evalir_choose_rules_branch.json");
    let state = fixture_value("initial_state_base.json");
    let input = eval_evalir_input_bytes(&eval_ir, &state, None, None);

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none());

    let result = result.expect("success should return EvalRunResultV0 bytes");
    let (terminal_control, step_results_len, primary_failure_code, failure_codes) =
        decode_eval_result(&result);
    assert_eq!(terminal_control, "end");
    assert_eq!(step_results_len, 0);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn eval_evalir_branch_sexpr_fixture_sets_open_case_and_ends() {
    let eval_ir = fixture_value("evalir_choose_rules_branch_sexpr.json");
    let state = fixture_value("initial_state_base.json");
    let input = eval_evalir_input_bytes(&eval_ir, &state, None, None);

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none());

    let result = result.expect("success should return EvalRunResultV0 bytes");
    let (terminal_control, step_results_len, primary_failure_code, failure_codes) =
        decode_eval_result(&result);
    assert_eq!(terminal_control, "end");
    assert_eq!(step_results_len, 0);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn eval_evalir_join_any_of_fixture_reaches_end() {
    let eval_ir = fixture_value("evalir_join_any_of_satisfied.json");
    let state = fixture_value("initial_state_base.json");
    let history = fixture_value("history_prefix_join_one_receipt.json");
    let gamma_core = fixture_value("gamma_core_main.json");
    let input = eval_evalir_input_bytes(&eval_ir, &state, Some(&history), Some(&gamma_core));

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none());

    let result = result.expect("success should return EvalRunResultV0 bytes");
    let (terminal_control, step_results_len, primary_failure_code, failure_codes) =
        decode_eval_result(&result);
    assert_eq!(terminal_control, "end");
    assert_eq!(step_results_len, 0);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn eval_evalir_join_all_of_missing_fixture_suspends() {
    let eval_ir = fixture_value("evalir_join_all_of_missing.json");
    let state = fixture_value("initial_state_base.json");
    let history = fixture_value("history_prefix_join_one_receipt.json");
    let gamma_core = fixture_value("gamma_core_main.json");
    let input = eval_evalir_input_bytes(&eval_ir, &state, Some(&history), Some(&gamma_core));

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none());

    let result = result.expect("success should return EvalRunResultV0 bytes");
    let (terminal_control, step_results_len, primary_failure_code, failure_codes) =
        decode_eval_result(&result);
    assert_eq!(terminal_control, "suspend");
    assert_eq!(step_results_len, 0);
    assert_eq!(primary_failure_code, None);
    assert_eq!(failure_codes, Vec::<String>::new());
}

#[test]
fn eval_evalir_validation_failures_are_ordered_deterministically() {
    let invalid_eval_ir = Value::Map(vec![
        (
            Value::String("format_id".to_string()),
            Value::String("invalid.format".to_string()),
        ),
        (
            Value::String("ir_version".to_string()),
            Value::String("v0".to_string()),
        ),
        (
            Value::String("entry_step_id".to_string()),
            Value::String("S0001".to_string()),
        ),
        (
            Value::String("steps".to_string()),
            Value::Vector(vec![Value::Map(vec![
                (
                    Value::String("step_id".to_string()),
                    Value::String("bad".to_string()),
                ),
                (
                    Value::String("op".to_string()),
                    Value::String("unknown".to_string()),
                ),
            ])]),
        ),
    ]);
    let state = fixture_value("initial_state_base.json");
    let input = eval_evalir_input_bytes(&invalid_eval_ir, &state, None, None);

    let (status, result, error) = call_eval_evalir(&input);
    assert_eq!(status, RuliaStatus::VerifyError);
    assert!(result.is_none(), "failure should not return result bytes");
    let error = error.expect("failure should return FfiErrorDetailV0 bytes");
    let codes = decode_failure_codes(&error);
    assert_eq!(
        codes,
        vec![
            "EVAL.E_STEP_IDENTITY".to_string(),
            "EVAL.E_STATE_INVALID".to_string(),
            "EVAL.E_STEP_CONTRACT".to_string()
        ]
    );
}
