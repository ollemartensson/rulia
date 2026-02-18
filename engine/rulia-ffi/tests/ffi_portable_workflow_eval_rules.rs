use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia::{Keyword, Symbol, TaggedValue, Value};
use rulia_ffi::{rulia_v1_bytes_free, rulia_v1_pw_eval_rules_v0, RuliaBytes, RuliaStatus};

const FAILURE_CODE_AMBIGUOUS_MATCH: &str = "EVAL.ambiguous_match";
const FAILURE_CODE_FORBIDDEN_FEATURE: &str = "EVAL.forbidden_feature";
const FAILURE_CODE_NO_MATCH: &str = "EVAL.no_match";
const FAILURE_CODE_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const FAILURE_CODE_UNBOUND_VAR: &str = "EVAL.unbound_var";

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

fn decode_value(bytes: &[u8]) -> Value {
    rulia::decode_value(bytes).expect("decode canonical value")
}

fn decode_ffi_value(bytes: &FfiBytes) -> Value {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    decode_value(slice)
}

fn eval_rules_input_bytes(rules_program: Vec<u8>, facts: Option<Vec<u8>>) -> Vec<u8> {
    let mut entries = vec![
        (kw("format"), kw("rulia_eval_rules_input_v0")),
        (kw("rules_program_bytes"), Value::Bytes(rules_program)),
    ];
    if let Some(facts) = facts {
        entries.push((kw("facts_bytes"), Value::Bytes(facts)));
    }
    canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("eval_rules_input_v0"),
        Value::Map(entries),
    )))
}

fn route_atom_value(name: &str) -> Value {
    Value::Keyword(Keyword::simple(name))
}

fn route_atom_to_string(value: &Value) -> String {
    match value {
        Value::Keyword(keyword) => format!(":{}", keyword.as_symbol().as_str()),
        Value::String(raw) => raw.clone(),
        _ => panic!("expected keyword/string route atom"),
    }
}

fn fact(predicate: &str, args: Vec<Value>) -> Value {
    let mut values = vec![Value::String(predicate.to_string())];
    values.extend(args);
    Value::Vector(values)
}

fn rule(head: Value, body: Vec<Value>) -> Value {
    Value::Map(vec![(kw("head"), head), (kw("body"), Value::Vector(body))])
}

fn predicate(pattern_name: &str, args: Vec<Value>) -> Value {
    let mut values = vec![Value::String(pattern_name.to_string())];
    values.extend(args);
    Value::Vector(values)
}

fn rules_program(
    facts: Vec<Value>,
    rules: Vec<Value>,
    no_match_policy: Value,
    ambiguous_policy: &str,
) -> Value {
    Value::Tagged(TaggedValue::new(
        Symbol::simple("rules_program_v0"),
        Value::Map(vec![
            (
                kw("format_id"),
                Value::String("portable_workflow.rules.v0".to_string()),
            ),
            (kw("version"), kw("v0")),
            (kw("facts"), Value::Vector(facts)),
            (kw("rules"), Value::Vector(rules)),
            (
                kw("query"),
                Value::Vector(vec![
                    Value::String("route".to_string()),
                    Value::String("?r".to_string()),
                ]),
            ),
            (
                kw("routing_policy"),
                Value::Map(vec![
                    (kw("route_predicate"), Value::String("route".to_string())),
                    (kw("no_match_policy"), no_match_policy),
                    (
                        kw("ambiguous_policy"),
                        Value::String(ambiguous_policy.to_string()),
                    ),
                ]),
            ),
        ]),
    ))
}

fn call_eval_rules(input: &[u8]) -> (RuliaStatus, Option<FfiBytes>, Option<FfiBytes>) {
    let mut out_result = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut out_error_detail = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe {
        rulia_v1_pw_eval_rules_v0(
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

fn decode_eval_rules_result(bytes: &FfiBytes) -> String {
    let slice = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) };
    let decoded = decode_value(slice);
    let reencoded = canonical_bytes(&decoded);
    assert_eq!(reencoded, slice, "result bytes must be canonical");

    let Value::Tagged(tagged) = decoded else {
        panic!("expected tagged EvalRulesResultV0");
    };
    assert_eq!(tagged.tag.as_str(), "eval_rules_result_v0");

    let Value::Map(entries) = tagged.value.as_ref() else {
        panic!("expected EvalRulesResultV0 map payload");
    };

    assert_exact_keys(entries, &["format", "selected_route", "route_candidates"]);
    assert!(map_get(entries, "explanation").is_none());

    let Some(Value::Vector(route_candidates)) = map_get(entries, "route_candidates") else {
        panic!("expected route_candidates");
    };
    for route in route_candidates {
        let _ = route_atom_to_string(route);
    }

    let Some(selected_route) = map_get(entries, "selected_route") else {
        panic!("expected selected_route");
    };
    route_atom_to_string(selected_route)
}

fn assert_failure_case(input: &[u8], expected_failure_code: &str) {
    let (status, result, error) = call_eval_rules(input);
    assert_eq!(status, RuliaStatus::VerifyError);
    assert!(result.is_none(), "failure should not return result bytes");

    let error = error.expect("failure should return FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![expected_failure_code.to_string()]
    );
}

#[test]
fn eval_rules_threshold_example_selects_open_case() {
    let program = rules_program(
        vec![
            fact(
                "risk_score",
                vec![Value::String("case-001".to_string()), Value::Int(82)],
            ),
            fact(
                "doc_complete",
                vec![Value::String("case-001".to_string()), Value::Bool(true)],
            ),
        ],
        vec![
            rule(
                predicate("route", vec![route_atom_value("open_case")]),
                vec![
                    predicate(
                        "risk_score",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("?score".to_string()),
                        ],
                    ),
                    predicate(
                        ">=",
                        vec![Value::String("?score".to_string()), Value::Int(80)],
                    ),
                    predicate(
                        "doc_complete",
                        vec![Value::String("?case".to_string()), Value::Bool(true)],
                    ),
                ],
            ),
            rule(
                predicate("route", vec![route_atom_value("wait_docs")]),
                vec![predicate(
                    "doc_complete",
                    vec![Value::String("?case".to_string()), Value::Bool(false)],
                )],
            ),
        ],
        Value::String("error".to_string()),
        "allow_multiple",
    );
    let input = eval_rules_input_bytes(canonical_bytes(&program), None);

    let (status, result, error) = call_eval_rules(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none(), "success should not return error detail");

    let result = result.expect("success should return EvalRulesResultV0 bytes");
    assert_eq!(decode_eval_rules_result(&result), ":open_case");
}

#[test]
fn eval_rules_allowlist_example_selects_wait_docs() {
    let program = rules_program(
        vec![
            fact(
                "country",
                vec![
                    Value::String("case-002".to_string()),
                    Value::String("SE".to_string()),
                ],
            ),
            fact(
                "doc_status",
                vec![
                    Value::String("case-002".to_string()),
                    Value::String("missing_income_proof".to_string()),
                ],
            ),
        ],
        vec![
            rule(
                predicate("route", vec![route_atom_value("wait_docs")]),
                vec![
                    predicate(
                        "country",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("?c".to_string()),
                        ],
                    ),
                    predicate(
                        "in",
                        vec![
                            Value::String("?c".to_string()),
                            Value::Vector(vec![
                                Value::String("US".to_string()),
                                Value::String("CA".to_string()),
                                Value::String("SE".to_string()),
                            ]),
                        ],
                    ),
                    predicate(
                        "doc_status",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("missing_income_proof".to_string()),
                        ],
                    ),
                ],
            ),
            rule(
                predicate("route", vec![route_atom_value("open_case")]),
                vec![
                    predicate(
                        "country",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("?c".to_string()),
                        ],
                    ),
                    predicate(
                        "in",
                        vec![
                            Value::String("?c".to_string()),
                            Value::Vector(vec![
                                Value::String("US".to_string()),
                                Value::String("CA".to_string()),
                                Value::String("SE".to_string()),
                            ]),
                        ],
                    ),
                    predicate(
                        "doc_status",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("complete".to_string()),
                        ],
                    ),
                ],
            ),
        ],
        Value::String("error".to_string()),
        "allow_multiple",
    );
    let input = eval_rules_input_bytes(canonical_bytes(&program), None);

    let (status, result, error) = call_eval_rules(&input);
    assert_eq!(status, RuliaStatus::Ok);
    assert!(error.is_none(), "success should not return error detail");

    let result = result.expect("success should return EvalRulesResultV0 bytes");
    assert_eq!(decode_eval_rules_result(&result), ":wait_docs");
}

#[test]
fn eval_rules_negation_reports_forbidden_feature() {
    let program = rules_program(
        vec![fact(
            "doc_complete",
            vec![Value::String("case-005".to_string()), Value::Bool(false)],
        )],
        vec![rule(
            predicate("route", vec![route_atom_value("open_case")]),
            vec![
                predicate(
                    "doc_complete",
                    vec![
                        Value::String("?case".to_string()),
                        Value::String("?ok".to_string()),
                    ],
                ),
                predicate(
                    "not",
                    vec![Value::Vector(vec![
                        Value::String("=".to_string()),
                        Value::String("?ok".to_string()),
                        Value::Bool(false),
                    ])],
                ),
            ],
        )],
        Value::String("error".to_string()),
        "error",
    );
    assert_failure_case(
        &eval_rules_input_bytes(canonical_bytes(&program), None),
        FAILURE_CODE_FORBIDDEN_FEATURE,
    );
}

#[test]
fn eval_rules_unbound_head_variable_reports_unbound_var() {
    let program = rules_program(
        vec![fact(
            "risk_score",
            vec![Value::String("case-006".to_string()), Value::Int(91)],
        )],
        vec![rule(
            predicate("route", vec![Value::String("?r".to_string())]),
            vec![
                predicate(
                    "risk_score",
                    vec![
                        Value::String("case-006".to_string()),
                        Value::String("?score".to_string()),
                    ],
                ),
                predicate(
                    ">",
                    vec![Value::String("?score".to_string()), Value::Int(70)],
                ),
            ],
        )],
        Value::String("error".to_string()),
        "allow_multiple",
    );
    assert_failure_case(
        &eval_rules_input_bytes(canonical_bytes(&program), None),
        FAILURE_CODE_UNBOUND_VAR,
    );
}

#[test]
fn eval_rules_ambiguous_policy_error_reports_ambiguous_match() {
    let program = rules_program(
        vec![fact(
            "risk_score",
            vec![Value::String("case-003".to_string()), Value::Int(75)],
        )],
        vec![
            rule(
                predicate("route", vec![route_atom_value("open_case")]),
                vec![
                    predicate(
                        "risk_score",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("?score".to_string()),
                        ],
                    ),
                    predicate(
                        ">=",
                        vec![Value::String("?score".to_string()), Value::Int(70)],
                    ),
                ],
            ),
            rule(
                predicate("route", vec![route_atom_value("wait_docs")]),
                vec![
                    predicate(
                        "risk_score",
                        vec![
                            Value::String("?case".to_string()),
                            Value::String("?score".to_string()),
                        ],
                    ),
                    predicate(
                        ">=",
                        vec![Value::String("?score".to_string()), Value::Int(70)],
                    ),
                ],
            ),
        ],
        Value::String("error".to_string()),
        "error",
    );
    assert_failure_case(
        &eval_rules_input_bytes(canonical_bytes(&program), None),
        FAILURE_CODE_AMBIGUOUS_MATCH,
    );
}

#[test]
fn eval_rules_no_match_policy_error_reports_no_match() {
    let program = rules_program(
        vec![fact(
            "risk_score",
            vec![Value::String("case-004".to_string()), Value::Int(10)],
        )],
        vec![rule(
            predicate("route", vec![route_atom_value("open_case")]),
            vec![
                predicate(
                    "risk_score",
                    vec![
                        Value::String("?case".to_string()),
                        Value::String("?score".to_string()),
                    ],
                ),
                predicate(
                    ">",
                    vec![Value::String("?score".to_string()), Value::Int(70)],
                ),
            ],
        )],
        Value::String("error".to_string()),
        "allow_multiple",
    );
    assert_failure_case(
        &eval_rules_input_bytes(canonical_bytes(&program), None),
        FAILURE_CODE_NO_MATCH,
    );
}

#[test]
fn eval_rules_rejects_legacy_root_tag_alias() {
    let program = rules_program(
        vec![fact(
            "risk_score",
            vec![Value::String("case-001".to_string()), Value::Int(82)],
        )],
        vec![rule(
            predicate("route", vec![route_atom_value("open_case")]),
            vec![predicate(
                "risk_score",
                vec![
                    Value::String("?case".to_string()),
                    Value::String("?score".to_string()),
                ],
            )],
        )],
        Value::String("error".to_string()),
        "allow_multiple",
    );
    let legacy_tag_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("rules_eval_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_eval_rules_input_v0")),
            (
                kw("rules_program_bytes"),
                Value::Bytes(canonical_bytes(&program)),
            ),
        ]),
    )));

    let (status, result, error) = call_eval_rules(&legacy_tag_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(result.is_none());
    let error = error.expect("expected FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}

#[test]
fn eval_rules_rejects_legacy_key_alias() {
    let program = rules_program(
        vec![fact(
            "risk_score",
            vec![Value::String("case-001".to_string()), Value::Int(82)],
        )],
        vec![rule(
            predicate("route", vec![route_atom_value("open_case")]),
            vec![predicate(
                "risk_score",
                vec![
                    Value::String("?case".to_string()),
                    Value::String("?score".to_string()),
                ],
            )],
        )],
        Value::String("error".to_string()),
        "allow_multiple",
    );
    let legacy_key_input = canonical_bytes(&Value::Tagged(TaggedValue::new(
        Symbol::simple("eval_rules_input_v0"),
        Value::Map(vec![
            (kw("format"), kw("rulia_eval_rules_input_v0")),
            (kw("rules_bytes"), Value::Bytes(canonical_bytes(&program))),
        ]),
    )));

    let (status, result, error) = call_eval_rules(&legacy_key_input);
    assert_eq!(status, RuliaStatus::DecodeError);
    assert!(result.is_none());
    let error = error.expect("expected FfiErrorDetailV0 bytes");
    assert_eq!(
        decode_failure_codes(&error),
        vec![FAILURE_CODE_SCHEMA_MISMATCH.to_string()]
    );
}
