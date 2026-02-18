use rulia::{text, Keyword, RuliaError, Value};

#[test]
fn parse_string_map_key_literal() {
    let value =
        text::parse(r#"("content-type" = "application/json")"#).expect("parse string key map");
    let Value::Map(entries) = value else {
        panic!("expected map value");
    };
    assert!(entries.iter().any(|(key, val)| {
        matches!(
            (key, val),
            (Value::String(k), Value::String(v))
                if k == "content-type" && v == "application/json"
        )
    }));
}

#[test]
fn parse_keyword_map_key_literal() {
    let value = text::parse(r#"(:ce_specversion = "1.0")"#).expect("parse keyword key map");
    let Value::Map(entries) = value else {
        panic!("expected map value");
    };
    let expected = Keyword::new(Some("ce".to_string()), "specversion");
    assert!(entries.iter().any(|(key, val)| {
        matches!(
            (key, val),
            (Value::Keyword(k), Value::String(v)) if *k == expected && v == "1.0"
        )
    }));
}

#[test]
fn duplicate_identifier_keys_rejected() {
    let err = text::parse("(a = 1, a = 2)").expect_err("expected duplicate key error");
    match err {
        RuliaError::DuplicateMapKeyLiteral(key) => assert_eq!(key, ":a"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn duplicate_string_keys_rejected() {
    let err = text::parse("(\"x\" = 1, \"x\" = 2)").expect_err("expected duplicate key error");
    match err {
        RuliaError::DuplicateMapKeyLiteral(key) => assert_eq!(key, "\"x\""),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn duplicate_keyword_keys_rejected() {
    let err = text::parse("(:k = 1, :k = 2)").expect_err("expected duplicate key error");
    match err {
        RuliaError::DuplicateMapKeyLiteral(key) => assert_eq!(key, ":k"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn interpolated_string_key_rejected() {
    let err = text::parse("(\"x$y\" = 1)").expect_err("expected interpolation error");
    match err {
        RuliaError::Parse(msg) => {
            assert_eq!(msg, "map string keys must be literal (no interpolation)")
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
