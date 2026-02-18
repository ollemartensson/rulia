use rulia::{text, RuliaError, Value};

fn assert_instant_ok(payload: &str) {
    let src = format!(r#"Instant("{payload}")"#);
    let value = text::parse(&src).expect("parse instant");
    match value {
        Value::Tagged(tagged) => {
            assert_eq!(tagged.tag.to_string(), "instant");
            assert_eq!(*tagged.value, Value::String(payload.to_string()));
        }
        other => panic!("expected tagged instant, got {other:?}"),
    }
}

fn assert_instant_err(payload: &str) {
    let src = format!(r#"Instant("{payload}")"#);
    let err = text::parse(&src).expect_err("expected instant error");
    match err {
        RuliaError::Parse(msg) => assert!(
            msg.contains("Instant() expects canonical RFC3339 UTC string"),
            "unexpected error message: {msg}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn instant_conformance_valid() {
    let cases = [
        "2026-02-04T12:34:56Z",
        "2026-02-04T12:34:56.1Z",
        "2026-02-04T12:34:56.123456789Z",
    ];

    for case in cases {
        assert_instant_ok(case);
    }
}

#[test]
fn instant_conformance_invalid() {
    let cases = [
        "2026-02-04T12:34:56+01:00",
        "2026-02-04T12:34:56.120Z",
        "2026-02-04T12:34:56.Z",
        "2026-02-04T12:34:56.1234567890Z",
        " 2026-02-04T12:34:56Z",
        "2026-02-04T12:34:56Z ",
        "2026-02-04T12:34:56 Z",
    ];

    for case in cases {
        assert_instant_err(case);
    }
}
