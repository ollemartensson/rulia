use ordered_float::OrderedFloat;
use rulia::{text, Keyword, Symbol, TaggedValue, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[test]
fn parse_and_roundtrip_textual() {
    let input = r#"
    (service="transactor",
     weights=[1, 2, 3.5],
     tags=Set([:alpha, :beta]),
     location=GeoPoint([12.5, -99.4]),
     blob=0x[deadbeef]
    )
    "#;

    let value = text::parse(input).expect("parse");
    let rendered = text::to_string(&value);
    let reparsed = text::parse(&rendered).expect("reparse");
    assert_eq!(value, reparsed);

    if let Value::Map(entries) = value {
        let (_, location) = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Keyword(kv) if kv.name() == "location"))
            .unwrap();
        if let Value::Tagged(tagged) = location {
            assert_eq!(tagged.tag.to_string(), "geo/point");
            if let Value::Vector(items) = &*tagged.value {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], Value::Float64(OrderedFloat(12.5)));
            } else {
                panic!("expected tagged vector");
            }
        } else {
            panic!("expected tagged value");
        }
    } else {
        panic!("expected map");
    }
}

#[test]
fn evaluate_let_and_functions() {
    let config = r#"
    let make_config = fn(ip) =>
      (ip=ip, dc="eqdc10")

    (alpha=(make_config "10.0.0.1"),
     beta=(make_config "10.0.0.2"))
    "#;

    let parsed = text::parse(config).expect("config parse");
    if let Value::Map(entries) = parsed {
        let (_, alpha) = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Keyword(kv) if kv.name() == "alpha"))
            .expect("alpha");
        if let Value::Map(alpha_entries) = alpha {
            assert_eq!(alpha_entries.len(), 2);
            // Verify ip field
            assert!(alpha_entries.iter().any(
                |(k, v)| matches!(k, Value::Keyword(kv) if kv.name() == "ip")
                    && matches!(v, Value::String(s) if s == "10.0.0.1")
            ));
        } else {
            panic!("alpha should be a map");
        }
    } else {
        panic!("expected top-level map");
    }
}

#[test]
fn import_with_hash() {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let fixture_path = base_dir.join("common.rjl");
    let bytes = fs::read(&fixture_path).expect("read fixture");
    let hash = hex::encode(Sha256::digest(&bytes));

    let script = format!("let settings = import \"common.rjl\" sha256:{hash}\n(config=settings)\n");

    let value = text::parse_in_dir(&script, &base_dir).expect("parse import");
    if let Value::Map(entries) = value {
        assert!(entries.iter().any(|(k, v)| matches!(k, Value::Keyword(kv) if kv.name() == "config" && matches!(v, Value::Map(_)))));
    } else {
        panic!("expected map");
    }

    let blake_hash = hex::encode(blake3::hash(&bytes).as_bytes());
    let blake_script =
        format!("let settings = import \"common.rjl\" blake3:{blake_hash}\n(config=settings)\n");
    let value_blake = text::parse_in_dir(&blake_script, &base_dir).expect("parse blake3 import");
    assert!(matches!(value_blake, Value::Map(_)));

    let bad_hash = "0".repeat(64);
    let bad_script = format!("import \"common.rjl\" sha256:{bad_hash}");
    let err = text::parse_in_dir(&bad_script, &base_dir).expect_err("hash mismatch");
    match err {
        rulia::RuliaError::HashMismatch { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn multi_binding_let_block() {
    let script = r#"
    let {
      host = "localhost"
      port = 8001
    }
    (host=host, port=port)
    "#;

    let value = text::parse(script).expect("parse");
    if let Value::Map(entries) = value {
        assert!(entries.contains(&(
            Value::Keyword(Keyword::simple("host")),
            Value::String("localhost".into())
        )));
    } else {
        panic!("expected map");
    }
}

// ============================================================================
// Edge Case Tests for Underscore/Namespace Handling
// ============================================================================

#[test]
fn underscore_namespace_first_split_rule() {
    // user_id -> :user/id
    let input = "(user_id=123)";
    let value = text::parse(input).expect("parse");
    if let Value::Map(entries) = &value {
        let (key, _) = &entries[0];
        if let Value::Keyword(kw) = key {
            assert_eq!(kw.namespace(), Some("user"));
            assert_eq!(kw.name(), "id");
        } else {
            panic!("expected keyword key");
        }
    }

    // user_first_name -> :user/first_name (NOT :user_first/name)
    let input2 = "(user_first_name=\"Alice\")";
    let value2 = text::parse(input2).expect("parse");
    if let Value::Map(entries) = &value2 {
        let (key, _) = &entries[0];
        if let Value::Keyword(kw) = key {
            assert_eq!(kw.namespace(), Some("user"));
            assert_eq!(kw.name(), "first_name");
        } else {
            panic!("expected keyword key");
        }
    }
}

#[test]
fn explicit_keyword_constructor() {
    // Keyword("my_app/config") for complex namespaces
    let input = r#"Keyword("my_app/config")"#;
    let value = text::parse(input).expect("parse");
    if let Value::Keyword(kw) = value {
        assert_eq!(kw.namespace(), Some("my_app"));
        assert_eq!(kw.name(), "config");
    } else {
        panic!("expected keyword");
    }
}

#[test]
fn explicit_symbol_constructor() {
    let input = r#"Symbol("special/value")"#;
    let value = text::parse(input).expect("parse");
    if let Value::Symbol(sym) = value {
        assert_eq!(sym.namespace(), Some("special"));
        assert_eq!(sym.name(), "value");
    } else {
        panic!("expected symbol");
    }
}

#[test]
fn explicit_tagged_constructor() {
    let input = r#"Tagged("complex_ns/tag", "data")"#;
    let value = text::parse(input).expect("parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.namespace(), Some("complex_ns"));
        assert_eq!(tagged.tag.name(), "tag");
        assert_eq!(*tagged.value, Value::String("data".into()));
    } else {
        panic!("expected tagged value");
    }
}

// ============================================================================
// Edge Case Tests for PascalCase Tag Conversion
// ============================================================================

#[test]
fn uuid_all_caps_stays_simple() {
    // UUID should become tag "uuid", not "u/u/i/d"
    let input = r#"UUID("550e8400-e29b-41d4-a716-446655440000")"#;
    let value = text::parse(input).expect("parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.namespace(), None);
        assert_eq!(tagged.tag.name(), "uuid");
        assert_eq!(
            *tagged.value,
            Value::Bytes(vec![
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55,
                0x44, 0x00, 0x00
            ])
        );
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn uuid_constructor_rejects_invalid_strings() {
    let err = text::parse(r#"UUID("not-a-uuid")"#).expect_err("expected invalid uuid parse error");
    match err {
        rulia::RuliaError::Parse(message) => {
            assert!(message.contains("UUID() expects a valid UUID string"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn single_word_pascal_stays_simple() {
    // Point -> tag "point" (no namespace)
    let input = "Point([1, 2])";
    let value = text::parse(input).expect("parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.namespace(), None);
        assert_eq!(tagged.tag.name(), "point");
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn multi_word_pascal_splits_correctly() {
    // GeoPoint -> tag "geo/point"
    let input = "GeoPoint([12.5, -99.4])";
    let value = text::parse(input).expect("parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.namespace(), Some("geo"));
        assert_eq!(tagged.tag.name(), "point");
    } else {
        panic!("expected tagged value");
    }

    // RuliaTaggedUnion -> tag "rulia/tagged-union"
    let input2 = "RuliaTaggedUnion((a=1))";
    let value2 = text::parse(input2).expect("parse");
    if let Value::Tagged(tagged) = value2 {
        assert_eq!(tagged.tag.namespace(), Some("rulia"));
        assert_eq!(tagged.tag.name(), "tagged-union");
    } else {
        panic!("expected tagged value");
    }
}

// ============================================================================
// Roundtrip Tests for Ambiguous Cases
// ============================================================================

#[test]
fn roundtrip_ambiguous_keyword_uses_explicit() {
    // Create a keyword with underscore in namespace
    let kw = Keyword::new(Some("my_app".to_string()), "config");
    let value = Value::Keyword(kw);

    let rendered = text::to_string(&value);
    // Should use explicit form, not underscore sugar
    assert!(
        rendered.contains("Keyword("),
        "Expected explicit form, got: {}",
        rendered
    );

    // Should roundtrip correctly
    let reparsed = text::parse(&rendered).expect("reparse");
    assert_eq!(value, reparsed);
}

#[test]
fn roundtrip_simple_keyword_uses_sugar() {
    // Simple namespace without underscore
    let kw = Keyword::new(Some("user".to_string()), "name");
    let value = Value::Keyword(kw);

    let rendered = text::to_string(&value);
    // Should use sugar form
    assert_eq!(rendered, ":user_name");

    // Should roundtrip correctly
    let reparsed = text::parse(&rendered).expect("reparse");
    assert_eq!(value, reparsed);
}

#[test]
fn roundtrip_complex_tagged_value() {
    // Create a tagged value that needs explicit form
    let tag = Symbol::new(Some("complex_ns".to_string()), "my_tag");
    let value = Value::Tagged(TaggedValue::new(tag, Value::Int(42)));

    let rendered = text::to_string(&value);
    // Should use explicit Tagged() form
    assert!(
        rendered.contains("Tagged("),
        "Expected explicit form, got: {}",
        rendered
    );

    // Should roundtrip correctly
    let reparsed = text::parse(&rendered).expect("reparse");
    assert_eq!(value, reparsed);
}
