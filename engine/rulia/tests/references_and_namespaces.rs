use rulia::{text, Annotation, Keyword, Value};

// ============================================================================
// Graph Reference Tests (Ref)
// ============================================================================

#[test]
fn ref_single_arg_parses_to_tagged() {
    // Ref(100) -> #ref 100
    let input = "Ref(100)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.namespace(), None);
        assert_eq!(tagged.tag.name(), "ref");
        assert_eq!(*tagged.value, Value::Int(100));
    } else {
        panic!("expected tagged value, got {:?}", value);
    }
}

#[test]
fn ref_multiple_args_parses_to_tagged_vector() {
    // Ref(:email, "a@b.com") -> #ref [:email, "a@b.com"]
    let input = r#"Ref(:email, "a@b.com")"#;
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "ref");
        if let Value::Vector(items) = &*tagged.value {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], Value::Keyword(Keyword::simple("email")));
            assert_eq!(items[1], Value::String("a@b.com".into()));
        } else {
            panic!("expected vector inside ref");
        }
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn ref_roundtrip() {
    let input = "Ref(42)";
    let value = text::parse(input).expect("parse");
    let rendered = text::to_string(&value);
    let reparsed = text::parse(&rendered).expect("reparse");
    assert_eq!(value, reparsed);
}

#[test]
fn ref_lookup_roundtrip() {
    let input = r#"Ref(:user_id, 123)"#;
    let value = text::parse(input).expect("parse");
    let rendered = text::to_string(&value);
    let reparsed = text::parse(&rendered).expect("reparse");
    assert_eq!(value, reparsed);
}

// ============================================================================
// Namespace Macro Tests (@ns)
// ============================================================================

#[test]
fn ns_macro_prefixes_simple_keys() {
    let input = r#"
    @ns user begin
        (id = 101, name = "Bob")
    end
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Map(entries) = value {
        // Both keys should be namespaced with "user"
        assert!(entries.iter().any(|(k, _)| {
            if let Value::Keyword(kw) = k {
                kw.namespace() == Some("user") && kw.name() == "id"
            } else {
                false
            }
        }));
        assert!(entries.iter().any(|(k, _)| {
            if let Value::Keyword(kw) = k {
                kw.namespace() == Some("user") && kw.name() == "name"
            } else {
                false
            }
        }));
    } else {
        panic!("expected map");
    }
}

#[test]
fn ns_macro_nested() {
    let input = r#"
    @ns outer begin
        (
            id = 1,
            inner = @ns inner begin
                (value = 42)
            end
        )
    end
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Map(entries) = value {
        // Outer keys should be namespaced with "outer"
        let (_, inner_val) = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Keyword(kw) if kw.name() == "inner"))
            .expect("inner key");

        if let Value::Map(inner_entries) = inner_val {
            // Inner key should be namespaced with "inner"
            assert!(inner_entries.iter().any(|(k, _)| {
                if let Value::Keyword(kw) = k {
                    kw.namespace() == Some("inner") && kw.name() == "value"
                } else {
                    false
                }
            }));
        } else {
            panic!("expected inner map");
        }
    } else {
        panic!("expected outer map");
    }
}

// ============================================================================
// Metadata Decorator Tests (@meta)
// ============================================================================

#[test]
fn meta_decorator_creates_annotation() {
    let input = r#"
    @meta(author = "admin", deprecated = true)
    User(id = 101)
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        // Check metadata
        let author_key = Value::Keyword(Keyword::simple("author"));
        let deprecated_key = Value::Keyword(Keyword::simple("deprecated"));

        let author = annotation.metadata.iter().find(|(k, _)| k == &author_key);
        assert!(author.is_some());
        assert_eq!(author.unwrap().1, Value::String("admin".into()));

        let deprecated = annotation
            .metadata
            .iter()
            .find(|(k, _)| k == &deprecated_key);
        assert!(deprecated.is_some());
        assert_eq!(deprecated.unwrap().1, Value::Bool(true));

        // Check inner value is a tagged User
        if let Value::Tagged(tagged) = annotation.inner() {
            assert_eq!(tagged.tag.name(), "user");
        } else {
            panic!("expected tagged value");
        }
    } else {
        panic!("expected annotated value");
    }
}

#[test]
fn meta_decorator_merges_with_docstring() {
    let input = r#"
    @meta(version = "1.0")
    "A user entity."
    User(id = 1)
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        // Should have both version and doc metadata
        let version_key = Value::Keyword(Keyword::simple("version"));
        let doc_key = Value::Keyword(Keyword::simple("doc"));

        assert!(annotation.metadata.iter().any(|(k, _)| k == &version_key));
        assert!(annotation.metadata.iter().any(|(k, _)| k == &doc_key));
    } else {
        panic!("expected annotated value");
    }
}

#[test]
fn meta_decorator_accepts_keyword_and_string_keys() {
    let input = r#"
    @meta(:owner = "admin", "x-trace-id" = "abc123")
    User(id = 1)
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        assert!(annotation.metadata.iter().any(|(k, v)| {
            matches!(
                (k, v),
                (Value::Keyword(kw), Value::String(owner))
                    if kw.namespace().is_none() && kw.name() == "owner" && owner == "admin"
            )
        }));
        assert!(annotation.metadata.iter().any(|(k, v)| {
            matches!(
                (k, v),
                (Value::String(key), Value::String(trace)) if key == "x-trace-id" && trace == "abc123"
            )
        }));
    } else {
        panic!("expected annotated value");
    }
}

#[test]
fn meta_decorator_keys_do_not_inherit_ns_scope() {
    let input = r#"
    @ns user begin
      @meta(author = "admin")
      User(id = 1)
    end
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        assert!(annotation.metadata.iter().any(|(k, v)| {
            matches!(
                (k, v),
                (Value::Keyword(kw), Value::String(author))
                    if kw.namespace().is_none() && kw.name() == "author" && author == "admin"
            )
        }));
    } else {
        panic!("expected annotated value");
    }
}

// ============================================================================
// Docstring Tests
// ============================================================================

#[test]
fn docstring_before_constructor() {
    let input = r#"
    "A user entity."
    User(id = 1)
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        assert_eq!(annotation.doc(), Some("A user entity."));
        assert!(matches!(annotation.inner(), Value::Tagged(_)));
    } else {
        panic!("expected annotated value");
    }
}

#[test]
fn triple_quoted_docstring() {
    let input = r#"
    """
    A multiline
    docstring.
    """
    User(id = 1)
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        let doc = annotation.doc().expect("doc");
        assert!(doc.contains("multiline"));
        assert!(doc.contains("docstring"));
    } else {
        panic!("expected annotated value");
    }
}

#[test]
fn docstring_before_keyword_value() {
    let input = r#"
    "A status keyword."
    :status
    "#;
    let value = text::parse(input).expect("parse");

    if let Value::Annotated(annotation) = value {
        assert_eq!(annotation.doc(), Some("A status keyword."));
        assert_eq!(
            *annotation.inner(),
            Value::Keyword(Keyword::simple("status"))
        );
    } else {
        panic!("expected annotated value");
    }
}

#[test]
fn docstring_does_not_capture_regular_strings() {
    // A string followed by a closing bracket should not be a docstring
    let input = r#"["hello", "world"]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], Value::String("hello".into()));
        assert_eq!(items[1], Value::String("world".into()));
    } else {
        panic!("expected vector");
    }
}

// ============================================================================
// Binary Roundtrip Tests for Annotated Values
// ============================================================================

#[test]
fn annotated_value_binary_roundtrip() {
    let annotation = Annotation::with_doc("Test documentation", Value::Int(42));
    let value = Value::Annotated(Box::new(annotation));

    let encoded = rulia::encode_value(&value).expect("encode");
    let decoded = rulia::decode_value(&encoded).expect("decode");

    assert_eq!(value, decoded);
}

#[test]
fn complex_annotated_value_roundtrip() {
    let metadata = vec![
        (
            Value::Keyword(Keyword::simple("author")),
            Value::String("admin".into()),
        ),
        (
            Value::Keyword(Keyword::simple("version")),
            Value::String("1.0".into()),
        ),
        (
            Value::Keyword(Keyword::simple("deprecated")),
            Value::Bool(false),
        ),
    ];
    let inner = Value::Map(vec![
        (Value::Keyword(Keyword::simple("id")), Value::Int(1)),
        (
            Value::Keyword(Keyword::simple("name")),
            Value::String("Alice".into()),
        ),
    ]);
    let annotation = Annotation::new(metadata, inner);
    let value = Value::Annotated(Box::new(annotation));

    let encoded = rulia::encode_value(&value).expect("encode");
    let decoded = rulia::decode_value(&encoded).expect("decode");

    assert_eq!(value, decoded);
}

// ============================================================================
// Text Serialization Roundtrip Tests
// ============================================================================

#[test]
fn annotated_text_roundtrip() {
    let input = r#"
    @meta(author = "admin")
    "A simple value."
    Point([1, 2])
    "#;
    let value = text::parse(input).expect("parse");
    let rendered = text::to_string(&value);
    let reparsed = text::parse(&rendered).expect("reparse");

    // Compare the inner values (metadata order might differ)
    assert_eq!(value.unwrap_annotations(), reparsed.unwrap_annotations());
}

// ============================================================================
// Value Helper Method Tests
// ============================================================================

#[test]
fn value_unwrap_annotations() {
    let inner = Value::Int(42);
    let annotated = inner.clone().with_doc("test");

    assert_eq!(annotated.unwrap_annotations(), &inner);
}

#[test]
fn value_annotations_helper() {
    let value = Value::Int(42).with_doc("test doc");

    let ann = value.annotations().expect("should have annotations");
    assert_eq!(ann.doc(), Some("test doc"));
}

#[test]
fn nested_annotations_unwrap() {
    let inner = Value::Int(42);
    let annotated1 = inner.clone().with_doc("first");
    let annotated2 = annotated1.with_doc("second");

    // Should unwrap all layers
    assert_eq!(annotated2.unwrap_annotations(), &inner);
}
