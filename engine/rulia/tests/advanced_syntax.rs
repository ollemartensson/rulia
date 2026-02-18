use rulia::{text, Keyword, Symbol, Value};

// ============================================================================
// ULID Constructor Tests
// ============================================================================

#[test]
fn ulid_constructor_valid() {
    let input = r#"ULID("01ARZ3NDEKTSV4RRFFQ69G5FAV")"#;
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "ulid");
        assert_eq!(
            *tagged.value,
            Value::String("01ARZ3NDEKTSV4RRFFQ69G5FAV".into())
        );
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn ulid_constructor_lowercase_valid() {
    // ULID should accept lowercase (internally normalized)
    let input = r#"ULID("01arz3ndektsv4rrffq69g5fav")"#;
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "ulid");
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn ulid_constructor_invalid_length() {
    let input = r#"ULID("too_short")"#;
    let result = text::parse(input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("26 characters"));
}

#[test]
fn ulid_constructor_invalid_chars() {
    // 'I', 'L', 'O', 'U' are invalid in Crockford Base32
    let input = r#"ULID("01ARZ3NDEKTSV4RRFFQ69GIFAV")"#; // Contains 'I'
    let result = text::parse(input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("invalid character"));
}

// ============================================================================
// Generator Constructor Tests (Deferred Generation)
// ============================================================================

#[test]
fn generator_uuid() {
    let input = "Generator(:uuid)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "generator");
        assert_eq!(*tagged.value, Value::Keyword(Keyword::simple("uuid")));
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn generator_ulid() {
    let input = "Generator(:ulid)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "generator");
        assert_eq!(*tagged.value, Value::Keyword(Keyword::simple("ulid")));
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn generator_now() {
    let input = "Generator(:now)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "generator");
        assert_eq!(*tagged.value, Value::Keyword(Keyword::simple("now")));
    } else {
        panic!("expected tagged value");
    }
}

// ============================================================================
// @new Immediate Generation Tests
// ============================================================================

#[test]
fn new_uuid_generates_bytes() {
    let input = "@new(:uuid)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "uuid");
        if let Value::Bytes(bytes) = &*tagged.value {
            assert_eq!(bytes.len(), 16); // UUID is 16 bytes
        } else {
            panic!("expected bytes value");
        }
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn new_uuid_generates_unique() {
    let input1 = "@new(:uuid)";
    let input2 = "@new(:uuid)";
    let value1 = text::parse(input1).expect("parse");
    let value2 = text::parse(input2).expect("parse");

    // Each @new(:uuid) should generate a unique UUID
    assert_ne!(value1, value2);
}

#[test]
fn new_ulid_generates_string() {
    let input = "@new(:ulid)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "ulid");
        if let Value::String(s) = &*tagged.value {
            assert_eq!(s.len(), 26); // ULID canonical string is 26 chars
        } else {
            panic!("expected string value");
        }
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn new_now_generates_timestamp() {
    let input = "@new(:now)";
    let value = text::parse(input).expect("parse");

    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "inst");
        if let Value::Int(ms) = &*tagged.value {
            // Should be a reasonable timestamp (after year 2020)
            assert!(*ms > 1577836800000); // 2020-01-01 in ms
        } else {
            panic!("expected int value");
        }
    } else {
        panic!("expected tagged value");
    }
}

#[test]
fn new_invalid_type() {
    let input = "@new(:invalid)";
    let result = text::parse(input);
    assert!(result.is_err());
}

// ============================================================================
// Wildcard Tests
// ============================================================================

#[test]
fn wildcard_standalone() {
    let input = "_";
    let value = text::parse(input).expect("parse");

    if let Value::Symbol(sym) = value {
        assert_eq!(sym.name(), "_");
        assert!(sym.namespace().is_none());
    } else {
        panic!("expected symbol");
    }
}

#[test]
fn wildcard_in_vector() {
    let input = "[_, 1, _]";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], Value::Symbol(Symbol::simple("_")));
        assert_eq!(items[1], Value::Int(1));
        assert_eq!(items[2], Value::Symbol(Symbol::simple("_")));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn wildcard_in_datalog_pattern() {
    // Common pattern: [@?e, :user/friends, _]
    let input = "[@?e, :user_friends, _]";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 3);
        // First item is logic variable
        if let Value::Symbol(sym) = &items[0] {
            assert_eq!(sym.name(), "?e");
        }
        // Third item is wildcard
        if let Value::Symbol(sym) = &items[2] {
            assert_eq!(sym.name(), "_");
        }
    } else {
        panic!("expected vector");
    }
}

// ============================================================================
// Infix Operator Desugaring Tests
// ============================================================================

#[test]
fn infix_greater_equal() {
    let input = "(@?age >= 18)";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 3);
        // First item is the operator symbol
        assert_eq!(items[0], Value::Symbol(Symbol::simple(">=")));
        // Second item is the logic variable
        if let Value::Symbol(sym) = &items[1] {
            assert_eq!(sym.name(), "?age");
        } else {
            panic!("expected symbol for lhs");
        }
        // Third item is the literal
        assert_eq!(items[2], Value::Int(18));
    } else {
        panic!("expected vector from infix desugaring");
    }
}

#[test]
fn infix_less_than() {
    let input = "(@?x < 100)";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items[0], Value::Symbol(Symbol::simple("<")));
        assert_eq!(items[2], Value::Int(100));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn infix_equal() {
    let input = "(@?x == 42)";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items[0], Value::Symbol(Symbol::simple("==")));
        assert_eq!(items[2], Value::Int(42));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn infix_not_equal() {
    let input = "(@?x != 10)";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items[0], Value::Symbol(Symbol::simple("!=")));
        assert_eq!(items[2], Value::Int(10));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn infix_with_ulid() {
    let input = r#"(@?id == ULID("01ARZ3NDEKTSV4RRFFQ69G5FAV"))"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], Value::Symbol(Symbol::simple("==")));
        // RHS should be a tagged ULID
        if let Value::Tagged(tagged) = &items[2] {
            assert_eq!(tagged.tag.name(), "ulid");
        } else {
            panic!("expected tagged ULID");
        }
    } else {
        panic!("expected vector");
    }
}

// ============================================================================
// Integration Test: Complete Query Structure
// ============================================================================

#[test]
fn complete_query_structure() {
    let input = r#"
    (
        # Immediate generation (Parse time)
        seedId = @new(:ulid),
        createdAt = @new(:now),

        # Deferred generation (Schema default)
        defaultPolicy = Generator(:uuid),

        # Query with logic syntax
        query = Query(
            find = [@?e],
            where = [
                # Wildcard pattern
                [@?e, :user_friends, _],
                # Infix comparison
                (@?age >= 18)
            ]
        )
    )
    "#;

    let value = text::parse(input).expect("parse");

    if let Value::Map(entries) = value {
        // Check that seedId was generated (is a tagged ULID)
        let seed_id = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Keyword(kw) if kw.name() == "seedId"));
        assert!(seed_id.is_some(), "seedId not found");
        if let Some((_, val)) = seed_id {
            if let Value::Tagged(tagged) = val {
                assert_eq!(tagged.tag.name(), "ulid");
            } else {
                panic!("seedId should be a tagged ULID");
            }
        }

        // Check defaultPolicy is a Generator
        let policy = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Keyword(kw) if kw.name() == "defaultPolicy"));
        assert!(policy.is_some(), "defaultPolicy not found");
        if let Some((_, Value::Tagged(tagged))) = policy {
            assert_eq!(tagged.tag.name(), "generator");
        }

        // Check query is present and is a tagged Query
        let query = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Keyword(kw) if kw.name() == "query"));
        assert!(query.is_some(), "query not found");
        if let Some((_, Value::Tagged(tagged))) = query {
            assert_eq!(tagged.tag.name(), "query");
        }
    } else {
        panic!("expected map");
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn map_with_equals_not_infix() {
    // Map syntax should not be confused with == operator
    let input = "(foo = 1, bar = 2)";
    let value = text::parse(input).expect("parse");

    if let Value::Map(entries) = value {
        assert_eq!(entries.len(), 2);
    } else {
        panic!("expected map, got {:?}", value);
    }
}

#[test]
fn nested_infix_in_vector() {
    let input = "[(@?x > 1), (@?y < 10)]";
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 2);
        // Each item should be a desugared infix expression (vector)
        for item in &items {
            assert!(matches!(item, Value::Vector(_)));
        }
    } else {
        panic!("expected vector");
    }
}
