use rulia::{text, Value};

// ============================================================================
// String Interpolation Tests
// ============================================================================

#[test]
fn simple_string_no_interpolation() {
    let input = r#""Hello World""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Hello World".into()));
}

#[test]
fn interpolation_single_variable() {
    let input = r#"let name = "Alice" "Hello $name""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Hello Alice".into()));
}

#[test]
fn interpolation_multiple_variables() {
    let input = r#"let { first = "Hello"; second = "World" } "$first $second!""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Hello World!".into()));
}

#[test]
fn interpolation_expression() {
    let input = r#"let x = 5 "Result: $(x)""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Result: 5".into()));
}

#[test]
fn interpolation_complex_expression() {
    // Note: Our language doesn't support arithmetic operators in expressions directly,
    // so we test with function calls instead
    let input = r#"let items = [1, 2, 3] "First: $(get(items, 0))""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("First: 1".into()));
}

#[test]
fn interpolation_at_start() {
    let input = r#"let name = "Alice" "$name says hi""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Alice says hi".into()));
}

#[test]
fn interpolation_at_end() {
    let input = r#"let name = "Alice" "Hi there $name""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Hi there Alice".into()));
}

#[test]
fn interpolation_escaped_dollar() {
    let input = r#""Price: \$99""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Price: $99".into()));
}

#[test]
fn interpolation_dollar_not_followed_by_ident() {
    let input = r#""Price: $ 99""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Price: $ 99".into()));
}

#[test]
fn interpolation_with_int_value() {
    let input = r#"let age = 30 "Age: $age years""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Age: 30 years".into()));
}

#[test]
fn interpolation_with_bool_value() {
    let input = r#"let active = true "Active: $active""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Active: true".into()));
}

// ============================================================================
// Destructuring Tests
// ============================================================================

#[test]
fn destructure_tuple_simple() {
    let input = r#"let (a, b) = [1, 2] [a, b]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], Value::Int(1));
        assert_eq!(items[1], Value::Int(2));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn destructure_vector_simple() {
    let input = r#"let [x, y] = [10, 20] [y, x]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], Value::Int(20));
        assert_eq!(items[1], Value::Int(10));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn destructure_with_strings() {
    let input = r#"let (first, last) = ["Alice", "Smith"] "$first $last""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Alice Smith".into()));
}

#[test]
fn destructure_three_elements() {
    let input = r#"let (a, b, c) = [1, 2, 3] [c, b, a]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], Value::Int(3));
        assert_eq!(items[1], Value::Int(2));
        assert_eq!(items[2], Value::Int(1));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn destructure_in_block() {
    let input = r#"let {
        coords = [10, 20];
        (x, y) = coords
    } [x, y]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], Value::Int(10));
        assert_eq!(items[1], Value::Int(20));
    } else {
        panic!("expected vector");
    }
}

#[test]
fn destructure_trailing_comma() {
    let input = r#"let (a, b,) = [1, 2] [a, b]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items[0], Value::Int(1));
        assert_eq!(items[1], Value::Int(2));
    } else {
        panic!("expected vector");
    }
}

// ============================================================================
// Combined Tests
// ============================================================================

#[test]
fn destructure_with_interpolation() {
    let input = r#"let (name, age) = ["Bob", 25] "$name is $age""#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Bob is 25".into()));
}

#[test]
fn multiple_destructures_in_block() {
    let input = r#"let {
        (a, b) = [1, 2];
        (c, d) = [3, 4]
    } [a, b, c, d]"#;
    let value = text::parse(input).expect("parse");

    if let Value::Vector(items) = value {
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], Value::Int(1));
        assert_eq!(items[1], Value::Int(2));
        assert_eq!(items[2], Value::Int(3));
        assert_eq!(items[3], Value::Int(4));
    } else {
        panic!("expected vector");
    }
}

// ============================================================================
// Builtin Function Tests
// ============================================================================

#[test]
fn get_vector_positive_index() {
    let input = r#"get([1, 2, 3], 1)"#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::Int(2));
}

#[test]
fn get_vector_first_element() {
    let input = r#"get(["a", "b", "c"], 0)"#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("a".into()));
}

#[test]
fn concat_strings() {
    let input = r#"concat("Hello", " ", "World")"#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Hello World".into()));
}

#[test]
fn concat_mixed_types() {
    let input = r#"concat("Count: ", 42)"#;
    let value = text::parse(input).expect("parse");
    assert_eq!(value, Value::String("Count: 42".into()));
}
