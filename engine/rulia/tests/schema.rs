use rulia::{text, Schema};

#[test]
fn parse_and_validate_schema() {
    let schema_text = r#"
    (defs=(
        Point=RuliaStruct((
            x=:f64,
            y=:f64
        )),
        Shape=RuliaTaggedUnion((
            circle=RuliaStruct((radius=:f64)),
            rect=RuliaStruct((width=:f64, height=:f64))
        ))
    ),
     root=:Shape)
    "#;

    let schema = Schema::from_text(schema_text).expect("schema");

    let value = text::parse("Circle((radius=2.0))").expect("value");

    schema.validate(&value).expect("validate");

    let bad_value = text::parse("Rect((width=2.0))").expect("value");

    assert!(schema.validate(&bad_value).is_err());
}
