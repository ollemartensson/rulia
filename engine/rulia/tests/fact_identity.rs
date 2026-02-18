use rulia::security::{fact_digest, object_digest, validate_fact, DigestAlg};
use rulia::{Annotation, Keyword, Symbol, TaggedValue, Value};

#[test]
fn fact_digest_ignores_annotations() {
    let base = Value::String("hello".into());
    let annotated = base.clone().with_doc("docstring");

    let object_base = object_digest(&base, DigestAlg::Sha256).expect("object digest");
    let object_annotated =
        object_digest(&annotated, DigestAlg::Sha256).expect("object digest annotated");
    assert_ne!(object_base, object_annotated);

    let fact_base = fact_digest(&base, DigestAlg::Sha256).expect("fact digest");
    let fact_annotated = fact_digest(&annotated, DigestAlg::Sha256).expect("fact digest annotated");
    assert_eq!(fact_base, fact_annotated);
}

#[test]
fn fact_digest_strips_nested_annotation_layers() {
    let base = Value::Map(vec![(
        Value::Keyword(Keyword::simple("id")),
        Value::Int(42),
    )]);

    let nested = base.clone().with_doc("outer").annotate(vec![(
        Value::Keyword(Keyword::simple("author")),
        Value::String("alice".into()),
    )]);

    let fact_base = fact_digest(&base, DigestAlg::Sha256).expect("fact digest");
    let fact_nested = fact_digest(&nested, DigestAlg::Sha256).expect("fact digest nested");
    assert_eq!(fact_base, fact_nested);
}

#[test]
fn validate_fact_rejects_generator_values() {
    let generator = Value::Tagged(TaggedValue::new(
        Symbol::simple("generator"),
        Value::Keyword(Keyword::simple("uuid")),
    ));

    let err = validate_fact(&generator).expect_err("expected generator rejection");
    match err {
        rulia::RuliaError::Security(message) => {
            assert_eq!(message, "fact: generator forbidden");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validate_fact_rejects_generators_in_metadata() {
    let generator = Value::Tagged(TaggedValue::new(
        Symbol::simple("generator"),
        Value::Keyword(Keyword::simple("uuid")),
    ));
    let annotated = Value::Annotated(Box::new(Annotation::new(
        vec![(Value::Keyword(Keyword::simple("doc")), generator.clone())],
        Value::String("payload".into()),
    )));

    let err = validate_fact(&annotated).expect_err("expected metadata generator rejection");
    match err {
        rulia::RuliaError::Security(message) => {
            assert_eq!(message, "fact: generator forbidden");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
