use rulia::binary::TypeTag;
use rulia::RuliaError;

#[test]
fn typetag_numeric_mapping_matches_adr_0001() {
    let table = [
        (0u16, TypeTag::Nil),
        (1u16, TypeTag::Bool),
        (2u16, TypeTag::Int),
        (3u16, TypeTag::UInt),
        (4u16, TypeTag::BigInt),
        (5u16, TypeTag::Float32),
        (6u16, TypeTag::Float64),
        (7u16, TypeTag::String),
        (8u16, TypeTag::Bytes),
        (9u16, TypeTag::Symbol),
        (10u16, TypeTag::Keyword),
        (11u16, TypeTag::Vector),
        (12u16, TypeTag::Set),
        (13u16, TypeTag::Map),
        (14u16, TypeTag::Tagged),
        (15u16, TypeTag::Annotated),
    ];

    for (id, tag) in table {
        assert_eq!(tag as u16, id, "enum discriminant mismatch for {tag:?}");
        assert_eq!(TypeTag::from_u16(id).expect("decode typetag"), tag);
    }
}

#[test]
fn unknown_typetag_values_are_rejected() {
    match TypeTag::from_u16(16) {
        Err(RuliaError::UnknownTypeTag(16)) => {}
        Err(other) => panic!("unexpected error variant: {other}"),
        Ok(tag) => panic!("expected unknown typetag error, got {tag:?}"),
    }
}
