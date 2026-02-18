use num_bigint::BigInt;
use ordered_float::OrderedFloat;
use rulia::binary::{MessageBuilder, MessageReader};
use rulia::{Keyword, Symbol, TaggedValue, Value};

#[test]
fn roundtrip_complex_value() {
    let value = Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("service")),
            Value::String("transactor".into()),
        ),
        (
            Value::Keyword(Keyword::simple("enabled")),
            Value::Bool(true),
        ),
        (
            Value::Keyword(Keyword::simple("ratio")),
            Value::Float64(OrderedFloat(0.875)),
        ),
        (
            Value::Keyword(Keyword::simple("ids")),
            Value::Vector(vec![Value::UInt(1), Value::UInt(2), Value::UInt(3)]),
        ),
        (
            Value::Keyword(Keyword::simple("threshold")),
            Value::Tagged(TaggedValue::new(
                Symbol::parse("geo/point"),
                Value::Vector(vec![
                    Value::Float64(OrderedFloat(12.5)),
                    Value::Float64(OrderedFloat(-3.0)),
                ]),
            )),
        ),
        (
            Value::Keyword(Keyword::simple("big")),
            Value::BigInt(BigInt::parse_bytes(b"123456789012345678901234567890", 10).unwrap()),
        ),
    ]);

    let bytes = MessageBuilder::encode(&value).expect("encode");
    let reader = MessageReader::new(&bytes).expect("reader");
    let decoded = reader.root().expect("root").deserialize().expect("decode");
    assert_eq!(value, decoded);
}

#[test]
fn iter_vector_without_alloc() {
    let value = Value::Vector(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
    let bytes = MessageBuilder::encode(&value).unwrap();
    let reader = MessageReader::new(&bytes).unwrap();
    let root = reader.root().unwrap().as_value();
    let collected: Vec<i64> = root
        .vector_iter()
        .unwrap()
        .map(|res| res.unwrap().as_int().unwrap())
        .collect();
    assert_eq!(collected, vec![1, 2, 3]);
}
