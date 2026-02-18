use rulia::binary::{encode_with_digest, encode_with_digest_using, verify_digest, MessageReader};
use rulia::{HashAlgorithm, Keyword, RuliaError, Value};

fn digest_trailer_start(bytes: &[u8]) -> usize {
    let dictionary_offset =
        u64::from_le_bytes(bytes[16..24].try_into().expect("dictionary offset"));
    let dictionary_length =
        u64::from_le_bytes(bytes[24..32].try_into().expect("dictionary length"));
    (dictionary_offset + dictionary_length) as usize
}

#[test]
fn encode_and_verify_digest() {
    let value = Value::Map(vec![(
        Value::Keyword(Keyword::simple("service")),
        Value::String("transactor".into()),
    )]);

    let encoded = encode_with_digest(&value).expect("encode");
    assert!(encoded.bytes.len() > 32);
    assert_eq!(encoded.algorithm, HashAlgorithm::Sha256);

    let (verified_algorithm, verified_digest) = verify_digest(&encoded.bytes).expect("verify");
    assert_eq!(verified_algorithm, HashAlgorithm::Sha256);
    assert_eq!(verified_digest, encoded.digest);

    let reader = MessageReader::new(&encoded.bytes).expect("reader");
    let (algorithm, digest) = reader.digest().expect("digest present");
    assert_eq!(algorithm, HashAlgorithm::Sha256);
    assert_eq!(digest, encoded.digest.as_slice());
    let decoded = reader.root().unwrap().deserialize().expect("decode");
    assert_eq!(decoded, value);
}

#[test]
fn corrupt_digest_is_rejected() {
    let value = Value::Vector(vec![Value::Int(1), Value::Int(2)]);
    let mut encoded = encode_with_digest(&value).expect("encode");
    let last_index = encoded.bytes.len() - 1;
    encoded.bytes[last_index] ^= 0xFF;

    match verify_digest(&encoded.bytes) {
        Err(RuliaError::HashMismatch { .. }) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected hash mismatch"),
    }

    match MessageReader::new(&encoded.bytes) {
        Err(RuliaError::HashMismatch { .. }) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected hash mismatch"),
    }
}

#[test]
fn canonical_digest_stable_across_map_order() {
    let value_a = Value::Map(vec![
        (Value::Keyword(Keyword::simple("alpha")), Value::Int(1)),
        (Value::Keyword(Keyword::simple("beta")), Value::Int(2)),
    ]);
    let value_b = Value::Map(vec![
        (Value::Keyword(Keyword::simple("beta")), Value::Int(2)),
        (Value::Keyword(Keyword::simple("alpha")), Value::Int(1)),
    ]);

    let encoded_a = encode_with_digest(&value_a).expect("encode a");
    let encoded_b = encode_with_digest(&value_b).expect("encode b");

    assert_eq!(encoded_a.algorithm, encoded_b.algorithm);
    assert_eq!(encoded_a.digest, encoded_b.digest);
    assert_eq!(encoded_a.bytes, encoded_b.bytes);
}

#[test]
fn known_digest_algorithm_ids_are_accepted() {
    let value = Value::Vector(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);

    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Blake3] {
        let encoded = encode_with_digest_using(&value, algorithm).expect("encode");

        let (verified_algorithm, verified_digest) = verify_digest(&encoded.bytes).expect("verify");
        assert_eq!(verified_algorithm, algorithm);
        assert_eq!(verified_digest, encoded.digest);

        let reader = MessageReader::new(&encoded.bytes).expect("reader");
        let (reader_algorithm, reader_digest) = reader.digest().expect("digest");
        assert_eq!(reader_algorithm, algorithm);
        assert_eq!(reader_digest, encoded.digest.as_slice());
    }
}

#[test]
fn unknown_digest_algorithm_id_in_trailer_start_is_rejected() {
    let value = Value::String("digest-algorithm".into());
    let mut encoded = encode_with_digest(&value).expect("encode");

    let digest_id_index = encoded.bytes.len() - encoded.algorithm.digest_len() - 1;
    encoded.bytes[digest_id_index] = 0xFF;

    match verify_digest(&encoded.bytes) {
        Err(RuliaError::InvalidHash(message)) => {
            assert_eq!(message, "unknown digest algorithm id");
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected invalid hash error"),
    }

    match MessageReader::new(&encoded.bytes) {
        Err(RuliaError::InvalidHash(message)) => {
            assert_eq!(message, "unknown digest algorithm id");
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected invalid hash error"),
    }
}

#[test]
fn truncated_digest_trailer_is_rejected() {
    let value = Value::Vector(vec![Value::Int(7), Value::Int(8), Value::Int(9)]);
    let mut encoded = encode_with_digest(&value).expect("encode");
    encoded.bytes.pop();

    match verify_digest(&encoded.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected buffer too small"),
    }

    match MessageReader::new(&encoded.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected buffer too small"),
    }
}

#[test]
fn oversized_digest_trailer_is_rejected() {
    let value = Value::Vector(vec![Value::Int(7), Value::Int(8), Value::Int(9)]);
    let mut encoded = encode_with_digest(&value).expect("encode");
    encoded.bytes.push(0);

    match verify_digest(&encoded.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected buffer too small"),
    }

    match MessageReader::new(&encoded.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected buffer too small"),
    }
}

#[test]
fn digest_trailer_layout_is_algorithm_id_followed_by_digest() {
    let value = Value::Map(vec![(
        Value::Keyword(Keyword::simple("service")),
        Value::String("transactor".into()),
    )]);

    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Blake3] {
        let encoded = encode_with_digest_using(&value, algorithm).expect("encode");
        let trailer_start = digest_trailer_start(&encoded.bytes);

        assert_eq!(encoded.bytes[trailer_start], algorithm.id());
        assert_eq!(
            &encoded.bytes[trailer_start + 1..],
            encoded.digest.as_slice()
        );
        assert_eq!(
            trailer_start + 1 + algorithm.digest_len(),
            encoded.bytes.len()
        );
        assert_eq!(
            algorithm.compute(&encoded.bytes[..trailer_start]),
            encoded.digest
        );
    }
}

#[test]
fn digest_algorithm_id_registry_is_canonical() {
    assert_eq!(HashAlgorithm::Sha256.id(), 1);
    assert_eq!(HashAlgorithm::Blake3.id(), 2);
    assert_eq!(HashAlgorithm::from_id(1), Some(HashAlgorithm::Sha256));
    assert_eq!(HashAlgorithm::from_id(2), Some(HashAlgorithm::Blake3));
    assert_eq!(HashAlgorithm::from_id(0), None);
    assert_eq!(HashAlgorithm::from_id(3), None);
    assert_eq!(HashAlgorithm::Sha256.digest_len(), 32);
    assert_eq!(HashAlgorithm::Blake3.digest_len(), 32);
}

#[test]
fn unknown_digest_algorithm_id_is_rejected() {
    let value = Value::Vector(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
    let mut encoded = encode_with_digest(&value).expect("encode");
    let trailer_start = digest_trailer_start(&encoded.bytes);
    encoded.bytes[trailer_start] = 0xFF;

    match verify_digest(&encoded.bytes) {
        Err(RuliaError::InvalidHash(_)) => {}
        Err(other) => panic!("unexpected verify_digest error: {other}"),
        Ok(_) => panic!("expected invalid hash error"),
    }

    match MessageReader::new(&encoded.bytes) {
        Err(RuliaError::InvalidHash(_)) => {}
        Err(other) => panic!("unexpected reader error: {other}"),
        Ok(_) => panic!("expected invalid hash error"),
    }
}

#[test]
fn digest_trailer_length_mismatch_is_rejected() {
    let value = Value::Vector(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);

    let mut truncated = encode_with_digest(&value).expect("encode");
    truncated.bytes.pop();

    match verify_digest(&truncated.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected verify_digest error for truncated trailer: {other}"),
        Ok(_) => panic!("expected BufferTooSmall"),
    }
    match MessageReader::new(&truncated.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected reader error for truncated trailer: {other}"),
        Ok(_) => panic!("expected BufferTooSmall"),
    }

    let mut extended = encode_with_digest(&value).expect("encode");
    extended.bytes.push(0x00);

    match verify_digest(&extended.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected verify_digest error for extended trailer: {other}"),
        Ok(_) => panic!("expected BufferTooSmall"),
    }
    match MessageReader::new(&extended.bytes) {
        Err(RuliaError::BufferTooSmall) => {}
        Err(other) => panic!("unexpected reader error for extended trailer: {other}"),
        Ok(_) => panic!("expected BufferTooSmall"),
    }
}
