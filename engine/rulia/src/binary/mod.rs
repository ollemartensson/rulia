mod builder;
mod dictionary;
mod header;
mod pointer;
mod reader;
mod value_ref;

pub use builder::MessageBuilder;
pub use header::FLAG_MESSAGE_DIGEST;
pub use pointer::{Pointer, TypeTag};
pub use reader::{MessageReader, RootRef};
pub use value_ref::{CollectionIter, MapIter, ValueRef};

use crate::error::{RuliaError, RuliaResult};
use crate::hash::HashAlgorithm;
use crate::value::{Annotation, TaggedValue, Value};
use hex;

pub struct EncodedWithDigest {
    pub bytes: Vec<u8>,
    pub digest: Vec<u8>,
    pub algorithm: HashAlgorithm,
}

pub fn encode_canonical(value: &Value) -> RuliaResult<Vec<u8>> {
    let canonical = canonicalize_value(value);
    let builder = MessageBuilder::new();
    builder.finish_with_flags(&canonical, 0)
}

pub fn encode_with_digest(value: &Value) -> RuliaResult<EncodedWithDigest> {
    encode_with_digest_using(value, HashAlgorithm::Sha256)
}

pub fn encode_with_digest_using(
    value: &Value,
    algorithm: HashAlgorithm,
) -> RuliaResult<EncodedWithDigest> {
    let canonical = canonicalize_value(value);
    let builder = MessageBuilder::new();
    let mut bytes = builder.finish_with_flags(&canonical, FLAG_MESSAGE_DIGEST)?;
    let digest = algorithm.compute(&bytes);
    bytes.push(algorithm.id());
    bytes.extend_from_slice(&digest);
    Ok(EncodedWithDigest {
        bytes,
        digest,
        algorithm,
    })
}

pub fn verify_digest(bytes: &[u8]) -> RuliaResult<(HashAlgorithm, Vec<u8>)> {
    if bytes.len() < header::HEADER_SIZE {
        return Err(RuliaError::BufferTooSmall);
    }
    let (header, _) = header::Header::parse(bytes)?;
    if header.flags() & FLAG_MESSAGE_DIGEST == 0 {
        return Err(RuliaError::UnexpectedValueKind(
            "message does not contain digest",
        ));
    }
    let digest_start = (header.dictionary_offset + header.dictionary_length) as usize;
    if digest_start + 1 > bytes.len() {
        return Err(RuliaError::BufferTooSmall);
    }
    let algorithm = HashAlgorithm::from_id(bytes[digest_start])
        .ok_or_else(|| RuliaError::InvalidHash("unknown digest algorithm id".into()))?;
    let digest_len = algorithm.digest_len();
    if digest_start + 1 + digest_len != bytes.len() {
        return Err(RuliaError::BufferTooSmall);
    }
    let digest_bytes = bytes[digest_start + 1..].to_vec();
    let computed = algorithm.compute(&bytes[..digest_start]);
    if digest_bytes != computed {
        return Err(RuliaError::HashMismatch {
            expected: hex::encode(digest_bytes),
            actual: hex::encode(computed),
        });
    }
    Ok((algorithm, bytes[digest_start + 1..].to_vec()))
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Vector(items) => Value::Vector(items.iter().map(canonicalize_value).collect()),
        Value::Set(items) => {
            let mut canonical_items: Vec<Value> = items.iter().map(canonicalize_value).collect();
            canonical_items.sort_by_key(canonical_sort_key);
            canonical_items.dedup();
            Value::Set(canonical_items)
        }
        Value::Map(entries) => {
            let mut canonical_entries: Vec<(String, Value, Value)> = entries
                .iter()
                .map(|(key, value)| {
                    let canonical_key = canonicalize_value(key);
                    let canonical_value = canonicalize_value(value);
                    let sort_key = canonical_sort_key(&canonical_key);
                    (sort_key, canonical_key, canonical_value)
                })
                .collect();
            canonical_entries.sort_by(|a, b| a.0.cmp(&b.0));
            canonical_entries.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
            Value::Map(
                canonical_entries
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            )
        }
        Value::Tagged(TaggedValue { tag, value: inner }) => Value::Tagged(TaggedValue::new(
            tag.clone(),
            canonicalize_value(inner.as_ref()),
        )),
        Value::Annotated(annotation) => {
            // Canonicalize both metadata and inner value
            let canonical_metadata: Vec<(Value, Value)> = annotation
                .metadata
                .iter()
                .map(|(key, value)| (canonicalize_value(key), canonicalize_value(value)))
                .collect();
            // Sort metadata by key for canonical ordering
            let mut sorted_metadata: Vec<(String, Value, Value)> = canonical_metadata
                .into_iter()
                .map(|(key, value)| {
                    let sort_key = canonical_sort_key(&key);
                    (sort_key, key, value)
                })
                .collect();
            sorted_metadata.sort_by(|a, b| a.0.cmp(&b.0));
            let metadata = sorted_metadata
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
            let canonical_value = canonicalize_value(&annotation.value);
            Value::Annotated(Box::new(Annotation::new(metadata, canonical_value)))
        }
        Value::Bytes(_)
        | Value::Nil
        | Value::Bool(_)
        | Value::Int(_)
        | Value::UInt(_)
        | Value::BigInt(_)
        | Value::Float32(_)
        | Value::Float64(_)
        | Value::String(_)
        | Value::Symbol(_)
        | Value::Keyword(_) => value.clone(),
    }
}

fn canonical_sort_key(value: &Value) -> String {
    crate::text::to_string(value)
}
