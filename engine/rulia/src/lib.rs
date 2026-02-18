/* Copyright (c) 2026 Olle Mårtensson. This Source Code Form is subject to the terms of the Eclipse Public License, v. 2.0. */
//! Rulia: dual-format data notation implementation.
//!
//! This crate exposes APIs for constructing, encoding, and reading Rulia
//! messages in their binary representation as well as utilities for working
//! with the abstract data model.
//!
//! # Examples
//! ```
//! use ordered_float::OrderedFloat;
//! use rulia::{encode_value, decode_value, Keyword, Value};
//!
//! let value = Value::Map(vec![
//!     (Value::Keyword(Keyword::simple("service")), Value::String("transactor".into())),
//!     (Value::Keyword(Keyword::simple("cpu")), Value::Float64(OrderedFloat(0.82))),
//! ]);
//!
//! let bytes = encode_value(&value).expect("encode");
//! let decoded = decode_value(&bytes).expect("decode");
//! assert_eq!(decoded, value);
//! ```

mod error;
pub mod value;

pub mod binary;
pub mod hash;
pub mod imports;
pub mod kernel_expression;
pub mod schema;
pub mod security;
pub mod text;

#[cfg(feature = "serde")]
pub mod serde_support;

pub use binary::{
    encode_canonical, encode_with_digest, encode_with_digest_using, verify_digest,
    EncodedWithDigest,
};
pub use error::{RuliaError, RuliaResult};
pub use hash::HashAlgorithm;
pub use imports::{
    resolver_from_callback, CallbackImportResolver, ImportResolver, InMemoryImportResolver,
    ResolvedImport,
};
pub use kernel_expression::{
    evaluate_kernel_expression_payload, payload_contains_kernel_expression,
};
pub use schema::Schema;
pub use security::{
    canonical_digest, verify_manifest, verify_signed, DigestAlg, SigAlg, Signer, Verifier,
    VerifyPolicy,
};
pub use text::{NewValueProvider, ParseOptions};
pub use value::{Annotation, Keyword, Symbol, TaggedValue, Value};

#[cfg(feature = "serde")]
pub use serde_support::{from_bytes, from_value, to_bytes, to_value};

/// Encode a [`Value`] into its binary Rulia representation.
pub fn encode_value(value: &Value) -> RuliaResult<Vec<u8>> {
    binary::MessageBuilder::encode(value)
}

/// Decode a binary Rulia message into the dynamic value tree.
pub fn decode_value(bytes: &[u8]) -> RuliaResult<Value> {
    let reader = binary::MessageReader::new(bytes)?;
    reader.root()?.deserialize()
}

/// Encode, decode, and re-encode a [`Value`] to assert canonical replay determinism.
pub fn replay_roundtrip(value: &Value, algo: HashAlgorithm) -> RuliaResult<()> {
    let encoded = encode_with_digest_using(value, algo)?;
    verify_digest(&encoded.bytes)?;

    let decoded = decode_value(&encoded.bytes)?;
    let encoded_again = encode_with_digest_using(&decoded, algo)?;

    if encoded.bytes != encoded_again.bytes || encoded.digest != encoded_again.digest {
        return Err(RuliaError::ReplayMismatch {
            algorithm: algo,
            bytes_len: encoded.bytes.len(),
            reencoded_len: encoded_again.bytes.len(),
            first_byte_mismatch: first_mismatch_index(&encoded.bytes, &encoded_again.bytes),
            digest_len: encoded.digest.len(),
            reencoded_digest_len: encoded_again.digest.len(),
            first_digest_mismatch: first_mismatch_index(&encoded.digest, &encoded_again.digest),
        });
    }

    Ok(())
}

fn first_mismatch_index(left: &[u8], right: &[u8]) -> Option<usize> {
    let shared_len = left.len().min(right.len());
    for idx in 0..shared_len {
        if left[idx] != right[idx] {
            return Some(idx);
        }
    }
    if left.len() != right.len() {
        Some(shared_len)
    } else {
        None
    }
}
