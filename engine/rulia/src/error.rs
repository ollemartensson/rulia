use thiserror::Error;

use crate::hash::HashAlgorithm;

/// Result alias used across the crate.
pub type RuliaResult<T> = Result<T, RuliaError>;

/// Error variants surfaced by the Rulia implementation.
#[derive(Debug, Error)]
pub enum RuliaError {
    #[error("buffer is too small to contain a valid Rulia message")]
    BufferTooSmall,
    #[error("invalid magic header")]
    InvalidMagic,
    #[error("unsupported Rulia version: {0}")]
    UnsupportedVersion(u16),
    #[error("value segment offset {0} exceeds message length")]
    OffsetOutOfBounds(u64),
    #[error("dictionary index {0} is out of bounds")]
    DictionaryIndexOutOfBounds(u32),
    #[error("invalid utf-8 data in dictionary entry")]
    InvalidUtf8,
    #[error("pointer uses unknown type tag {0}")]
    UnknownTypeTag(u16),
    #[error("unexpected value kind: {0}")]
    UnexpectedValueKind(&'static str),
    #[error("builder ran out of address space (offset {0})")]
    BuilderOffsetOverflow(u64),
    #[error("map keys must be unique")]
    DuplicateMapKey,
    #[error("duplicate map key: {0}")]
    DuplicateMapKeyLiteral(String),
    #[error("set members must be unique")]
    DuplicateSetValue,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("evaluation error: {0}")]
    Evaluation(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid import hash specification: {0}")]
    InvalidHash(String),
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("cyclic import detected at {0}")]
    ImportCycle(String),
    #[error("import I/O is disabled by parse options")]
    ImportIoDisabled,
    #[error("deterministic mode disallows @new")]
    DeterministicNewDisabled,
    #[error("serde conversion error: {0}")]
    Serde(String),
    #[error("schema error: {0}")]
    Schema(String),
    #[error("security error: {0}")]
    Security(&'static str),
    #[error(
        "replay mismatch for {algorithm:?}: bytes {bytes_len} vs {reencoded_len}, first byte mismatch at {first_byte_mismatch:?}; digest {digest_len} vs {reencoded_digest_len}, first digest mismatch at {first_digest_mismatch:?}"
    )]
    ReplayMismatch {
        algorithm: HashAlgorithm,
        bytes_len: usize,
        reencoded_len: usize,
        first_byte_mismatch: Option<usize>,
        digest_len: usize,
        reencoded_digest_len: usize,
        first_digest_mismatch: Option<usize>,
    },
}
