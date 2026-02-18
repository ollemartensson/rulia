use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(crate) type DigestV0 = String;

// Request ordinals are 1-based in v0. Current request steps emit one request.
pub(crate) const REQUEST_ORDINAL_BASE_V0: u64 = 1;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RequestSeedV0 {
    pub(crate) artifact_hash: String,
    pub(crate) step_id: String,
    pub(crate) request_ordinal: u64,
    pub(crate) args_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) history_cursor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) process_id: Option<String>,
}

pub(crate) fn compute_args_hash_v0(args: &Value) -> Result<DigestV0, String> {
    let canonical_bytes = canonical_json_bytes(args)
        .map_err(|_| "failed to canonicalize request args".to_string())?;
    Ok(sha256_prefixed(&canonical_bytes))
}

pub(crate) fn compute_request_key_v0(seed: &RequestSeedV0) -> Result<DigestV0, String> {
    let seed_value =
        serde_json::to_value(seed).map_err(|_| "failed to encode request seed".to_string())?;
    let canonical_bytes = canonical_json_bytes(&seed_value)
        .map_err(|_| "failed to canonicalize request seed".to_string())?;
    Ok(sha256_prefixed(&canonical_bytes))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let canonical_value = canonicalize_json_value(value);
    serde_json::to_vec(&canonical_value)
}

fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(entries) => {
            let mut sorted = BTreeMap::new();
            for (key, candidate) in entries {
                sorted.insert(key.clone(), canonicalize_json_value(candidate));
            }
            let mut object = Map::new();
            for (key, candidate) in sorted {
                object.insert(key, candidate);
            }
            Value::Object(object)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        _ => value.clone(),
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
