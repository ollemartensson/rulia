use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rulia::{
    decode_value, encode_with_digest_using, replay_roundtrip, text, HashAlgorithm, ImportResolver,
    NewValueProvider, ResolvedImport, RuliaError,
};

struct TestNewProvider {
    uuid: [u8; 16],
    ulid: String,
    now_millis: i64,
}

impl NewValueProvider for TestNewProvider {
    fn new_uuid(&self) -> [u8; 16] {
        self.uuid
    }

    fn new_ulid(&self) -> String {
        self.ulid.clone()
    }

    fn now_millis(&self) -> i64 {
        self.now_millis
    }
}

struct TestImportResolver {
    origin: String,
    entries: HashMap<String, String>,
}

impl TestImportResolver {
    fn new(origin: &str, entries: HashMap<String, String>) -> Self {
        Self {
            origin: origin.to_string(),
            entries,
        }
    }
}

impl ImportResolver for TestImportResolver {
    fn resolve(&self, _base_dir: Option<&Path>, path: &str) -> rulia::RuliaResult<ResolvedImport> {
        let contents = self
            .entries
            .get(path)
            .ok_or_else(|| rulia::RuliaError::Parse(format!("import not found: {path}")))?;
        Ok(ResolvedImport {
            origin: self.origin.clone(),
            contents: contents.clone(),
        })
    }
}

#[test]
fn hermetic_replay_determinism() {
    let provider = Arc::new(TestNewProvider {
        uuid: [0x42; 16],
        ulid: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
        now_millis: 1_700_000_123_456,
    });

    let mut entries = HashMap::new();
    entries.insert(
        "dep.rjl".to_string(),
        "(id = @new(:uuid), t = @new(:now))".to_string(),
    );
    let resolver = Arc::new(TestImportResolver::new("mem", entries));

    let options = text::ParseOptions {
        deterministic: true,
        allow_import_io: false,
        allow_disk_cache: false,
        new_provider: Some(provider),
        import_resolver: Some(resolver),
    };

    let input = r#"let dep = import "dep.rjl"
        (dep = dep, u = @new(:ulid))"#;

    let value = text::parse_with_options(input, options).expect("parse");
    let encoded = encode_with_digest_using(&value, HashAlgorithm::Sha256).expect("encode");

    let decoded = decode_value(&encoded.bytes).expect("decode");
    let encoded_again =
        encode_with_digest_using(&decoded, HashAlgorithm::Sha256).expect("encode again");

    assert_eq!(encoded.bytes, encoded_again.bytes);
    assert_eq!(encoded.digest, encoded_again.digest);
    assert_eq!(encoded.algorithm, encoded_again.algorithm);
}

#[test]
fn replay_roundtrip_helper_smoke() {
    let value = text::parse(r#"(name = "Alice", tags = [1, 2, 3], active = true)"#).expect("parse");

    replay_roundtrip(&value, HashAlgorithm::Sha256).expect("replay");
}

#[test]
fn replay_mismatch_error_is_deterministic_and_bounded() {
    fn replay_mismatch_result() -> rulia::RuliaResult<()> {
        Err(RuliaError::ReplayMismatch {
            algorithm: HashAlgorithm::Sha256,
            bytes_len: 42,
            reencoded_len: 43,
            first_byte_mismatch: Some(9),
            digest_len: 32,
            reencoded_digest_len: 32,
            first_digest_mismatch: None,
        })
    }

    let err = replay_mismatch_result().expect_err("expected replay mismatch");

    assert!(matches!(&err, RuliaError::ReplayMismatch { .. }));

    let display = err.to_string();
    let debug = format!("{err:?}");

    let expected_display = "replay mismatch for Sha256: bytes 42 vs 43, first byte mismatch at Some(9); digest 32 vs 32, first digest mismatch at None";
    let expected_debug = "ReplayMismatch { algorithm: Sha256, bytes_len: 42, reencoded_len: 43, first_byte_mismatch: Some(9), digest_len: 32, reencoded_digest_len: 32, first_digest_mismatch: None }";

    assert_eq!(display, expected_display);
    assert_eq!(debug, expected_debug);
    assert!(!display.contains("0x"));
    assert!(!debug.contains("0x"));
    assert!(!display.contains('\n'));
    assert!(!debug.contains('\n'));
}
