use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rulia::{text, ImportResolver, Keyword, ResolvedImport, RuliaError, Value};
use sha2::{Digest, Sha256};

struct TestResolver {
    origin: String,
    entries: HashMap<String, String>,
}

impl TestResolver {
    fn new(origin: &str, entries: HashMap<String, String>) -> Self {
        Self {
            origin: origin.to_string(),
            entries,
        }
    }
}

impl ImportResolver for TestResolver {
    fn resolve(&self, _base_dir: Option<&Path>, path: &str) -> rulia::RuliaResult<ResolvedImport> {
        let contents = self
            .entries
            .get(path)
            .ok_or_else(|| RuliaError::Parse(format!("import not found: {path}")))?;
        Ok(ResolvedImport {
            origin: self.origin.clone(),
            contents: contents.clone(),
        })
    }
}

#[test]
fn hermetic_import_success() {
    let mut entries = HashMap::new();
    entries.insert("a.rjl".to_string(), "(a=1)".to_string());
    let resolver = Arc::new(TestResolver::new("mem", entries));
    let options = text::ParseOptions {
        allow_import_io: false,
        import_resolver: Some(resolver),
        ..Default::default()
    };

    let value = text::parse_with_options("import \"a.rjl\"", options).expect("parse import");
    if let Value::Map(entries) = value {
        assert!(entries.contains(&(Value::Keyword(Keyword::simple("a")), Value::Int(1))));
    } else {
        panic!("expected map value");
    }
}

#[test]
fn deterministic_constructor_allows_imports_with_resolver() {
    let mut entries = HashMap::new();
    entries.insert("a.rjl".to_string(), "(a=1)".to_string());
    let resolver = Arc::new(TestResolver::new("mem", entries));
    let options = text::ParseOptions {
        import_resolver: Some(resolver),
        ..text::ParseOptions::deterministic()
    };

    let value = text::parse_with_options("import \"a.rjl\"", options).expect("parse import");
    if let Value::Map(entries) = value {
        assert!(entries.contains(&(Value::Keyword(Keyword::simple("a")), Value::Int(1))));
    } else {
        panic!("expected map value");
    }
}

#[test]
fn hermetic_import_hash_verification() {
    let contents = "(a=1)";
    let mut entries = HashMap::new();
    entries.insert("a.rjl".to_string(), contents.to_string());
    let resolver = Arc::new(TestResolver::new("mem", entries));
    let options = text::ParseOptions {
        allow_import_io: false,
        import_resolver: Some(resolver),
        ..Default::default()
    };

    let hash = hex::encode(Sha256::digest(contents.as_bytes()));
    let script = format!("import \"a.rjl\" sha256:{hash}");
    let value = text::parse_with_options(&script, options.clone()).expect("hash import");
    assert!(matches!(value, Value::Map(_)));

    let bad_hash = "0".repeat(64);
    let bad_script = format!("import \"a.rjl\" sha256:{bad_hash}");
    let err = text::parse_with_options(&bad_script, options).expect_err("hash mismatch");
    assert!(matches!(err, RuliaError::HashMismatch { .. }));
}

#[test]
fn hermetic_import_cycle_detection() {
    let mut entries = HashMap::new();
    entries.insert("a.rjl".to_string(), "import \"b.rjl\"".to_string());
    entries.insert("b.rjl".to_string(), "import \"a.rjl\"".to_string());
    let resolver = Arc::new(TestResolver::new("mem", entries));
    let options = text::ParseOptions {
        allow_import_io: false,
        import_resolver: Some(resolver),
        ..Default::default()
    };

    let err = text::parse_with_options("import \"a.rjl\"", options).expect_err("cycle");
    assert!(matches!(err, RuliaError::ImportCycle(_)));
}
