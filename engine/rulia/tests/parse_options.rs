use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use rulia::{text, NewValueProvider, RuliaError, Value};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let base = env::temp_dir();
    let pid = std::process::id();
    let count = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    base.join(format!("{prefix}-{pid}-{count}"))
}

struct EnvRestore {
    key: String,
    old: Option<String>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.old {
            Some(value) => env::set_var(&self.key, value),
            None => env::remove_var(&self.key),
        }
    }
}

fn with_env_var<T>(key: &str, value: &Path, f: impl FnOnce() -> T) -> T {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let old = env::var(key).ok();
    env::set_var(key, value);
    let _restore = EnvRestore {
        key: key.to_string(),
        old,
    };
    f()
}

fn test_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

struct FixedNewProvider {
    uuid: [u8; 16],
    ulid: String,
    now_millis: i64,
}

impl NewValueProvider for FixedNewProvider {
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

#[test]
fn deterministic_constructor_sets_flags() {
    let options = text::ParseOptions::deterministic();
    assert!(!options.allow_import_io);
    assert!(!options.allow_disk_cache);
    assert!(options.deterministic);
    assert!(options.new_provider.is_none());
    assert!(options.import_resolver.is_none());
}

#[test]
fn deterministic_constructor_rejects_new_without_provider() {
    let options = text::ParseOptions::deterministic();
    for input in ["@new(:now)", "@new(:uuid)", "@new(:ulid)"] {
        let err = text::parse_with_options(input, options.clone()).expect_err("@new rejected");
        assert!(matches!(err, RuliaError::DeterministicNewDisabled));
    }
}

#[test]
fn deterministic_constructor_rejects_imports_without_resolver() {
    let options = text::ParseOptions::deterministic();
    let base_dir = test_data_dir();
    let err = text::parse_in_dir_with_options("import \"common.rjl\"", &base_dir, options)
        .expect_err("import blocked without resolver");
    assert!(matches!(err, RuliaError::ImportIoDisabled));
}

#[test]
fn deterministic_constructor_uses_provider() {
    let provider = Arc::new(FixedNewProvider {
        uuid: [0xCD; 16],
        ulid: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
        now_millis: 1_700_000_000_123,
    });
    let options = text::ParseOptions {
        new_provider: Some(provider),
        ..text::ParseOptions::deterministic()
    };

    let value = text::parse_with_options("@new(:now)", options).expect("now parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "inst");
        assert_eq!(*tagged.value, Value::Int(1_700_000_000_123));
    } else {
        panic!("expected tagged inst value");
    }
}

#[test]
fn deterministic_rejects_new_macros() {
    let options = text::ParseOptions {
        deterministic: true,
        ..Default::default()
    };
    for input in ["@new(:now)", "@new(:uuid)", "@new(:ulid)"] {
        let err = text::parse_with_options(input, options.clone()).expect_err("@new rejected");
        assert!(matches!(err, RuliaError::DeterministicNewDisabled));
    }
}

#[test]
fn deterministic_new_uses_provider() {
    let provider = Arc::new(FixedNewProvider {
        uuid: [0xAB; 16],
        ulid: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
        now_millis: 1_700_000_000_000,
    });
    let options = text::ParseOptions {
        deterministic: true,
        new_provider: Some(provider),
        ..Default::default()
    };

    let value = text::parse_with_options("@new(:uuid)", options.clone()).expect("uuid parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "uuid");
        assert_eq!(*tagged.value, Value::Bytes(vec![0xAB; 16]));
    } else {
        panic!("expected tagged uuid value");
    }

    let value = text::parse_with_options("@new(:ulid)", options.clone()).expect("ulid parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "ulid");
        assert_eq!(
            *tagged.value,
            Value::String("01ARZ3NDEKTSV4RRFFQ69G5FAV".into())
        );
    } else {
        panic!("expected tagged ulid value");
    }

    let value = text::parse_with_options("@new(:now)", options).expect("now parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "inst");
        assert_eq!(*tagged.value, Value::Int(1_700_000_000_000));
    } else {
        panic!("expected tagged inst value");
    }
}

#[test]
fn nondeterministic_new_types() {
    let options = text::ParseOptions {
        deterministic: false,
        ..Default::default()
    };

    let value = text::parse_with_options("@new(:uuid)", options.clone()).expect("uuid parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "uuid");
        assert!(matches!(*tagged.value, Value::Bytes(_)));
    } else {
        panic!("expected tagged uuid value");
    }

    let value = text::parse_with_options("@new(:ulid)", options.clone()).expect("ulid parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "ulid");
        assert!(matches!(*tagged.value, Value::String(_)));
    } else {
        panic!("expected tagged ulid value");
    }

    let value = text::parse_with_options("@new(:now)", options).expect("now parse");
    if let Value::Tagged(tagged) = value {
        assert_eq!(tagged.tag.name(), "inst");
        assert!(matches!(*tagged.value, Value::Int(_)));
    } else {
        panic!("expected tagged inst value");
    }
}

#[test]
fn import_io_disabled_rejects_imports() {
    let options = text::ParseOptions {
        allow_import_io: false,
        ..Default::default()
    };
    let base_dir = test_data_dir();
    let err = text::parse_in_dir_with_options("import \"common.rjl\"", &base_dir, options)
        .expect_err("import io disabled");
    assert!(matches!(err, RuliaError::ImportIoDisabled));
}

#[test]
fn deterministic_disables_disk_cache_writes() {
    let options = text::ParseOptions {
        deterministic: true,
        ..Default::default()
    };
    let base_dir = test_data_dir();
    let cache_dir = unique_temp_dir("rulia-cache-deterministic");
    fs::create_dir_all(&cache_dir).expect("create cache dir");

    with_env_var("RULIA_CACHE_DIR", &cache_dir, || {
        let _value = text::parse_in_dir_with_options("import \"common.rjl\"", &base_dir, options)
            .expect("parse import");
        let entries: Vec<_> = fs::read_dir(&cache_dir)
            .expect("read cache dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("list cache dir");
        assert!(entries.is_empty(), "cache dir should stay empty");
    });

    let _ = fs::remove_dir_all(&cache_dir);
}

#[test]
fn allow_disk_cache_false_disables_disk_cache_writes() {
    let options = text::ParseOptions {
        allow_disk_cache: false,
        ..Default::default()
    };
    let base_dir = test_data_dir();
    let cache_dir = unique_temp_dir("rulia-cache-disabled");
    fs::create_dir_all(&cache_dir).expect("create cache dir");

    with_env_var("RULIA_CACHE_DIR", &cache_dir, || {
        let _value = text::parse_in_dir_with_options("import \"common.rjl\"", &base_dir, options)
            .expect("parse import");
        let entries: Vec<_> = fs::read_dir(&cache_dir)
            .expect("read cache dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("list cache dir");
        assert!(entries.is_empty(), "cache dir should stay empty");
    });

    let _ = fs::remove_dir_all(&cache_dir);
}
