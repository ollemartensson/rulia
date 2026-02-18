use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{RuliaError, RuliaResult};

pub trait ImportResolver {
    fn resolve(&self, base_dir: Option<&Path>, path: &str) -> RuliaResult<ResolvedImport>;
}

#[derive(Clone, Debug)]
pub struct ResolvedImport {
    pub origin: String,
    pub contents: String,
}

pub type ImportResolverCallback =
    dyn Fn(Option<&Path>, &str) -> RuliaResult<ResolvedImport> + Send + Sync + 'static;

#[derive(Clone)]
pub struct CallbackImportResolver {
    callback: Arc<ImportResolverCallback>,
}

impl CallbackImportResolver {
    pub fn new(callback: Arc<ImportResolverCallback>) -> Self {
        Self { callback }
    }
}

impl ImportResolver for CallbackImportResolver {
    fn resolve(&self, base_dir: Option<&Path>, path: &str) -> RuliaResult<ResolvedImport> {
        (self.callback)(base_dir, path)
    }
}

pub fn resolver_from_callback<F>(callback: F) -> Arc<dyn ImportResolver + Send + Sync>
where
    F: Fn(Option<&Path>, &str) -> RuliaResult<ResolvedImport> + Send + Sync + 'static,
{
    Arc::new(CallbackImportResolver::new(Arc::new(callback)))
}

#[derive(Clone, Debug)]
pub struct InMemoryImportResolver {
    origin: String,
    entries: HashMap<String, String>,
}

impl InMemoryImportResolver {
    pub fn new(origin: impl Into<String>) -> Self {
        Self {
            origin: origin.into(),
            entries: HashMap::new(),
        }
    }

    pub fn from_map(origin: impl Into<String>, entries: HashMap<String, String>) -> Self {
        Self {
            origin: origin.into(),
            entries,
        }
    }

    pub fn insert(&mut self, path: impl Into<String>, contents: impl Into<String>) {
        self.entries.insert(path.into(), contents.into());
    }

    fn lookup_key(base_dir: Option<&Path>, path: &str) -> PathBuf {
        let raw = Path::new(path);
        if raw.is_absolute() {
            raw.to_path_buf()
        } else if let Some(base) = base_dir {
            base.join(raw)
        } else {
            raw.to_path_buf()
        }
    }
}

impl ImportResolver for InMemoryImportResolver {
    fn resolve(&self, base_dir: Option<&Path>, path: &str) -> RuliaResult<ResolvedImport> {
        let lookup = Self::lookup_key(base_dir, path).display().to_string();
        let contents = self
            .entries
            .get(&lookup)
            .or_else(|| self.entries.get(path))
            .ok_or_else(|| RuliaError::Parse(format!("import not found: {path}")))?;

        Ok(ResolvedImport {
            origin: self.origin.clone(),
            contents: contents.clone(),
        })
    }
}
