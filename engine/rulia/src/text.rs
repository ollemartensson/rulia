use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt::{self, Write};
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hex;
use num_bigint::BigInt;
use ordered_float::OrderedFloat;
use sha2::{Digest, Sha256};
use ulid::Ulid;
use uuid::Uuid;

use crate::error::{RuliaError, RuliaResult};
use crate::hash::HashAlgorithm;
pub use crate::imports::{
    resolver_from_callback, CallbackImportResolver, ImportResolver, InMemoryImportResolver,
    ResolvedImport,
};
use crate::value::{Annotation, Keyword, Symbol, TaggedValue, Value};

pub trait NewValueProvider {
    fn new_uuid(&self) -> [u8; 16];
    fn new_ulid(&self) -> String;
    fn now_millis(&self) -> i64;
}

#[derive(Clone)]
pub struct ParseOptions {
    pub allow_import_io: bool,
    pub allow_disk_cache: bool,
    pub deterministic: bool,
    pub new_provider: Option<Arc<dyn NewValueProvider + Send + Sync>>,
    pub import_resolver: Option<Arc<dyn ImportResolver + Send + Sync>>,
}

impl fmt::Debug for ParseOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParseOptions")
            .field("allow_import_io", &self.allow_import_io)
            .field("allow_disk_cache", &self.allow_disk_cache)
            .field("deterministic", &self.deterministic)
            .field("new_provider", &self.new_provider.is_some())
            .field("import_resolver", &self.import_resolver.is_some())
            .finish()
    }
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            allow_import_io: true,
            allow_disk_cache: true,
            deterministic: false,
            new_provider: None,
            import_resolver: None,
        }
    }
}

impl ParseOptions {
    pub fn deterministic() -> Self {
        Self {
            allow_import_io: false,
            allow_disk_cache: false,
            deterministic: true,
            new_provider: None,
            import_resolver: None,
        }
    }

    fn normalized(mut self) -> Self {
        if self.deterministic {
            self.allow_disk_cache = false;
        }
        self
    }
}

#[derive(Clone)]
enum Expr {
    Literal(Value),
    Identifier(String),
    Let {
        bindings: Vec<(String, Expr)>,
        body: Box<Expr>,
    },
    Function {
        params: Vec<String>,
        body: Box<Expr>,
    },
    Call {
        function: Box<Expr>,
        args: Vec<Expr>,
    },
    Vector(Vec<Expr>),
    Set(Vec<Expr>),
    Map(Vec<(Expr, Expr)>),
    Tagged(Symbol, Box<Expr>),
    Import(ImportSpec),
    /// Annotated expression with metadata
    Annotated {
        metadata: Vec<(Expr, Expr)>,
        value: Box<Expr>,
    },
}

#[derive(Clone)]
struct ImportSpec {
    path: String,
    hash: Option<HashExpectation>,
}

#[derive(Clone)]
struct HashExpectation {
    algorithm: HashAlgorithm,
    value: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum ImportKey {
    Fs(PathBuf),
    Resolver { origin: String, path: String },
}

impl ImportKey {
    fn display(&self) -> String {
        match self {
            ImportKey::Fs(path) => path.display().to_string(),
            ImportKey::Resolver { origin, path } => format!("{origin}:{path}"),
        }
    }
}

#[derive(Clone)]
enum RuntimeValue {
    Data(Value),
    Function(Rc<FunctionImpl>),
}

impl RuntimeValue {
    fn into_value(self) -> RuliaResult<Value> {
        match self {
            RuntimeValue::Data(value) => Ok(value),
            RuntimeValue::Function(_) => Err(RuliaError::Evaluation(
                "cannot convert function into value".into(),
            )),
        }
    }
}

#[derive(Clone)]
enum FunctionImpl {
    User {
        params: Vec<String>,
        body: Expr,
        captures: Vec<HashMap<String, RuntimeValue>>,
        base_dir: Option<PathBuf>,
    },
    Builtin {
        handler: fn(Vec<RuntimeValue>) -> RuliaResult<RuntimeValue>,
    },
}

struct Environment {
    stack: Vec<HashMap<String, RuntimeValue>>,
}

impl Environment {
    fn new() -> Self {
        Self { stack: Vec::new() }
    }

    fn push_scope(&mut self) {
        self.stack.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.stack.pop();
    }

    fn define(&mut self, name: String, value: RuntimeValue) {
        if let Some(scope) = self.stack.last_mut() {
            scope.insert(name, value);
        }
    }

    fn get(&self, name: &str) -> Option<RuntimeValue> {
        for scope in self.stack.iter().rev() {
            if let Some(value) = scope.get(name) {
                return Some(value.clone());
            }
        }
        None
    }

    fn snapshot(&self) -> Vec<HashMap<String, RuntimeValue>> {
        self.stack.clone()
    }

    fn from_snapshot(snapshot: Vec<HashMap<String, RuntimeValue>>) -> Self {
        Self { stack: snapshot }
    }
}

pub fn parse(input: &str) -> RuliaResult<Value> {
    parse_with_options(input, ParseOptions::default())
}

pub fn parse_in_dir(input: &str, base_dir: impl AsRef<Path>) -> RuliaResult<Value> {
    parse_in_dir_with_options(input, base_dir, ParseOptions::default())
}

pub fn parse_file(path: impl AsRef<Path>) -> RuliaResult<Value> {
    parse_file_with_options(path, ParseOptions::default())
}

#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub byte_offset: Option<usize>,
}

impl ParseError {
    fn from_rulia(err: RuliaError, byte_offset: Option<usize>) -> Self {
        let is_parse = matches!(&err, RuliaError::Parse(_));
        let message = err.to_string();
        Self {
            message,
            byte_offset: if is_parse { byte_offset } else { None },
        }
    }
}

pub fn parse_with_options(input: &str, options: ParseOptions) -> RuliaResult<Value> {
    parse_with_base(input, None, options)
}

pub fn parse_with_options_diagnostics(
    input: &str,
    options: ParseOptions,
) -> Result<Value, ParseError> {
    parse_with_base_diagnostics(input, None, options)
}

pub fn parse_in_dir_with_options(
    input: &str,
    base_dir: impl AsRef<Path>,
    options: ParseOptions,
) -> RuliaResult<Value> {
    parse_with_base(input, Some(base_dir.as_ref().to_path_buf()), options)
}

pub fn parse_file_with_options(
    path: impl AsRef<Path>,
    options: ParseOptions,
) -> RuliaResult<Value> {
    let options = options.normalized();
    if !options.allow_import_io {
        return Err(RuliaError::ImportIoDisabled);
    }
    let path = path.as_ref();
    let content = fs::read_to_string(path)?;
    let base_dir = path.parent().map(|p| p.to_path_buf());
    parse_with_base(&content, base_dir, options)
}

pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out).expect("string writer");
    out
}

pub fn to_canonical_string(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_value(value, &mut out).expect("string writer");
    out
}

fn format_map_key_for_error(key: &Value) -> String {
    let mut out = String::new();
    write_value(key, &mut out).expect("string writer");
    out
}

fn parse_with_base(
    input: &str,
    base_dir: Option<PathBuf>,
    options: ParseOptions,
) -> RuliaResult<Value> {
    let options = options.normalized();
    let resolver = Rc::new(RefCell::new(ImportState::new(options.clone())));
    parse_with_context(input, base_dir, resolver, options)
}

fn parse_with_base_diagnostics(
    input: &str,
    base_dir: Option<PathBuf>,
    options: ParseOptions,
) -> Result<Value, ParseError> {
    let options = options.normalized();
    let resolver = Rc::new(RefCell::new(ImportState::new(options.clone())));
    parse_with_context_diagnostics(input, base_dir, resolver, options)
}

fn parse_with_context(
    input: &str,
    base_dir: Option<PathBuf>,
    resolver: Rc<RefCell<ImportState>>,
    options: ParseOptions,
) -> RuliaResult<Value> {
    let mut parser = Parser::new(input, options);
    let expr = parser.parse_expression()?;
    parser.skip_ws();
    if !parser.is_eof() {
        return Err(RuliaError::Parse("trailing characters".into()));
    }
    let mut evaluator = Evaluator::new(base_dir, resolver);
    evaluator.evaluate(expr)
}

fn parse_with_context_diagnostics(
    input: &str,
    base_dir: Option<PathBuf>,
    resolver: Rc<RefCell<ImportState>>,
    options: ParseOptions,
) -> Result<Value, ParseError> {
    let mut parser = Parser::new(input, options);
    let expr = match parser.parse_expression() {
        Ok(expr) => expr,
        Err(err) => return Err(ParseError::from_rulia(err, Some(parser.pos))),
    };
    parser.skip_ws();
    if !parser.is_eof() {
        return Err(ParseError::from_rulia(
            RuliaError::Parse("trailing characters".into()),
            Some(parser.pos),
        ));
    }
    let mut evaluator = Evaluator::new(base_dir, resolver);
    evaluator
        .evaluate(expr)
        .map_err(|err| ParseError::from_rulia(err, None))
}

fn write_value(value: &Value, out: &mut String) -> std::fmt::Result {
    match value {
        Value::Nil => out.push_str("nil"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(v) => write!(out, "{}", v)?,
        Value::UInt(v) => write!(out, "{}u", v)?,
        Value::BigInt(v) => write!(out, "{}N", v)?,
        Value::Float32(v) => write!(out, "{}f", v)?,
        Value::Float64(v) => write!(out, "{}", v)?,
        Value::String(s) => {
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    _ => out.push(ch),
                }
            }
            out.push('"');
        }
        Value::Bytes(bytes) => {
            out.push_str("0x[");
            for byte in bytes {
                write!(out, "{:02x}", byte)?;
            }
            out.push(']');
        }
        Value::Symbol(sym) => {
            // Logic variables (starting with ?) get @? prefix
            let name = sym.name();
            if name.starts_with('?') {
                write!(out, "@{}", sym)?
            } else {
                write!(out, "'{}", sym)?
            }
        }
        Value::Keyword(kw) => {
            if keyword_is_simple_sugar(kw) {
                // Use underscore sugar: :ns_name
                out.push(':');
                if let Some(ns) = kw.namespace() {
                    write!(out, "{}_{}", ns, kw.name())?;
                } else {
                    out.push_str(kw.name());
                }
            } else {
                // Explicit form for ambiguous cases: Keyword("ns/name")
                out.push_str("Keyword(\"");
                if let Some(ns) = kw.namespace() {
                    write!(out, "{}/{}", ns, kw.name())?;
                } else {
                    out.push_str(kw.name());
                }
                out.push_str("\")");
            }
        }
        Value::Vector(values) => {
            out.push('[');
            let mut first = true;
            for item in values {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Set(values) => {
            out.push_str("Set([");
            let mut first = true;
            for item in values {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_value(item, out)?;
            }
            out.push_str("])");
        }
        Value::Map(entries) => {
            out.push('(');
            let mut first = true;
            for (key, val) in entries {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                // For keyword keys, output as identifier sugar if possible
                if let Value::Keyword(kw) = key {
                    if keyword_is_simple_sugar(kw) {
                        if let Some(ns) = kw.namespace() {
                            write!(out, "{}_{}", ns, kw.name())?;
                        } else {
                            out.push_str(kw.name());
                        }
                    } else {
                        // Explicit form for ambiguous keyword keys
                        write_value(key, out)?;
                    }
                } else {
                    write_value(key, out)?;
                }
                out.push('=');
                write_value(val, out)?;
            }
            out.push(')');
        }
        Value::Tagged(tagged) => {
            // Special case: #ref tag -> Ref(...) syntax
            if tagged.tag.namespace().is_none() && tagged.tag.name() == "ref" {
                out.push_str("Ref(");
                // If inner value is a vector, unwrap it as multiple args
                if let Value::Vector(items) = &*tagged.value {
                    let mut first = true;
                    for item in items {
                        if !first {
                            out.push_str(", ");
                        }
                        first = false;
                        write_value(item, out)?;
                    }
                } else {
                    write_value(&tagged.value, out)?;
                }
                out.push(')');
            } else if symbol_is_simple_pascal(&tagged.tag) {
                // Use PascalCase sugar: GeoPoint(value)
                let tag_str = if let Some(ns) = tagged.tag.namespace() {
                    format!(
                        "{}{}",
                        to_pascal_case(ns),
                        to_pascal_case(tagged.tag.name())
                    )
                } else {
                    to_pascal_case(tagged.tag.name())
                };
                write!(out, "{}(", tag_str)?;
                write_value(&tagged.value, out)?;
                out.push(')');
            } else {
                // Explicit form for complex tags: Tagged("ns/name", value)
                out.push_str("Tagged(\"");
                if let Some(ns) = tagged.tag.namespace() {
                    write!(out, "{}/{}", ns, tagged.tag.name())?;
                } else {
                    out.push_str(tagged.tag.name());
                }
                out.push_str("\", ");
                write_value(&tagged.value, out)?;
                out.push(')');
            }
        }
        Value::Annotated(annotation) => {
            write_annotation(annotation, out)?;
        }
    }
    Ok(())
}

fn write_canonical_value(value: &Value, out: &mut String) -> std::fmt::Result {
    match value {
        Value::Nil => out.push_str("nil"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(v) => write!(out, "{}", v)?,
        Value::UInt(v) => write!(out, "{}u", v)?,
        Value::BigInt(v) => write!(out, "{}N", v)?,
        Value::Float32(v) => write!(out, "{}f", v)?,
        Value::Float64(v) => {
            let mut rendered = v.to_string();
            if !rendered.contains('.') && !rendered.contains('e') && !rendered.contains('E') {
                rendered.push_str(".0");
            }
            out.push_str(&rendered);
        }
        Value::String(s) => {
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '$' => out.push_str("\\$"),
                    _ => out.push(ch),
                }
            }
            out.push('"');
        }
        Value::Bytes(bytes) => {
            out.push_str("0x[");
            for byte in bytes {
                write!(out, "{:02x}", byte)?;
            }
            out.push(']');
        }
        Value::Symbol(sym) => {
            let name = sym.name();
            if name.starts_with('?') {
                write!(out, "@{}", sym)?
            } else {
                write!(out, "'{}", sym)?
            }
        }
        Value::Keyword(kw) => {
            if keyword_is_simple_sugar(kw) {
                out.push(':');
                if let Some(ns) = kw.namespace() {
                    write!(out, "{}_{}", ns, kw.name())?;
                } else {
                    out.push_str(kw.name());
                }
            } else {
                out.push_str("Keyword(\"");
                if let Some(ns) = kw.namespace() {
                    write!(out, "{}/{}", ns, kw.name())?;
                } else {
                    out.push_str(kw.name());
                }
                out.push_str("\")");
            }
        }
        Value::Vector(values) => {
            out.push('[');
            let mut first = true;
            for item in values {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_canonical_value(item, out)?;
            }
            out.push(']');
        }
        Value::Set(values) => {
            out.push_str("Set([");
            let mut items: Vec<(String, &Value)> = values
                .iter()
                .map(|item| (canonical_sort_key(item), item))
                .collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            let mut first = true;
            for (_, item) in items {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_canonical_value(item, out)?;
            }
            out.push_str("])");
        }
        Value::Map(entries) => {
            out.push('(');
            let mut ordered: Vec<(String, &Value, &Value)> = entries
                .iter()
                .map(|(key, value)| (canonical_sort_key(key), key, value))
                .collect();
            ordered.sort_by(|a, b| a.0.cmp(&b.0));
            let mut first = true;
            for (_, key, val) in ordered {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                if let Value::Keyword(kw) = key {
                    if keyword_is_simple_sugar(kw) {
                        if let Some(ns) = kw.namespace() {
                            write!(out, "{}_{}", ns, kw.name())?;
                        } else {
                            out.push_str(kw.name());
                        }
                    } else {
                        write_canonical_value(key, out)?;
                    }
                } else {
                    write_canonical_value(key, out)?;
                }
                out.push('=');
                write_canonical_value(val, out)?;
            }
            out.push(')');
        }
        Value::Tagged(tagged) => {
            if tagged.tag.namespace().is_none() && tagged.tag.name() == "ref" {
                out.push_str("Ref(");
                if let Value::Vector(items) = &*tagged.value {
                    let mut first = true;
                    for item in items {
                        if !first {
                            out.push_str(", ");
                        }
                        first = false;
                        write_canonical_value(item, out)?;
                    }
                } else {
                    write_canonical_value(&tagged.value, out)?;
                }
                out.push(')');
            } else if symbol_is_simple_pascal(&tagged.tag) {
                let tag_str = if let Some(ns) = tagged.tag.namespace() {
                    format!(
                        "{}{}",
                        to_pascal_case(ns),
                        to_pascal_case(tagged.tag.name())
                    )
                } else {
                    to_pascal_case(tagged.tag.name())
                };
                write!(out, "{}(", tag_str)?;
                write_canonical_value(&tagged.value, out)?;
                out.push(')');
            } else {
                out.push_str("Tagged(\"");
                if let Some(ns) = tagged.tag.namespace() {
                    write!(out, "{}/{}", ns, tagged.tag.name())?;
                } else {
                    out.push_str(tagged.tag.name());
                }
                out.push_str("\", ");
                write_canonical_value(&tagged.value, out)?;
                out.push(')');
            }
        }
        Value::Annotated(annotation) => {
            write_canonical_annotation(annotation, out)?;
        }
    }
    Ok(())
}

fn canonical_sort_key(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_value(value, &mut out).expect("string writer");
    out
}

fn write_canonical_annotation(annotation: &Annotation, out: &mut String) -> std::fmt::Result {
    let doc_key = Value::Keyword(Keyword::simple("doc"));

    let mut doc_value: Option<&str> = None;
    let mut other_metadata: Vec<(&Value, &Value)> = Vec::new();

    for (key, value) in &annotation.metadata {
        if key == &doc_key {
            if let Value::String(s) = value {
                doc_value = Some(s);
                continue;
            }
        }
        other_metadata.push((key, value));
    }

    if !other_metadata.is_empty() {
        let mut ordered: Vec<(String, &Value, &Value)> = other_metadata
            .into_iter()
            .map(|(key, value)| (canonical_sort_key(key), key, value))
            .collect();
        ordered.sort_by(|a, b| a.0.cmp(&b.0));
        out.push_str("@meta(");
        let mut first = true;
        for (_, key, value) in ordered {
            if !first {
                out.push_str(", ");
            }
            first = false;
            if let Value::Keyword(kw) = key {
                if keyword_is_simple_sugar(kw) {
                    if let Some(ns) = kw.namespace() {
                        write!(out, "{}_{}", ns, kw.name())?;
                    } else {
                        out.push_str(kw.name());
                    }
                } else {
                    write_canonical_value(key, out)?;
                }
            } else {
                write_canonical_value(key, out)?;
            }
            out.push_str(" = ");
            write_canonical_value(value, out)?;
        }
        out.push_str(")\n");
    }

    if let Some(doc) = doc_value {
        if doc.contains('\n') {
            out.push_str("\"\"\"\n");
            out.push_str(doc);
            if !doc.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("\"\"\"\n");
        } else {
            out.push('"');
            for ch in doc.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '$' => out.push_str("\\$"),
                    _ => out.push(ch),
                }
            }
            out.push_str("\"\n");
        }
    }

    write_canonical_value(&annotation.value, out)?;

    Ok(())
}

/// Write an annotated value with its metadata decorators.
///
/// Output format:
/// - @meta(...) for structured metadata (if any non-doc keys present)
/// - "docstring" for documentation (if :doc key present)
/// - then the inner value
fn write_annotation(annotation: &Annotation, out: &mut String) -> std::fmt::Result {
    let doc_key = Value::Keyword(Keyword::simple("doc"));

    // Separate doc from other metadata
    let mut doc_value: Option<&str> = None;
    let mut other_metadata: Vec<(&Value, &Value)> = Vec::new();

    for (key, value) in &annotation.metadata {
        if key == &doc_key {
            if let Value::String(s) = value {
                doc_value = Some(s);
            }
        } else {
            other_metadata.push((key, value));
        }
    }

    // Write @meta(...) if there's non-doc metadata
    if !other_metadata.is_empty() {
        out.push_str("@meta(");
        let mut first = true;
        for (key, value) in &other_metadata {
            if !first {
                out.push_str(", ");
            }
            first = false;
            // For keyword keys, use identifier sugar
            if let Value::Keyword(kw) = key {
                if keyword_is_simple_sugar(kw) {
                    if let Some(ns) = kw.namespace() {
                        write!(out, "{}_{}", ns, kw.name())?;
                    } else {
                        out.push_str(kw.name());
                    }
                } else {
                    write_value(key, out)?;
                }
            } else {
                write_value(key, out)?;
            }
            out.push_str(" = ");
            write_value(value, out)?;
        }
        out.push_str(")\n");
    }

    // Write docstring if present
    if let Some(doc) = doc_value {
        // Use triple-quoted string for multiline docs
        if doc.contains('\n') {
            out.push_str("\"\"\"\n");
            out.push_str(doc);
            if !doc.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("\"\"\"\n");
        } else {
            out.push('"');
            for ch in doc.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    _ => out.push(ch),
                }
            }
            out.push_str("\"\n");
        }
    }

    // Write the inner value
    write_value(&annotation.value, out)?;

    Ok(())
}

fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;
    for ch in s.chars() {
        if ch == '_' || ch == '-' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }
    result
}

struct Evaluator {
    env: Environment,
    current_dir: Option<PathBuf>,
    resolver: Rc<RefCell<ImportState>>,
}

impl Evaluator {
    fn new(current_dir: Option<PathBuf>, resolver: Rc<RefCell<ImportState>>) -> Self {
        let mut env = Environment::new();
        env.push_scope();
        env.define(
            "merge".to_string(),
            RuntimeValue::Function(Rc::new(FunctionImpl::Builtin {
                handler: builtin_merge,
            })),
        );
        env.define(
            "concat".to_string(),
            RuntimeValue::Function(Rc::new(FunctionImpl::Builtin {
                handler: builtin_concat,
            })),
        );
        env.define(
            "get".to_string(),
            RuntimeValue::Function(Rc::new(FunctionImpl::Builtin {
                handler: builtin_get,
            })),
        );
        Self {
            env,
            current_dir,
            resolver,
        }
    }

    fn from_environment(
        env: Environment,
        current_dir: Option<PathBuf>,
        resolver: Rc<RefCell<ImportState>>,
    ) -> Self {
        Self {
            env,
            current_dir,
            resolver,
        }
    }

    fn evaluate(&mut self, expr: Expr) -> RuliaResult<Value> {
        let runtime = self.eval_expr(expr)?;
        runtime.into_value()
    }

    fn eval_expr(&mut self, expr: Expr) -> RuliaResult<RuntimeValue> {
        match expr {
            Expr::Literal(value) => Ok(RuntimeValue::Data(value)),
            Expr::Identifier(name) => self
                .env
                .get(&name)
                .ok_or_else(|| RuliaError::Evaluation(format!("unknown identifier '{name}'"))),
            Expr::Let { bindings, body } => {
                self.env.push_scope();
                for (name, expr) in bindings {
                    let value_runtime = self.eval_expr(expr)?;
                    self.env.define(name, value_runtime);
                }
                let result = self.eval_expr(*body);
                self.env.pop_scope();
                result
            }
            Expr::Function { params, body } => {
                Ok(RuntimeValue::Function(Rc::new(FunctionImpl::User {
                    params,
                    body: (*body).clone(),
                    captures: self.env.snapshot(),
                    base_dir: self.current_dir.clone(),
                })))
            }
            Expr::Call { function, args } => {
                // Check if this is a Datalog predicate/aggregate (symbol function) that should be a vector
                if let Expr::Literal(Value::Symbol(sym)) = &*function {
                    // All symbol-based calls in Datalog/EDN should be literal vectors, not function calls
                    // Convert to vector: (>= ?age 18) -> [>= ?age 18]
                    let mut values = Vec::with_capacity(args.len() + 1);
                    values.push(Value::Symbol(sym.clone()));
                    for arg in args {
                        values.push(self.eval_expr(arg)?.into_value()?);
                    }
                    return Ok(RuntimeValue::Data(Value::Vector(values)));
                }

                // Normal function call
                let func_runtime = self.eval_expr(*function)?;
                let mut evaluated_args = Vec::with_capacity(args.len());
                for arg in args {
                    evaluated_args.push(self.eval_expr(arg)?);
                }
                self.invoke(func_runtime, evaluated_args)
            }
            Expr::Import(spec) => {
                let value = ImportState::resolve(
                    Rc::clone(&self.resolver),
                    spec,
                    self.current_dir.clone(),
                )?;
                Ok(RuntimeValue::Data(value))
            }
            Expr::Vector(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.eval_expr(item)?.into_value()?);
                }
                Ok(RuntimeValue::Data(Value::Vector(values)))
            }
            Expr::Set(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.eval_expr(item)?.into_value()?);
                }
                Ok(RuntimeValue::Data(Value::Set(values)))
            }
            Expr::Map(entries) => {
                let mut values = Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    let key_value = self.eval_expr(key)?.into_value()?;
                    let value_value = self.eval_expr(value)?.into_value()?;
                    values.push((key_value, value_value));
                }
                Ok(RuntimeValue::Data(Value::Map(values)))
            }
            Expr::Tagged(tag, value) => {
                let value = self.eval_expr(*value)?.into_value()?;
                Ok(RuntimeValue::Data(Value::Tagged(TaggedValue::new(
                    tag, value,
                ))))
            }
            Expr::Annotated { metadata, value } => {
                let mut evaluated_metadata = Vec::with_capacity(metadata.len());
                for (key, val) in metadata {
                    let key_value = self.eval_expr(key)?.into_value()?;
                    let val_value = self.eval_expr(val)?.into_value()?;
                    evaluated_metadata.push((key_value, val_value));
                }
                let inner_value = self.eval_expr(*value)?.into_value()?;
                Ok(RuntimeValue::Data(Value::Annotated(Box::new(
                    Annotation::new(evaluated_metadata, inner_value),
                ))))
            }
        }
    }

    fn invoke(
        &mut self,
        function: RuntimeValue,
        args: Vec<RuntimeValue>,
    ) -> RuliaResult<RuntimeValue> {
        match function {
            RuntimeValue::Function(func) => match &*func {
                FunctionImpl::User {
                    params,
                    body,
                    captures,
                    base_dir,
                } => {
                    if params.len() != args.len() {
                        return Err(RuliaError::Evaluation(format!(
                            "expected {} arguments, received {}",
                            params.len(),
                            args.len()
                        )));
                    }
                    let mut env = Environment::from_snapshot(captures.clone());
                    env.push_scope();
                    for (name, arg) in params.iter().cloned().zip(args) {
                        env.define(name, arg);
                    }
                    let mut evaluator = Evaluator::from_environment(
                        env,
                        base_dir.clone(),
                        Rc::clone(&self.resolver),
                    );
                    evaluator.eval_expr(body.clone())
                }
                FunctionImpl::Builtin { handler } => handler(args),
            },
            RuntimeValue::Data(_) => Err(RuliaError::Evaluation(
                "attempted to call a non-function".into(),
            )),
        }
    }
}

struct PreparedImport {
    key: ImportKey,
    base_dir: Option<PathBuf>,
    content: String,
    #[allow(dead_code)]
    digest: Option<[u8; 32]>,
}

struct CachedDigest {
    digest: [u8; 32],
    len: u64,
    modified: Option<SystemTime>,
}

struct ImportState {
    cache: HashMap<ImportKey, Value>,
    stack: Vec<ImportKey>,
    digest_cache: HashMap<(PathBuf, HashAlgorithm), CachedDigest>,
    cache_dir: Option<PathBuf>,
    options: ParseOptions,
}

impl ImportState {
    fn new(options: ParseOptions) -> Self {
        let options = options.normalized();
        let use_disk_cache = options.allow_import_io
            && options.allow_disk_cache
            && options.import_resolver.is_none();
        let cache_dir = if use_disk_cache {
            determine_cache_dir()
        } else {
            None
        };
        if use_disk_cache {
            if let Some(dir) = &cache_dir {
                let _ = fs::create_dir_all(dir);
            }
        }
        Self {
            cache: HashMap::new(),
            stack: Vec::new(),
            digest_cache: HashMap::new(),
            cache_dir,
            options,
        }
    }

    fn resolve(
        resolver: Rc<RefCell<Self>>,
        spec: ImportSpec,
        current_dir: Option<PathBuf>,
    ) -> RuliaResult<Value> {
        let ImportSpec { path, hash } = spec;
        let (options, import_resolver) = {
            let resolver_ref = resolver.borrow();
            (
                resolver_ref.options.clone(),
                resolver_ref.options.import_resolver.clone(),
            )
        };
        if let Some(import_resolver) = import_resolver {
            return Self::resolve_with_resolver(
                resolver,
                import_resolver,
                path,
                hash,
                current_dir,
                options,
            );
        }
        if !options.allow_import_io {
            return Err(RuliaError::ImportIoDisabled);
        }
        Self::resolve_with_fs(resolver, path, hash, current_dir, options)
    }

    fn resolve_with_resolver(
        resolver: Rc<RefCell<Self>>,
        import_resolver: Arc<dyn ImportResolver + Send + Sync>,
        path: String,
        hash: Option<HashExpectation>,
        current_dir: Option<PathBuf>,
        options: ParseOptions,
    ) -> RuliaResult<Value> {
        let resolved = import_resolver.resolve(current_dir.as_deref(), &path)?;
        let key = ImportKey::Resolver {
            origin: resolved.origin.clone(),
            path: path.clone(),
        };
        if let Some(value) = {
            let resolver_ref = resolver.borrow();
            resolver_ref.cache.get(&key).cloned()
        } {
            return Ok(value);
        }

        let prepared = {
            let mut resolver_mut = resolver.borrow_mut();
            resolver_mut.prepare_resolved(
                key.clone(),
                current_dir.as_deref(),
                &path,
                resolved,
                hash.as_ref(),
            )?
        };

        let result = parse_with_context(
            &prepared.content,
            prepared.base_dir.clone(),
            Rc::clone(&resolver),
            options,
        );

        match result {
            Ok(value) => {
                let mut resolver_mut = resolver.borrow_mut();
                resolver_mut.complete_success(&prepared.key, value.clone());
                Ok(value)
            }
            Err(err) => {
                let mut resolver_mut = resolver.borrow_mut();
                resolver_mut.complete_failure(&prepared.key);
                Err(err)
            }
        }
    }

    fn resolve_with_fs(
        resolver: Rc<RefCell<Self>>,
        path: String,
        hash: Option<HashExpectation>,
        current_dir: Option<PathBuf>,
        options: ParseOptions,
    ) -> RuliaResult<Value> {
        let canonical = Self::canonicalize_path(&path, current_dir.as_deref())?;
        let key = ImportKey::Fs(canonical.clone());
        if let Some(value) = {
            let resolver_ref = resolver.borrow();
            resolver_ref.cache.get(&key).cloned()
        } {
            return Ok(value);
        }

        let prepared = {
            let mut resolver_mut = resolver.borrow_mut();
            resolver_mut.prepare_fs(key.clone(), canonical, hash.as_ref())?
        };

        let result = parse_with_context(
            &prepared.content,
            prepared.base_dir.clone(),
            Rc::clone(&resolver),
            options,
        );

        match result {
            Ok(value) => {
                let mut resolver_mut = resolver.borrow_mut();
                resolver_mut.complete_success(&prepared.key, value.clone());
                Ok(value)
            }
            Err(err) => {
                let mut resolver_mut = resolver.borrow_mut();
                resolver_mut.complete_failure(&prepared.key);
                Err(err)
            }
        }
    }

    fn canonicalize_path(path: &str, current_dir: Option<&Path>) -> RuliaResult<PathBuf> {
        let raw = Path::new(path);
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else if let Some(base) = current_dir {
            base.join(raw)
        } else {
            PathBuf::from(raw)
        };
        Ok(fs::canonicalize(&joined)?)
    }

    fn prepare_fs(
        &mut self,
        key: ImportKey,
        path: PathBuf,
        hash: Option<&HashExpectation>,
    ) -> RuliaResult<PreparedImport> {
        if self.stack.contains(&key) {
            return Err(RuliaError::ImportCycle(key.display()));
        }
        self.stack.push(key.clone());
        let result = (|| {
            let metadata = fs::metadata(&path)?;
            let bytes = fs::read(&path)?;
            let digest = self.verify_hash(hash, &path, &metadata, &bytes)?;
            let content = String::from_utf8(bytes)
                .map_err(|_| RuliaError::Parse("import is not valid utf-8".into()))?;
            let base_dir = path.parent().map(|p| p.to_path_buf());
            Ok(PreparedImport {
                key,
                base_dir,
                content,
                digest,
            })
        })();
        if result.is_err() {
            self.stack.pop();
        }
        result
    }

    fn prepare_resolved(
        &mut self,
        key: ImportKey,
        current_dir: Option<&Path>,
        requested_path: &str,
        resolved: ResolvedImport,
        hash: Option<&HashExpectation>,
    ) -> RuliaResult<PreparedImport> {
        if self.stack.contains(&key) {
            return Err(RuliaError::ImportCycle(key.display()));
        }
        self.stack.push(key.clone());
        let result = (|| {
            let bytes = resolved.contents.as_bytes();
            let digest = self.verify_hash_bytes(hash, bytes)?;
            let base_dir = Self::virtual_base_dir(current_dir, requested_path);
            Ok(PreparedImport {
                key,
                base_dir,
                content: resolved.contents,
                digest,
            })
        })();
        if result.is_err() {
            self.stack.pop();
        }
        result
    }

    fn virtual_base_dir(current_dir: Option<&Path>, path: &str) -> Option<PathBuf> {
        let raw = Path::new(path);
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else if let Some(base) = current_dir {
            base.join(raw)
        } else {
            PathBuf::from(raw)
        };
        joined.parent().map(|p| p.to_path_buf())
    }

    fn verify_hash(
        &mut self,
        expectation: Option<&HashExpectation>,
        path: &Path,
        metadata: &fs::Metadata,
        bytes: &[u8],
    ) -> RuliaResult<Option<[u8; 32]>> {
        let modified = metadata.modified().ok();
        let len = metadata.len();
        if let Some(expect) = expectation {
            if let Some(cached) = self.load_cached_digest(path, expect.algorithm, modified, len)? {
                let expected_bytes = hex::decode(&expect.value)
                    .map_err(|_| RuliaError::InvalidHash("sha256".into()))?;
                if expected_bytes.as_slice() != cached.as_slice() {
                    return Err(RuliaError::HashMismatch {
                        expected: expect.value.clone(),
                        actual: hex::encode(cached),
                    });
                }
                return Ok(Some(cached));
            }
        }

        let algorithm = expectation
            .map(|e| e.algorithm)
            .unwrap_or(HashAlgorithm::Sha256);
        let digest_vec = algorithm.compute(bytes);
        if digest_vec.len() != 32 {
            return Err(RuliaError::InvalidHash("unsupported digest length".into()));
        }
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(&digest_vec);
        if let Some(expect) = expectation {
            let expected_bytes =
                hex::decode(&expect.value).map_err(|_| RuliaError::InvalidHash("sha256".into()))?;
            if expected_bytes.as_slice() != digest_arr.as_slice() {
                return Err(RuliaError::HashMismatch {
                    expected: expect.value.clone(),
                    actual: hex::encode(digest_arr),
                });
            }
        }
        self.store_digest(path, algorithm, modified, len, digest_arr);
        Ok(Some(digest_arr))
    }

    fn verify_hash_bytes(
        &mut self,
        expectation: Option<&HashExpectation>,
        bytes: &[u8],
    ) -> RuliaResult<Option<[u8; 32]>> {
        let algorithm = expectation
            .map(|e| e.algorithm)
            .unwrap_or(HashAlgorithm::Sha256);
        let digest_vec = algorithm.compute(bytes);
        if digest_vec.len() != 32 {
            return Err(RuliaError::InvalidHash("unsupported digest length".into()));
        }
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(&digest_vec);
        if let Some(expect) = expectation {
            let expected_bytes =
                hex::decode(&expect.value).map_err(|_| RuliaError::InvalidHash("sha256".into()))?;
            if expected_bytes.as_slice() != digest_arr.as_slice() {
                return Err(RuliaError::HashMismatch {
                    expected: expect.value.clone(),
                    actual: hex::encode(digest_arr),
                });
            }
        }
        Ok(Some(digest_arr))
    }

    fn load_cached_digest(
        &mut self,
        path: &Path,
        algorithm: HashAlgorithm,
        modified: Option<SystemTime>,
        len: u64,
    ) -> RuliaResult<Option<[u8; 32]>> {
        let key = (path.to_path_buf(), algorithm);
        if let Some(entry) = self.digest_cache.get(&key) {
            if entry.len == len && entry.modified == modified {
                return Ok(Some(entry.digest));
            }
        }
        let Some(dir) = &self.cache_dir else {
            return Ok(None);
        };
        let cache_path = dir.join(digest_cache_key(path, algorithm));
        let data = match fs::read_to_string(&cache_path) {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };
        let mut parts = data.split(':');
        let len_str = parts.next().unwrap_or("0");
        let mtime_str = parts.next().unwrap_or("0");
        let digest_hex = parts.next().unwrap_or("").trim();
        let cached_len: u64 = len_str.parse().unwrap_or(0);
        let cached_mtime = mtime_str.parse::<u128>().ok().and_then(|nanos| {
            if nanos > u128::from(u64::MAX) {
                None
            } else {
                UNIX_EPOCH.checked_add(std::time::Duration::from_nanos(nanos as u64))
            }
        });
        if cached_len != len || cached_mtime != modified {
            let _ = fs::remove_file(&cache_path);
            return Ok(None);
        }
        let digest_vec = match hex::decode(digest_hex) {
            Ok(vec) => vec,
            Err(_) => return Ok(None),
        };
        if digest_vec.len() != 32 {
            let _ = fs::remove_file(&cache_path);
            return Ok(None);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_vec);
        self.digest_cache.insert(
            key,
            CachedDigest {
                digest,
                len,
                modified,
            },
        );
        Ok(Some(digest))
    }

    fn store_digest(
        &mut self,
        path: &Path,
        algorithm: HashAlgorithm,
        modified: Option<SystemTime>,
        len: u64,
        digest: [u8; 32],
    ) {
        self.digest_cache.insert(
            (path.to_path_buf(), algorithm),
            CachedDigest {
                digest,
                len,
                modified,
            },
        );
        if let Some(dir) = &self.cache_dir {
            let cache_path = dir.join(digest_cache_key(path, algorithm));
            let mtime = modified
                .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
                .map(|dur| dur.as_nanos())
                .unwrap_or(0);
            let _ = fs::create_dir_all(dir);
            let _ = fs::write(
                cache_path,
                format!("{}:{}:{}", len, mtime, hex::encode(digest)),
            );
        }
    }

    fn complete_success(&mut self, key: &ImportKey, value: Value) {
        self.cache.insert(key.clone(), value);
        self.pop_key(key);
    }

    fn complete_failure(&mut self, key: &ImportKey) {
        self.pop_key(key);
    }

    fn pop_key(&mut self, key: &ImportKey) {
        if let Some(last) = self.stack.pop() {
            if last != *key {
                self.stack.clear();
            }
        }
    }
}

fn builtin_merge(args: Vec<RuntimeValue>) -> RuliaResult<RuntimeValue> {
    if args.is_empty() {
        return Err(RuliaError::Evaluation(
            "merge requires at least one argument".into(),
        ));
    }
    let mut entries: Vec<(Value, Value)> = Vec::new();
    let mut index: HashMap<Value, usize> = HashMap::new();
    for arg in args {
        let value = arg.into_value()?;
        let Value::Map(pairs) = value else {
            return Err(RuliaError::Evaluation("merge expects map arguments".into()));
        };
        for (key, value) in pairs {
            if let Some(idx) = index.get(&key).copied() {
                entries[idx].1 = value;
            } else {
                index.insert(key.clone(), entries.len());
                entries.push((key, value));
            }
        }
    }
    Ok(RuntimeValue::Data(Value::Map(entries)))
}

fn builtin_get(args: Vec<RuntimeValue>) -> RuliaResult<RuntimeValue> {
    if args.len() != 2 {
        return Err(RuliaError::Evaluation(
            "get requires exactly 2 arguments".into(),
        ));
    }
    let collection = args[0].clone().into_value()?;
    let index = args[1].clone().into_value()?;

    match (collection, index) {
        (Value::Vector(items), Value::Int(i)) => {
            let idx = if i < 0 {
                // Negative indexing from end
                items.len().checked_sub((-i) as usize)
            } else {
                Some(i as usize)
            };
            match idx {
                Some(i) if i < items.len() => Ok(RuntimeValue::Data(items[i].clone())),
                _ => Err(RuliaError::Evaluation(format!("index {} out of bounds", i))),
            }
        }
        (Value::Map(entries), key) => {
            for (k, v) in entries {
                if k == key {
                    return Ok(RuntimeValue::Data(v));
                }
            }
            Err(RuliaError::Evaluation("key not found in map".into()))
        }
        _ => Err(RuliaError::Evaluation(
            "get expects vector with int index or map with key".into(),
        )),
    }
}

fn builtin_concat(args: Vec<RuntimeValue>) -> RuliaResult<RuntimeValue> {
    let mut result = String::new();
    for arg in args {
        let value = arg.into_value()?;
        match value {
            Value::String(s) => result.push_str(&s),
            Value::Int(n) => result.push_str(&n.to_string()),
            Value::UInt(n) => result.push_str(&n.to_string()),
            Value::Float64(f) => result.push_str(&f.to_string()),
            Value::Float32(f) => result.push_str(&f.to_string()),
            Value::Bool(b) => result.push_str(if b { "true" } else { "false" }),
            Value::Nil => result.push_str("nil"),
            other => {
                // For complex types, use the text serialization
                let mut buf = String::new();
                write_value(&other, &mut buf).map_err(|e| {
                    RuliaError::Evaluation(format!("failed to convert value to string: {e}"))
                })?;
                result.push_str(&buf);
            }
        }
    }
    Ok(RuntimeValue::Data(Value::String(result)))
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    active_namespace: Option<String>,
    options: ParseOptions,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str, options: ParseOptions) -> Self {
        Self {
            input,
            pos: 0,
            active_namespace: None,
            options,
        }
    }

    fn parse_expression(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();
        if self.consume_keyword("let") {
            return self.parse_let();
        }
        if self.consume_keyword("fn") {
            return self.parse_function();
        }
        if self.consume_keyword("import") {
            return self.parse_import();
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();
        let Some(ch) = self.peek() else {
            return Err(RuliaError::Parse("unexpected EOF".into()));
        };
        match ch {
            '[' => self.parse_vector(),
            '(' => self.parse_paren_expr(),
            '"' => {
                // Check for triple-quoted string or docstring
                if self.lookahead("\"\"\"") {
                    let string_val = self.parse_triple_string()?;
                    if self.can_start_docstring_target() {
                        let inner_expr = self.parse_expression()?;
                        let doc_key = Expr::Literal(Value::Keyword(Keyword::simple("doc")));
                        let doc_val = Expr::Literal(Value::String(string_val));
                        return Ok(Expr::Annotated {
                            metadata: vec![(doc_key, doc_val)],
                            value: Box::new(inner_expr),
                        });
                    }
                    // Just a regular string (no interpolation in triple-quoted for now)
                    return Ok(Expr::Literal(Value::String(string_val)));
                }

                // Regular string with interpolation support
                let string_expr = self.parse_interpolated_string()?;

                // Check if this is a docstring (only if it's a simple literal)
                if let Expr::Literal(Value::String(ref string_val)) = string_expr {
                    if self.can_start_docstring_target() {
                        let inner_expr = self.parse_expression()?;
                        let doc_key = Expr::Literal(Value::Keyword(Keyword::simple("doc")));
                        let doc_val = Expr::Literal(Value::String(string_val.clone()));
                        return Ok(Expr::Annotated {
                            metadata: vec![(doc_key, doc_val)],
                            value: Box::new(inner_expr),
                        });
                    }
                }

                Ok(string_expr)
            }
            ':' => Ok(Expr::Literal(Value::Keyword(self.parse_keyword()?))),
            '0' => {
                if self.lookahead("0x[") {
                    Ok(Expr::Literal(Value::Bytes(self.parse_bytes()?)))
                } else {
                    self.parse_number_or_identifier()
                }
            }
            '-' | '+' | '1'..='9' => self.parse_number_or_identifier(),
            '@' => {
                self.bump(); // consume '@'
                             // Check for @meta metadata macro
                if self.lookahead("meta") {
                    let start = self.pos;
                    if let Ok(ident) = self.parse_identifier() {
                        if ident == "meta" {
                            return self.parse_meta_decorator();
                        }
                    }
                    self.pos = start;
                }
                // Check for @new immediate generation macro
                if self.lookahead("new") {
                    let start = self.pos;
                    if let Ok(ident) = self.parse_identifier() {
                        if ident == "new" {
                            return self.parse_new_macro();
                        }
                    }
                    self.pos = start;
                }
                // Check for @ns namespace macro
                if self.lookahead("ns") && !self.lookahead("ns_") {
                    // Verify it's exactly "ns" followed by whitespace
                    let start = self.pos;
                    if let Ok(ident) = self.parse_identifier() {
                        if ident == "ns" {
                            return self.parse_ns_macro();
                        }
                    }
                    self.pos = start;
                }
                // @?var syntax for logic variables
                if self.peek() == Some('?') {
                    let token = self.parse_symbol_token()?;
                    Ok(Expr::Literal(Value::Symbol(Symbol::parse(&token))))
                } else {
                    Err(RuliaError::Parse(
                        "expected '?' after '@' or valid macro name".into(),
                    ))
                }
            }
            // Wildcard symbol for "don't care" pattern matching
            '_' => {
                self.bump();
                // Check if it's a standalone underscore (not part of identifier)
                if self.peek().is_none_or(|ch| !is_identifier_part(ch)) {
                    Ok(Expr::Literal(Value::Symbol(Symbol::simple("_"))))
                } else {
                    // It's part of an identifier like _foo, parse the rest
                    let rest = self.parse_identifier()?;
                    let full_ident = format!("_{}", rest);
                    Ok(Expr::Identifier(full_ident))
                }
            }
            '\'' => {
                self.bump();
                let token = self.parse_symbol_token()?;
                Ok(Expr::Literal(Value::Symbol(Symbol::parse(&token))))
            }
            '>' | '<' | '!' => {
                // Comparison operators and predicates: parse as symbols
                let token = self.parse_symbol_token()?;
                Ok(Expr::Literal(Value::Symbol(Symbol::parse(&token))))
            }
            _ => {
                if is_identifier_start(ch) {
                    let ident = self.parse_identifier()?;
                    // Special case for boolean literals
                    if ident == "true" {
                        return Ok(Expr::Literal(Value::Bool(true)));
                    } else if ident == "false" {
                        return Ok(Expr::Literal(Value::Bool(false)));
                    } else if ident == "nil" {
                        return Ok(Expr::Literal(Value::Nil));
                    }
                    // Check if this is a constructor or function call: Identifier(...)
                    self.skip_ws();
                    if self.peek() == Some('(') {
                        // PascalCase identifiers are constructors
                        if ident.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                            return self.parse_constructor_call(ident);
                        }
                        // lowercase identifiers are regular function calls
                        return self.parse_function_call(ident);
                    }
                    // Special case for aggregate/predicate functions in Datalog
                    if matches!(
                        ident.as_str(),
                        "count" | "sum" | "min" | "max" | "avg" | "distinct"
                    ) {
                        return Ok(Expr::Literal(Value::Symbol(Symbol::simple(&ident))));
                    }
                    Ok(Expr::Identifier(ident))
                } else {
                    Err(RuliaError::Parse(format!("unexpected character '{ch}'")))
                }
            }
        }
    }

    /// Parse a regular function call like get(items, 0) or concat("a", "b")
    fn parse_function_call(&mut self, name: String) -> RuliaResult<Expr> {
        self.expect('(')?;
        let mut args = Vec::new();

        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                self.bump();
                break;
            }
            // Skip comma if present (after first argument)
            if !args.is_empty() && self.peek() == Some(',') {
                self.bump();
                self.skip_ws();
                // Handle trailing comma
                if self.peek() == Some(')') {
                    self.bump();
                    break;
                }
            }
            let arg = self.parse_expression()?;
            args.push(arg);
        }

        Ok(Expr::Call {
            function: Box::new(Expr::Identifier(name)),
            args,
        })
    }

    /// Parse a constructor call like Set([1, 2, 3]) or UUID("...")
    ///
    /// Special constructors:
    /// - Set([...]) -> Value::Set
    /// - Keyword("ns/name") -> Value::Keyword (explicit form)
    /// - Symbol("ns/name") -> Value::Symbol (explicit form)
    /// - Tagged("ns/name", value) -> Value::Tagged (explicit form)
    /// - Ref(id) -> Value::Tagged(Symbol("ref"), id) (ID reference)
    /// - Ref(attr, val) -> Value::Tagged(Symbol("ref"), Vector([attr, val])) (lookup ref)
    /// - Other(value) -> Value::Tagged with PascalCase->snake_case conversion
    /// - PascalCase(key=val, ...) -> Value::Tagged with inner map
    fn parse_constructor_call(&mut self, name: String) -> RuliaResult<Expr> {
        self.expect('(')?;
        self.skip_ws();

        // Handle empty constructor
        if self.peek() == Some(')') {
            self.bump();
            // Empty Set
            if name == "Set" {
                return Ok(Expr::Set(Vec::new()));
            }
            // Empty tagged value with empty map
            let tag = symbol_from_pascal_case(&name);
            return Ok(Expr::Tagged(tag, Box::new(Expr::Map(Vec::new()))));
        }

        // Check if this looks like map-style arguments (key = value).
        let start_pos = self.pos;
        if self.looks_like_map_entry() {
            if name == "Instant" {
                return Err(RuliaError::Parse(
                    "Instant() expects a string argument".into(),
                ));
            }
            // This is map-style: reset and parse as map entries
            self.pos = start_pos;
            let map_expr = self.parse_map_entries()?;
            // For non-special constructors, wrap the map in a tagged value
            if name == "Set" {
                return Err(RuliaError::Parse(
                    "Set() expects a vector argument, not key=value syntax".into(),
                ));
            }
            let tag = symbol_from_pascal_case(&name);
            return Ok(Expr::Tagged(tag, Box::new(map_expr)));
        }

        // Parse the first argument as a regular expression
        let arg = self.parse_expression()?;
        self.skip_ws();

        // Special handling for explicit Keyword("ns/name")
        if name == "Keyword" {
            self.expect(')')?;
            if let Expr::Literal(Value::String(s)) = arg {
                return Ok(Expr::Literal(Value::Keyword(Keyword::parse(&s))));
            } else {
                return Err(RuliaError::Parse(
                    "Keyword() expects a string argument".into(),
                ));
            }
        }

        // Special handling for explicit Symbol("ns/name")
        if name == "Symbol" {
            self.expect(')')?;
            if let Expr::Literal(Value::String(s)) = arg {
                return Ok(Expr::Literal(Value::Symbol(Symbol::parse(&s))));
            } else {
                return Err(RuliaError::Parse(
                    "Symbol() expects a string argument".into(),
                ));
            }
        }

        // Special handling for explicit Tagged("ns/name", value)
        if name == "Tagged" {
            if let Expr::Literal(Value::String(tag_str)) = arg {
                // Expect comma and second argument
                if self.peek() == Some(',') {
                    self.bump();
                    self.skip_ws();
                    let value_arg = self.parse_expression()?;
                    self.skip_ws();
                    self.expect(')')?;
                    let tag = Symbol::parse(&tag_str);
                    return Ok(Expr::Tagged(tag, Box::new(value_arg)));
                } else {
                    return Err(RuliaError::Parse(
                        "Tagged() expects two arguments: tag string and value".into(),
                    ));
                }
            } else {
                return Err(RuliaError::Parse(
                    "Tagged() first argument must be a string".into(),
                ));
            }
        }

        // Special handling for Ref(...) - Graph References
        // Ref(id) -> Tagged(Symbol("ref"), id)
        // Ref(attr, value) -> Tagged(Symbol("ref"), Vector([attr, value]))
        if name == "Ref" {
            let ref_tag = Symbol::simple("ref");
            // Check for additional arguments
            if self.peek() == Some(',') {
                // Multiple arguments - collect into vector
                let mut args = vec![arg];
                while self.peek() == Some(',') {
                    self.bump();
                    self.skip_ws();
                    if self.peek() == Some(')') {
                        break;
                    }
                    args.push(self.parse_expression()?);
                    self.skip_ws();
                }
                self.expect(')')?;
                return Ok(Expr::Tagged(ref_tag, Box::new(Expr::Vector(args))));
            } else {
                // Single argument - wrap directly
                self.expect(')')?;
                return Ok(Expr::Tagged(ref_tag, Box::new(arg)));
            }
        }

        self.expect(')')?;

        // Special handling for UUID constructor
        // UUID("550e8400-e29b-41d4-a716-446655440000") -> Tagged(Symbol("uuid"), Bytes([16 bytes]))
        if name == "UUID" {
            if let Expr::Literal(Value::String(s)) = arg {
                let uuid = Uuid::parse_str(&s)
                    .map_err(|_| RuliaError::Parse("UUID() expects a valid UUID string".into()))?;
                let uuid_tag = Symbol::simple("uuid");
                return Ok(Expr::Tagged(
                    uuid_tag,
                    Box::new(Expr::Literal(Value::Bytes(uuid.as_bytes().to_vec()))),
                ));
            } else {
                return Err(RuliaError::Parse("UUID() expects a string argument".into()));
            }
        }

        // Special handling for Set constructor
        if name == "Set" {
            // Set([...]) - the argument should be a vector
            if let Expr::Vector(items) = arg {
                return Ok(Expr::Set(items));
            } else if let Expr::Literal(Value::Vector(items)) = arg {
                return Ok(Expr::Set(items.into_iter().map(Expr::Literal).collect()));
            } else {
                return Err(RuliaError::Parse("Set() expects a vector argument".into()));
            }
        }

        // Special handling for ULID constructor
        // ULID("01ARZ3NDEKTSV4RRFFQ69G5FAV") -> Tagged(Symbol("ulid"), String("..."))
        if name == "ULID" {
            if let Expr::Literal(Value::String(s)) = arg {
                // Validate ULID format: 26 characters, Crockford Base32
                if s.len() != 26 {
                    return Err(RuliaError::Parse(format!(
                        "ULID must be 26 characters, got {}",
                        s.len()
                    )));
                }
                // Validate charset (Crockford Base32: 0-9, A-Z excluding I, L, O, U)
                let valid_chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
                for ch in s.to_uppercase().chars() {
                    if !valid_chars.contains(ch) {
                        return Err(RuliaError::Parse(format!(
                            "ULID contains invalid character: '{}'",
                            ch
                        )));
                    }
                }
                let ulid_tag = Symbol::simple("ulid");
                return Ok(Expr::Tagged(
                    ulid_tag,
                    Box::new(Expr::Literal(Value::String(s))),
                ));
            } else {
                return Err(RuliaError::Parse("ULID() expects a string argument".into()));
            }
        }

        // Special handling for Instant constructor
        // Instant("2025-01-01T00:00:00Z") -> Tagged(Symbol("instant"), String("..."))
        if name == "Instant" {
            if let Expr::Literal(Value::String(s)) = arg {
                validate_instant_canonical(&s)?;
                let instant_tag = symbol_from_pascal_case(&name);
                return Ok(Expr::Tagged(
                    instant_tag,
                    Box::new(Expr::Literal(Value::String(s))),
                ));
            } else {
                return Err(RuliaError::Parse(
                    "Instant() expects a string argument".into(),
                ));
            }
        }

        // Special handling for Generator constructor (deferred generation)
        // Generator(:uuid) -> Tagged(Symbol("generator"), Keyword("uuid"))
        if name == "Generator" {
            if let Expr::Literal(Value::Keyword(kw)) = arg {
                let gen_tag = Symbol::simple("generator");
                return Ok(Expr::Tagged(
                    gen_tag,
                    Box::new(Expr::Literal(Value::Keyword(kw))),
                ));
            } else {
                return Err(RuliaError::Parse(
                    "Generator() expects a keyword argument like :uuid, :ulid, or :now".into(),
                ));
            }
        }

        // For other constructors, treat as tagged value
        // Convert PascalCase name to snake_case with optional namespace
        let tag = symbol_from_pascal_case(&name);
        Ok(Expr::Tagged(tag, Box::new(arg)))
    }

    /// Parse the @ns namespace macro: `@ns identifier begin ... end`
    ///
    /// This temporarily sets the active namespace for parsing the inner expression,
    /// which causes simple keywords in maps to be prefixed with the namespace.
    ///
    /// Example:
    /// ```text
    /// @ns user begin
    ///     (id = 101, name = "Bob")
    /// end
    /// ```
    /// Produces: `(user_id = 101, user_name = "Bob")` which becomes `(:user/id = 101, :user/name = "Bob")`
    fn parse_ns_macro(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();

        // Parse the namespace identifier
        let namespace = self.parse_identifier()?;
        self.skip_ws();

        // Expect "begin" keyword
        if !self.consume_keyword("begin") {
            return Err(RuliaError::Parse(
                "expected 'begin' after @ns namespace".into(),
            ));
        }

        // Save the previous namespace (for nested scopes)
        let prev_namespace = self.active_namespace.take();

        // Set the new namespace
        self.active_namespace = Some(namespace);

        // Parse the inner expression
        let expr = self.parse_expression()?;
        self.skip_ws();

        // Expect "end" keyword
        if !self.consume_keyword("end") {
            // Restore namespace before returning error
            self.active_namespace = prev_namespace;
            return Err(RuliaError::Parse(
                "expected 'end' to close @ns block".into(),
            ));
        }

        // Restore the previous namespace
        self.active_namespace = prev_namespace;

        Ok(expr)
    }

    /// Parse the @meta decorator: `@meta(key = value, ...) inner_value`
    ///
    /// This attaches structured metadata to the following value.
    ///
    /// Example:
    /// ```text
    /// @meta(author = "admin", deprecated = true)
    /// User(id = 101)
    /// ```
    fn parse_meta_decorator(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();
        self.expect('(')?;

        // Parse metadata entries (key = value pairs)
        let mut metadata = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                self.bump();
                break;
            }

            // Skip comma if present
            if self.peek() == Some(',') {
                self.bump();
                self.skip_ws();
                if self.peek() == Some(')') {
                    self.bump();
                    break;
                }
            }

            // Parse key (same forms as map keys: identifier | keyword | string),
            // but metadata keys should not inherit @ns map-key namespacing.
            let saved_namespace = self.active_namespace.take();
            let parsed_key = self.parse_map_key();
            self.active_namespace = saved_namespace;
            let key = Expr::Literal(parsed_key?);

            self.skip_ws();
            self.expect('=')?;

            // Parse value
            let value = self.parse_expression()?;
            metadata.push((key, value));
        }

        self.skip_ws();

        // Parse the inner expression that this metadata applies to
        let inner_expr = self.parse_expression()?;

        // If inner is already annotated, merge the metadata
        if let Expr::Annotated {
            metadata: inner_meta,
            value,
        } = inner_expr
        {
            let mut combined = metadata;
            combined.extend(inner_meta);
            Ok(Expr::Annotated {
                metadata: combined,
                value,
            })
        } else {
            Ok(Expr::Annotated {
                metadata,
                value: Box::new(inner_expr),
            })
        }
    }

    fn can_start_docstring_target(&mut self) -> bool {
        self.skip_ws();
        let Some(ch) = self.peek() else {
            return false;
        };

        match ch {
            '[' | '(' | '"' | ':' | '0'..='9' | '-' | '+' | '@' | '_' | '\'' | '>' | '<' | '!' => {
                true
            }
            _ if is_identifier_start(ch) => {
                let start = self.pos;
                let ident = self.parse_identifier().ok();
                self.skip_ws();
                // Avoid capturing map-entry/binding starts like: key = value
                if self.peek() == Some('=') && !self.lookahead("==") {
                    self.pos = start;
                    return false;
                }
                self.pos = start;
                ident.is_some_and(|token| token != "end")
            }
            _ => false,
        }
    }

    /// Parse the @new immediate generation macro: `@new(:type)`
    ///
    /// Generates values at parse time for seeding data.
    ///
    /// Supported types:
    /// - `:uuid` -> Generate v4 UUID, return Tagged("uuid", bytes)
    /// - `:ulid` -> Generate ULID, return Tagged("ulid", string)
    /// - `:now` -> Generate UTC timestamp, return Tagged("inst", milliseconds)
    ///
    /// Example:
    /// ```text
    /// @new(:uuid)   # Generates a new UUID immediately
    /// @new(:ulid)   # Generates a new ULID immediately
    /// @new(:now)    # Generates current timestamp
    /// ```
    fn parse_new_macro(&mut self) -> RuliaResult<Expr> {
        if self.options.deterministic && self.options.new_provider.is_none() {
            return Err(RuliaError::DeterministicNewDisabled);
        }
        self.skip_ws();
        self.expect('(')?;
        self.skip_ws();

        // Parse the type keyword
        let type_kw = self.parse_keyword()?;
        self.skip_ws();
        self.expect(')')?;

        // Generate value based on type
        let value = if self.options.deterministic {
            let provider = self
                .options
                .new_provider
                .as_ref()
                .expect("deterministic provider checked");
            match type_kw.name() {
                "uuid" => {
                    let uuid_bytes = provider.new_uuid().to_vec();
                    Value::Tagged(TaggedValue::new(
                        Symbol::simple("uuid"),
                        Value::Bytes(uuid_bytes),
                    ))
                }
                "ulid" => Value::Tagged(TaggedValue::new(
                    Symbol::simple("ulid"),
                    Value::String(provider.new_ulid()),
                )),
                "now" => Value::Tagged(TaggedValue::new(
                    Symbol::simple("inst"),
                    Value::Int(provider.now_millis()),
                )),
                other => {
                    return Err(RuliaError::Parse(format!(
                        "@new expects :uuid, :ulid, or :now, got :{}",
                        other
                    )));
                }
            }
        } else {
            match type_kw.name() {
                "uuid" => {
                    // Generate v4 UUID and store as bytes
                    let uuid = Uuid::new_v4();
                    let uuid_bytes = uuid.as_bytes().to_vec();
                    Value::Tagged(TaggedValue::new(
                        Symbol::simple("uuid"),
                        Value::Bytes(uuid_bytes),
                    ))
                }
                "ulid" => {
                    // Generate ULID and store as canonical string
                    let ulid = Ulid::new();
                    Value::Tagged(TaggedValue::new(
                        Symbol::simple("ulid"),
                        Value::String(ulid.to_string()),
                    ))
                }
                "now" => {
                    // Generate current UTC timestamp in milliseconds
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("time went backwards")
                        .as_millis() as i64;
                    Value::Tagged(TaggedValue::new(Symbol::simple("inst"), Value::Int(now)))
                }
                other => {
                    return Err(RuliaError::Parse(format!(
                        "@new expects :uuid, :ulid, or :now, got :{}",
                        other
                    )));
                }
            }
        };

        Ok(Expr::Literal(value))
    }

    /// Parse a triple-quoted string: `"""content"""`
    ///
    /// Triple-quoted strings preserve newlines and don't require escaping.
    fn parse_triple_string(&mut self) -> RuliaResult<String> {
        self.expect('"')?;
        self.expect('"')?;
        self.expect('"')?;

        // Skip leading newline if present
        if self.peek() == Some('\n') {
            self.bump();
        } else if self.peek() == Some('\r') {
            self.bump();
            if self.peek() == Some('\n') {
                self.bump();
            }
        }

        let mut out = String::new();
        loop {
            // Check for closing """
            if self.lookahead("\"\"\"") {
                self.bump();
                self.bump();
                self.bump();
                // Remove trailing newline if present
                if out.ends_with('\n') {
                    out.pop();
                    if out.ends_with('\r') {
                        out.pop();
                    }
                }
                return Ok(out);
            }

            match self.bump() {
                Some(ch) => out.push(ch),
                None => {
                    return Err(RuliaError::Parse(
                        "unterminated triple-quoted string".into(),
                    ))
                }
            }
        }
    }

    /// Parse parenthesized expression - either a map (key=val, ...), infix expression, or a call expression
    ///
    /// Infix operators for logic: >, <, >=, <=, ==, !=
    /// These are desugared to prefix vectors: `(@?age >= 18)` -> `[>=, @?age, 18]`
    fn parse_paren_expr(&mut self) -> RuliaResult<Expr> {
        self.expect('(')?;
        self.skip_ws();

        // Empty parens
        if self.peek() == Some(')') {
            self.bump();
            return Ok(Expr::Map(Vec::new()));
        }

        if self.looks_like_map_entry() {
            return self.parse_map_entries();
        }

        // Parse the first expression (could be LHS of infix or function)
        let first = self.parse_expression()?;
        self.skip_ws();

        // Check for infix operators (for Datalog logic expressions)
        if let Some(op) = self.try_parse_infix_operator() {
            // This is an infix expression: (A op B) -> [op, A, B]
            self.skip_ws();
            let rhs = self.parse_expression()?;
            self.skip_ws();
            self.expect(')')?;

            // Return as vector [op, lhs, rhs]
            let op_symbol = Expr::Literal(Value::Symbol(Symbol::simple(&op)));
            return Ok(Expr::Vector(vec![op_symbol, first, rhs]));
        }

        // Parse as call expression (function args...)
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                self.bump();
                break;
            }
            // Skip comma if present
            if self.peek() == Some(',') {
                self.bump();
                self.skip_ws();
            }
            if self.peek() == Some(')') {
                self.bump();
                break;
            }
            let arg = self.parse_expression()?;
            args.push(arg);
        }
        Ok(Expr::Call {
            function: Box::new(first),
            args,
        })
    }

    /// Try to parse an infix comparison operator.
    /// Returns Some(operator_string) if found, None otherwise.
    fn try_parse_infix_operator(&mut self) -> Option<String> {
        // Check for two-character operators first
        if self.lookahead(">=") {
            self.bump();
            self.bump();
            return Some(">=".to_string());
        }
        if self.lookahead("<=") {
            self.bump();
            self.bump();
            return Some("<=".to_string());
        }
        if self.lookahead("==") {
            self.bump();
            self.bump();
            return Some("==".to_string());
        }
        if self.lookahead("!=") {
            self.bump();
            self.bump();
            return Some("!=".to_string());
        }
        // Single-character operators
        if self.peek() == Some('>') {
            self.bump();
            return Some(">".to_string());
        }
        if self.peek() == Some('<') {
            self.bump();
            return Some("<".to_string());
        }
        None
    }

    /// Look ahead to see if the next token sequence is a map entry (key = value).
    fn looks_like_map_entry(&mut self) -> bool {
        let start = self.pos;
        let mut is_map = false;

        if let Some(ch) = self.peek() {
            match ch {
                ':' => {
                    if self.parse_keyword().is_ok() {
                        self.skip_ws();
                        is_map = self.peek() == Some('=') && !self.lookahead("==");
                    }
                }
                '"' => {
                    if self.lookahead("\"\"\"") {
                        let _ = self.parse_triple_string();
                    } else {
                        let _ = self.parse_interpolated_string();
                    }
                    self.skip_ws();
                    is_map = self.peek() == Some('=') && !self.lookahead("==");
                }
                _ => {
                    if is_identifier_start(ch) {
                        if let Ok(ident) = self.parse_identifier() {
                            self.skip_ws();
                            if self.peek() == Some('=') && !self.lookahead("==") {
                                is_map = true;
                            } else if ident == "Keyword"
                                && self.peek() == Some('(')
                                && self.parse_constructor_call(ident).is_ok()
                            {
                                self.skip_ws();
                                is_map = self.peek() == Some('=') && !self.lookahead("==");
                            }
                        }
                    }
                }
            }
        }

        self.pos = start;
        is_map
    }

    fn parse_map_key(&mut self) -> RuliaResult<Value> {
        self.skip_ws();
        let Some(ch) = self.peek() else {
            return Err(RuliaError::Parse("expected map key".into()));
        };

        match ch {
            ':' => Ok(Value::Keyword(self.parse_keyword()?)),
            '"' => {
                if self.lookahead("\"\"\"") {
                    return Ok(Value::String(self.parse_triple_string()?));
                }
                let expr = self.parse_interpolated_string()?;
                match expr {
                    Expr::Literal(Value::String(s)) => Ok(Value::String(s)),
                    _ => Err(RuliaError::Parse(
                        "map string keys must be literal (no interpolation)".into(),
                    )),
                }
            }
            _ => {
                if !is_identifier_start(ch) {
                    return Err(RuliaError::Parse(
                        "map keys must be identifiers, keywords, or string literals".into(),
                    ));
                }
                let ident = self.parse_identifier()?;
                self.skip_ws();
                if ident == "Keyword" && self.peek() == Some('(') {
                    let expr = self.parse_constructor_call(ident)?;
                    if let Expr::Literal(Value::Keyword(kw)) = expr {
                        return Ok(Value::Keyword(kw));
                    }
                    return Err(RuliaError::Parse(
                        "Keyword() map keys must be literal keywords".into(),
                    ));
                }
                if self.peek() == Some('(') {
                    return Err(RuliaError::Parse(
                        "map keys must be identifiers, keywords, or string literals".into(),
                    ));
                }

                // Apply namespace if active and key is simple (no existing namespace via _)
                let keyword = if let Some(ref ns) = self.active_namespace {
                    // Only apply namespace if key doesn't already have one
                    if !ident.contains('_') {
                        Keyword::new(Some(ns.clone()), ident)
                    } else {
                        keyword_from_identifier(&ident)
                    }
                } else {
                    keyword_from_identifier(&ident)
                };
                Ok(Value::Keyword(keyword))
            }
        }
    }

    /// Parse map entries: key=val, key2=val2, ...
    /// If active_namespace is set, simple keys are prefixed with the namespace.
    fn parse_map_entries(&mut self) -> RuliaResult<Expr> {
        let mut entries = Vec::new();
        let mut seen_keys: HashSet<Value> = HashSet::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                self.bump();
                break;
            }

            // Skip comma if present
            if self.peek() == Some(',') {
                self.bump();
                self.skip_ws();
                if self.peek() == Some(')') {
                    self.bump();
                    break;
                }
            }

            let key_value = self.parse_map_key()?;
            if !seen_keys.insert(key_value.clone()) {
                let key_display = format_map_key_for_error(&key_value);
                return Err(RuliaError::DuplicateMapKeyLiteral(key_display));
            }
            let key = Expr::Literal(key_value);

            self.skip_ws();
            self.expect('=')?;

            // Parse value
            let value = self.parse_expression()?;
            entries.push((key, value));
        }
        Ok(Expr::Map(entries))
    }

    fn parse_let(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();
        let bindings = if self.peek() == Some('{') {
            self.bump();
            self.parse_let_bindings_block()?
        } else {
            self.parse_single_binding()?
        };
        let body = Box::new(self.parse_expression()?);
        Ok(Expr::Let { bindings, body })
    }

    /// Parse a single binding which can be either:
    /// - Simple: `name = expr`
    /// - Destructuring tuple: `(a, b) = expr`
    /// - Destructuring vector: `[a, b] = expr`
    fn parse_single_binding(&mut self) -> RuliaResult<Vec<(String, Expr)>> {
        self.skip_ws();
        match self.peek() {
            Some('(') => self.parse_destructuring_tuple(),
            Some('[') => self.parse_destructuring_vector(),
            _ => {
                let name = self.parse_identifier()?;
                self.skip_ws();
                self.expect('=')?;
                let value = self.parse_expression()?;
                Ok(vec![(name, value)])
            }
        }
    }

    /// Parse destructuring tuple pattern: `(a, b) = expr`
    /// Desugars to: temp = expr; a = get(temp, 0); b = get(temp, 1)
    fn parse_destructuring_tuple(&mut self) -> RuliaResult<Vec<(String, Expr)>> {
        self.expect('(')?;
        let names = self.parse_destructuring_names(')')?;
        self.skip_ws();
        self.expect('=')?;
        let value_expr = self.parse_expression()?;
        Ok(self.desugar_destructuring(names, value_expr))
    }

    /// Parse destructuring vector pattern: `[a, b] = expr`
    /// Desugars to: temp = expr; a = get(temp, 0); b = get(temp, 1)
    fn parse_destructuring_vector(&mut self) -> RuliaResult<Vec<(String, Expr)>> {
        self.expect('[')?;
        let names = self.parse_destructuring_names(']')?;
        self.skip_ws();
        self.expect('=')?;
        let value_expr = self.parse_expression()?;
        Ok(self.desugar_destructuring(names, value_expr))
    }

    /// Parse a list of identifiers separated by commas until end_char
    fn parse_destructuring_names(&mut self, end_char: char) -> RuliaResult<Vec<String>> {
        let mut names = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(end_char) {
                self.bump();
                break;
            }
            if !names.is_empty() {
                if self.peek() == Some(',') {
                    self.bump();
                    self.skip_ws();
                    // Handle trailing comma
                    if self.peek() == Some(end_char) {
                        self.bump();
                        break;
                    }
                } else {
                    return Err(RuliaError::Parse(
                        "expected ',' in destructuring pattern".into(),
                    ));
                }
            }
            let name = self.parse_identifier()?;
            names.push(name);
        }
        Ok(names)
    }

    /// Generate bindings for destructuring pattern
    fn desugar_destructuring(&self, names: Vec<String>, value_expr: Expr) -> Vec<(String, Expr)> {
        // Generate a unique temp variable name
        let temp_name = format!("__destructure_{}", self.pos);
        let mut bindings = Vec::with_capacity(names.len() + 1);

        // First binding: temp = expr
        bindings.push((temp_name.clone(), value_expr));

        // Subsequent bindings: name = get(temp, index)
        for (i, name) in names.into_iter().enumerate() {
            let get_call = Expr::Call {
                function: Box::new(Expr::Identifier("get".into())),
                args: vec![
                    Expr::Identifier(temp_name.clone()),
                    Expr::Literal(Value::Int(i as i64)),
                ],
            };
            bindings.push((name, get_call));
        }

        bindings
    }

    fn parse_let_bindings_block(&mut self) -> RuliaResult<Vec<(String, Expr)>> {
        let mut bindings = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some('}') {
                self.bump();
                break;
            }
            // Support destructuring in block bindings too
            let new_bindings = self.parse_single_binding()?;
            bindings.extend(new_bindings);
            self.skip_ws();
            if matches!(self.peek(), Some(';') | Some(',')) {
                self.bump();
            }
        }
        Ok(bindings)
    }

    fn parse_import(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();
        let path = self.parse_string()?;
        self.skip_ws();
        let hash = self.parse_hash_expectation()?;
        self.skip_ws();
        Ok(Expr::Import(ImportSpec { path, hash }))
    }

    fn parse_hash_expectation(&mut self) -> RuliaResult<Option<HashExpectation>> {
        self.skip_ws();
        let start = self.pos;
        let mut ident = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() {
                ident.push(ch.to_ascii_lowercase());
                self.bump();
            } else {
                break;
            }
        }
        if ident.is_empty() {
            self.pos = start;
            return Ok(None);
        }
        if self.peek() != Some(':') {
            self.pos = start;
            return Ok(None);
        }
        self.bump();
        let Some(algorithm) = HashAlgorithm::from_prefix(&ident) else {
            return Err(RuliaError::InvalidHash(format!(
                "unsupported hash algorithm '{ident}'",
            )));
        };
        let mut hex_value = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_hexdigit() {
                hex_value.push(ch.to_ascii_lowercase());
                self.bump();
            } else {
                break;
            }
        }
        let expected_len = algorithm.digest_len() * 2;
        if hex_value.len() != expected_len {
            return Err(RuliaError::InvalidHash(format!(
                "{} hash must have {} hex digits, found {}",
                algorithm.as_str(),
                expected_len,
                hex_value.len()
            )));
        }
        if hex::decode(&hex_value).is_err() {
            return Err(RuliaError::InvalidHash(algorithm.as_str().into()));
        }
        Ok(Some(HashExpectation {
            algorithm,
            value: hex_value,
        }))
    }

    fn parse_function(&mut self) -> RuliaResult<Expr> {
        self.skip_ws();
        self.expect('(')?;
        let mut params = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                self.bump();
                break;
            }
            let name = self.parse_identifier()?;
            params.push(name);
            self.skip_ws();
            if self.peek() == Some(',') {
                self.bump();
            }
        }
        self.skip_ws();
        self.expect('=')?;
        self.expect('>')?;
        let body = Box::new(self.parse_expression()?);
        Ok(Expr::Function { params, body })
    }

    fn parse_vector(&mut self) -> RuliaResult<Expr> {
        self.expect('[')?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(']') {
                self.bump();
                break;
            }
            items.push(self.parse_expression()?);
            self.skip_ws();
            // Require comma or closing bracket
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {} // will be handled at top of loop
                Some(ch) => {
                    return Err(RuliaError::Parse(format!(
                        "expected ',' or ']' in vector, found '{ch}'"
                    )));
                }
                None => {
                    return Err(RuliaError::Parse("unterminated vector".into()));
                }
            }
        }
        Ok(Expr::Vector(items))
    }

    fn parse_string(&mut self) -> RuliaResult<String> {
        self.expect('"')?;
        let mut out = String::new();
        while let Some(ch) = self.bump() {
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let escape = self
                        .bump()
                        .ok_or_else(|| RuliaError::Parse("unterminated escape".into()))?;
                    let resolved = match escape {
                        '"' => '"',
                        '\\' => '\\',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '$' => '$', // Allow escaping $ to prevent interpolation
                        other => {
                            return Err(RuliaError::Parse(format!("unsupported escape \\{other}")))
                        }
                    };
                    out.push(resolved);
                }
                other => out.push(other),
            }
        }
        Err(RuliaError::Parse("unterminated string".into()))
    }

    /// Parse a string with interpolation support.
    /// - `$identifier` is replaced with the value of that identifier
    /// - `$(expr)` is replaced with the evaluated expression
    ///   Returns an Expr that is either a literal string or a concat call.
    fn parse_interpolated_string(&mut self) -> RuliaResult<Expr> {
        self.expect('"')?;

        enum Segment {
            Literal(String),
            Interpolation(Expr),
        }

        let mut segments: Vec<Segment> = Vec::new();
        let mut current_literal = String::new();

        while let Some(ch) = self.bump() {
            match ch {
                '"' => {
                    // End of string
                    if !current_literal.is_empty() {
                        segments.push(Segment::Literal(current_literal));
                    }

                    // If no interpolation occurred, return a simple string literal
                    if segments.is_empty() {
                        return Ok(Expr::Literal(Value::String(String::new())));
                    }

                    // Check if it's just a single literal (no interpolation)
                    if segments.len() == 1 {
                        if let Segment::Literal(s) = segments.remove(0) {
                            return Ok(Expr::Literal(Value::String(s)));
                        }
                    }

                    // Build concat call from segments
                    let args: Vec<Expr> = segments
                        .into_iter()
                        .map(|seg| match seg {
                            Segment::Literal(s) => Expr::Literal(Value::String(s)),
                            Segment::Interpolation(e) => e,
                        })
                        .collect();

                    return Ok(Expr::Call {
                        function: Box::new(Expr::Identifier("concat".into())),
                        args,
                    });
                }
                '\\' => {
                    let escape = self
                        .bump()
                        .ok_or_else(|| RuliaError::Parse("unterminated escape".into()))?;
                    let resolved = match escape {
                        '"' => '"',
                        '\\' => '\\',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '$' => '$', // Escape $ to prevent interpolation
                        other => {
                            return Err(RuliaError::Parse(format!("unsupported escape \\{other}")))
                        }
                    };
                    current_literal.push(resolved);
                }
                '$' => {
                    // Start of interpolation
                    let next = self.peek();
                    if next == Some('(') {
                        // Expression interpolation: $(expr)
                        if !current_literal.is_empty() {
                            segments.push(Segment::Literal(std::mem::take(&mut current_literal)));
                        }
                        self.bump(); // consume '('
                        let expr = self.parse_expression()?;
                        self.skip_ws();
                        self.expect(')')?;
                        segments.push(Segment::Interpolation(expr));
                    } else if next
                        .map(|c| c.is_ascii_alphabetic() || c == '_')
                        .unwrap_or(false)
                    {
                        // Variable interpolation: $identifier
                        if !current_literal.is_empty() {
                            segments.push(Segment::Literal(std::mem::take(&mut current_literal)));
                        }
                        // Parse identifier (simple variable name)
                        let mut ident = String::new();
                        while let Some(c) = self.peek() {
                            if c.is_ascii_alphanumeric() || c == '_' {
                                ident.push(c);
                                self.bump();
                            } else {
                                break;
                            }
                        }
                        segments.push(Segment::Interpolation(Expr::Identifier(ident)));
                    } else {
                        // Just a literal $
                        current_literal.push('$');
                    }
                }
                other => current_literal.push(other),
            }
        }
        Err(RuliaError::Parse("unterminated string".into()))
    }

    fn parse_keyword(&mut self) -> RuliaResult<Keyword> {
        self.expect(':')?;
        let token = self.parse_symbol_token()?;
        // Use underscore-to-namespace rule: user_name -> :user/name
        Ok(keyword_from_identifier(&token))
    }

    fn parse_bytes(&mut self) -> RuliaResult<Vec<u8>> {
        self.expect('0')?;
        self.expect('x')?;
        self.expect('[')?;
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(']') {
                self.bump();
                break;
            }
            let high = self
                .bump()
                .ok_or_else(|| RuliaError::Parse("unterminated bytes".into()))?;
            let low = self
                .bump()
                .ok_or_else(|| RuliaError::Parse("unterminated bytes".into()))?;
            let byte = parse_hex_pair(high, low)?;
            out.push(byte);
        }
        Ok(out)
    }

    fn parse_number_or_identifier(&mut self) -> RuliaResult<Expr> {
        let start = self.pos;
        if matches!(self.peek(), Some('-' | '+')) {
            self.bump();
        }
        let mut is_float = false;
        while let Some(ch) = self.peek() {
            match ch {
                '0'..='9' => {
                    self.bump();
                }
                '.' | 'e' | 'E' => {
                    is_float = true;
                    self.bump();
                }
                _ => break,
            }
        }
        let mut suffix = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphabetic() {
                suffix.push(ch);
                self.bump();
            } else {
                break;
            }
        }
        let literal_end = self.pos - suffix.len();
        let literal = &self.input[start..literal_end];
        if !suffix.is_empty() && literal.is_empty() {
            self.pos = start;
            return Ok(Expr::Identifier(self.parse_identifier()?));
        }
        if suffix == "N" {
            let bigint = BigInt::parse_bytes(literal.as_bytes(), 10)
                .ok_or_else(|| RuliaError::Parse("invalid bigint".into()))?;
            return Ok(Expr::Literal(Value::BigInt(bigint)));
        }
        if suffix == "u" {
            let value = literal
                .parse::<u64>()
                .map_err(|_| RuliaError::Parse("invalid unsigned integer".into()))?;
            return Ok(Expr::Literal(Value::UInt(value)));
        }
        if suffix == "f" {
            let value = literal
                .parse::<f32>()
                .map_err(|_| RuliaError::Parse("invalid float".into()))?;
            return Ok(Expr::Literal(Value::Float32(OrderedFloat(value))));
        }
        if is_float {
            let value = literal
                .parse::<f64>()
                .map_err(|_| RuliaError::Parse("invalid float".into()))?;
            return Ok(Expr::Literal(Value::Float64(OrderedFloat(value))));
        }
        if !literal.is_empty() {
            if let Ok(int) = literal.parse::<i64>() {
                return Ok(Expr::Literal(Value::Int(int)));
            }
            if let Some(bigint) = BigInt::parse_bytes(literal.as_bytes(), 10) {
                return Ok(Expr::Literal(Value::BigInt(bigint)));
            }
        }
        self.pos = start;
        let ident = self.parse_identifier()?;
        Ok(Expr::Identifier(ident))
    }

    fn parse_identifier(&mut self) -> RuliaResult<String> {
        self.skip_ws();
        let Some(ch) = self.peek() else {
            return Err(RuliaError::Parse("expected identifier".into()));
        };
        if !is_identifier_start(ch) {
            return Err(RuliaError::Parse("expected identifier".into()));
        }
        let mut token = String::new();
        while let Some(ch) = self.peek() {
            if token.is_empty() {
                if !is_identifier_start(ch) {
                    break;
                }
            } else if !is_identifier_part(ch) {
                break;
            }
            token.push(ch);
            self.bump();
        }
        if token.is_empty() {
            return Err(RuliaError::Parse("expected identifier".into()));
        }
        Ok(token)
    }

    fn parse_symbol_token(&mut self) -> RuliaResult<String> {
        self.skip_ws();
        let mut token = String::new();
        while let Some(ch) = self.peek() {
            if token.is_empty() {
                if !is_symbol_start(ch) {
                    break;
                }
            } else if !is_symbol_part(ch) {
                break;
            }
            token.push(ch);
            self.bump();
        }
        if token.is_empty() {
            Err(RuliaError::Parse("expected symbol".into()))
        } else {
            Ok(token)
        }
    }

    fn skip_ws(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\n' | '\r' | '\t') => {
                    self.bump();
                }
                Some('#') => {
                    // # starts a line comment in the new syntax
                    while let Some(ch) = self.bump() {
                        if ch == '\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn lookahead(&self, prefix: &str) -> bool {
        self.input[self.pos..].starts_with(prefix)
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.input[self.pos..].starts_with(keyword) {
            let next = self.input[self.pos + keyword.len()..].chars().next();
            if next.is_none_or(|ch| !is_identifier_part(ch)) {
                self.pos += keyword.len();
                return true;
            }
        }
        false
    }

    fn expect(&mut self, ch: char) -> RuliaResult<()> {
        match self.bump() {
            Some(actual) if actual == ch => Ok(()),
            Some(actual) => Err(RuliaError::Parse(format!(
                "expected '{ch}', found '{actual}'"
            ))),
            None => Err(RuliaError::Parse(format!("expected '{ch}', found EOF"))),
        }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }
}

fn parse_hex_pair(high: char, low: char) -> RuliaResult<u8> {
    let high = high
        .to_digit(16)
        .ok_or_else(|| RuliaError::Parse("invalid hex digit".into()))?;
    let low = low
        .to_digit(16)
        .ok_or_else(|| RuliaError::Parse("invalid hex digit".into()))?;
    Ok(((high << 4) | low) as u8)
}

const INSTANT_CANONICAL_ERROR: &str = "Instant() expects canonical RFC3339 UTC string";

fn instant_error() -> RuliaError {
    RuliaError::Parse(INSTANT_CANONICAL_ERROR.into())
}

fn instant_parse_error<T>() -> RuliaResult<T> {
    Err(instant_error())
}

fn parse_fixed_digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    if start + len > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for &b in &bytes[start..start + len] {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + (b - b'0') as u32;
    }
    Some(value)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn validate_instant_canonical(s: &str) -> RuliaResult<()> {
    if s.is_empty() || s.chars().any(|ch| ch.is_whitespace()) {
        return instant_parse_error();
    }

    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return instant_parse_error();
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return instant_parse_error();
    }
    if *bytes.last().unwrap() != b'Z' {
        return instant_parse_error();
    }

    let year = parse_fixed_digits(bytes, 0, 4).ok_or_else(instant_error)?;
    let month = parse_fixed_digits(bytes, 5, 2).ok_or_else(instant_error)?;
    let day = parse_fixed_digits(bytes, 8, 2).ok_or_else(instant_error)?;
    let hour = parse_fixed_digits(bytes, 11, 2).ok_or_else(instant_error)?;
    let minute = parse_fixed_digits(bytes, 14, 2).ok_or_else(instant_error)?;
    let second = parse_fixed_digits(bytes, 17, 2).ok_or_else(instant_error)?;

    if month == 0 || month > 12 {
        return instant_parse_error();
    }

    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return instant_parse_error(),
    };

    if day == 0 || day > max_day {
        return instant_parse_error();
    }

    if hour > 23 || minute > 59 || second > 59 {
        return instant_parse_error();
    }

    if bytes.len() == 20 {
        return Ok(());
    }

    if bytes[19] != b'.' {
        return instant_parse_error();
    }

    let fraction = &bytes[20..bytes.len() - 1];
    if fraction.is_empty() || fraction.len() > 9 {
        return instant_parse_error();
    }
    if fraction.last() == Some(&b'0') {
        return instant_parse_error();
    }
    if !fraction.iter().all(|b| b.is_ascii_digit()) {
        return instant_parse_error();
    }

    Ok(())
}

fn is_symbol_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || matches!(ch, '_' | '?' | '*' | '+' | '!' | '-' | '<' | '>' | '/')
}

fn is_symbol_part(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '!' | '?' | '*' | '+' | '<' | '>')
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || matches!(ch, '_' | '*' | '+' | '!' | '-' | '<' | '>' | '/')
}

fn is_identifier_part(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '!' | '?' | '*' | '+' | '<' | '>')
}

fn determine_cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = env::var("RULIA_CACHE_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(dir) = env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(dir).join("rulia"));
    }
    if let Ok(home) = env::var("HOME") {
        return Some(Path::new(&home).join(".cache").join("rulia"));
    }
    None
}

fn digest_cache_key(path: &Path, algorithm: HashAlgorithm) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(algorithm.as_str().as_bytes());
    hasher.update(canonical.to_string_lossy().as_bytes());
    format!(
        "{}-{}.digest",
        algorithm.as_str(),
        hex::encode(hasher.finalize())
    )
}

/// Convert a PascalCase identifier to a Symbol
///
/// Rules:
/// - All-caps words (UUID, HTTP) -> simple lowercase (uuid, http)
/// - Single PascalCase word (Point, Circle) -> simple lowercase (point, circle)
/// - Multi-word PascalCase (GeoPoint) -> namespaced (geo/point)
/// - CamelCase boundaries only split on lowercase->uppercase transitions
///
/// Examples:
///   "UUID" -> Symbol::simple("uuid")
///   "Point" -> Symbol::simple("point")
///   "GeoPoint" -> Symbol::new(Some("geo"), "point")
///   "RuliaTaggedUnion" -> Symbol::new(Some("rulia"), "tagged-union")
fn symbol_from_pascal_case(name: &str) -> Symbol {
    // Check if all-caps (like UUID, HTTP) - treat as simple lowercase
    if name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Symbol::simple(name.to_ascii_lowercase());
    }

    // Split on camelCase boundaries (lowercase followed by uppercase)
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;

    for ch in name.chars() {
        let is_upper = ch.is_ascii_uppercase();

        // Split when we see lowercase->uppercase transition
        if is_upper && prev_lower && !current.is_empty() {
            parts.push(current.to_ascii_lowercase());
            current = String::new();
        }

        current.push(ch);
        prev_lower = ch.is_ascii_lowercase();
    }
    if !current.is_empty() {
        parts.push(current.to_ascii_lowercase());
    }

    if parts.len() >= 2 {
        // Take first part as namespace, rest joined with hyphen as name
        let ns = parts[0].clone();
        let name = parts[1..].join("-");
        Symbol::new(Some(ns), name)
    } else if parts.len() == 1 {
        Symbol::simple(&parts[0])
    } else {
        Symbol::simple(name.to_ascii_lowercase())
    }
}

/// Convert an identifier to a Keyword
///
/// Rule: First underscore separates namespace from name.
///
/// Examples:
///   "service"        -> Keyword::simple("service")        = :service
///   "user_id"        -> Keyword::new("user", "id")        = :user/id
///   "user_first_name"-> Keyword::new("user", "first_name")= :user/first_name
///
/// Note: If you need a namespace with underscores (e.g., :my_app/config),
/// use the explicit constructor: Keyword("my_app/config")
fn keyword_from_identifier(ident: &str) -> Keyword {
    // Split on FIRST underscore only - rest stays in name
    if let Some((ns, name)) = ident.split_once('_') {
        Keyword::new(Some(ns.to_string()), name)
    } else {
        Keyword::simple(ident)
    }
}

/// Check if a keyword can be represented unambiguously as identifier sugar.
/// Returns false if the namespace contains underscores (would be ambiguous).
fn keyword_is_simple_sugar(kw: &Keyword) -> bool {
    match kw.namespace() {
        None => true,                  // No namespace, always safe
        Some(ns) => !ns.contains('_'), // Namespace with underscore is ambiguous
    }
}

/// Check if a symbol can be represented unambiguously as PascalCase.
/// Returns false if the name contains characters that don't roundtrip cleanly.
fn symbol_is_simple_pascal(sym: &Symbol) -> bool {
    let name = sym.name();
    // Simple lowercase names are safe
    if sym.namespace().is_none()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return true;
    }
    // Namespaced symbols with simple parts are safe
    if let Some(ns) = sym.namespace() {
        let ns_ok = ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let name_ok = name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        return ns_ok && name_ok;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_file(prefix: &str) -> PathBuf {
        let base = env::temp_dir();
        let pid = std::process::id();
        let count = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        base.join(format!("{prefix}-{pid}-{count}.rjl"))
    }

    #[test]
    fn deterministic_normalization_disables_disk_cache() {
        let options = ParseOptions {
            deterministic: true,
            allow_import_io: true,
            allow_disk_cache: true,
            ..Default::default()
        }
        .normalized();
        assert!(options.deterministic);
        assert!(options.allow_import_io);
        assert!(!options.allow_disk_cache);
    }

    #[test]
    fn parse_file_no_io_fails_before_filesystem_read() {
        let missing = unique_temp_file("rulia-no-io-parse-file");
        let err = parse_file_with_options(&missing, ParseOptions::deterministic())
            .expect_err("deterministic/no-io parse_file should fail");
        assert!(matches!(err, RuliaError::ImportIoDisabled));
    }

    #[test]
    fn import_state_no_io_skips_cache_discovery() {
        let options = ParseOptions {
            allow_import_io: false,
            allow_disk_cache: true,
            ..Default::default()
        };
        let state = ImportState::new(options);
        assert!(state.cache_dir.is_none());
    }
}
