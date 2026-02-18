use std::fmt::{self, Display, Formatter};

use num_bigint::BigInt;
use ordered_float::OrderedFloat;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Representation of a namespaced symbol identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Symbol {
    namespace: Option<String>,
    name: String,
}

impl Symbol {
    pub fn new(namespace: Option<String>, name: impl Into<String>) -> Self {
        Self {
            namespace,
            name: name.into(),
        }
    }

    pub fn simple(name: impl Into<String>) -> Self {
        Self::new(None, name)
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn as_str(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}", ns, self.name),
            None => self.name.clone(),
        }
    }

    pub fn parse(input: &str) -> Self {
        if let Some((ns, name)) = input.split_once('/') {
            Self::new(Some(ns.to_string()), name)
        } else {
            Self::simple(input)
        }
    }
}

impl Display for Symbol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{}/{}", ns, self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// Keyword identifiers mirror symbols but are interned with a leading ':' in the
/// textual representation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Keyword(Symbol);

impl Keyword {
    pub fn new(namespace: Option<String>, name: impl Into<String>) -> Self {
        Self(Symbol::new(namespace, name))
    }

    pub fn simple(name: impl Into<String>) -> Self {
        Self(Symbol::simple(name))
    }

    pub fn namespace(&self) -> Option<&str> {
        self.0.namespace()
    }

    pub fn name(&self) -> &str {
        self.0.name()
    }

    pub fn as_symbol(&self) -> &Symbol {
        &self.0
    }

    pub fn parse(input: &str) -> Self {
        let trimmed = input.strip_prefix(':').unwrap_or(input);
        Self(Symbol::parse(trimmed))
    }
}

impl Display for Keyword {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(":")?;
        self.0.fmt(f)
    }
}

/// Tagged values allow extensible semantics.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaggedValue {
    pub tag: Symbol,
    pub value: Box<Value>,
}

impl TaggedValue {
    pub fn new(tag: Symbol, value: Value) -> Self {
        Self {
            tag,
            value: Box::new(value),
        }
    }
}

/// Wraps a value with metadata for documentation and tooling.
///
/// Annotations provide "living documentation" that travels with the data.
/// The metadata is purely auxiliary - it affects tooling/docs but is
/// typically ignored by equality checks on the underlying data.
///
/// # Standard Metadata Keys
///
/// - `:doc` - Documentation string (Markdown supported)
/// - `:author` - Author identifier
/// - `:version` - Version string
/// - `:deprecated` - Boolean deprecation flag
/// - `:see` - Related schema/entity references
/// - `:sensitive` - Boolean flag for sensitive data (PII, secrets)
/// - `:diagram` - Embedded diagram (Mermaid/Graphviz)
/// - `:graph_node` - Visual properties for graph rendering
/// - `:links` - External documentation links
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Annotation {
    /// Metadata map containing documentation, links, etc.
    pub metadata: Vec<(Value, Value)>,
    /// The annotated value itself.
    pub value: Box<Value>,
}

impl Annotation {
    pub fn new(metadata: Vec<(Value, Value)>, value: Value) -> Self {
        Self {
            metadata,
            value: Box::new(value),
        }
    }

    /// Create an annotation with just a doc string.
    pub fn with_doc(doc: impl Into<String>, value: Value) -> Self {
        Self::new(
            vec![(
                Value::Keyword(Keyword::simple("doc")),
                Value::String(doc.into()),
            )],
            value,
        )
    }

    /// Get the documentation string if present.
    pub fn doc(&self) -> Option<&str> {
        self.get_string(&Keyword::simple("doc"))
    }

    /// Get a string value from metadata by keyword.
    pub fn get_string(&self, key: &Keyword) -> Option<&str> {
        let key_val = Value::Keyword(key.clone());
        for (k, v) in &self.metadata {
            if k == &key_val {
                if let Value::String(s) = v {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Get a boolean value from metadata by keyword.
    pub fn get_bool(&self, key: &Keyword) -> Option<bool> {
        let key_val = Value::Keyword(key.clone());
        for (k, v) in &self.metadata {
            if k == &key_val {
                if let Value::Bool(b) = v {
                    return Some(*b);
                }
            }
        }
        None
    }

    /// Get the inner value, unwrapping the annotation.
    pub fn unwrap(self) -> Value {
        *self.value
    }

    /// Get a reference to the inner value.
    pub fn inner(&self) -> &Value {
        &self.value
    }
}

// Annotations compare equal based on their content (metadata + value)
impl PartialEq for Annotation {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata && self.value == other.value
    }
}

impl Eq for Annotation {}

// Hash implementation for Annotation
impl std::hash::Hash for Annotation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.metadata.hash(state);
        self.value.hash(state);
    }
}

/// The canonical Rulia data model.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    UInt(u64),
    BigInt(BigInt),
    Float32(OrderedFloat<f32>),
    Float64(OrderedFloat<f64>),
    String(String),
    Bytes(Vec<u8>),
    Symbol(Symbol),
    Keyword(Keyword),
    Vector(Vec<Value>),
    Set(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tagged(TaggedValue),
    /// Wraps another value with metadata (documentation, author, etc.).
    /// Zero overhead for regular values - only annotated values carry metadata.
    Annotated(Box<Annotation>),
}

impl Value {
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Nil => "nil",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::UInt(_) => "uint",
            Value::BigInt(_) => "bigint",
            Value::Float32(_) => "f32",
            Value::Float64(_) => "f64",
            Value::String(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::Symbol(_) => "symbol",
            Value::Keyword(_) => "keyword",
            Value::Vector(_) => "vector",
            Value::Set(_) => "set",
            Value::Map(_) => "map",
            Value::Tagged(_) => "tagged",
            Value::Annotated(_) => "annotated",
        }
    }

    /// Unwrap any annotations to get the underlying data value.
    /// Useful when you want to ignore metadata and work with raw data.
    pub fn unwrap_annotations(&self) -> &Value {
        match self {
            Value::Annotated(ann) => ann.inner().unwrap_annotations(),
            other => other,
        }
    }

    /// Produce a value tree with all annotations removed (metadata stripped recursively).
    pub fn strip_annotations(&self) -> Value {
        match self {
            Value::Annotated(annotation) => annotation.value.strip_annotations(),
            Value::Vector(values) => {
                Value::Vector(values.iter().map(|v| v.strip_annotations()).collect())
            }
            Value::Set(values) => {
                Value::Set(values.iter().map(|v| v.strip_annotations()).collect())
            }
            Value::Map(entries) => Value::Map(
                entries
                    .iter()
                    .map(|(key, value)| (key.strip_annotations(), value.strip_annotations()))
                    .collect(),
            ),
            Value::Tagged(tagged) => Value::Tagged(TaggedValue::new(
                tagged.tag.clone(),
                tagged.value.strip_annotations(),
            )),
            other => other.clone(),
        }
    }

    /// Consume self and unwrap all annotations to get the underlying data value.
    pub fn into_unwrapped(self) -> Value {
        match self {
            Value::Annotated(ann) => ann.unwrap().into_unwrapped(),
            other => other,
        }
    }

    /// Check if this value has any annotations.
    pub fn is_annotated(&self) -> bool {
        matches!(self, Value::Annotated(_))
    }

    /// Get annotations if present.
    pub fn annotations(&self) -> Option<&Annotation> {
        match self {
            Value::Annotated(ann) => Some(ann),
            _ => None,
        }
    }

    /// Wrap this value with an annotation.
    pub fn annotate(self, metadata: Vec<(Value, Value)>) -> Value {
        Value::Annotated(Box::new(Annotation::new(metadata, self)))
    }

    /// Add a doc string annotation to this value.
    pub fn with_doc(self, doc: impl Into<String>) -> Value {
        Value::Annotated(Box::new(Annotation::with_doc(doc, self)))
    }
}
