use num_bigint::BigInt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    UInt(u64),
    BigInt(BigInt),
    Float32(f32),
    Float64(f64),
    String(String),
    Bytes(Vec<u8>),
    Keyword(Keyword),
    Symbol(Symbol),
    Vector(Vec<Value>),
    Set(Vec<Value>),
    Map(Vec<(MapKey, Value)>),
    Tagged(TaggedValue),
    Call(Call),
    Import(Import),
    Generator(Generator),
    Let(LetExpr),
    Fn(FnExpr),
    Ns(NsMacro),
    Infix(InfixExpr),
    Annotated(Annotation),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Keyword {
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MapKey {
    Identifier(String),
    Keyword(Keyword),
    String(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaggedValue {
    pub tag: Symbol,
    pub value: Box<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub name: String,
    pub args: Args,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Args {
    Map(Vec<(MapKey, Value)>),
    Positional(Vec<Value>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    pub path: String,
    pub hash: Option<HashSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashSpec {
    pub algorithm: HashAlgorithm,
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Generator {
    pub kind: GeneratorKind,
    pub keyword: Keyword,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorKind {
    New,
    Generator,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LetExpr {
    pub bindings: Vec<Binding>,
    pub body: Box<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Binding {
    pub pattern: Pattern,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    Identifier(String),
    Tuple(Vec<String>),
    Vector(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FnExpr {
    pub params: Vec<String>,
    pub body: Box<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NsMacro {
    pub namespace: String,
    pub value: Box<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InfixExpr {
    pub items: Vec<Value>,
    pub operators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    pub metadata: Vec<(MapKey, Value)>,
    pub value: Box<Value>,
}
