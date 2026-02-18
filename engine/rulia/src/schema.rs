use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::{RuliaError, RuliaResult};
use crate::text;
use crate::value::{Keyword, TaggedValue, Value};

#[derive(Clone, Debug)]
pub struct Schema {
    defs: HashMap<String, Definition>,
    root: Option<TypeRef>,
}

#[derive(Clone, Debug)]
pub enum Definition {
    Struct(StructDef),
    TaggedUnion(TagUnionDef),
}

#[derive(Clone, Debug)]
pub struct StructDef {
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Clone, Debug)]
pub struct TagUnionDef {
    pub variants: Vec<UnionVariant>,
}

#[derive(Clone, Debug)]
pub struct UnionVariant {
    pub name: String,
    pub ty: Option<TypeRef>,
}

#[derive(Clone, Debug)]
pub enum TypeRef {
    Primitive(PrimitiveType),
    Named(String),
    Vector(Box<TypeRef>),
    Set(Box<TypeRef>),
    Map(Box<TypeRef>, Box<TypeRef>),
    Struct(Box<StructDef>),
    TaggedUnion(Box<TagUnionDef>),
}

#[derive(Clone, Copy, Debug)]
pub enum PrimitiveType {
    Nil,
    Bool,
    Int,
    UInt,
    Float32,
    Float64,
    String,
    Bytes,
    Keyword,
    Symbol,
}

impl Schema {
    pub fn from_value(value: Value) -> RuliaResult<Self> {
        parse_schema(value)
    }

    pub fn from_text(input: &str) -> RuliaResult<Self> {
        let value = text::parse(input)?;
        Self::from_value(value)
    }

    pub fn from_file(path: impl AsRef<Path>) -> RuliaResult<Self> {
        let value = text::parse_file(path)?;
        Self::from_value(value)
    }

    pub fn validate(&self, value: &Value) -> RuliaResult<()> {
        let Some(root) = &self.root else {
            return Err(RuliaError::Schema("schema does not declare a root".into()));
        };
        let mut stack = HashSet::new();
        self.validate_type(root, value, &mut stack)
    }

    pub fn definition(&self, name: &str) -> Option<&Definition> {
        self.defs.get(name)
    }

    pub fn root_type(&self) -> Option<&TypeRef> {
        self.root.as_ref()
    }
}

fn parse_schema(value: Value) -> RuliaResult<Schema> {
    let map = expect_map(&value, "schema")?;
    let mut defs_value = None;
    let mut root_value = None;
    for (key, val) in map {
        let key_name = keyword_name(&key)?;
        match key_name.as_str() {
            "defs" => defs_value = Some(val),
            "root" => root_value = Some(val),
            other => {
                return Err(RuliaError::Schema(format!(
                    "unknown top-level key :{other}"
                )));
            }
        }
    }
    let defs_value = defs_value.ok_or_else(|| RuliaError::Schema("schema missing :defs".into()))?;
    let defs_map = expect_map(&defs_value, "defs")?;
    let mut defs = HashMap::new();
    for (key, val) in defs_map {
        let name = keyword_name(&key)?;
        let def = parse_definition(&val)?;
        defs.insert(name, def);
    }
    let root = if let Some(root) = root_value {
        Some(parse_type(&root)?)
    } else {
        None
    };
    Ok(Schema { defs, root })
}

fn parse_definition(value: &Value) -> RuliaResult<Definition> {
    match value {
        Value::Tagged(TaggedValue { tag, value }) => match tag.as_str().as_str() {
            "rulia/struct" => Ok(Definition::Struct(parse_struct_body(value)?)),
            "rulia/tagged-union" => Ok(Definition::TaggedUnion(parse_union_body(value)?)),
            other => Err(RuliaError::Schema(format!(
                "unsupported definition tag #{other}"
            ))),
        },
        _ => Err(RuliaError::Schema(
            "definition must be tagged with #rulia/struct or #rulia/tagged-union".into(),
        )),
    }
}

fn parse_struct_body(value: &Value) -> RuliaResult<StructDef> {
    let map = expect_map(value, "struct definition")?;
    let mut fields = Vec::new();
    for (key, val) in map {
        let name = keyword_name(&key)?;
        let ty = parse_type(&val)?;
        fields.push(Field { name, ty });
    }
    Ok(StructDef { fields })
}

fn parse_union_body(value: &Value) -> RuliaResult<TagUnionDef> {
    let map = expect_map(value, "tagged union definition")?;
    let mut variants = Vec::new();
    for (key, val) in map {
        let name = keyword_name(&key)?;
        let ty = if matches!(val, Value::Nil) {
            None
        } else {
            Some(parse_type(&val)?)
        };
        variants.push(UnionVariant { name, ty });
    }
    Ok(TagUnionDef { variants })
}

fn parse_type(value: &Value) -> RuliaResult<TypeRef> {
    match value {
        Value::Keyword(kw) => match primitive_from_keyword(kw) {
            Some(p) => Ok(TypeRef::Primitive(p)),
            None => Ok(TypeRef::Named(identifier_from_keyword(kw))),
        },
        Value::Symbol(sym) => Ok(TypeRef::Named(sym.to_string())),
        Value::Tagged(TaggedValue { tag, value }) => match tag.as_str().as_str() {
            "rulia/vector" => Ok(TypeRef::Vector(Box::new(parse_type(value)?))),
            "rulia/set" => Ok(TypeRef::Set(Box::new(parse_type(value)?))),
            "rulia/map" => {
                let entries = expect_map(value, "map type")?;
                let mut key_ty = None;
                let mut value_ty = None;
                for (key, val) in entries {
                    let key_name = keyword_name(&key)?;
                    match key_name.as_str() {
                        "key" => key_ty = Some(parse_type(&val)?),
                        "value" => value_ty = Some(parse_type(&val)?),
                        other => {
                            return Err(RuliaError::Schema(format!(
                                "unknown key :{other} in #rulia/map"
                            )));
                        }
                    }
                }
                let key =
                    key_ty.ok_or_else(|| RuliaError::Schema("#rulia/map requires :key".into()))?;
                let val = value_ty
                    .ok_or_else(|| RuliaError::Schema("#rulia/map requires :value".into()))?;
                Ok(TypeRef::Map(Box::new(key), Box::new(val)))
            }
            "rulia/struct" => Ok(TypeRef::Struct(Box::new(parse_struct_body(value)?))),
            "rulia/tagged-union" => Ok(TypeRef::TaggedUnion(Box::new(parse_union_body(value)?))),
            other => Err(RuliaError::Schema(format!("unsupported type tag #{other}"))),
        },
        _ => Err(RuliaError::Schema("invalid type expression".into())),
    }
}

fn primitive_from_keyword(kw: &Keyword) -> Option<PrimitiveType> {
    match kw.name() {
        "nil" => Some(PrimitiveType::Nil),
        "bool" => Some(PrimitiveType::Bool),
        "int" | "i64" => Some(PrimitiveType::Int),
        "uint" | "u64" => Some(PrimitiveType::UInt),
        "f32" | "float32" => Some(PrimitiveType::Float32),
        "f64" | "float64" => Some(PrimitiveType::Float64),
        "string" => Some(PrimitiveType::String),
        "bytes" => Some(PrimitiveType::Bytes),
        "keyword" => Some(PrimitiveType::Keyword),
        "symbol" => Some(PrimitiveType::Symbol),
        _ => None,
    }
}

fn expect_map(value: &Value, ctx: &str) -> RuliaResult<Vec<(Value, Value)>> {
    if let Value::Map(entries) = value {
        Ok(entries.clone())
    } else {
        Err(RuliaError::Schema(format!("expected map for {ctx}")))
    }
}

fn keyword_name(value: &Value) -> RuliaResult<String> {
    match value {
        Value::Keyword(kw) => Ok(identifier_from_keyword(kw)),
        other => Err(RuliaError::Schema(format!(
            "expected keyword key, found {:#?}",
            other.kind()
        ))),
    }
}

fn identifier_from_keyword(kw: &Keyword) -> String {
    if let Some(ns) = kw.namespace() {
        format!("{}/{}", ns, kw.name())
    } else {
        kw.name().to_string()
    }
}

impl Schema {
    fn validate_type(
        &self,
        ty: &TypeRef,
        value: &Value,
        stack: &mut HashSet<String>,
    ) -> RuliaResult<()> {
        match ty {
            TypeRef::Primitive(p) => validate_primitive(*p, value),
            TypeRef::Vector(inner) => {
                let list = expect_vector(value)?;
                for item in list {
                    self.validate_type(inner, item, stack)?;
                }
                Ok(())
            }
            TypeRef::Set(inner) => {
                let list = expect_set(value)?;
                for item in list {
                    self.validate_type(inner, item, stack)?;
                }
                Ok(())
            }
            TypeRef::Map(key_ty, value_ty) => {
                let map = expect_map_value(value)?;
                for (k, v) in map {
                    self.validate_type(key_ty, k, stack)?;
                    self.validate_type(value_ty, v, stack)?;
                }
                Ok(())
            }
            TypeRef::Struct(def) => self.validate_struct(def, value, stack),
            TypeRef::TaggedUnion(def) => self.validate_union(def, value, stack),
            TypeRef::Named(name) => {
                if !stack.insert(name.clone()) {
                    return Err(RuliaError::Schema(format!(
                        "recursive type cycle involving {name}"
                    )));
                }
                let def = self
                    .defs
                    .get(name)
                    .ok_or_else(|| RuliaError::Schema(format!("unknown type '{name}'")))?;
                let result = match def {
                    Definition::Struct(def) => self.validate_struct(def, value, stack),
                    Definition::TaggedUnion(def) => self.validate_union(def, value, stack),
                };
                stack.remove(name);
                result
            }
        }
    }

    fn validate_struct(
        &self,
        def: &StructDef,
        value: &Value,
        stack: &mut HashSet<String>,
    ) -> RuliaResult<()> {
        let map = expect_map_value(value)?;
        for field in &def.fields {
            let field_value = map
                .iter()
                .find(|(k, _)| matches!(k, Value::Keyword(kv) if kv.name() == field.name))
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    RuliaError::Schema(format!("missing field :{} in struct", field.name))
                })?;
            self.validate_type(&field.ty, field_value, stack)?;
        }
        Ok(())
    }

    fn validate_union(
        &self,
        def: &TagUnionDef,
        value: &Value,
        stack: &mut HashSet<String>,
    ) -> RuliaResult<()> {
        let Value::Tagged(tagged) = value else {
            return Err(RuliaError::Schema(
                "tagged union values must be tagged".into(),
            ));
        };
        let variant_name = tagged.tag.to_string();
        let variant = def
            .variants
            .iter()
            .find(|v| v.name == variant_name)
            .ok_or_else(|| {
                RuliaError::Schema(format!("unknown union variant '{}", variant_name))
            })?;
        if let Some(ty) = &variant.ty {
            self.validate_type(ty, &tagged.value, stack)
        } else {
            if !matches!(*tagged.value, Value::Nil) {
                return Err(RuliaError::Schema(format!(
                    "variant '{}' expects no payload",
                    variant_name
                )));
            }
            Ok(())
        }
    }
}

fn expect_vector(value: &Value) -> RuliaResult<&[Value]> {
    if let Value::Vector(values) = value {
        Ok(values)
    } else {
        Err(RuliaError::Schema("expected vector".into()))
    }
}

fn expect_set(value: &Value) -> RuliaResult<&[Value]> {
    if let Value::Set(values) = value {
        Ok(values)
    } else {
        Err(RuliaError::Schema("expected set".into()))
    }
}

fn expect_map_value(value: &Value) -> RuliaResult<&[(Value, Value)]> {
    if let Value::Map(entries) = value {
        Ok(entries)
    } else {
        Err(RuliaError::Schema("expected map".into()))
    }
}

fn validate_primitive(expected: PrimitiveType, value: &Value) -> RuliaResult<()> {
    let ok = match expected {
        PrimitiveType::Nil => matches!(value, Value::Nil),
        PrimitiveType::Bool => matches!(value, Value::Bool(_)),
        PrimitiveType::Int => matches!(value, Value::Int(_)),
        PrimitiveType::UInt => matches!(value, Value::UInt(_)),
        PrimitiveType::Float32 => matches!(value, Value::Float32(_)),
        PrimitiveType::Float64 => matches!(value, Value::Float64(_)),
        PrimitiveType::String => matches!(value, Value::String(_)),
        PrimitiveType::Bytes => matches!(value, Value::Bytes(_)),
        PrimitiveType::Keyword => matches!(value, Value::Keyword(_)),
        PrimitiveType::Symbol => matches!(value, Value::Symbol(_)),
    };
    if ok {
        Ok(())
    } else {
        Err(RuliaError::Schema(format!(
            "expected {:?}, found {}",
            expected,
            value.kind()
        )))
    }
}
