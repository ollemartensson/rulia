use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanArray, Float32Array, Float64Array, Int64Array, ListArray, MapArray, NullArray,
    StringArray, StructArray, UInt64Array,
};
use arrow::array::{BinaryViewArray, StringViewArray};
use arrow::datatypes::{DataType, Field, Fields, Schema as ArrowSchema};
use arrow::record_batch::RecordBatch;
use arrow_buffer::{NullBuffer, NullBufferBuilder, OffsetBuffer};
use rulia::binary::{MessageReader, TypeTag, ValueRef};
use rulia::schema::{
    Definition, PrimitiveType, Schema as RuliaSchema, StructDef, TagUnionDef, TypeRef,
};
use rulia::value::{Keyword, Symbol, Value};
use rulia::RuliaError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("schema missing root type")]
    MissingRoot,

    #[error("unsupported rulia type in Arrow conversion: {ty}")]
    UnsupportedType { ty: String },

    #[error("unknown named type: {name}")]
    UnknownType { name: String },

    #[error("unsupported named definition '{name}' for Arrow conversion")]
    UnsupportedDefinition { name: String },

    #[error("column {field} type mismatch: expected {expected}, found {found}")]
    TypeMismatch {
        field: String,
        expected: &'static str,
        found: String,
    },

    #[error("struct row must be a map, found {found}")]
    ExpectedStructMap { found: String },

    #[error("binary root value must be a vector of structs")]
    InvalidBinaryRoot,

    #[error("Arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),

    #[error("rulia error: {0}")]
    Rulia(#[from] RuliaError),
}

pub fn arrow_schema_from_rulia(schema: &RuliaSchema) -> Result<Arc<ArrowSchema>> {
    let root = schema.root_type().ok_or(Error::MissingRoot)?;
    let struct_def = resolve_struct(schema, root)?;
    let fields = struct_fields_to_arrow(schema, struct_def)?;
    let mut metadata = HashMap::new();
    metadata.insert("rulia:root".to_string(), type_ref_signature(root));
    Ok(Arc::new(ArrowSchema::new_with_metadata(fields, metadata)))
}

pub fn record_batch_from_values(schema: &RuliaSchema, rows: &[Value]) -> Result<RecordBatch> {
    let root = schema.root_type().ok_or(Error::MissingRoot)?;
    let struct_def = resolve_struct(schema, root)?;
    let arrow_fields = struct_fields_to_arrow(schema, struct_def)?;
    let mut columns = Vec::with_capacity(struct_def.fields.len());
    for field in &struct_def.fields {
        columns.push(build_column(rows, schema, &field.ty, &field.name)?);
    }
    let mut metadata = HashMap::new();
    metadata.insert("rulia:root".to_string(), type_ref_signature(root));
    let arrow_schema = Arc::new(ArrowSchema::new_with_metadata(arrow_fields, metadata));
    RecordBatch::try_new(arrow_schema, columns).map_err(Error::from)
}

pub fn record_batch_from_reader(
    schema: &RuliaSchema,
    reader: &MessageReader<'_>,
) -> Result<RecordBatch> {
    let root = reader.root()?;
    let root_value = root.as_value();
    let iter = root_value
        .vector_iter()
        .map_err(|_| Error::InvalidBinaryRoot)?;
    let mut row_refs = Vec::new();
    for item in iter {
        let value_ref = item?;
        if matches!(value_ref.kind(), TypeTag::Nil) {
            row_refs.push(None);
        } else {
            row_refs.push(Some(value_ref));
        }
    }

    let root_type = schema.root_type().ok_or(Error::MissingRoot)?;
    let struct_def = resolve_struct(schema, root_type)?;
    let arrow_fields = struct_fields_to_arrow(schema, struct_def)?;
    let mut columns = Vec::with_capacity(struct_def.fields.len());
    let mut owned_rows: Option<Vec<Value>> = None;

    for field in &struct_def.fields {
        let field_refs = gather_field_refs(&row_refs, &field.name)?;
        if let Some(array) = build_column_from_refs(&field_refs, schema, &field.ty, &field.name)? {
            columns.push(array);
        } else {
            if owned_rows.is_none() {
                let mut converted = Vec::with_capacity(row_refs.len());
                for row in &row_refs {
                    if let Some(value_ref) = row {
                        converted.push(value_ref.to_value()?);
                    } else {
                        converted.push(Value::Nil);
                    }
                }
                owned_rows = Some(converted);
            }
            columns.push(build_column(
                owned_rows.as_ref().unwrap(),
                schema,
                &field.ty,
                &field.name,
            )?);
        }
    }

    let mut metadata = HashMap::new();
    metadata.insert("rulia:root".to_string(), type_ref_signature(root_type));
    let arrow_schema = Arc::new(ArrowSchema::new_with_metadata(arrow_fields, metadata));
    RecordBatch::try_new(arrow_schema, columns).map_err(Error::from)
}

fn resolve_struct<'a>(schema: &'a RuliaSchema, ty: &'a TypeRef) -> Result<&'a StructDef> {
    match ty {
        TypeRef::Struct(def) => Ok(def.as_ref()),
        TypeRef::Named(name) => match schema.definition(name) {
            Some(Definition::Struct(def)) => Ok(def),
            Some(Definition::TaggedUnion(_)) => {
                Err(Error::UnsupportedDefinition { name: name.clone() })
            }
            None => Err(Error::UnknownType { name: name.clone() }),
        },
        other => Err(Error::UnsupportedType {
            ty: format!("{other:?}"),
        }),
    }
}

fn struct_fields_to_arrow(schema: &RuliaSchema, def: &StructDef) -> Result<Vec<Field>> {
    let mut fields = Vec::with_capacity(def.fields.len());
    for field in &def.fields {
        let data_type = type_ref_to_arrow(schema, &field.ty)?;
        fields.push(
            Field::new(&field.name, data_type, true).with_metadata(field_metadata(&field.ty)),
        );
    }
    Ok(fields)
}

fn tagged_union_fields_to_arrow(schema: &RuliaSchema, def: &TagUnionDef) -> Result<Vec<Field>> {
    let mut fields = Vec::with_capacity(def.variants.len());
    for variant in &def.variants {
        let (data_type, metadata) = if let Some(ty) = &variant.ty {
            (
                type_ref_to_arrow(schema, ty)?,
                variant_metadata(&variant.name, Some(ty)),
            )
        } else {
            (DataType::Boolean, variant_metadata(&variant.name, None))
        };
        fields.push(Field::new(&variant.name, data_type, true).with_metadata(metadata));
    }
    Ok(fields)
}

fn type_ref_to_arrow(schema: &RuliaSchema, ty: &TypeRef) -> Result<DataType> {
    match ty {
        TypeRef::Primitive(primitive) => primitive_to_arrow(*primitive),
        TypeRef::Struct(def) => Ok(DataType::Struct(
            struct_fields_to_arrow(schema, def)?.into(),
        )),
        TypeRef::Named(name) => match schema.definition(name) {
            Some(Definition::Struct(def)) => Ok(DataType::Struct(
                struct_fields_to_arrow(schema, def)?.into(),
            )),
            Some(Definition::TaggedUnion(def)) => Ok(DataType::Struct(
                tagged_union_fields_to_arrow(schema, def)?.into(),
            )),
            None => Err(Error::UnknownType { name: name.clone() }),
        },
        TypeRef::Vector(inner) | TypeRef::Set(inner) => {
            let child_type = type_ref_to_arrow(schema, inner)?;
            let field = Field::new("item", child_type, true).with_metadata(field_metadata(inner));
            Ok(DataType::List(Arc::new(field)))
        }
        TypeRef::Map(key_ty, value_ty) => {
            let key_type = type_ref_to_arrow(schema, key_ty)?;
            let value_type = type_ref_to_arrow(schema, value_ty)?;
            let entry_fields: Fields = vec![
                Field::new("key", key_type.clone(), false).with_metadata(field_metadata(key_ty)),
                Field::new("value", value_type.clone(), true)
                    .with_metadata(field_metadata(value_ty)),
            ]
            .into();
            let mut map_meta = HashMap::new();
            map_meta.insert("rulia:kind".into(), "map_entries".into());
            let entry_struct = Field::new("entries", DataType::Struct(entry_fields), false)
                .with_metadata(map_meta);
            Ok(DataType::Map(Arc::new(entry_struct), false))
        }
        TypeRef::TaggedUnion(def) => Ok(DataType::Struct(
            tagged_union_fields_to_arrow(schema, def)?.into(),
        )),
    }
}

fn primitive_to_arrow(primitive: PrimitiveType) -> Result<DataType> {
    Ok(match primitive {
        PrimitiveType::Nil => DataType::Null,
        PrimitiveType::Bool => DataType::Boolean,
        PrimitiveType::Int => DataType::Int64,
        PrimitiveType::UInt => DataType::UInt64,
        PrimitiveType::Float32 => DataType::Float32,
        PrimitiveType::Float64 => DataType::Float64,
        PrimitiveType::String => DataType::Utf8View,
        PrimitiveType::Bytes => DataType::BinaryView,
        PrimitiveType::Keyword | PrimitiveType::Symbol => DataType::Utf8,
    })
}

fn build_column(
    rows: &[Value],
    schema: &RuliaSchema,
    ty: &TypeRef,
    field_name: &str,
) -> Result<ArrayRef> {
    let values = collect_field_values(rows, field_name)?;
    build_array_from_values(schema, ty, &values, field_name)
}

fn collect_field_values<'a>(rows: &'a [Value], field_name: &str) -> Result<Vec<Option<&'a Value>>> {
    rows.iter()
        .map(|row| extract_field(row, field_name))
        .collect()
}

fn build_array_from_values(
    schema: &RuliaSchema,
    ty: &TypeRef,
    values: &[Option<&Value>],
    field_path: &str,
) -> Result<ArrayRef> {
    match ty {
        TypeRef::Primitive(primitive) => build_primitive_column(values, *primitive, field_path),
        TypeRef::Struct(def) => build_struct_array(schema, def, values, field_path),
        TypeRef::Named(name) => match schema.definition(name) {
            Some(Definition::Struct(def)) => build_struct_array(schema, def, values, field_path),
            Some(Definition::TaggedUnion(def)) => {
                build_tagged_union_array(schema, def, values, field_path)
            }
            None => Err(Error::UnknownType { name: name.clone() }),
        },
        TypeRef::Vector(inner) => build_list_array(schema, inner, values, field_path, "vector"),
        TypeRef::Set(inner) => build_list_array(schema, inner, values, field_path, "set"),
        TypeRef::Map(key_ty, value_ty) => {
            build_map_array(schema, key_ty, value_ty, values, field_path)
        }
        TypeRef::TaggedUnion(def) => build_tagged_union_array(schema, def, values, field_path),
    }
}

fn build_struct_array(
    schema: &RuliaSchema,
    def: &StructDef,
    values: &[Option<&Value>],
    field_path: &str,
) -> Result<ArrayRef> {
    let mut normalized: Vec<Option<&Value>> = Vec::with_capacity(values.len());
    let mut nulls = NullBufferBuilder::new(values.len());

    for value in values {
        match value {
            None => {
                nulls.append_null();
                normalized.push(None);
            }
            Some(inner @ Value::Map(_)) => {
                nulls.append_non_null();
                normalized.push(Some(inner));
            }
            Some(Value::Nil) => {
                nulls.append_null();
                normalized.push(None);
            }
            Some(other) => {
                return Err(Error::ExpectedStructMap {
                    found: other.kind().to_string(),
                });
            }
        }
    }

    let mut child_arrays = Vec::with_capacity(def.fields.len());
    for field in &def.fields {
        let child_path = format!("{field_path}.{}", field.name);
        let mut field_values: Vec<Option<&Value>> = Vec::with_capacity(normalized.len());
        for parent in &normalized {
            if let Some(Value::Map(entries)) = parent {
                if let Some(value) = extract_from_entries(entries, &field.name) {
                    field_values.push(value_option(value));
                } else {
                    field_values.push(None);
                }
            } else {
                field_values.push(None);
            }
        }
        let child_array = build_array_from_values(schema, &field.ty, &field_values, &child_path)?;
        child_arrays.push(child_array);
    }

    let arrow_fields = struct_fields_to_arrow(schema, def)?;
    let fields: Fields = arrow_fields.into();
    let null_buffer: Option<NullBuffer> = nulls.finish();
    let struct_array =
        StructArray::try_new(fields, child_arrays, null_buffer).map_err(Error::from)?;
    Ok(Arc::new(struct_array) as ArrayRef)
}

fn build_list_array(
    schema: &RuliaSchema,
    element_ty: &TypeRef,
    values: &[Option<&Value>],
    field_path: &str,
    expected_kind: &'static str,
) -> Result<ArrayRef> {
    let mut lengths = Vec::with_capacity(values.len());
    let mut nulls = NullBufferBuilder::new(values.len());
    let mut element_values: Vec<Option<&Value>> = Vec::new();

    for value in values {
        match value {
            None | Some(Value::Nil) => {
                lengths.push(0);
                nulls.append_null();
            }
            Some(Value::Vector(items)) | Some(Value::Set(items)) => {
                nulls.append_non_null();
                lengths.push(items.len());
                for item in items {
                    element_values.push(value_option(item));
                }
            }
            Some(other) => {
                return Err(Error::TypeMismatch {
                    field: field_path.to_string(),
                    expected: expected_kind,
                    found: other.kind().to_string(),
                });
            }
        }
    }

    let child_path = format!("{field_path}[]");
    let child_array = build_array_from_values(schema, element_ty, &element_values, &child_path)?;
    let offsets = OffsetBuffer::<i32>::from_lengths(lengths);
    let null_buffer = nulls.finish();
    let child_type = child_array.data_type().clone();
    let field =
        Arc::new(Field::new("item", child_type, true).with_metadata(field_metadata(element_ty)));
    let list_array =
        ListArray::try_new(field, offsets, child_array, null_buffer).map_err(Error::from)?;
    Ok(Arc::new(list_array) as ArrayRef)
}

fn build_map_array(
    schema: &RuliaSchema,
    key_ty: &TypeRef,
    value_ty: &TypeRef,
    values: &[Option<&Value>],
    field_path: &str,
) -> Result<ArrayRef> {
    let mut lengths = Vec::with_capacity(values.len());
    let mut nulls = NullBufferBuilder::new(values.len());
    let mut key_values: Vec<Option<&Value>> = Vec::new();
    let mut value_values: Vec<Option<&Value>> = Vec::new();

    for value in values {
        match value {
            None | Some(Value::Nil) => {
                lengths.push(0);
                nulls.append_null();
            }
            Some(Value::Map(entries)) => {
                nulls.append_non_null();
                lengths.push(entries.len());
                for (key, val) in entries {
                    if matches!(key, Value::Nil) {
                        return Err(Error::TypeMismatch {
                            field: format!("{field_path}.key"),
                            expected: "non-null",
                            found: key.kind().to_string(),
                        });
                    }
                    key_values.push(Some(key));
                    value_values.push(value_option(val));
                }
            }
            Some(other) => {
                return Err(Error::TypeMismatch {
                    field: field_path.to_string(),
                    expected: "map",
                    found: other.kind().to_string(),
                });
            }
        }
    }

    let keys_array =
        build_array_from_values(schema, key_ty, &key_values, &format!("{field_path}.key"))?;
    let values_array = build_array_from_values(
        schema,
        value_ty,
        &value_values,
        &format!("{field_path}.value"),
    )?;

    let entry_fields_vec = vec![
        Field::new("key", keys_array.data_type().clone(), false)
            .with_metadata(field_metadata(key_ty)),
        Field::new("value", values_array.data_type().clone(), true)
            .with_metadata(field_metadata(value_ty)),
    ];
    let entry_fields: Fields = entry_fields_vec.clone().into();
    let entries_struct =
        StructArray::try_new(entry_fields.clone(), vec![keys_array, values_array], None)
            .map_err(Error::from)?;
    let mut map_meta = HashMap::new();
    map_meta.insert("rulia:kind".into(), "map_entries".into());
    let map_field = Arc::new(
        Field::new("entries", DataType::Struct(entry_fields), false).with_metadata(map_meta),
    );
    let offsets = OffsetBuffer::<i32>::from_lengths(lengths);
    let null_buffer = nulls.finish();
    let map_array = MapArray::try_new(map_field, offsets, entries_struct, null_buffer, false)
        .map_err(Error::from)?;
    Ok(Arc::new(map_array) as ArrayRef)
}

fn build_tagged_union_array(
    schema: &RuliaSchema,
    def: &TagUnionDef,
    values: &[Option<&Value>],
    field_path: &str,
) -> Result<ArrayRef> {
    let mut nulls = NullBufferBuilder::new(values.len());
    enum VariantCollector<'a> {
        Typed {
            name: &'a str,
            ty: &'a TypeRef,
            values: Vec<Option<&'a Value>>,
        },
        Flag {
            name: &'a str,
            values: Vec<Option<bool>>,
        },
    }

    let mut collectors: Vec<VariantCollector<'_>> = def
        .variants
        .iter()
        .map(|variant| {
            if let Some(ty) = &variant.ty {
                VariantCollector::Typed {
                    name: variant.name.as_str(),
                    ty,
                    values: vec![None; values.len()],
                }
            } else {
                VariantCollector::Flag {
                    name: variant.name.as_str(),
                    values: vec![None; values.len()],
                }
            }
        })
        .collect();

    for (idx, value) in values.iter().enumerate() {
        match value {
            None | Some(Value::Nil) => nulls.append_null(),
            Some(Value::Tagged(tagged)) => {
                let variant_name = symbol_identifier(&tagged.tag);
                let mut matched = false;
                for collector in &mut collectors {
                    match collector {
                        VariantCollector::Typed { name, values, .. } if *name == variant_name => {
                            values[idx] = value_option(&tagged.value);
                            matched = true;
                            break;
                        }
                        VariantCollector::Flag { name, values } if *name == variant_name => {
                            if !matches!(tagged.value.as_ref(), Value::Nil) {
                                return Err(Error::TypeMismatch {
                                    field: format!("{field_path}.{}", name),
                                    expected: "unit variant",
                                    found: tagged.value.kind().to_string(),
                                });
                            }
                            values[idx] = Some(true);
                            matched = true;
                            break;
                        }
                        _ => {}
                    }
                }
                if !matched {
                    return Err(Error::TypeMismatch {
                        field: field_path.to_string(),
                        expected: "tagged union variant",
                        found: variant_name,
                    });
                }
                nulls.append_non_null();
            }
            Some(other) => {
                return Err(Error::TypeMismatch {
                    field: field_path.to_string(),
                    expected: "tagged union",
                    found: other.kind().to_string(),
                });
            }
        }
    }

    let arrow_fields = tagged_union_fields_to_arrow(schema, def)?;
    let mut child_arrays = Vec::with_capacity(collectors.len());
    for collector in collectors {
        match collector {
            VariantCollector::Typed { name, ty, values } => {
                let child =
                    build_array_from_values(schema, ty, &values, &format!("{field_path}.{name}"))?;
                child_arrays.push(child);
            }
            VariantCollector::Flag { values, .. } => {
                let column = BooleanArray::from(values);
                child_arrays.push(Arc::new(column) as ArrayRef);
            }
        }
    }
    let struct_array = StructArray::try_new(arrow_fields.into(), child_arrays, nulls.finish())
        .map_err(Error::from)?;
    Ok(Arc::new(struct_array) as ArrayRef)
}

fn build_primitive_column(
    values: &[Option<&Value>],
    primitive: PrimitiveType,
    field_path: &str,
) -> Result<ArrayRef> {
    match primitive {
        PrimitiveType::Nil => {
            for inner in values.iter().copied().flatten() {
                if !matches!(inner, Value::Nil) {
                    return Err(Error::TypeMismatch {
                        field: field_path.to_string(),
                        expected: "nil",
                        found: inner.kind().to_string(),
                    });
                }
            }
            Ok(Arc::new(NullArray::new(values.len())) as ArrayRef)
        }
        PrimitiveType::Bool => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Bool(v)) => column.push(Some(*v)),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "bool",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(BooleanArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Int => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Int(v)) => column.push(Some(*v)),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "int",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(Int64Array::from(column)) as ArrayRef)
        }
        PrimitiveType::UInt => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::UInt(v)) => column.push(Some(*v)),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "uint",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(UInt64Array::from(column)) as ArrayRef)
        }
        PrimitiveType::Float32 => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Float32(v)) => column.push(Some(**v)),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "float32",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(Float32Array::from(column)) as ArrayRef)
        }
        PrimitiveType::Float64 => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Float64(v)) => column.push(Some(**v)),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "float64",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(Float64Array::from(column)) as ArrayRef)
        }
        PrimitiveType::String => {
            let mut column: Vec<Option<&str>> = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::String(v)) => column.push(Some(v.as_str())),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "string",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(StringViewArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Bytes => {
            let mut column: Vec<Option<&[u8]>> = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Bytes(v)) => column.push(Some(v.as_slice())),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "bytes",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(BinaryViewArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Keyword => {
            let mut column: Vec<Option<String>> = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Keyword(v)) => column.push(Some(keyword_identifier(v))),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "keyword",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(StringArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Symbol => {
            let mut column: Vec<Option<String>> = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(Value::Symbol(v)) => column.push(Some(symbol_identifier(v))),
                    Some(other) => {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "symbol",
                            found: other.kind().to_string(),
                        })
                    }
                    None => column.push(None),
                }
            }
            Ok(Arc::new(StringArray::from(column)) as ArrayRef)
        }
    }
}

fn extract_field<'a>(row: &'a Value, field_name: &str) -> Result<Option<&'a Value>> {
    let entries = match row {
        Value::Nil => return Ok(None),
        Value::Map(entries) => entries,
        other => {
            return Err(Error::ExpectedStructMap {
                found: other.kind().to_string(),
            })
        }
    };
    if let Some(value) = extract_from_entries(entries, field_name) {
        if matches!(value, Value::Nil) {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    } else {
        Ok(None)
    }
}

fn extract_from_entries<'a>(entries: &'a [(Value, Value)], field_name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| matches_field_name(key, field_name))
        .map(|(_, value)| value)
}

fn matches_field_name(key: &Value, expected: &str) -> bool {
    match key {
        Value::Keyword(kw) => keyword_identifier(kw) == expected,
        Value::Symbol(sym) => symbol_identifier(sym) == expected,
        Value::String(s) => s == expected,
        _ => false,
    }
}

fn keyword_identifier(kw: &Keyword) -> String {
    match kw.namespace() {
        Some(ns) => format!("{ns}/{name}", name = kw.name()),
        None => kw.name().to_string(),
    }
}

fn symbol_identifier(sym: &Symbol) -> String {
    match sym.namespace() {
        Some(ns) => format!("{ns}/{name}", name = sym.name()),
        None => sym.name().to_string(),
    }
}

fn value_option(value: &Value) -> Option<&Value> {
    if matches!(value, Value::Nil) {
        None
    } else {
        Some(value)
    }
}

fn gather_field_refs<'a>(
    rows: &[Option<ValueRef<'a>>],
    field_name: &str,
) -> Result<Vec<Option<ValueRef<'a>>>> {
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let field_ref = extract_field_ref(row.as_ref().cloned(), field_name)?;
        result.push(field_ref);
    }
    Ok(result)
}

fn build_column_from_refs<'a>(
    field_refs: &[Option<ValueRef<'a>>],
    schema: &RuliaSchema,
    ty: &TypeRef,
    field_path: &str,
) -> Result<Option<ArrayRef>> {
    match ty {
        TypeRef::Primitive(primitive) => Ok(Some(build_primitive_column_from_refs(
            field_refs, *primitive, field_path,
        )?)),
        TypeRef::Struct(def) => build_struct_array_from_refs(schema, def, field_refs, field_path),
        TypeRef::Named(name) => match schema.definition(name) {
            Some(Definition::Struct(def)) => {
                build_struct_array_from_refs(schema, def, field_refs, field_path)
            }
            Some(Definition::TaggedUnion(def)) => {
                build_tagged_union_array_from_refs(schema, def, field_refs, field_path)
            }
            None => Err(Error::UnknownType { name: name.clone() }),
        },
        TypeRef::Vector(inner) => {
            build_list_array_from_refs(schema, inner, field_refs, field_path, "vector")
        }
        TypeRef::Set(inner) => {
            build_list_array_from_refs(schema, inner, field_refs, field_path, "set")
        }
        TypeRef::Map(key_ty, value_ty) => {
            build_map_array_from_refs(schema, key_ty, value_ty, field_refs, field_path)
        }
        TypeRef::TaggedUnion(def) => {
            build_tagged_union_array_from_refs(schema, def, field_refs, field_path)
        }
    }
}

fn build_primitive_column_from_refs(
    values: &[Option<ValueRef<'_>>],
    primitive: PrimitiveType,
    field_path: &str,
) -> Result<ArrayRef> {
    match primitive {
        PrimitiveType::Nil => {
            if let Some(value_ref) = values.iter().flatten().next() {
                return Err(Error::TypeMismatch {
                    field: field_path.to_string(),
                    expected: "nil",
                    found: format!("{:?}", value_ref.kind()),
                });
            }
            Ok(Arc::new(NullArray::new(values.len())) as ArrayRef)
        }
        PrimitiveType::Bool => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_bool()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(BooleanArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Int => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_int()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(Int64Array::from(column)) as ArrayRef)
        }
        PrimitiveType::UInt => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_uint()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(UInt64Array::from(column)) as ArrayRef)
        }
        PrimitiveType::Float32 => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_float32()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(Float32Array::from(column)) as ArrayRef)
        }
        PrimitiveType::Float64 => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_float64()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(Float64Array::from(column)) as ArrayRef)
        }
        PrimitiveType::String => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_string()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(StringViewArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Bytes => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref.as_bytes()?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(BinaryViewArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Keyword => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref_keyword_identifier(value_ref)?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(StringArray::from(column)) as ArrayRef)
        }
        PrimitiveType::Symbol => {
            let mut column = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Some(value_ref) => column.push(Some(value_ref_symbol_identifier(value_ref)?)),
                    None => column.push(None),
                }
            }
            Ok(Arc::new(StringArray::from(column)) as ArrayRef)
        }
    }
}

fn build_struct_array_from_refs(
    schema: &RuliaSchema,
    def: &StructDef,
    refs: &[Option<ValueRef<'_>>],
    field_path: &str,
) -> Result<Option<ArrayRef>> {
    let mut nulls = NullBufferBuilder::new(refs.len());
    let mut normalized = Vec::with_capacity(refs.len());
    for value in refs {
        match value {
            None => {
                nulls.append_null();
                normalized.push(None);
            }
            Some(value_ref) => match value_ref.kind() {
                TypeTag::Map => {
                    nulls.append_non_null();
                    normalized.push(Some(value_ref.clone()));
                }
                TypeTag::Nil => {
                    nulls.append_null();
                    normalized.push(None);
                }
                other => {
                    return Err(Error::ExpectedStructMap {
                        found: format!("{:?}", other),
                    });
                }
            },
        }
    }

    let mut child_arrays = Vec::with_capacity(def.fields.len());
    for field in &def.fields {
        let child_path = format!("{field_path}.{}", field.name);
        let child_refs = gather_field_refs(&normalized, &field.name)?;
        if let Some(array) = build_column_from_refs(&child_refs, schema, &field.ty, &child_path)? {
            child_arrays.push(array);
        } else {
            return Ok(None);
        }
    }

    let arrow_fields = struct_fields_to_arrow(schema, def)?;
    let fields: Fields = arrow_fields.into();
    let struct_array =
        StructArray::try_new(fields, child_arrays, nulls.finish()).map_err(Error::from)?;
    Ok(Some(Arc::new(struct_array) as ArrayRef))
}

fn build_list_array_from_refs(
    schema: &RuliaSchema,
    element_ty: &TypeRef,
    refs: &[Option<ValueRef<'_>>],
    field_path: &str,
    expected_kind: &'static str,
) -> Result<Option<ArrayRef>> {
    let mut lengths = Vec::with_capacity(refs.len());
    let mut nulls = NullBufferBuilder::new(refs.len());
    let mut element_refs: Vec<Option<ValueRef<'_>>> = Vec::new();

    for value in refs {
        match value {
            None => {
                lengths.push(0);
                nulls.append_null();
            }
            Some(value_ref) => match value_ref.kind() {
                TypeTag::Vector => {
                    nulls.append_non_null();
                    let iter = value_ref.vector_iter()?;
                    let mut count = 0;
                    for item in iter {
                        let child = item?;
                        if matches!(child.kind(), TypeTag::Nil) {
                            element_refs.push(None);
                        } else {
                            element_refs.push(Some(child));
                        }
                        count += 1;
                    }
                    lengths.push(count);
                }
                TypeTag::Set => {
                    nulls.append_non_null();
                    let iter = value_ref.set_iter()?;
                    let mut count = 0;
                    for item in iter {
                        let child = item?;
                        if matches!(child.kind(), TypeTag::Nil) {
                            element_refs.push(None);
                        } else {
                            element_refs.push(Some(child));
                        }
                        count += 1;
                    }
                    lengths.push(count);
                }
                TypeTag::Nil => {
                    lengths.push(0);
                    nulls.append_null();
                }
                other => {
                    return Err(Error::TypeMismatch {
                        field: field_path.to_string(),
                        expected: expected_kind,
                        found: format!("{:?}", other),
                    });
                }
            },
        }
    }

    let child_path = format!("{field_path}[]");
    let child_array = match build_column_from_refs(&element_refs, schema, element_ty, &child_path)?
    {
        Some(array) => array,
        None => return Ok(None),
    };
    let offsets = OffsetBuffer::<i32>::from_lengths(lengths);
    let field = Arc::new(
        Field::new("item", child_array.data_type().clone(), true)
            .with_metadata(field_metadata(element_ty)),
    );
    let list_array =
        ListArray::try_new(field, offsets, child_array, nulls.finish()).map_err(Error::from)?;
    Ok(Some(Arc::new(list_array) as ArrayRef))
}

fn build_map_array_from_refs(
    schema: &RuliaSchema,
    key_ty: &TypeRef,
    value_ty: &TypeRef,
    refs: &[Option<ValueRef<'_>>],
    field_path: &str,
) -> Result<Option<ArrayRef>> {
    let mut lengths = Vec::with_capacity(refs.len());
    let mut nulls = NullBufferBuilder::new(refs.len());
    let mut key_refs = Vec::new();
    let mut value_refs = Vec::new();

    for value in refs {
        match value {
            None => {
                lengths.push(0);
                nulls.append_null();
            }
            Some(value_ref) => match value_ref.kind() {
                TypeTag::Map => {
                    nulls.append_non_null();
                    let iter = value_ref.map_iter()?;
                    let mut count = 0;
                    for entry in iter {
                        let (key, val) = entry?;
                        if matches!(key.kind(), TypeTag::Nil) {
                            return Err(Error::TypeMismatch {
                                field: format!("{field_path}.key"),
                                expected: "non-null",
                                found: "nil".into(),
                            });
                        }
                        key_refs.push(Some(key));
                        if matches!(val.kind(), TypeTag::Nil) {
                            value_refs.push(None);
                        } else {
                            value_refs.push(Some(val));
                        }
                        count += 1;
                    }
                    lengths.push(count);
                }
                TypeTag::Nil => {
                    lengths.push(0);
                    nulls.append_null();
                }
                other => {
                    return Err(Error::TypeMismatch {
                        field: field_path.to_string(),
                        expected: "map",
                        found: format!("{:?}", other),
                    });
                }
            },
        }
    }

    let key_array =
        match build_column_from_refs(&key_refs, schema, key_ty, &format!("{field_path}.key"))? {
            Some(array) => array,
            None => return Ok(None),
        };
    let value_array = match build_column_from_refs(
        &value_refs,
        schema,
        value_ty,
        &format!("{field_path}.value"),
    )? {
        Some(array) => array,
        None => return Ok(None),
    };

    let entry_fields: Fields = vec![
        Field::new("key", key_array.data_type().clone(), false)
            .with_metadata(field_metadata(key_ty)),
        Field::new("value", value_array.data_type().clone(), true)
            .with_metadata(field_metadata(value_ty)),
    ]
    .into();
    let entries_struct =
        StructArray::try_new(entry_fields.clone(), vec![key_array, value_array], None)
            .map_err(Error::from)?;
    let mut map_meta = HashMap::new();
    map_meta.insert("rulia:kind".into(), "map_entries".into());
    let map_field = Arc::new(
        Field::new("entries", DataType::Struct(entry_fields), false).with_metadata(map_meta),
    );
    let offsets = OffsetBuffer::<i32>::from_lengths(lengths);
    let map_array = MapArray::try_new(map_field, offsets, entries_struct, nulls.finish(), false)
        .map_err(Error::from)?;
    Ok(Some(Arc::new(map_array) as ArrayRef))
}

fn build_tagged_union_array_from_refs(
    schema: &RuliaSchema,
    def: &TagUnionDef,
    refs: &[Option<ValueRef<'_>>],
    field_path: &str,
) -> Result<Option<ArrayRef>> {
    let mut nulls = NullBufferBuilder::new(refs.len());
    enum VariantCollector<'a> {
        Typed {
            name: &'a str,
            ty: &'a TypeRef,
            values: Vec<Option<ValueRef<'a>>>,
        },
        Flag {
            name: &'a str,
            values: Vec<Option<bool>>,
        },
    }

    let mut collectors: Vec<VariantCollector<'_>> = def
        .variants
        .iter()
        .map(|variant| {
            if let Some(ty) = &variant.ty {
                VariantCollector::Typed {
                    name: variant.name.as_str(),
                    ty,
                    values: vec![None; refs.len()],
                }
            } else {
                VariantCollector::Flag {
                    name: variant.name.as_str(),
                    values: vec![None; refs.len()],
                }
            }
        })
        .collect();

    for (idx, value) in refs.iter().enumerate() {
        match value {
            None => nulls.append_null(),
            Some(value_ref) => match value_ref.kind() {
                TypeTag::Tagged => {
                    let tagged = value_ref.tagged()?;
                    let variant_name = symbol_identifier(&tagged.0);
                    let mut matched = false;
                    for collector in &mut collectors {
                        match collector {
                            VariantCollector::Typed { name, values, .. }
                                if *name == variant_name =>
                            {
                                if matches!(tagged.1.kind(), TypeTag::Nil) {
                                    values[idx] = None;
                                } else {
                                    values[idx] = Some(tagged.1.clone());
                                }
                                matched = true;
                                break;
                            }
                            VariantCollector::Flag { name, values } if *name == variant_name => {
                                if !matches!(tagged.1.kind(), TypeTag::Nil) {
                                    return Err(Error::TypeMismatch {
                                        field: format!("{field_path}.{}", name),
                                        expected: "unit variant",
                                        found: format!("{:?}", tagged.1.kind()),
                                    });
                                }
                                values[idx] = Some(true);
                                matched = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    if !matched {
                        return Err(Error::TypeMismatch {
                            field: field_path.to_string(),
                            expected: "tagged union variant",
                            found: variant_name,
                        });
                    }
                    nulls.append_non_null();
                }
                TypeTag::Nil => nulls.append_null(),
                other => {
                    return Err(Error::TypeMismatch {
                        field: field_path.to_string(),
                        expected: "tagged union",
                        found: format!("{:?}", other),
                    });
                }
            },
        }
    }

    let mut child_arrays = Vec::with_capacity(collectors.len());
    for collector in collectors {
        match collector {
            VariantCollector::Typed { name, ty, values } => {
                let child = match build_column_from_refs(
                    &values,
                    schema,
                    ty,
                    &format!("{field_path}.{name}"),
                )? {
                    Some(array) => array,
                    None => return Ok(None),
                };
                child_arrays.push(child);
            }
            VariantCollector::Flag { values, .. } => {
                let column = BooleanArray::from(values);
                child_arrays.push(Arc::new(column) as ArrayRef);
            }
        }
    }

    let arrow_fields = tagged_union_fields_to_arrow(schema, def)?;
    let struct_array = StructArray::try_new(arrow_fields.into(), child_arrays, nulls.finish())
        .map_err(Error::from)?;
    Ok(Some(Arc::new(struct_array) as ArrayRef))
}

fn extract_field_ref<'a>(
    row: Option<ValueRef<'a>>,
    field_name: &str,
) -> Result<Option<ValueRef<'a>>> {
    let Some(row_ref) = row else {
        return Ok(None);
    };
    if matches!(row_ref.kind(), TypeTag::Nil) {
        return Ok(None);
    }
    if !matches!(row_ref.kind(), TypeTag::Map) {
        return Err(Error::ExpectedStructMap {
            found: format!("{:?}", row_ref.kind()),
        });
    }
    let entries = row_ref.map_iter()?;
    for entry in entries {
        let (key, value) = entry?;
        if matches_field_name_ref(&key, field_name)? {
            if matches!(value.kind(), TypeTag::Nil) {
                return Ok(None);
            }
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn matches_field_name_ref(key: &ValueRef<'_>, expected: &str) -> Result<bool> {
    Ok(match key.kind() {
        TypeTag::Keyword => value_ref_keyword_identifier(key)? == expected,
        TypeTag::Symbol => value_ref_symbol_identifier(key)? == expected,
        TypeTag::String => key.as_string()? == expected,
        _ => false,
    })
}

fn value_ref_keyword_identifier(key: &ValueRef<'_>) -> Result<String> {
    let keyword = key.as_keyword()?;
    Ok(keyword_identifier(&keyword))
}

fn value_ref_symbol_identifier(key: &ValueRef<'_>) -> Result<String> {
    let symbol = key.as_symbol()?;
    Ok(symbol_identifier(&symbol))
}

fn type_ref_signature(ty: &TypeRef) -> String {
    match ty {
        TypeRef::Primitive(p) => match p {
            PrimitiveType::Nil => "nil".into(),
            PrimitiveType::Bool => "bool".into(),
            PrimitiveType::Int => "int".into(),
            PrimitiveType::UInt => "uint".into(),
            PrimitiveType::Float32 => "float32".into(),
            PrimitiveType::Float64 => "float64".into(),
            PrimitiveType::String => "string".into(),
            PrimitiveType::Bytes => "bytes".into(),
            PrimitiveType::Keyword => "keyword".into(),
            PrimitiveType::Symbol => "symbol".into(),
        },
        TypeRef::Named(name) => name.clone(),
        TypeRef::Vector(inner) => format!("vector<{}>", type_ref_signature(inner)),
        TypeRef::Set(inner) => format!("set<{}>", type_ref_signature(inner)),
        TypeRef::Map(key, value) => {
            let key_sig = type_ref_signature(key);
            let value_sig = type_ref_signature(value);
            format!("map<key={},value={}>", key_sig, value_sig)
        }
        TypeRef::Struct(def) => {
            let names: Vec<_> = def
                .fields
                .iter()
                .map(|field| format!("{}:{}", field.name, type_ref_signature(&field.ty)))
                .collect();
            format!("struct{{{}}}", names.join(","))
        }
        TypeRef::TaggedUnion(def) => {
            let names: Vec<_> = def
                .variants
                .iter()
                .map(|variant| match &variant.ty {
                    Some(ty) => format!("{}:{}", variant.name, type_ref_signature(ty)),
                    None => variant.name.to_string(),
                })
                .collect();
            format!("union{{{}}}", names.join("|"))
        }
    }
}

fn field_metadata(ty: &TypeRef) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    metadata.insert("rulia:type".into(), type_ref_signature(ty));
    metadata
}

fn variant_metadata(name: &str, ty: Option<&TypeRef>) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    metadata.insert("rulia:variant".into(), name.to_string());
    if let Some(ty) = ty {
        metadata.insert("rulia:type".into(), type_ref_signature(ty));
    }
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{
        Array, BooleanArray, Int64Array, ListArray, MapArray, StringArray, StringViewArray,
        StructArray,
    };
    use arrow::datatypes::DataType;
    use rulia::encode_value;
    use rulia::value::{Keyword, Symbol, TaggedValue};

    #[test]
    fn converts_struct_rows_to_record_batch() {
        let schema_text = "(defs=(Person=RuliaStruct((name=:string, age=:int))), root=:Person)";
        let schema = RuliaSchema::from_text(schema_text).expect("schema");
        let rows = vec![
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("name")),
                    Value::String("Alice".into()),
                ),
                (Value::Keyword(Keyword::simple("age")), Value::Int(30)),
            ]),
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("name")),
                    Value::String("Bob".into()),
                ),
                (Value::Keyword(Keyword::simple("age")), Value::Nil),
            ]),
        ];

        let batch = record_batch_from_values(&schema, &rows).expect("batch");
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 2);

        let name_col = batch.column(0);
        assert_eq!(string_value(name_col, 0), "Alice");
        assert_eq!(string_value(name_col, 1), "Bob");

        let age_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int column");
        assert_eq!(age_col.value(0), 30);
        assert!(age_col.is_null(1));
    }

    #[test]
    fn converts_nested_structs() {
        let schema_text = "(defs=(Address=RuliaStruct((street=:string, city=:string)), Person=RuliaStruct((name=:string, address=:Address))), root=:Person)";
        let schema = RuliaSchema::from_text(schema_text).expect("schema");
        let rows = vec![
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("name")),
                    Value::String("Ada".into()),
                ),
                (
                    Value::Keyword(Keyword::simple("address")),
                    Value::Map(vec![
                        (
                            Value::Keyword(Keyword::simple("street")),
                            Value::String("Main".into()),
                        ),
                        (
                            Value::Keyword(Keyword::simple("city")),
                            Value::String("Oxford".into()),
                        ),
                    ]),
                ),
            ]),
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("name")),
                    Value::String("Bob".into()),
                ),
                (Value::Keyword(Keyword::simple("address")), Value::Nil),
            ]),
        ];

        let batch = record_batch_from_values(&schema, &rows).expect("batch");
        assert_eq!(batch.num_columns(), 2);
        let schema = batch.schema();
        let schema_ref = schema.as_ref();
        assert_eq!(
            schema_ref.metadata().get("rulia:root"),
            Some(&"Person".to_string())
        );
        let field_meta = schema_ref.field(0).metadata();
        assert_eq!(field_meta.get("rulia:type"), Some(&"string".to_string()));

        let address_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<StructArray>()
            .expect("struct column");
        assert_eq!(address_col.num_columns(), 2);
        let street = address_col.column(0);
        assert_eq!(string_value(street, 0), "Main");
        assert!(string_is_null(street, 1));
        assert!(address_col.is_null(1));
    }

    #[test]
    fn converts_vectors_and_sets() {
        let schema_text = "(defs=(Row=RuliaStruct((name=:string, scores=RuliaVector(:int), tags=RuliaSet(:string)))), root=:Row)";
        let schema = RuliaSchema::from_text(schema_text).expect("schema");
        let rows = vec![
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("name")),
                    Value::String("Alice".into()),
                ),
                (
                    Value::Keyword(Keyword::simple("scores")),
                    Value::Vector(vec![Value::Int(10), Value::Int(20)]),
                ),
                (
                    Value::Keyword(Keyword::simple("tags")),
                    Value::Set(vec![Value::String("vip".into())]),
                ),
            ]),
            Value::Map(vec![
                (
                    Value::Keyword(Keyword::simple("name")),
                    Value::String("Bob".into()),
                ),
                (Value::Keyword(Keyword::simple("scores")), Value::Nil),
                (
                    Value::Keyword(Keyword::simple("tags")),
                    Value::Set(Vec::new()),
                ),
            ]),
        ];

        let batch = record_batch_from_values(&schema, &rows).expect("batch");
        let scores = batch
            .column(1)
            .as_any()
            .downcast_ref::<ListArray>()
            .expect("scores list");
        assert_eq!(scores.value(0).len(), 2);
        assert!(scores.is_null(1));

        let tags = batch
            .column(2)
            .as_any()
            .downcast_ref::<ListArray>()
            .expect("tags list");
        let tag_values = tags.value(0);
        assert_eq!(string_value(&tag_values, 0), "vip");
    }

    #[test]
    fn converts_maps() {
        let schema_text =
            "(defs=(Row=RuliaStruct((props=RuliaMap((key=:string, value=:int))))), root=:Row)";
        let schema = RuliaSchema::from_text(schema_text).expect("schema");
        let rows = vec![
            Value::Map(vec![(
                Value::Keyword(Keyword::simple("props")),
                Value::Map(vec![
                    (Value::String("height".into()), Value::Int(180)),
                    (Value::String("weight".into()), Value::Nil),
                ]),
            )]),
            Value::Map(vec![(Value::Keyword(Keyword::simple("props")), Value::Nil)]),
        ];

        let batch = record_batch_from_values(&schema, &rows).expect("batch");
        let map_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<MapArray>()
            .expect("map");
        assert_eq!(map_col.value(0).len(), 2);
        assert!(map_col.is_null(1));
    }

    #[test]
    fn builds_from_message_reader() {
        let schema_text = "(defs=(Row=RuliaStruct((value=:int))), root=:Row)";
        let schema = RuliaSchema::from_text(schema_text).expect("schema");
        let rows = vec![
            Value::Map(vec![(
                Value::Keyword(Keyword::simple("value")),
                Value::Int(42),
            )]),
            Value::Map(vec![(Value::Keyword(Keyword::simple("value")), Value::Nil)]),
        ];
        let message = Value::Vector(rows.clone());
        let bytes = encode_value(&message).expect("encode");
        let reader = MessageReader::new(&bytes).expect("reader");
        let batch = record_batch_from_reader(&schema, &reader).expect("batch");
        assert_eq!(batch.num_rows(), 2);
        let col = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int column");
        assert_eq!(col.value(0), 42);
        assert!(col.is_null(1));
    }

    #[test]
    fn converts_tagged_union() {
        let schema_value = Value::Map(vec![
            (
                Value::Keyword(Keyword::simple("defs")),
                Value::Map(vec![
                    (
                        Value::Keyword(Keyword::simple("Event")),
                        Value::Tagged(TaggedValue::new(
                            Symbol::parse("rulia/tagged-union"),
                            Value::Map(vec![
                                (
                                    Value::Keyword(Keyword::simple("event/created")),
                                    Value::Keyword(Keyword::simple("string")),
                                ),
                                (Value::Keyword(Keyword::simple("event/deleted")), Value::Nil),
                            ]),
                        )),
                    ),
                    (
                        Value::Keyword(Keyword::simple("Row")),
                        Value::Tagged(TaggedValue::new(
                            Symbol::parse("rulia/struct"),
                            Value::Map(vec![(
                                Value::Keyword(Keyword::simple("event")),
                                Value::Keyword(Keyword::simple("Event")),
                            )]),
                        )),
                    ),
                ]),
            ),
            (
                Value::Keyword(Keyword::simple("root")),
                Value::Keyword(Keyword::simple("Row")),
            ),
        ]);
        let schema = RuliaSchema::from_value(schema_value).expect("schema");
        let rows = vec![
            Value::Map(vec![(
                Value::Keyword(Keyword::simple("event")),
                Value::Tagged(TaggedValue::new(
                    Symbol::parse("event/created"),
                    Value::String("signup".into()),
                )),
            )]),
            Value::Map(vec![(
                Value::Keyword(Keyword::simple("event")),
                Value::Tagged(TaggedValue::new(Symbol::parse("event/deleted"), Value::Nil)),
            )]),
        ];

        let batch = record_batch_from_values(&schema, &rows).expect("batch");
        let event = batch
            .column(0)
            .as_any()
            .downcast_ref::<StructArray>()
            .expect("event struct");

        let schema = batch.schema();
        let event_field = schema.field(0);
        assert_eq!(
            event_field.metadata().get("rulia:type"),
            Some(&"Event".to_string())
        );
        if let DataType::Struct(children) = event_field.data_type() {
            let created_field = children
                .iter()
                .find(|f| f.name() == "event/created")
                .unwrap();
            assert_eq!(
                created_field.metadata().get("rulia:variant"),
                Some(&"event/created".to_string())
            );
            assert_eq!(
                created_field.metadata().get("rulia:type"),
                Some(&"string".to_string())
            );
            let deleted_field = children
                .iter()
                .find(|f| f.name() == "event/deleted")
                .unwrap();
            assert_eq!(
                deleted_field.metadata().get("rulia:variant"),
                Some(&"event/deleted".to_string())
            );
        } else {
            panic!("expected event field to be struct");
        }

        let created = event.column(0);
        assert_eq!(string_value(created, 0), "signup");
        assert!(string_is_null(created, 1));

        let deleted = event
            .column(1)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .expect("deleted flag");
        assert!(deleted.is_null(0));
        assert!(deleted.value(1));
    }

    fn string_value(array: &ArrayRef, idx: usize) -> &str {
        if let Some(view) = array.as_any().downcast_ref::<StringViewArray>() {
            view.value(idx)
        } else {
            array
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("string array")
                .value(idx)
        }
    }

    fn string_is_null(array: &ArrayRef, idx: usize) -> bool {
        if let Some(view) = array.as_any().downcast_ref::<StringViewArray>() {
            view.is_null(idx)
        } else {
            array
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("string array")
                .is_null(idx)
        }
    }
}
