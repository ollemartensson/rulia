use std::fmt;

use num_bigint::BigInt;
use ordered_float::OrderedFloat;
use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};
use serde::forward_to_deserialize_any;
use serde::ser;
use serde::Serialize;

use crate::error::{RuliaError, RuliaResult};
use crate::value::{Keyword, Symbol, TaggedValue, Value};

#[derive(Debug)]
pub struct SerdeError(String);

impl fmt::Display for SerdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ser::Error for SerdeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        SerdeError(msg.to_string())
    }
}

impl de::Error for SerdeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        SerdeError(msg.to_string())
    }
}

impl std::error::Error for SerdeError {}

impl From<SerdeError> for RuliaError {
    fn from(value: SerdeError) -> Self {
        RuliaError::Serde(value.0)
    }
}

pub fn to_value<T>(value: &T) -> Result<Value, SerdeError>
where
    T: Serialize + ?Sized,
{
    value.serialize(ValueSerializer)
}

pub fn from_value<T>(value: Value) -> Result<T, SerdeError>
where
    T: DeserializeOwned,
{
    T::deserialize(ValueDeserializer { value })
}

pub fn to_bytes<T>(value: &T) -> RuliaResult<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    let dynamic = to_value(value).map_err(RuliaError::from)?;
    crate::encode_value(&dynamic)
}

pub fn from_bytes<T>(bytes: &[u8]) -> RuliaResult<T>
where
    T: DeserializeOwned,
{
    let value = crate::decode_value(bytes)?;
    from_value(value).map_err(RuliaError::from)
}

struct ValueSerializer;

impl ser::Serializer for ValueSerializer {
    type Ok = Value;
    type Error = SerdeError;
    type SerializeSeq = SeqSerializer;
    type SerializeTuple = SeqSerializer;
    type SerializeTupleStruct = SeqSerializer;
    type SerializeTupleVariant = VariantSeqSerializer;
    type SerializeMap = MapSerializer;
    type SerializeStruct = StructSerializer;
    type SerializeStructVariant = VariantStructSerializer;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Int(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        Ok(Value::BigInt(BigInt::from(v)))
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        Ok(Value::UInt(v))
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        Ok(Value::BigInt(BigInt::from(v)))
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Float32(OrderedFloat(v)))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Float64(OrderedFloat(v)))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(v.to_owned()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Bytes(v.to_vec()))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Nil)
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Nil)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Nil)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Tagged(TaggedValue::new(
            Symbol::simple(variant),
            Value::Nil,
        )))
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let inner = value.serialize(ValueSerializer)?;
        Ok(Value::Tagged(TaggedValue::new(
            Symbol::simple(variant),
            inner,
        )))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SeqSerializer {
            elements: Vec::with_capacity(len.unwrap_or(0)),
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(VariantSeqSerializer {
            tag: Symbol::simple(variant),
            elements: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(MapSerializer {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            next_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(StructSerializer {
            entries: Vec::with_capacity(len),
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(VariantStructSerializer {
            tag: Symbol::simple(variant),
            entries: Vec::with_capacity(len),
        })
    }

    fn collect_str<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + fmt::Display,
    {
        Ok(Value::String(value.to_string()))
    }
}

struct SeqSerializer {
    elements: Vec<Value>,
}

impl ser::SerializeSeq for SeqSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.elements.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Vector(self.elements))
    }
}

impl ser::SerializeTuple for SeqSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SeqSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        ser::SerializeSeq::end(self)
    }
}

struct VariantSeqSerializer {
    tag: Symbol,
    elements: Vec<Value>,
}

impl ser::SerializeTupleVariant for VariantSeqSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.elements.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Tagged(TaggedValue::new(
            self.tag,
            Value::Vector(self.elements),
        )))
    }
}

struct MapSerializer {
    entries: Vec<(Value, Value)>,
    next_key: Option<Value>,
}

impl ser::SerializeMap for MapSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        if self.next_key.is_some() {
            return Err(SerdeError(
                "serialize_value called before key was consumed".into(),
            ));
        }
        self.next_key = Some(key.serialize(ValueSerializer)?);
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let key = self
            .next_key
            .take()
            .ok_or_else(|| SerdeError("serialize_value called before key".into()))?;
        let val = value.serialize(ValueSerializer)?;
        self.entries.push((key, val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        if self.next_key.is_some() {
            return Err(SerdeError(
                "map serialization ended with dangling key".into(),
            ));
        }
        Ok(Value::Map(self.entries))
    }
}

struct StructSerializer {
    entries: Vec<(Value, Value)>,
}

struct VariantStructSerializer {
    tag: Symbol,
    entries: Vec<(Value, Value)>,
}

impl ser::SerializeStruct for StructSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let key_value = Value::Keyword(Keyword::simple(key));
        let value_value = value.serialize(ValueSerializer)?;
        self.entries.push((key_value, value_value));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Map(self.entries))
    }
}

impl ser::SerializeStructVariant for VariantStructSerializer {
    type Ok = Value;
    type Error = SerdeError;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let key_value = Value::Keyword(Keyword::simple(key));
        let value_value = value.serialize(ValueSerializer)?;
        self.entries.push((key_value, value_value));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Tagged(TaggedValue::new(
            self.tag,
            Value::Map(self.entries),
        )))
    }
}

struct ValueDeserializer {
    value: Value,
}

impl<'de> de::Deserializer<'de> for ValueDeserializer {
    type Error = SerdeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Value::Nil => visitor.visit_none(),
            Value::Bool(v) => visitor.visit_bool(v),
            Value::Int(v) => visitor.visit_i64(v),
            Value::UInt(v) => visitor.visit_u64(v),
            Value::BigInt(v) => visitor.visit_string(v.to_string()),
            Value::Float32(v) => visitor.visit_f32(v.into_inner()),
            Value::Float64(v) => visitor.visit_f64(v.into_inner()),
            Value::String(s) => visitor.visit_string(s),
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Symbol(s) => visitor.visit_string(s.as_str()),
            Value::Keyword(k) => visitor.visit_string(k.as_symbol().as_str()),
            Value::Vector(values) => {
                let len = values.len();
                let iter = values.into_iter().map(|v| ValueDeserializer { value: v });
                visitor.visit_seq(SeqDeserializer {
                    iter: iter.collect(),
                    index: 0,
                    len,
                })
            }
            Value::Set(values) => {
                let len = values.len();
                let iter = values.into_iter().map(|v| ValueDeserializer { value: v });
                visitor.visit_seq(SeqDeserializer {
                    iter: iter.collect(),
                    index: 0,
                    len,
                })
            }
            Value::Map(entries) => visitor.visit_map(MapDeserializer { entries, index: 0 }),
            Value::Tagged(tagged) => visitor.visit_enum(EnumDeserializer { tagged }),
            // For annotated values, deserialize the inner value (unwrap the annotation)
            Value::Annotated(annotation) => ValueDeserializer {
                value: annotation.unwrap(),
            }
            .deserialize_any(visitor),
        }
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Value::Nil => visitor.visit_none(),
            other => visitor.visit_some(ValueDeserializer { value: other }),
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        unit unit_struct newtype_struct seq tuple tuple_struct map struct identifier ignored_any
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Value::Tagged(tagged) => visitor.visit_enum(EnumDeserializer { tagged }),
            other => Err(SerdeError(format!(
                "expected tagged value for enum, found {:?}",
                other.kind()
            ))),
        }
    }
}

struct SeqDeserializer {
    iter: Vec<ValueDeserializer>,
    index: usize,
    len: usize,
}

impl<'de> de::SeqAccess<'de> for SeqDeserializer {
    type Error = SerdeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        if self.index >= self.len {
            return Ok(None);
        }
        let deserializer = self.iter[self.index].clone();
        self.index += 1;
        seed.deserialize(deserializer).map(Some)
    }
}

impl Clone for ValueDeserializer {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

struct MapDeserializer {
    entries: Vec<(Value, Value)>,
    index: usize,
}

impl<'de> de::MapAccess<'de> for MapDeserializer {
    type Error = SerdeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: de::DeserializeSeed<'de>,
    {
        if self.index >= self.entries.len() {
            return Ok(None);
        }
        let key_deserializer = ValueDeserializer {
            value: self.entries[self.index].0.clone(),
        };
        seed.deserialize(key_deserializer).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: de::DeserializeSeed<'de>,
    {
        let value_deserializer = ValueDeserializer {
            value: self.entries[self.index].1.clone(),
        };
        self.index += 1;
        seed.deserialize(value_deserializer)
    }
}

struct EnumDeserializer {
    tagged: TaggedValue,
}

impl<'de> de::EnumAccess<'de> for EnumDeserializer {
    type Error = SerdeError;
    type Variant = VariantDeserializer;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: de::DeserializeSeed<'de>,
    {
        let TaggedValue { tag, value } = self.tagged;
        let variant_name = tag.as_str();
        let variant = seed.deserialize(variant_name.into_deserializer())?;
        Ok((variant, VariantDeserializer { value }))
    }
}

struct VariantDeserializer {
    value: Box<Value>,
}

impl<'de> de::VariantAccess<'de> for VariantDeserializer {
    type Error = SerdeError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        match *self.value {
            Value::Nil => Ok(()),
            other => Err(SerdeError(format!(
                "expected unit variant payload, found {:?}",
                other.kind()
            ))),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        seed.deserialize(ValueDeserializer { value: *self.value })
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if let Value::Vector(values) = *self.value {
            visitor.visit_seq(SeqDeserializer {
                iter: values
                    .into_iter()
                    .map(|v| ValueDeserializer { value: v })
                    .collect(),
                index: 0,
                len,
            })
        } else {
            Err(SerdeError("expected tuple variant payload".into()))
        }
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if let Value::Map(entries) = *self.value {
            visitor.visit_map(MapDeserializer { entries, index: 0 })
        } else {
            Err(SerdeError("expected struct variant payload".into()))
        }
    }
}
