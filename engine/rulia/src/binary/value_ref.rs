use std::convert::TryInto;

use super::dictionary::DictionaryKind;
use super::pointer::{Pointer, TypeTag};
use super::reader::MessageReader;
use crate::error::{RuliaError, RuliaResult};
use crate::value::{Annotation, Keyword, Symbol, TaggedValue, Value};
use num_bigint::{BigInt, Sign};
use ordered_float::OrderedFloat;

pub struct ValueRef<'a> {
    pub(crate) reader: &'a MessageReader<'a>,
    pub(crate) pointer: Pointer,
}

impl<'a> Clone for ValueRef<'a> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader,
            pointer: self.pointer,
        }
    }
}

impl<'a> ValueRef<'a> {
    pub(crate) fn new(reader: &'a MessageReader<'a>, pointer: Pointer) -> Self {
        Self { reader, pointer }
    }

    pub fn kind(&self) -> TypeTag {
        self.pointer.tag()
    }

    pub fn as_bool(&self) -> RuliaResult<bool> {
        ensure_tag(self.pointer, TypeTag::Bool)?;
        let bytes = self.reader.read_bytes(self.pointer.offset(), 1)?;
        Ok(bytes[0] != 0)
    }

    pub fn as_int(&self) -> RuliaResult<i64> {
        ensure_tag(self.pointer, TypeTag::Int)?;
        let bytes = self.reader.read_bytes(self.pointer.offset(), 8)?;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn as_uint(&self) -> RuliaResult<u64> {
        ensure_tag(self.pointer, TypeTag::UInt)?;
        let bytes = self.reader.read_bytes(self.pointer.offset(), 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn as_float32(&self) -> RuliaResult<f32> {
        ensure_tag(self.pointer, TypeTag::Float32)?;
        let bytes = self.reader.read_bytes(self.pointer.offset(), 4)?;
        Ok(f32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn as_float64(&self) -> RuliaResult<f64> {
        ensure_tag(self.pointer, TypeTag::Float64)?;
        let bytes = self.reader.read_bytes(self.pointer.offset(), 8)?;
        Ok(f64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn as_string(&self) -> RuliaResult<&'a str> {
        read_dict_index(
            self.reader,
            self.pointer,
            TypeTag::String,
            DictionaryKind::String,
        )
    }

    pub fn as_symbol(&self) -> RuliaResult<Symbol> {
        let value = read_dict_index(
            self.reader,
            self.pointer,
            TypeTag::Symbol,
            DictionaryKind::Symbol,
        )?;
        Ok(Symbol::parse(value))
    }

    pub fn as_keyword(&self) -> RuliaResult<Keyword> {
        let value = read_dict_index(
            self.reader,
            self.pointer,
            TypeTag::Keyword,
            DictionaryKind::Keyword,
        )?;
        Ok(Keyword::parse(value))
    }

    pub fn as_bytes(&self) -> RuliaResult<&'a [u8]> {
        ensure_tag(self.pointer, TypeTag::Bytes)?;
        let len = self.reader.read_u32(self.pointer.offset())? as usize;
        let data_offset = self.pointer.offset() + 4;
        self.reader.read_bytes(data_offset, len)
    }

    pub fn tagged(&self) -> RuliaResult<(Symbol, ValueRef<'a>)> {
        ensure_tag(self.pointer, TypeTag::Tagged)?;
        let tag_index = self.reader.read_u32(self.pointer.offset())?;
        let tag_symbol = {
            let dict = self.reader.dictionary();
            let entry = dict.get(tag_index, DictionaryKind::Symbol)?;
            Symbol::parse(entry)
        };
        let value_ptr_offset = self.pointer.offset() + 8;
        let value_pointer = self.reader.read_pointer_at(value_ptr_offset)?;
        Ok((tag_symbol, ValueRef::new(self.reader, value_pointer)))
    }

    /// Get the metadata map and inner value for an annotated value.
    pub fn annotated(&self) -> RuliaResult<(ValueRef<'a>, ValueRef<'a>)> {
        ensure_tag(self.pointer, TypeTag::Annotated)?;
        let metadata_pointer = self.reader.read_pointer_at(self.pointer.offset())?;
        let value_pointer = self.reader.read_pointer_at(self.pointer.offset() + 8)?;
        Ok((
            ValueRef::new(self.reader, metadata_pointer),
            ValueRef::new(self.reader, value_pointer),
        ))
    }

    pub fn vector_iter(&self) -> RuliaResult<CollectionIter<'a>> {
        ensure_tag(self.pointer, TypeTag::Vector)?;
        let length = self.reader.read_u32(self.pointer.offset())? as usize;
        let start = self.pointer.offset() + 8;
        Ok(CollectionIter::new(self.reader, length, start))
    }

    pub fn set_iter(&self) -> RuliaResult<CollectionIter<'a>> {
        ensure_tag(self.pointer, TypeTag::Set)?;
        let length = self.reader.read_u32(self.pointer.offset())? as usize;
        let start = self.pointer.offset() + 8;
        Ok(CollectionIter::new(self.reader, length, start))
    }

    pub fn map_iter(&self) -> RuliaResult<MapIter<'a>> {
        ensure_tag(self.pointer, TypeTag::Map)?;
        let length = self.reader.read_u32(self.pointer.offset())? as usize;
        let start = self.pointer.offset() + 8;
        Ok(MapIter::new(self.reader, length, start))
    }

    pub fn to_value(&self) -> RuliaResult<Value> {
        match self.pointer.tag() {
            TypeTag::Nil => Ok(Value::Nil),
            TypeTag::Bool => Ok(Value::Bool(self.as_bool()?)),
            TypeTag::Int => Ok(Value::Int(self.as_int()?)),
            TypeTag::UInt => Ok(Value::UInt(self.as_uint()?)),
            TypeTag::Float32 => Ok(Value::Float32(OrderedFloat(self.as_float32()?))),
            TypeTag::Float64 => Ok(Value::Float64(OrderedFloat(self.as_float64()?))),
            TypeTag::String => Ok(Value::String(self.as_string()?.to_owned())),
            TypeTag::Symbol => Ok(Value::Symbol(self.as_symbol()?)),
            TypeTag::Keyword => Ok(Value::Keyword(self.as_keyword()?)),
            TypeTag::Bytes => Ok(Value::Bytes(self.as_bytes()?.to_vec())),
            TypeTag::BigInt => {
                let (sign, magnitude) = read_bigint(self.reader, self.pointer.offset())?;
                let bigint = BigInt::from_bytes_le(sign, &magnitude);
                Ok(Value::BigInt(bigint))
            }
            TypeTag::Vector => {
                let mut values = Vec::new();
                for element in self.vector_iter()? {
                    values.push(element?.to_value()?);
                }
                Ok(Value::Vector(values))
            }
            TypeTag::Set => {
                let mut values = Vec::new();
                for element in self.set_iter()? {
                    values.push(element?.to_value()?);
                }
                Ok(Value::Set(values))
            }
            TypeTag::Map => {
                let mut pairs = Vec::new();
                for entry in self.map_iter()? {
                    let (k, v) = entry?;
                    pairs.push((k.to_value()?, v.to_value()?));
                }
                Ok(Value::Map(pairs))
            }
            TypeTag::Tagged => {
                let (tag, value) = self.tagged()?;
                Ok(Value::Tagged(TaggedValue::new(tag, value.to_value()?)))
            }
            TypeTag::Annotated => {
                let (metadata_ref, value_ref) = self.annotated()?;
                // Metadata is stored as a map
                let mut metadata = Vec::new();
                for entry in metadata_ref.map_iter()? {
                    let (k, v) = entry?;
                    metadata.push((k.to_value()?, v.to_value()?));
                }
                let value = value_ref.to_value()?;
                Ok(Value::Annotated(Box::new(Annotation::new(metadata, value))))
            }
        }
    }
}

fn ensure_tag(pointer: Pointer, expected: TypeTag) -> RuliaResult<()> {
    if pointer.tag() != expected {
        return Err(RuliaError::UnexpectedValueKind("unexpected type"));
    }
    Ok(())
}

fn read_dict_index<'a>(
    reader: &'a MessageReader<'a>,
    pointer: Pointer,
    expected_tag: TypeTag,
    dict_kind: DictionaryKind,
) -> RuliaResult<&'a str> {
    ensure_tag(pointer, expected_tag)?;
    let index_bytes = reader.read_bytes(pointer.offset(), 4)?;
    let index = u32::from_le_bytes(index_bytes.try_into().unwrap());
    reader.dictionary().get(index, dict_kind)
}

fn read_bigint(reader: &MessageReader<'_>, offset: u64) -> RuliaResult<(Sign, Vec<u8>)> {
    let len = reader.read_u32(offset)? as usize;
    let sign_byte = reader.read_bytes(offset + 4, 1)?[0];
    let sign = match sign_byte {
        0 => Sign::NoSign,
        1 => Sign::Plus,
        2 => Sign::Minus,
        _ => return Err(RuliaError::UnexpectedValueKind("invalid bigint sign")),
    };
    let bytes = reader.read_bytes(offset + 8, len)?;
    Ok((sign, bytes.to_vec()))
}

pub struct CollectionIter<'a> {
    reader: &'a MessageReader<'a>,
    remaining: usize,
    next_offset: u64,
}

impl<'a> CollectionIter<'a> {
    pub(crate) fn new(reader: &'a MessageReader<'a>, length: usize, start_offset: u64) -> Self {
        Self {
            reader,
            remaining: length,
            next_offset: start_offset,
        }
    }
}

impl<'a> Iterator for CollectionIter<'a> {
    type Item = RuliaResult<ValueRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let result = self
            .reader
            .read_pointer_at(self.next_offset)
            .map(|ptr| ValueRef::new(self.reader, ptr));
        self.next_offset += 8;
        self.remaining -= 1;
        Some(result)
    }
}

pub struct MapIter<'a> {
    reader: &'a MessageReader<'a>,
    remaining: usize,
    next_offset: u64,
}

impl<'a> MapIter<'a> {
    pub(crate) fn new(reader: &'a MessageReader<'a>, length: usize, start_offset: u64) -> Self {
        Self {
            reader,
            remaining: length,
            next_offset: start_offset,
        }
    }
}

impl<'a> Iterator for MapIter<'a> {
    type Item = RuliaResult<(ValueRef<'a>, ValueRef<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let key = match self.reader.read_pointer_at(self.next_offset) {
            Ok(ptr) => ValueRef::new(self.reader, ptr),
            Err(err) => {
                self.remaining = 0;
                return Some(Err(err));
            }
        };
        self.next_offset += 8;
        let value = match self.reader.read_pointer_at(self.next_offset) {
            Ok(ptr) => ValueRef::new(self.reader, ptr),
            Err(err) => {
                self.remaining = 0;
                return Some(Err(err));
            }
        };
        self.next_offset += 8;
        self.remaining -= 1;
        Some(Ok((key, value)))
    }
}
