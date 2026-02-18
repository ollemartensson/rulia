use std::collections::HashSet;

use num_bigint::BigInt;

use super::dictionary::DictionaryBuilder;
use super::header::{Header, HEADER_SIZE};
use super::pointer::{Pointer, TypeTag};
use crate::error::{RuliaError, RuliaResult};
use crate::value::{Annotation, TaggedValue, Value};

pub struct MessageBuilder {
    dictionary: DictionaryBuilder,
    value_segment: Vec<u8>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        let value_segment = vec![0; 8]; // reserve space for root pointer
        Self {
            dictionary: DictionaryBuilder::new(),
            value_segment,
        }
    }

    pub fn encode(value: &Value) -> RuliaResult<Vec<u8>> {
        let builder = Self::new();
        builder.finish(value)
    }

    pub fn finish(self, value: &Value) -> RuliaResult<Vec<u8>> {
        self.finish_with_flags(value, 0)
    }

    pub fn finish_with_flags(mut self, value: &Value, flags: u16) -> RuliaResult<Vec<u8>> {
        let pointer = self.write_value(value)?;
        self.write_u64(0, pointer.to_u64());
        let dict_bytes = self.dictionary.to_bytes();
        let dict_offset = (HEADER_SIZE + self.value_segment.len()) as u64;
        let dict_len = dict_bytes.len() as u64;
        let header = Header::with_flags(flags, HEADER_SIZE as u64, dict_offset, dict_len);
        let mut buffer =
            Vec::with_capacity(HEADER_SIZE + self.value_segment.len() + dict_bytes.len());
        buffer.extend_from_slice(&header.encode());
        buffer.extend_from_slice(&self.value_segment);
        buffer.extend_from_slice(&dict_bytes);
        Ok(buffer)
    }

    fn write_value(&mut self, value: &Value) -> RuliaResult<Pointer> {
        match value {
            Value::Nil => Pointer::new(TypeTag::Nil, 0),
            Value::Bool(v) => {
                let offset = self.allocate(1, 1)?;
                self.value_segment[offset] = if *v { 1 } else { 0 };
                Pointer::new(TypeTag::Bool, offset as u64)
            }
            Value::Int(v) => {
                let offset = self.allocate(8, 8)?;
                self.value_segment[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
                Pointer::new(TypeTag::Int, offset as u64)
            }
            Value::UInt(v) => {
                let offset = self.allocate(8, 8)?;
                self.value_segment[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
                Pointer::new(TypeTag::UInt, offset as u64)
            }
            Value::BigInt(v) => self.write_bigint(v),
            Value::Float32(v) => {
                let offset = self.allocate(4, 4)?;
                self.value_segment[offset..offset + 4]
                    .copy_from_slice(&v.into_inner().to_le_bytes());
                Pointer::new(TypeTag::Float32, offset as u64)
            }
            Value::Float64(v) => {
                let offset = self.allocate(8, 8)?;
                self.value_segment[offset..offset + 8]
                    .copy_from_slice(&v.into_inner().to_le_bytes());
                Pointer::new(TypeTag::Float64, offset as u64)
            }
            Value::String(s) => {
                let idx = self.dictionary.intern_string(s);
                self.write_index(idx, TypeTag::String)
            }
            Value::Bytes(bytes) => {
                let offset = self.allocate(4 + bytes.len(), 4)?;
                let len = bytes.len() as u32;
                self.value_segment[offset..offset + 4].copy_from_slice(&len.to_le_bytes());
                self.value_segment[offset + 4..offset + 4 + bytes.len()].copy_from_slice(bytes);
                Pointer::new(TypeTag::Bytes, offset as u64)
            }
            Value::Symbol(sym) => {
                let idx = self.dictionary.intern_symbol(sym);
                self.write_index(idx, TypeTag::Symbol)
            }
            Value::Keyword(kw) => {
                let idx = self.dictionary.intern_keyword(kw);
                self.write_index(idx, TypeTag::Keyword)
            }
            Value::Vector(items) => self.write_collection(TypeTag::Vector, items),
            Value::Set(items) => self.write_set(items),
            Value::Map(entries) => self.write_map(entries),
            Value::Tagged(tagged) => self.write_tagged(tagged),
            Value::Annotated(annotation) => self.write_annotated(annotation),
        }
    }

    fn write_bigint(&mut self, value: &BigInt) -> RuliaResult<Pointer> {
        let (sign, bytes) = value.to_bytes_le();
        let sign_byte = match sign {
            num_bigint::Sign::NoSign => 0u8,
            num_bigint::Sign::Plus => 1u8,
            num_bigint::Sign::Minus => 2u8,
        };
        let total = 8 + bytes.len();
        let offset = self.allocate(total, 8)?;
        self.value_segment[offset..offset + 4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.value_segment[offset + 4] = sign_byte;
        self.value_segment[offset + 5..offset + 8].fill(0);
        self.value_segment[offset + 8..offset + 8 + bytes.len()].copy_from_slice(&bytes);
        Pointer::new(TypeTag::BigInt, offset as u64)
    }

    fn write_collection(&mut self, tag: TypeTag, items: &[Value]) -> RuliaResult<Pointer> {
        let len = items.len();
        let offset = self.allocate(8 + len * 8, 8)?;
        self.value_segment[offset..offset + 4].copy_from_slice(&(len as u32).to_le_bytes());
        self.value_segment[offset + 4..offset + 8].fill(0);
        let mut cursor = offset + 8;
        for item in items {
            let ptr = self.write_value(item)?;
            self.value_segment[cursor..cursor + 8].copy_from_slice(&ptr.to_u64().to_le_bytes());
            cursor += 8;
        }
        Pointer::new(tag, offset as u64)
    }

    fn write_set(&mut self, items: &[Value]) -> RuliaResult<Pointer> {
        let mut seen = HashSet::new();
        for item in items {
            if !seen.insert(item.clone()) {
                return Err(RuliaError::DuplicateSetValue);
            }
        }
        self.write_collection(TypeTag::Set, items)
    }

    fn write_map(&mut self, entries: &[(Value, Value)]) -> RuliaResult<Pointer> {
        let mut seen = HashSet::new();
        for (key, _) in entries {
            if !seen.insert(key.clone()) {
                return Err(RuliaError::DuplicateMapKey);
            }
        }
        let len = entries.len();
        let offset = self.allocate(8 + len * 16, 8)?;
        self.value_segment[offset..offset + 4].copy_from_slice(&(len as u32).to_le_bytes());
        self.value_segment[offset + 4..offset + 8].fill(0);
        let mut cursor = offset + 8;
        for (key, value) in entries {
            let key_ptr = self.write_value(key)?;
            self.value_segment[cursor..cursor + 8].copy_from_slice(&key_ptr.to_u64().to_le_bytes());
            cursor += 8;
            let value_ptr = self.write_value(value)?;
            self.value_segment[cursor..cursor + 8]
                .copy_from_slice(&value_ptr.to_u64().to_le_bytes());
            cursor += 8;
        }
        Pointer::new(TypeTag::Map, offset as u64)
    }

    fn write_tagged(&mut self, tagged: &TaggedValue) -> RuliaResult<Pointer> {
        let tag_index = self.dictionary.intern_symbol(&tagged.tag);
        let offset = self.allocate(16, 8)?;
        self.value_segment[offset..offset + 4].copy_from_slice(&tag_index.to_le_bytes());
        self.value_segment[offset + 4..offset + 8].fill(0);
        let value_ptr = self.write_value(&tagged.value)?;
        self.value_segment[offset + 8..offset + 16]
            .copy_from_slice(&value_ptr.to_u64().to_le_bytes());
        Pointer::new(TypeTag::Tagged, offset as u64)
    }

    /// Write an annotated value: metadata map pointer + inner value pointer
    fn write_annotated(&mut self, annotation: &Annotation) -> RuliaResult<Pointer> {
        // Write metadata as a map
        let metadata_ptr = self.write_map(&annotation.metadata)?;
        // Write inner value
        let value_ptr = self.write_value(&annotation.value)?;
        // Layout: [metadata_ptr: 8 bytes][value_ptr: 8 bytes]
        let offset = self.allocate(16, 8)?;
        self.value_segment[offset..offset + 8]
            .copy_from_slice(&metadata_ptr.to_u64().to_le_bytes());
        self.value_segment[offset + 8..offset + 16]
            .copy_from_slice(&value_ptr.to_u64().to_le_bytes());
        Pointer::new(TypeTag::Annotated, offset as u64)
    }

    fn write_index(&mut self, index: u32, tag: TypeTag) -> RuliaResult<Pointer> {
        let offset = self.allocate(4, 4)?;
        self.value_segment[offset..offset + 4].copy_from_slice(&index.to_le_bytes());
        Pointer::new(tag, offset as u64)
    }

    fn allocate(&mut self, size: usize, alignment: usize) -> RuliaResult<usize> {
        let current = self.value_segment.len();
        let aligned = align_to(current, alignment);
        if aligned > current {
            self.value_segment.resize(aligned, 0);
        }
        let end = aligned
            .checked_add(size)
            .ok_or(RuliaError::BuilderOffsetOverflow(aligned as u64))?;
        self.value_segment.resize(end, 0);
        if (end as u64) >= (1u64 << 48) {
            return Err(RuliaError::BuilderOffsetOverflow(end as u64));
        }
        Ok(aligned)
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.value_segment[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn align_to(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    let mask = alignment - 1;
    (value + mask) & !mask
}
