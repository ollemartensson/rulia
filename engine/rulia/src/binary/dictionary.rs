use std::collections::HashMap;
use std::convert::TryInto;

use crate::error::{RuliaError, RuliaResult};
use crate::value::{Keyword, Symbol};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DictionaryKind {
    String = 0,
    Symbol = 1,
    Keyword = 2,
}

impl DictionaryKind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DictionaryKind::String),
            1 => Some(DictionaryKind::Symbol),
            2 => Some(DictionaryKind::Keyword),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct DictionaryEntryOwned {
    kind: DictionaryKind,
    value: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum DictionaryKey {
    String(String),
    Symbol(String),
    Keyword(String),
}

impl DictionaryKey {
    fn as_value(&self) -> (&str, DictionaryKind) {
        match self {
            DictionaryKey::String(s) => (s, DictionaryKind::String),
            DictionaryKey::Symbol(s) => (s, DictionaryKind::Symbol),
            DictionaryKey::Keyword(s) => (s, DictionaryKind::Keyword),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DictionaryEntry<'a> {
    pub kind: DictionaryKind,
    pub value: &'a str,
}

#[derive(Clone, Debug)]
pub struct DictionaryBuilder {
    entries: Vec<DictionaryEntryOwned>,
    index: HashMap<DictionaryKey, u32>,
}

impl DictionaryBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub fn intern_string(&mut self, value: &str) -> u32 {
        self.intern(DictionaryKey::String(value.to_owned()))
    }

    pub fn intern_symbol(&mut self, symbol: &Symbol) -> u32 {
        self.intern(DictionaryKey::Symbol(symbol.to_string()))
    }

    pub fn intern_keyword(&mut self, keyword: &Keyword) -> u32 {
        self.intern(DictionaryKey::Keyword(keyword.to_string()))
    }

    fn intern(&mut self, key: DictionaryKey) -> u32 {
        if let Some(index) = self.index.get(&key).copied() {
            return index;
        }
        let index = self.entries.len() as u32;
        let (value, kind) = key.as_value();
        self.entries.push(DictionaryEntryOwned {
            kind,
            value: value.to_owned(),
        });
        self.index.insert(key, index);
        index
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            bytes.push(entry.kind as u8);
            let value_bytes = entry.value.as_bytes();
            bytes.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value_bytes);
        }
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct Dictionary<'a> {
    entries: Vec<DictionaryEntry<'a>>,
}

impl<'a> Dictionary<'a> {
    pub fn parse(buffer: &'a [u8]) -> RuliaResult<(Self, &'a [u8])> {
        if buffer.len() < 4 {
            return Err(RuliaError::BufferTooSmall);
        }
        let count = u32::from_le_bytes(buffer[..4].try_into().unwrap()) as usize;
        let mut entries = Vec::with_capacity(count);
        let mut offset = 4usize;
        for _ in 0..count {
            if offset >= buffer.len() {
                return Err(RuliaError::BufferTooSmall);
            }
            let kind = DictionaryKind::from_u8(buffer[offset])
                .ok_or(RuliaError::UnexpectedValueKind("dictionary"))?;
            offset += 1;
            if offset + 4 > buffer.len() {
                return Err(RuliaError::BufferTooSmall);
            }
            let len = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + len > buffer.len() {
                return Err(RuliaError::BufferTooSmall);
            }
            let slice = &buffer[offset..offset + len];
            let value = std::str::from_utf8(slice).map_err(|_| RuliaError::InvalidUtf8)?;
            entries.push(DictionaryEntry { kind, value });
            offset += len;
        }
        Ok((Self { entries }, &buffer[offset..]))
    }

    pub fn get(&self, index: u32, expected: DictionaryKind) -> RuliaResult<&'a str> {
        let Some(entry) = self.entries.get(index as usize) else {
            return Err(RuliaError::DictionaryIndexOutOfBounds(index));
        };
        if entry.kind != expected {
            return Err(RuliaError::UnexpectedValueKind("dictionary kind mismatch"));
        }
        Ok(entry.value)
    }
}
