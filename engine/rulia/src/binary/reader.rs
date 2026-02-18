use std::convert::TryInto;

use super::dictionary::Dictionary;
use super::header::{Header, FLAG_MESSAGE_DIGEST, HEADER_SIZE};
use super::pointer::Pointer;
use super::value_ref::ValueRef;
use crate::error::{RuliaError, RuliaResult};
use crate::hash::HashAlgorithm;
use hex;

pub struct MessageReader<'a> {
    buffer: &'a [u8],
    value_segment: &'a [u8],
    dictionary: Dictionary<'a>,
    header: Header,
    digest: Option<DigestInfo>,
}

struct DigestInfo {
    algorithm: HashAlgorithm,
    bytes: Vec<u8>,
}

impl<'a> MessageReader<'a> {
    pub fn new(buffer: &'a [u8]) -> RuliaResult<Self> {
        let (header, _) = Header::parse(buffer)?;
        let dict_start = header.dictionary_offset as usize;
        let dict_len = header.dictionary_length as usize;
        if buffer.len() < dict_start + dict_len {
            return Err(RuliaError::BufferTooSmall);
        }
        if dict_start < HEADER_SIZE {
            return Err(RuliaError::OffsetOutOfBounds(header.dictionary_offset));
        }
        let value_segment = &buffer[HEADER_SIZE..dict_start];
        let dict_slice = &buffer[dict_start..dict_start + dict_len];
        let (dictionary, _) = Dictionary::parse(dict_slice)?;
        let digest = if header.flags() & FLAG_MESSAGE_DIGEST != 0 {
            let digest_start = header.dictionary_offset + header.dictionary_length;
            let digest_start_usize = digest_start as usize;
            if digest_start_usize + 1 > buffer.len() {
                return Err(RuliaError::BufferTooSmall);
            }
            let algo_id = buffer[digest_start_usize];
            let algorithm = HashAlgorithm::from_id(algo_id)
                .ok_or_else(|| RuliaError::InvalidHash("unknown digest algorithm id".into()))?;
            let digest_len = algorithm.digest_len();
            if digest_start_usize + 1 + digest_len != buffer.len() {
                return Err(RuliaError::BufferTooSmall);
            }
            let digest_bytes = buffer[digest_start_usize + 1..].to_vec();
            let computed = algorithm.compute(&buffer[..digest_start_usize]);
            if digest_bytes != computed {
                return Err(RuliaError::HashMismatch {
                    expected: hex::encode(&digest_bytes),
                    actual: hex::encode(computed),
                });
            }
            Some(DigestInfo {
                algorithm,
                bytes: digest_bytes,
            })
        } else {
            None
        };
        Ok(Self {
            buffer,
            value_segment,
            dictionary,
            header,
            digest,
        })
    }

    pub fn root(&'a self) -> RuliaResult<RootRef<'a>> {
        let offset = self.header.root_pointer_offset as usize;
        if offset + 8 > self.buffer.len() {
            return Err(RuliaError::OffsetOutOfBounds(
                self.header.root_pointer_offset,
            ));
        }
        let raw = u64::from_le_bytes(self.buffer[offset..offset + 8].try_into().unwrap());
        let pointer = Pointer::from_u64(raw)?;
        Ok(RootRef {
            reader: self,
            pointer,
        })
    }

    pub(crate) fn read_bytes(&'a self, offset: u64, len: usize) -> RuliaResult<&'a [u8]> {
        let start = offset as usize;
        let end = start
            .checked_add(len)
            .ok_or(RuliaError::OffsetOutOfBounds(offset))?;
        if end > self.value_segment.len() {
            return Err(RuliaError::OffsetOutOfBounds(offset));
        }
        Ok(&self.value_segment[start..end])
    }

    pub(crate) fn read_u32(&'a self, offset: u64) -> RuliaResult<u32> {
        let bytes = self.read_bytes(offset, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn read_u64(&'a self, offset: u64) -> RuliaResult<u64> {
        let bytes = self.read_bytes(offset, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn read_pointer_at(&'a self, offset: u64) -> RuliaResult<Pointer> {
        let raw = self.read_u64(offset)?;
        Pointer::from_u64(raw)
    }

    pub(crate) fn dictionary(&'a self) -> &'a Dictionary<'a> {
        &self.dictionary
    }

    pub fn digest(&self) -> Option<(HashAlgorithm, &[u8])> {
        self.digest
            .as_ref()
            .map(|info| (info.algorithm, info.bytes.as_slice()))
    }
}

pub struct RootRef<'a> {
    reader: &'a MessageReader<'a>,
    pointer: Pointer,
}

impl<'a> RootRef<'a> {
    pub fn as_value(&self) -> ValueRef<'a> {
        ValueRef::new(self.reader, self.pointer)
    }

    pub fn deserialize(&self) -> RuliaResult<crate::value::Value> {
        self.as_value().to_value()
    }
}
