use std::convert::TryInto;

use crate::error::{RuliaError, RuliaResult};

pub const MAGIC: &[u8; 4] = b"RULI";
pub const HEADER_SIZE: usize = 32;
pub const CURRENT_VERSION: u16 = 1;
pub const FLAG_MESSAGE_DIGEST: u16 = 0x0001;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub version: u16,
    pub flags: u16,
    pub root_pointer_offset: u64,
    pub dictionary_offset: u64,
    pub dictionary_length: u64,
}

impl Header {
    pub fn with_flags(
        flags: u16,
        root_pointer_offset: u64,
        dictionary_offset: u64,
        dictionary_length: u64,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            flags,
            root_pointer_offset,
            dictionary_offset,
            dictionary_length,
        }
    }

    pub fn encode(self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[..4].copy_from_slice(MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..16].copy_from_slice(&self.root_pointer_offset.to_le_bytes());
        buf[16..24].copy_from_slice(&self.dictionary_offset.to_le_bytes());
        buf[24..32].copy_from_slice(&self.dictionary_length.to_le_bytes());
        buf
    }

    pub fn parse(bytes: &[u8]) -> RuliaResult<(Self, &[u8])> {
        if bytes.len() < HEADER_SIZE {
            return Err(RuliaError::BufferTooSmall);
        }
        if &bytes[..4] != MAGIC {
            return Err(RuliaError::InvalidMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if version != CURRENT_VERSION {
            return Err(RuliaError::UnsupportedVersion(version));
        }
        let flags = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let root_pointer_offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let dictionary_offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let dictionary_length = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        Ok((
            Self {
                version,
                flags,
                root_pointer_offset,
                dictionary_offset,
                dictionary_length,
            },
            &bytes[HEADER_SIZE..],
        ))
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }
}
