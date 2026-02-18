use blake3;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Blake3 => "blake3",
        }
    }

    pub fn digest_len(&self) -> usize {
        32
    }

    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
        }
    }

    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "sha256" => Some(HashAlgorithm::Sha256),
            "blake3" => Some(HashAlgorithm::Blake3),
            _ => None,
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            HashAlgorithm::Sha256 => 1,
            HashAlgorithm::Blake3 => 2,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(HashAlgorithm::Sha256),
            2 => Some(HashAlgorithm::Blake3),
            _ => None,
        }
    }
}
