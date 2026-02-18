use crate::error::{RuliaError, RuliaResult};

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeTag {
    Nil = 0,
    Bool = 1,
    Int = 2,
    UInt = 3,
    BigInt = 4,
    Float32 = 5,
    Float64 = 6,
    String = 7,
    Bytes = 8,
    Symbol = 9,
    Keyword = 10,
    Vector = 11,
    Set = 12,
    Map = 13,
    Tagged = 14,
    /// Annotated value: metadata map + inner value
    Annotated = 15,
}

impl TypeTag {
    pub fn from_u16(value: u16) -> RuliaResult<Self> {
        match value {
            0 => Ok(TypeTag::Nil),
            1 => Ok(TypeTag::Bool),
            2 => Ok(TypeTag::Int),
            3 => Ok(TypeTag::UInt),
            4 => Ok(TypeTag::BigInt),
            5 => Ok(TypeTag::Float32),
            6 => Ok(TypeTag::Float64),
            7 => Ok(TypeTag::String),
            8 => Ok(TypeTag::Bytes),
            9 => Ok(TypeTag::Symbol),
            10 => Ok(TypeTag::Keyword),
            11 => Ok(TypeTag::Vector),
            12 => Ok(TypeTag::Set),
            13 => Ok(TypeTag::Map),
            14 => Ok(TypeTag::Tagged),
            15 => Ok(TypeTag::Annotated),
            other => Err(RuliaError::UnknownTypeTag(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer(u64);

impl Pointer {
    pub fn new(tag: TypeTag, offset: u64) -> RuliaResult<Self> {
        if offset >= (1u64 << 48) {
            return Err(RuliaError::BuilderOffsetOverflow(offset));
        }
        let value = ((tag as u64) << 48) | offset;
        Ok(Self(value))
    }

    pub fn from_u64(raw: u64) -> RuliaResult<Self> {
        let tag = TypeTag::from_u16((raw >> 48) as u16)?;
        let offset = raw & ((1u64 << 48) - 1);
        Pointer::new(tag, offset)
    }

    pub fn to_u64(self) -> u64 {
        self.0
    }

    pub fn tag(self) -> TypeTag {
        TypeTag::from_u16((self.0 >> 48) as u16).expect("validated tag")
    }

    pub fn offset(self) -> u64 {
        self.0 & ((1u64 << 48) - 1)
    }
}
