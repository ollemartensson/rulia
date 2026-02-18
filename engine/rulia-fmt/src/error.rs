use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Parse,
    NonCanonical,
    InvalidNumber,
    InvalidString,
    InvalidBytes,
    InvalidImportHash,
    Unsupported,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::Parse => "E_PARSE",
            ErrorCode::NonCanonical => "E_NONCANONICAL",
            ErrorCode::InvalidNumber => "E_INVALID_NUMBER",
            ErrorCode::InvalidString => "E_INVALID_STRING",
            ErrorCode::InvalidBytes => "E_INVALID_BYTES",
            ErrorCode::InvalidImportHash => "E_INVALID_IMPORT_HASH",
            ErrorCode::Unsupported => "E_UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError {
    pub code: ErrorCode,
    pub message: String,
    pub byte_offset: Option<usize>,
}

impl FormatError {
    pub fn new(code: ErrorCode, message: impl Into<String>, byte_offset: Option<usize>) -> Self {
        Self {
            code,
            message: message.into(),
            byte_offset,
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.byte_offset {
            Some(offset) => write!(
                f,
                "{}: {} at byte {}",
                self.code.as_str(),
                self.message,
                offset
            ),
            None => write!(f, "{}: {}", self.code.as_str(), self.message),
        }
    }
}

impl std::error::Error for FormatError {}
