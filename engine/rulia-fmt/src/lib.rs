mod ast;
mod error;
mod format;
mod parse;

pub use error::{ErrorCode, FormatError};

pub fn format(text: &str) -> Result<String, FormatError> {
    let value = parse::parse_value(text)?;
    Ok(format::format_value(&value))
}

pub fn check(text: &str) -> Result<(), FormatError> {
    let formatted = format(text)?;
    if formatted == text {
        Ok(())
    } else {
        let offset = first_difference_offset(text, &formatted);
        Err(FormatError::new(
            ErrorCode::NonCanonical,
            "text is not canonical",
            offset,
        ))
    }
}

fn first_difference_offset(left: &str, right: &str) -> Option<usize> {
    let mut idx = 0usize;
    let mut left_iter = left.as_bytes().iter();
    let mut right_iter = right.as_bytes().iter();
    loop {
        match (left_iter.next(), right_iter.next()) {
            (Some(l), Some(r)) => {
                if l != r {
                    return Some(idx);
                }
            }
            (None, None) => return None,
            _ => return Some(idx),
        }
        idx += 1;
    }
}
