use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SafeRelativePathError {
    BackslashSeparator,
    AbsolutePath,
    ForbiddenSegments,
    InvalidRelativePath,
}

pub(crate) fn safe_relative_path(path: &str) -> Result<&Path, SafeRelativePathError> {
    if path.contains('\\') {
        return Err(SafeRelativePathError::BackslashSeparator);
    }

    let relative = Path::new(path);
    if relative.is_absolute() {
        return Err(SafeRelativePathError::AbsolutePath);
    }

    let mut has_normal_segment = false;
    for component in relative.components() {
        match component {
            Component::Normal(_) => {
                has_normal_segment = true;
            }
            _ => return Err(SafeRelativePathError::ForbiddenSegments),
        }
    }
    if !has_normal_segment {
        return Err(SafeRelativePathError::InvalidRelativePath);
    }

    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::{safe_relative_path, SafeRelativePathError};

    #[test]
    fn safe_relative_path_accepts_normal_relative_path() {
        let relative = safe_relative_path("fixtures/bundle_minimal_v0/valid_bundle")
            .expect("path should be accepted");
        assert_eq!(
            relative.as_os_str(),
            "fixtures/bundle_minimal_v0/valid_bundle"
        );
    }

    #[test]
    fn safe_relative_path_rejects_backslash_before_other_checks() {
        let error = safe_relative_path("fixtures\\bundle_minimal_v0\\valid_bundle")
            .expect_err("path should be rejected");
        assert_eq!(error, SafeRelativePathError::BackslashSeparator);
    }

    #[test]
    fn safe_relative_path_rejects_absolute_before_component_validation() {
        let error = safe_relative_path("/tmp/../bundle").expect_err("path should be rejected");
        assert_eq!(error, SafeRelativePathError::AbsolutePath);
    }

    #[test]
    fn safe_relative_path_rejects_forbidden_segments() {
        let error = safe_relative_path("fixtures/../bundle").expect_err("path should be rejected");
        assert_eq!(error, SafeRelativePathError::ForbiddenSegments);
    }

    #[test]
    fn safe_relative_path_rejects_empty_path() {
        let error = safe_relative_path("").expect_err("path should be rejected");
        assert_eq!(error, SafeRelativePathError::InvalidRelativePath);
    }
}
