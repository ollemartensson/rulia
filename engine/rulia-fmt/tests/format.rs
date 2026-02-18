use std::fs;
use std::path::{Path, PathBuf};

use rulia_fmt::{check, format, ErrorCode};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rulia")
        .join("tests")
        .join("formatting")
}

fn read_fixture(rel: &str) -> String {
    let path = fixture_root().join(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {}", path.display(), err))
}

#[test]
fn canonical_fixtures_are_stable() {
    let fixtures = [
        (
            "canonical/canonical_1.rjl",
            "canonical/canonical_1.expected.rjl",
        ),
        (
            "canonical/canonical_2.rjl",
            "canonical/canonical_2.expected.rjl",
        ),
        (
            "canonical/canonical_import.rjl",
            "canonical/canonical_import.expected.rjl",
        ),
        (
            "canonical/canonical_new.rjl",
            "canonical/canonical_new.expected.rjl",
        ),
    ];

    for (input_rel, expected_rel) in fixtures {
        let input = read_fixture(input_rel);
        let expected = read_fixture(expected_rel);
        let rendered =
            format(&input).unwrap_or_else(|err| panic!("format failed for {}: {}", input_rel, err));

        assert_eq!(rendered, expected, "format mismatch for {}", input_rel);
        assert_eq!(
            input, expected,
            "canonical input mismatch for {}",
            input_rel
        );
        check(&input).unwrap_or_else(|err| panic!("check failed for {}: {}", input_rel, err));
    }
}

#[test]
fn noncanonical_fixtures_are_normalized() {
    let expected = read_fixture("canonical/canonical_1.expected.rjl");
    let fixtures = [
        "noncanonical/noncanonical_whitespace.rjl",
        "noncanonical/noncanonical_commas.rjl",
        "noncanonical/noncanonical_order.rjl",
    ];

    for input_rel in fixtures {
        let input = read_fixture(input_rel);
        let rendered =
            format(&input).unwrap_or_else(|err| panic!("format failed for {}: {}", input_rel, err));

        assert_ne!(
            input, rendered,
            "unexpected canonical input for {}",
            input_rel
        );
        assert_eq!(rendered, expected, "normalize mismatch for {}", input_rel);

        let err = check(&input).expect_err("check should fail for noncanonical");
        assert_eq!(err.code, ErrorCode::NonCanonical);
    }
}

#[test]
fn import_and_new_fixtures_are_normalized() {
    let import_expected = read_fixture("canonical/canonical_import.expected.rjl");
    let new_expected = read_fixture("canonical/canonical_new.expected.rjl");

    let import_input = read_fixture("noncanonical/noncanonical_import.rjl");
    let new_input = read_fixture("noncanonical/noncanonical_new.rjl");

    let import_rendered = format(&import_input).expect("format import");
    let new_rendered = format(&new_input).expect("format new");

    assert_eq!(import_rendered, import_expected, "import not canonicalized");
    assert_eq!(new_rendered, new_expected, "new not canonicalized");

    let err = check(&import_input).expect_err("check should fail for noncanonical import");
    assert_eq!(err.code, ErrorCode::NonCanonical);
}

#[test]
fn invalid_syntax_reports_code_and_offset() {
    let input = read_fixture("invalid/invalid_syntax.rjl");
    let err = format(&input).expect_err("format should fail");
    assert_eq!(err.code, ErrorCode::Parse);
    assert_eq!(err.byte_offset, Some(3));
}
