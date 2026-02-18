use std::fs;
use std::path::{Path, PathBuf};

use rulia::text;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/formatting")
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
    ];

    for (input_rel, expected_rel) in fixtures {
        let input = read_fixture(input_rel);
        let expected = read_fixture(expected_rel);

        let value = text::parse(&input)
            .unwrap_or_else(|err| panic!("parse failed for {}: {}", input_rel, err));
        let rendered = text::to_canonical_string(&value);

        assert_eq!(
            rendered, expected,
            "canonical render mismatch for {}",
            input_rel
        );
        assert_eq!(
            input, expected,
            "canonical input does not match expected for {}",
            input_rel
        );

        let reparsed = text::parse(&rendered)
            .unwrap_or_else(|err| panic!("reparse failed for {}: {}", input_rel, err));
        let rendered_again = text::to_canonical_string(&reparsed);
        assert_eq!(
            rendered_again, rendered,
            "canonical render not stable for {}",
            input_rel
        );
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
        let value = text::parse(&input)
            .unwrap_or_else(|err| panic!("parse failed for {}: {}", input_rel, err));
        let rendered = text::to_canonical_string(&value);

        assert_ne!(
            input, rendered,
            "noncanonical input unexpectedly matched canonical output for {}",
            input_rel
        );
        assert_eq!(
            rendered, expected,
            "noncanonical input did not normalize to expected canonical output for {}",
            input_rel
        );

        let reparsed = text::parse(&rendered)
            .unwrap_or_else(|err| panic!("reparse failed for {}: {}", input_rel, err));
        let rendered_again = text::to_canonical_string(&reparsed);
        assert_eq!(
            rendered_again, rendered,
            "canonical render not stable for {}",
            input_rel
        );
    }
}
