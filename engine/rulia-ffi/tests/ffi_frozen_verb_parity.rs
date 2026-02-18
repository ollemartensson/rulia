use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|parent| parent.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn extract_header_pw_verbs(header_text: &str) -> Vec<String> {
    let mut verbs = BTreeSet::new();

    for line in header_text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("rulia_status_t ") else {
            continue;
        };
        let Some(open_paren_index) = rest.find('(') else {
            continue;
        };

        let symbol = &rest[..open_paren_index];
        if symbol.starts_with("rulia_v1_pw_")
            && symbol
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            verbs.insert(symbol.to_string());
        }
    }

    verbs.into_iter().collect()
}

fn read_frozen_verb_list(path: &Path) -> Vec<String> {
    read_text(path)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn extract_fn_block<'a>(source_text: &'a str, fn_name: &str) -> &'a str {
    let signature = format!("fn {fn_name}");
    let start_index = source_text
        .find(&signature)
        .unwrap_or_else(|| panic!("missing function {fn_name}"));
    let source_from_fn = &source_text[start_index..];
    let brace_offset = source_from_fn
        .find('{')
        .unwrap_or_else(|| panic!("missing function body for {fn_name}"));

    let mut depth = 0usize;
    for (offset, ch) in source_from_fn[brace_offset..].char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                let end = brace_offset + offset + ch.len_utf8();
                return &source_from_fn[..end];
            }
        }
    }

    panic!("unterminated function body for {fn_name}");
}

#[test]
fn frozen_pw_header_verbs_match_expected_manifest() {
    let workspace_root = workspace_root();
    let header_path = workspace_root.join("include/rulia_ffi_v1.h");
    let expected_list_path = workspace_root.join("docs/design/FFI_FROZEN_VERBS_V0.txt");

    let declared_verbs = extract_header_pw_verbs(&read_text(&header_path));
    let expected_verbs = read_frozen_verb_list(&expected_list_path);

    assert_eq!(declared_verbs, expected_verbs);
}

#[test]
fn frozen_pw_input_decoder_blocks_do_not_contain_alias_compat_patterns() {
    let workspace_root = workspace_root();
    let lib_path = workspace_root.join("crates/rulia-ffi/src/lib.rs");
    let lib_source = read_text(&lib_path);

    let decoder_blocks = [
        "map_get_exact_any",
        "require_canonical_keys",
        "verify_input_entries",
        "validate_format_field",
        "extract_required_bytes_field",
        "extract_optional_bytes_field",
        "parse_verify_receipt_input_bytes_v0",
        "parse_verify_obligation_input_bytes_v0",
        "parse_match_capabilities_input_bytes_v0",
    ]
    .into_iter()
    .map(|fn_name| extract_fn_block(&lib_source, fn_name))
    .collect::<Vec<_>>()
    .join("\n\n");

    let forbidden_patterns = [
        "map_get_any",
        "normalize_key",
        "rules_program",
        "camelCase",
        "alias",
    ];

    for pattern in forbidden_patterns {
        assert!(
            !decoder_blocks.contains(pattern),
            "forbidden parser compatibility pattern `{pattern}` found in frozen ABI decoder blocks"
        );
    }
}
