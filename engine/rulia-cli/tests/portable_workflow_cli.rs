use assert_cmd::cargo::cargo_bin_cmd;
use ed25519_dalek::{Signer, SigningKey};
use rulia::{
    security::{fact_digest, DigestAlg},
    HashAlgorithm, Keyword, Symbol, TaggedValue, Value as RuliaValue,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: &str = "portable_workflow.offline_tools.result.v0";
const RECEIPT_SIGNATURE_DOMAIN: &str = "rulia:receipt:v0";
const TRUSTED_SIGNER_KEY_ID: &str = "key:test-signer-1";
const UNTRUSTED_SIGNER_KEY_ID: &str = "key:test-signer-2";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn copy_directory_recursive(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination directory");
    for entry in fs::read_dir(source).expect("read source directory") {
        let entry = entry.expect("read source directory entry");
        let entry_type = entry.file_type().expect("read source entry type");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry_type.is_dir() {
            copy_directory_recursive(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("copy source file");
        }
    }
}

fn write_import_rooted_assign_emit_end_fixture(root: &Path) -> PathBuf {
    let workflows = root.join("workflows");
    fs::create_dir_all(&workflows).expect("create workflows directory");
    let leaf_source = fs::read_to_string(fixture_path(
        "workflow_artifact_v0_subset/artifact_assign_emit_end.rjl",
    ))
    .expect("read artifact source fixture");
    fs::write(workflows.join("artifact_assign_emit_end.rjl"), leaf_source)
        .expect("write leaf artifact fixture");
    fs::write(
        workflows.join("root.rjl"),
        "import \"artifact_assign_emit_end.rjl\"\n",
    )
    .expect("write root import fixture");
    let main = root.join("main.rjl");
    fs::write(&main, "import \"workflows/root.rjl\"\n").expect("write main import fixture");
    main
}

fn assert_required_envelope(json: &Value, command: &str) {
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], command);
    assert_eq!(json["verdict"], "fail");
    assert!(json["failure_codes"].is_array());
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize_json_value).collect())
        }
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, entry_value) in entries {
                canonical.insert(key, canonicalize_json_value(entry_value));
            }
            Value::Object(canonical)
        }
        other => other,
    }
}

struct VerifyFixtureSet {
    _temp_dir: tempfile::TempDir,
    request_path: PathBuf,
    receipt_valid_path: PathBuf,
    receipt_hash_mismatch_path: PathBuf,
    receipt_invalid_signature_path: PathBuf,
    receipt_multi_failure_path: PathBuf,
    trust_dir: PathBuf,
    untrusted_trust_dir: PathBuf,
}

fn kw(name: &str) -> RuliaValue {
    RuliaValue::Keyword(Keyword::simple(name))
}

fn digest_value(hex: &str) -> RuliaValue {
    RuliaValue::Tagged(TaggedValue::new(
        Symbol::simple("digest"),
        RuliaValue::Map(vec![
            (kw("alg"), kw("sha256")),
            (kw("hex"), RuliaValue::String(hex.to_string())),
        ]),
    ))
}

fn request_v0_value() -> RuliaValue {
    RuliaValue::Tagged(TaggedValue::new(
        Symbol::simple("request_v0"),
        RuliaValue::Map(vec![
            (kw("format"), kw("rulia_request_v0")),
            (kw("step_id"), RuliaValue::String("S_http".to_string())),
            (kw("request_index"), RuliaValue::UInt(0)),
            (kw("capability_id"), kw("http_invoke")),
            (
                kw("capability_version"),
                RuliaValue::String("v1".to_string()),
            ),
            (kw("operation"), kw("post")),
        ]),
    ))
}

fn receipt_v0_value(request_hash_hex: &str, signer_key_id: &str, signature: Vec<u8>) -> RuliaValue {
    RuliaValue::Tagged(TaggedValue::new(
        Symbol::simple("receipt_v0"),
        RuliaValue::Map(vec![
            (kw("format"), kw("rulia_receipt_v0")),
            (kw("request_hash"), digest_value(request_hash_hex)),
            (
                kw("attestation"),
                RuliaValue::Map(vec![
                    (
                        kw("signer_key_id"),
                        RuliaValue::String(signer_key_id.to_string()),
                    ),
                    (kw("signature_alg"), kw("ed25519")),
                    (kw("scope"), kw("rulia_receipt_v0")),
                    (kw("sig"), RuliaValue::Bytes(signature)),
                ]),
            ),
        ]),
    ))
}

fn receipt_with_empty_signature(receipt: &RuliaValue) -> RuliaValue {
    let mut cloned = receipt.clone();
    let RuliaValue::Tagged(tagged) = &mut cloned else {
        panic!("receipt must be tagged");
    };
    let RuliaValue::Map(entries) = tagged.value.as_mut() else {
        panic!("receipt payload must be map");
    };
    let (_, attestation_value) = entries
        .iter_mut()
        .find(|(key, _)| matches!(key, RuliaValue::Keyword(keyword) if keyword.name() == "attestation"))
        .expect("receipt must include attestation");
    let RuliaValue::Map(attestation_entries) = attestation_value else {
        panic!("attestation must be map");
    };
    let (_, signature_value) = attestation_entries
        .iter_mut()
        .find(|(key, _)| matches!(key, RuliaValue::Keyword(keyword) if keyword.name() == "sig"))
        .expect("attestation must include sig");
    *signature_value = RuliaValue::Bytes(Vec::new());
    cloned
}

fn canonical_sha256_hex(value: &RuliaValue) -> String {
    let bytes = rulia::encode_canonical(value).expect("encode canonical value");
    hex::encode(HashAlgorithm::Sha256.compute(&bytes))
}

fn receipt_signature_input(receipt: &RuliaValue) -> Vec<u8> {
    let signing_body = receipt_with_empty_signature(receipt);
    let signing_body_bytes = rulia::encode_canonical(&signing_body).expect("encode signing body");
    let mut input =
        Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + 1 + signing_body_bytes.len());
    input.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN.as_bytes());
    input.push(0);
    input.extend_from_slice(&signing_body_bytes);
    input
}

fn sign_receipt(receipt: &RuliaValue, signing_key: &SigningKey) -> Vec<u8> {
    signing_key
        .sign(&receipt_signature_input(receipt))
        .to_bytes()
        .to_vec()
}

fn write_rulia_value(path: &Path, value: &RuliaValue) {
    let bytes = rulia::encode_canonical(value).expect("encode canonical fixture value");
    fs::write(path, bytes).expect("write canonical fixture value");
}

fn setup_verify_fixtures() -> VerifyFixtureSet {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let request_path = temp_dir.path().join("request.rulia.bin");
    let receipt_valid_path = temp_dir.path().join("receipt.valid.rulia.bin");
    let receipt_hash_mismatch_path = temp_dir.path().join("receipt.hash-mismatch.rulia.bin");
    let receipt_invalid_signature_path = temp_dir.path().join("receipt.sig-invalid.rulia.bin");
    let receipt_multi_failure_path = temp_dir.path().join("receipt.multi-failure.rulia.bin");
    let trust_dir = temp_dir.path().join("trust");
    let untrusted_trust_dir = temp_dir.path().join("trust-untrusted");
    fs::create_dir_all(&trust_dir).expect("create trust directory");
    fs::create_dir_all(&untrusted_trust_dir).expect("create untrusted trust directory");

    let request = request_v0_value();
    write_rulia_value(&request_path, &request);
    let request_hash_hex = canonical_sha256_hex(&request);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    fs::write(
        trust_dir.join(format!("{TRUSTED_SIGNER_KEY_ID}.pub")),
        verifying_key.to_bytes(),
    )
    .expect("write trusted public key");

    let other_signing_key = SigningKey::from_bytes(&[8u8; 32]);
    let other_verifying_key = other_signing_key.verifying_key();
    fs::write(
        untrusted_trust_dir.join(format!("{UNTRUSTED_SIGNER_KEY_ID}.pub")),
        other_verifying_key.to_bytes(),
    )
    .expect("write untrusted public key");

    let mut valid_receipt = receipt_v0_value(&request_hash_hex, TRUSTED_SIGNER_KEY_ID, Vec::new());
    let valid_signature = sign_receipt(&valid_receipt, &signing_key);
    valid_receipt = receipt_v0_value(&request_hash_hex, TRUSTED_SIGNER_KEY_ID, valid_signature);
    write_rulia_value(&receipt_valid_path, &valid_receipt);

    let mismatch_hash_hex = "11".repeat(32);
    let mut mismatch_receipt =
        receipt_v0_value(&mismatch_hash_hex, TRUSTED_SIGNER_KEY_ID, Vec::new());
    let mismatch_signature = sign_receipt(&mismatch_receipt, &signing_key);
    mismatch_receipt = receipt_v0_value(
        &mismatch_hash_hex,
        TRUSTED_SIGNER_KEY_ID,
        mismatch_signature,
    );
    write_rulia_value(&receipt_hash_mismatch_path, &mismatch_receipt);

    let mut invalid_signature = sign_receipt(&valid_receipt, &signing_key);
    invalid_signature[0] ^= 0xFF;
    let invalid_signature_receipt =
        receipt_v0_value(&request_hash_hex, TRUSTED_SIGNER_KEY_ID, invalid_signature);
    write_rulia_value(&receipt_invalid_signature_path, &invalid_signature_receipt);

    let mut multi_failure_signature = sign_receipt(&mismatch_receipt, &signing_key);
    multi_failure_signature[0] ^= 0x55;
    let multi_failure_receipt = receipt_v0_value(
        &mismatch_hash_hex,
        TRUSTED_SIGNER_KEY_ID,
        multi_failure_signature,
    );
    write_rulia_value(&receipt_multi_failure_path, &multi_failure_receipt);

    VerifyFixtureSet {
        _temp_dir: temp_dir,
        request_path,
        receipt_valid_path,
        receipt_hash_mismatch_path,
        receipt_invalid_signature_path,
        receipt_multi_failure_path,
        trust_dir,
        untrusted_trust_dir,
    }
}

#[test]
fn fact_digest_ignores_metadata_annotations() {
    let base = request_v0_value();
    let annotated = base.clone().with_doc("extra metadata");
    let alg = DigestAlg::Sha256;
    let base_digest = fact_digest(&base, alg).expect("fact digest base");
    let annotated_digest = fact_digest(&annotated, alg).expect("fact digest annotated");
    assert_eq!(base_digest, annotated_digest);
}

#[test]
fn fact_digest_ignores_nested_metadata_annotations() {
    let base = request_v0_value();
    let mut nested = base.clone();
    if let RuliaValue::Tagged(tagged) = &mut nested {
        if let RuliaValue::Map(entries) = tagged.value.as_mut() {
            if let Some((_, value)) = entries.iter_mut().find(
                |(key, _)| matches!(key, RuliaValue::Keyword(keyword) if keyword.name() == "operation"),
            ) {
                *value = value.clone().with_doc("nested metadata");
            }
        }
    }
    let alg = DigestAlg::Sha256;
    let base_digest = fact_digest(&base, alg).expect("base digest");
    let nested_digest = fact_digest(&nested, alg).expect("nested annotated digest");
    assert_eq!(base_digest, nested_digest);
}

#[test]
fn fact_digest_metadata_vectors_are_deterministic() {
    let base = request_v0_value();
    let mut nested_operation_annotated = base.clone();
    if let RuliaValue::Tagged(tagged) = &mut nested_operation_annotated {
        if let RuliaValue::Map(entries) = tagged.value.as_mut() {
            if let Some((_, value)) = entries.iter_mut().find(
                |(key, _)| matches!(key, RuliaValue::Keyword(keyword) if keyword.name() == "operation"),
            ) {
                *value = value.clone().with_doc("operation metadata");
            }
        }
    }
    let top_level_annotated = base.clone().with_doc("top-level metadata");
    let nested_then_top_level = nested_operation_annotated
        .clone()
        .with_doc("top-level metadata");

    let vectors = vec![
        ("base", base),
        ("nested_operation_annotated", nested_operation_annotated),
        ("top_level_annotated", top_level_annotated),
        ("nested_then_top_level", nested_then_top_level),
    ];

    let alg = DigestAlg::Sha256;
    let expected = fact_digest(&vectors[0].1, alg).expect("baseline digest");
    for (name, value) in &vectors {
        let digest = fact_digest(value, alg).unwrap_or_else(|_| panic!("digest {name}"));
        assert_eq!(
            digest, expected,
            "digest mismatch for metadata vector {name}"
        );
    }
}

#[test]
fn compile_artifact_assign_emit_end_matches_expected_evalir_fixture() {
    let artifact_path =
        fixture_path("workflow_artifact_v0_subset/artifact_assign_emit_end.rulia.bin");
    let expected_evalir_path = fixture_path("l2_evalir_v0/evalir_assign_emit_end.json");
    let out = tempfile::NamedTempFile::new().expect("create output file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "compile",
            "--artifact",
            artifact_path
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--out",
            out.path()
                .to_str()
                .expect("output path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow compile");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "compile");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));

    let actual_json: Value =
        serde_json::from_str(&fs::read_to_string(out.path()).expect("read compiled EvalIR output"))
            .expect("compiled EvalIR must be valid JSON");
    let expected_json: Value = serde_json::from_str(
        &fs::read_to_string(expected_evalir_path).expect("read expected EvalIR fixture"),
    )
    .expect("expected EvalIR fixture must be valid JSON");
    assert_eq!(
        canonicalize_json_value(actual_json),
        canonicalize_json_value(expected_json)
    );
}

#[test]
fn compile_artifact_request_suspend_matches_expected_evalir_fixture() {
    let artifact_path =
        fixture_path("workflow_artifact_v0_subset/artifact_request_suspend.rulia.bin");
    let expected_evalir_path = fixture_path("l2_evalir_v0/evalir_request_suspend.json");
    let out = tempfile::NamedTempFile::new().expect("create output file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "compile",
            "--artifact",
            artifact_path
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--out",
            out.path()
                .to_str()
                .expect("output path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow compile");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "compile");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));

    let actual_json: Value =
        serde_json::from_str(&fs::read_to_string(out.path()).expect("read compiled EvalIR output"))
            .expect("compiled EvalIR must be valid JSON");
    let expected_json: Value = serde_json::from_str(
        &fs::read_to_string(expected_evalir_path).expect("read expected EvalIR fixture"),
    )
    .expect("expected EvalIR fixture must be valid JSON");
    assert_eq!(
        canonicalize_json_value(actual_json),
        canonicalize_json_value(expected_json)
    );
}

#[test]
fn compile_artifact_expression_assign_request_matches_expected_evalir_fixture() {
    let artifact_path = fixture_path(
        "workflow_artifact_v0_subset/artifact_expression_assign_request_suspend.rulia.bin",
    );
    let expected_evalir_path =
        fixture_path("l2_evalir_v0/evalir_from_artifact_expression_assign_request_suspend.json");
    let out = tempfile::NamedTempFile::new().expect("create output file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "compile",
            "--artifact",
            artifact_path
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--out",
            out.path()
                .to_str()
                .expect("output path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow compile");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "compile");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));

    let actual_json: Value =
        serde_json::from_str(&fs::read_to_string(out.path()).expect("read compiled EvalIR output"))
            .expect("compiled EvalIR must be valid JSON");
    let expected_json: Value = serde_json::from_str(
        &fs::read_to_string(expected_evalir_path).expect("read expected EvalIR fixture"),
    )
    .expect("expected EvalIR fixture must be valid JSON");
    assert_eq!(
        canonicalize_json_value(actual_json),
        canonicalize_json_value(expected_json)
    );
}

#[test]
fn compile_artifact_choose_rules_branch_is_compatibility_gated() {
    let artifact_path =
        fixture_path("workflow_artifact_v0_subset/artifact_choose_rules_branch.rulia.bin");
    let out = tempfile::NamedTempFile::new().expect("create output file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "compile",
            "--artifact",
            artifact_path
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--out",
            out.path()
                .to_str()
                .expect("output path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow compile");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "compile");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_STEP_CONTRACT"]));
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("EVAL.E_STEP_CONTRACT".to_string())
    );
}

#[test]
fn compile_import_rooted_artifact_matches_expected_evalir_fixture() {
    let fixture_dir = tempfile::tempdir().expect("create temp fixture dir");
    let entrypoint = write_import_rooted_assign_emit_end_fixture(fixture_dir.path());
    let expected_evalir_path = fixture_path("l2_evalir_v0/evalir_assign_emit_end.json");
    let out = tempfile::NamedTempFile::new().expect("create output file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "compile",
            "--artifact",
            entrypoint
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--out",
            out.path()
                .to_str()
                .expect("output path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow compile");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "compile");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));

    let actual_json: Value =
        serde_json::from_str(&fs::read_to_string(out.path()).expect("read compiled EvalIR output"))
            .expect("compiled EvalIR must be valid JSON");
    let expected_json: Value = serde_json::from_str(
        &fs::read_to_string(expected_evalir_path).expect("read expected EvalIR fixture"),
    )
    .expect("expected EvalIR fixture must be valid JSON");
    assert_eq!(
        canonicalize_json_value(actual_json),
        canonicalize_json_value(expected_json)
    );
}

#[test]
fn compile_invalid_artifact_reports_deterministic_failure_code() {
    let artifact = tempfile::NamedTempFile::new().expect("create artifact file");
    fs::write(artifact.path(), [0xFF, 0x00, 0xAA]).expect("write invalid artifact bytes");
    let out = tempfile::NamedTempFile::new().expect("create output file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "compile",
            "--artifact",
            artifact
                .path()
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--out",
            out.path()
                .to_str()
                .expect("output path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow compile");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "compile");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_STATE_INVALID"]));
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("EVAL.E_STATE_INVALID".to_string())
    );
}

#[test]
fn validate_smoke_outputs_required_json() {
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--level",
            "L0",
            "--artifact",
            "artifact.rulia.bin",
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_required_envelope(&json, "validate");
}

#[test]
fn validate_l1_missing_artifact_reports_deterministic_failure_code() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let missing_artifact = temp_dir.path().join("missing-artifact.rulia.bin");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--level",
            "L1",
            "--artifact",
            missing_artifact
                .to_str()
                .expect("artifact path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_STATE_INVALID"]));
    assert_eq!(json["details"]["level_results"][0]["level"], "L1");
    assert_eq!(
        json["details"]["level_results"][0]["failure_codes"],
        json!(["EVAL.E_STATE_INVALID"])
    );
    assert_eq!(json["details"]["level_results"][0]["verdict"], "fail");
}

#[test]
fn validate_l1_empty_artifact_reports_artifact_identity_failure() {
    let empty_artifact = tempfile::NamedTempFile::new().expect("create empty artifact file");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--level",
            "L1",
            "--artifact",
            empty_artifact
                .path()
                .to_str()
                .expect("artifact path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_ARTIFACT_IDENTITY"]));
    assert_eq!(json["details"]["level_results"][0]["level"], "L1");
    assert_eq!(
        json["details"]["level_results"][0]["failure_codes"],
        json!(["EVAL.E_ARTIFACT_IDENTITY"])
    );
    assert_eq!(json["details"]["level_results"][0]["verdict"], "fail");
}

#[test]
fn validate_l1_non_empty_artifact_passes_and_emits_hash() {
    let artifact = tempfile::NamedTempFile::new().expect("create artifact file");
    let artifact_bytes = b"\xAA\xBB\xCC";
    fs::write(artifact.path(), artifact_bytes).expect("write artifact bytes");
    let expected_hash = format!(
        "sha256:{}",
        hex::encode(HashAlgorithm::Sha256.compute(artifact_bytes))
    );

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--level",
            "L1",
            "--artifact",
            artifact
                .path()
                .to_str()
                .expect("artifact path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(json["details"]["artifact_hash"], expected_hash);
    assert_eq!(
        json["details"]["level_results"][0]["artifact_hash"],
        expected_hash
    );
    assert_eq!(json["details"]["level_results"][0]["level"], "L1");
    assert_eq!(
        json["details"]["level_results"][0]["failure_codes"],
        json!([])
    );
    assert_eq!(json["details"]["level_results"][0]["verdict"], "pass");
}

#[test]
fn validate_bundle_missing_manifest_reports_deterministic_failure_code() {
    let bundle = fixture_path("bundle_minimal_v0/missing_manifest");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--bundle",
            bundle.to_str().expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_STATE_INVALID"]));
}

#[test]
fn validate_bundle_valid_fixture_passes_with_hash_details() {
    let bundle = fixture_path("bundle_minimal_v0/valid_bundle");
    let artifact_path = bundle.join("artifact").join("ir.rulia.bin");
    let artifact_bytes = fs::read(&artifact_path).expect("read artifact fixture");
    let expected_artifact_hash = format!(
        "sha256:{}",
        hex::encode(HashAlgorithm::Sha256.compute(&artifact_bytes))
    );

    let manifest_path = bundle.join("manifest.rulia.bin");
    let manifest_bytes = fs::read(&manifest_path).expect("read manifest fixture");
    let expected_manifest_hash = format!(
        "sha256:{}",
        hex::encode(HashAlgorithm::Sha256.compute(&manifest_bytes))
    );

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--bundle",
            bundle.to_str().expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(
        json["details"]["artifact_path"],
        Value::String("artifact/ir.rulia.bin".to_string())
    );
    assert_eq!(json["details"]["artifact_hash"], expected_artifact_hash);
    assert_eq!(
        json["details"]["bundle_manifest_hash"],
        expected_manifest_hash
    );
}

#[test]
fn validate_bundle_hash_mismatch_reports_artifact_identity_failure() {
    let bundle = fixture_path("bundle_minimal_v0/hash_mismatch");
    let artifact_path = bundle.join("artifact").join("ir.rulia.bin");
    let artifact_bytes = fs::read(&artifact_path).expect("read artifact fixture");
    let actual_artifact_hash = format!(
        "sha256:{}",
        hex::encode(HashAlgorithm::Sha256.compute(&artifact_bytes))
    );

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--bundle",
            bundle.to_str().expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_ARTIFACT_IDENTITY"]));
    assert_eq!(
        json["details"]["artifact_path"],
        Value::String("artifact/ir.rulia.bin".to_string())
    );
    assert_eq!(json["details"]["artifact_hash"], actual_artifact_hash);
    assert!(json["details"]["expected_artifact_hash"]
        .as_str()
        .map(|value| value.starts_with("sha256:"))
        .unwrap_or(false));
}

#[test]
fn validate_bundle_root_artifact_without_manifest_passes_with_recursive_imports() {
    let bundle = tempfile::tempdir().expect("create bundle fixture dir");
    let entrypoint = write_import_rooted_assign_emit_end_fixture(bundle.path());
    let expected_value =
        rulia::text::parse_file_with_options(&entrypoint, rulia::ParseOptions::default())
            .expect("parse import-rooted workflow");
    let expected_bytes =
        rulia::encode_canonical(&expected_value).expect("encode canonical workflow");
    let expected_hash = format!(
        "sha256:{}",
        hex::encode(HashAlgorithm::Sha256.compute(&expected_bytes))
    );

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--bundle",
            bundle
                .path()
                .to_str()
                .expect("bundle path should be valid UTF-8"),
            "--artifact",
            "main.rjl",
        ])
        .output()
        .expect("run portable-workflow validate");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(
        json["details"]["artifact_path"],
        Value::String("main.rjl".to_string())
    );
    assert_eq!(
        json["details"]["artifact_hash"],
        Value::String(expected_hash)
    );
}

#[test]
fn validate_bundle_root_artifact_missing_import_fails_deterministically() {
    let bundle = tempfile::tempdir().expect("create bundle fixture dir");
    fs::write(
        bundle.path().join("main.rjl"),
        "import \"missing/artifact.rjl\"\n",
    )
    .expect("write root artifact with missing import");
    let bundle_path = bundle
        .path()
        .to_str()
        .expect("bundle path should be valid UTF-8")
        .to_string();

    let output_first = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--bundle",
            bundle_path.as_str(),
            "--artifact",
            "main.rjl",
        ])
        .output()
        .expect("run portable-workflow validate (first run)");
    let output_second = cargo_bin_cmd!("portable-workflow")
        .args([
            "validate",
            "--bundle",
            bundle_path.as_str(),
            "--artifact",
            "main.rjl",
        ])
        .output()
        .expect("run portable-workflow validate (second run)");

    assert_eq!(output_first.status.code(), Some(1));
    assert_eq!(output_second.status.code(), Some(1));
    assert_eq!(output_first.stdout, output_second.stdout);
    let json: Value = serde_json::from_slice(&output_first.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "validate");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["EVAL.E_STATE_INVALID"]));
}

#[test]
fn verify_receipt_passes_with_trusted_signer() {
    let fixtures = setup_verify_fixtures();
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--request",
            fixtures
                .request_path
                .to_str()
                .expect("request path should be valid UTF-8"),
            "--receipt",
            fixtures
                .receipt_valid_path
                .to_str()
                .expect("receipt path should be valid UTF-8"),
            "--trust",
            fixtures
                .trust_dir
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
}

#[test]
fn verify_receipt_fails_with_request_hash_mismatch() {
    let fixtures = setup_verify_fixtures();
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--request",
            fixtures
                .request_path
                .to_str()
                .expect("request path should be valid UTF-8"),
            "--receipt",
            fixtures
                .receipt_hash_mismatch_path
                .to_str()
                .expect("receipt path should be valid UTF-8"),
            "--trust",
            fixtures
                .trust_dir
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["PROTOCOL.request_hash_mismatch"])
    );
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.request_hash_mismatch".to_string())
    );
}

#[test]
fn verify_receipt_fails_with_untrusted_signer() {
    let fixtures = setup_verify_fixtures();
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--request",
            fixtures
                .request_path
                .to_str()
                .expect("request path should be valid UTF-8"),
            "--receipt",
            fixtures
                .receipt_valid_path
                .to_str()
                .expect("receipt path should be valid UTF-8"),
            "--trust",
            fixtures
                .untrusted_trust_dir
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["PROTOCOL.untrusted_signer"]));
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.untrusted_signer".to_string())
    );
}

#[test]
fn verify_receipt_fails_with_invalid_signature() {
    let fixtures = setup_verify_fixtures();
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--request",
            fixtures
                .request_path
                .to_str()
                .expect("request path should be valid UTF-8"),
            "--receipt",
            fixtures
                .receipt_invalid_signature_path
                .to_str()
                .expect("receipt path should be valid UTF-8"),
            "--trust",
            fixtures
                .trust_dir
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["PROTOCOL.signature_invalid"]));
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.signature_invalid".to_string())
    );
}

#[test]
fn verify_receipt_reports_multi_failure_order_deterministically() {
    let fixtures = setup_verify_fixtures();
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--request",
            fixtures
                .request_path
                .to_str()
                .expect("request path should be valid UTF-8"),
            "--receipt",
            fixtures
                .receipt_multi_failure_path
                .to_str()
                .expect("receipt path should be valid UTF-8"),
            "--trust",
            fixtures
                .trust_dir
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!([
            "PROTOCOL.request_hash_mismatch",
            "PROTOCOL.signature_invalid"
        ])
    );
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.request_hash_mismatch".to_string())
    );
}

#[test]
fn verify_obligation_passes_with_matching_valid_receipt_from_bundle_history() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--obligation",
            fixture_root
                .join("obligation.rulia.bin")
                .to_str()
                .expect("obligation path should be valid UTF-8"),
            "--bundle",
            fixture_root
                .join("bundle")
                .join("pass")
                .to_str()
                .expect("bundle path should be valid UTF-8"),
            "--trust",
            fixture_root
                .join("trust")
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify for obligation pass");

    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(json["details"]["mode"], "obligation");
    assert_eq!(json["details"]["satisfaction"], "satisfied");
}

#[test]
fn verify_obligation_fails_with_missing_receipt_from_bundle_history() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--obligation",
            fixture_root
                .join("obligation.rulia.bin")
                .to_str()
                .expect("obligation path should be valid UTF-8"),
            "--bundle",
            fixture_root
                .join("bundle")
                .join("missing")
                .to_str()
                .expect("bundle path should be valid UTF-8"),
            "--trust",
            fixture_root
                .join("trust")
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify for obligation missing-receipt");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["PROTOCOL.missing_receipt"]));
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.missing_receipt".to_string())
    );
    assert_eq!(json["details"]["satisfaction"], "unsatisfied");
}

#[test]
fn verify_obligation_fails_with_invalid_signature_from_bundle_history() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--obligation",
            fixture_root
                .join("obligation.rulia.bin")
                .to_str()
                .expect("obligation path should be valid UTF-8"),
            "--bundle",
            fixture_root
                .join("bundle")
                .join("invalid_signature")
                .to_str()
                .expect("bundle path should be valid UTF-8"),
            "--trust",
            fixture_root
                .join("trust")
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify for obligation invalid-signature");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["failure_codes"], json!(["PROTOCOL.signature_invalid"]));
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.signature_invalid".to_string())
    );
    assert_eq!(json["details"]["satisfaction"], "unsatisfied");
}

#[test]
fn verify_obligation_reports_multi_failure_order_deterministically() {
    let fixture_root = fixture_path("obligation_receipt_valid_v0");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "verify",
            "--obligation",
            fixture_root
                .join("obligation.rulia.bin")
                .to_str()
                .expect("obligation path should be valid UTF-8"),
            "--history",
            fixture_root
                .join("history")
                .join("multi_failure")
                .to_str()
                .expect("history path should be valid UTF-8"),
            "--trust",
            fixture_root
                .join("trust")
                .to_str()
                .expect("trust path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow verify for obligation multi-failure");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "verify");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["PROTOCOL.untrusted_signer", "PROTOCOL.signature_invalid"])
    );
    assert_eq!(
        json["details"]["primary_failure"],
        Value::String("PROTOCOL.untrusted_signer".to_string())
    );
    assert_eq!(json["details"]["satisfaction"], "unsatisfied");
}

#[test]
fn match_cap_passes_when_all_required_capabilities_are_satisfied() {
    let fixture = fixture_path("match_cap_v0/pass");
    let requirements_path = fixture.join("requirements.rulia.bin");
    let gamma_cap_path = fixture.join("gamma_cap.rulia.bin");

    let output_first = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--requirements",
            requirements_path
                .to_str()
                .expect("requirements path should be valid UTF-8"),
            "--gamma-cap",
            gamma_cap_path
                .to_str()
                .expect("gamma_cap path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap (first pass fixture run)");
    let output_second = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--requirements",
            requirements_path
                .to_str()
                .expect("requirements path should be valid UTF-8"),
            "--gamma-cap",
            gamma_cap_path
                .to_str()
                .expect("gamma_cap path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap (second pass fixture run)");

    assert_eq!(output_first.status.code(), Some(0));
    assert_eq!(output_first.stdout, output_second.stdout);

    let json: Value = serde_json::from_slice(&output_first.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(json["details"]["status"], "accepted");
    assert_eq!(
        json["details"]["matched_required"][0]["requirement_id"],
        "net.egress"
    );
    assert_eq!(json["details"]["unmet_required"], json!([]));
}

#[test]
fn match_cap_bundle_passes_with_manifest_autodiscovery() {
    let fixture = fixture_path("match_cap_v0/bundle/pass");
    let output_first = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--bundle",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap with bundle autodiscovery (first run)");
    let output_second = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--bundle",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap with bundle autodiscovery (second run)");

    assert_eq!(output_first.status.code(), Some(0));
    assert_eq!(output_first.stdout, output_second.stdout);

    let json: Value = serde_json::from_slice(&output_first.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(json["details"]["status"], "accepted");
    assert_eq!(
        json["details"]["matched_required"][0]["requirement_id"],
        "net.egress"
    );
    assert_eq!(json["details"]["unmet_required"], json!([]));
}

#[test]
fn match_cap_bundle_missing_requirements_ref_fails_deterministically() {
    let fixture = fixture_path("match_cap_v0/bundle/missing_requirements_ref");
    let output_first = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--bundle",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap with missing requirements ref (first run)");
    let output_second = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--bundle",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap with missing requirements ref (second run)");

    assert_eq!(output_first.status.code(), Some(1));
    assert_eq!(output_first.stdout, output_second.stdout);

    let json: Value = serde_json::from_slice(&output_first.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["CAPABILITY.constraint_violation"])
    );
    assert_eq!(json["details"]["status"], "reject");
    assert_eq!(
        json["details"]["primary_failure"],
        "CAPABILITY.constraint_violation"
    );
    assert!(
        json["details"]["schema_issue"]
            .as_str()
            .map(|issue| issue.contains("capability_requirements_ref.path"))
            .unwrap_or(false),
        "expected missing capability requirements reference issue, got {:?}",
        json["details"]["schema_issue"]
    );
}

#[test]
fn match_cap_reports_missing_required_capability_deterministically() {
    let fixture = fixture_path("match_cap_v0/missing_required_capability");
    let requirements_path = fixture.join("requirements.rulia.bin");
    let gamma_cap_path = fixture.join("gamma_cap.rulia.bin");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--requirements",
            requirements_path
                .to_str()
                .expect("requirements path should be valid UTF-8"),
            "--gamma-cap",
            gamma_cap_path
                .to_str()
                .expect("gamma_cap path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap (missing required capability)");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["CAPABILITY.missing_required_capability"])
    );
    assert_eq!(json["details"]["status"], "reject");
    assert_eq!(
        json["details"]["primary_failure"],
        "CAPABILITY.missing_required_capability"
    );
}

#[test]
fn match_cap_reports_incompatible_version_deterministically() {
    let fixture = fixture_path("match_cap_v0/incompatible_version");
    let requirements_path = fixture.join("requirements.rulia.bin");
    let gamma_cap_path = fixture.join("gamma_cap.rulia.bin");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--requirements",
            requirements_path
                .to_str()
                .expect("requirements path should be valid UTF-8"),
            "--gamma-cap",
            gamma_cap_path
                .to_str()
                .expect("gamma_cap path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap (incompatible version)");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["CAPABILITY.incompatible_version"])
    );
    assert_eq!(json["details"]["status"], "reject");
    assert_eq!(
        json["details"]["primary_failure"],
        "CAPABILITY.incompatible_version"
    );
}

#[test]
fn match_cap_reports_constraint_violation_deterministically() {
    let fixture = fixture_path("match_cap_v0/constraint_violation");
    let requirements_path = fixture.join("requirements.rulia.bin");
    let gamma_cap_path = fixture.join("gamma_cap.rulia.bin");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--requirements",
            requirements_path
                .to_str()
                .expect("requirements path should be valid UTF-8"),
            "--gamma-cap",
            gamma_cap_path
                .to_str()
                .expect("gamma_cap path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap (constraint violation)");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["CAPABILITY.constraint_violation"])
    );
    assert_eq!(json["details"]["status"], "reject");
    assert_eq!(
        json["details"]["primary_failure"],
        "CAPABILITY.constraint_violation"
    );
}

#[test]
fn match_cap_reports_untrusted_or_missing_trust_anchor_deterministically() {
    let fixture = fixture_path("match_cap_v0/untrusted_or_missing_trust_anchor");
    let requirements_path = fixture.join("requirements.rulia.bin");
    let gamma_cap_path = fixture.join("gamma_cap.rulia.bin");

    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "match-cap",
            "--requirements",
            requirements_path
                .to_str()
                .expect("requirements path should be valid UTF-8"),
            "--gamma-cap",
            gamma_cap_path
                .to_str()
                .expect("gamma_cap path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow match-cap (trust anchor mismatch)");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "match-cap");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(
        json["failure_codes"],
        json!(["CAPABILITY.untrusted_or_missing_trust_anchor"])
    );
    assert_eq!(json["details"]["status"], "reject");
    assert_eq!(
        json["details"]["primary_failure"],
        "CAPABILITY.untrusted_or_missing_trust_anchor"
    );
}

#[test]
fn run_vectors_smoke_outputs_required_json() {
    let output = cargo_bin_cmd!("portable-workflow")
        .args(["run-vectors", "--vectorset", "vectorset.rulia.bin"])
        .output()
        .expect("run portable-workflow run-vectors");

    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_required_envelope(&json, "run-vectors");
}

#[test]
fn run_vectors_ci_v0_normalized_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_ci_all_pass.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L0,L1,L2,L3,L4",
            "--normalize",
            "ci-v0",
        ])
        .output()
        .expect("run portable-workflow run-vectors against CI fixture with normalization");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let expected_stdout =
        fs::read_to_string(fixture_path("ci_gate_expected_run_vectors_ci_v0.json"))
            .expect("read CI gate run-vectors expected fixture");
    assert_eq!(stdout, expected_stdout);
}

#[test]
fn run_vectors_structure_only_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_m0_golden.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
        ])
        .output()
        .expect("run portable-workflow run-vectors against golden fixture");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":1,\"mode\":\"structure_only\",\"pass_count\":1,\"vectors\":[{\"failure_codes\":[],\"id\":\"V0-001\",\"verdict\":\"pass\"},{\"failure_codes\":[\"EVAL.E_STEP_CONTRACT\"],\"id\":\"V0-002\",\"verdict\":\"fail\"}]},\"failure_codes\":[\"EVAL.E_STEP_CONTRACT\"],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"fail\"}\n"
    );
}

#[test]
fn run_vectors_l1_validate_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l1_validate.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L1",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L1 fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"validate\",\"pass_count\":2,\"vectors\":[{\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-010\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"EVAL.E_ARTIFACT_IDENTITY\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"EVAL.E_ARTIFACT_IDENTITY\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"EVAL.E_ARTIFACT_IDENTITY\"],\"id\":\"V0-011\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l2_eval_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l2_evalir_plan.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L2",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L2 fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"eval\",\"pass_count\":2,\"vectors\":[{\"actual_eval\":{\"control\":\"end\",\"emissions\":[{\"event\":\"order_activated\",\"kind\":\"audit\"}],\"obligations\":[],\"requests\":[],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"active\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"end\",\"emissions\":[{\"event\":\"order_activated\",\"kind\":\"audit\"}],\"obligations\":[],\"requests\":[]},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-201\",\"verdict\":\"pass\"},{\"actual_eval\":{\"control\":\"suspend\",\"emissions\":[],\"obligations\":[{\"obligation_id\":\"sha256:54e86a294e74a4656d0923a8c702527c0ee045c9a1e8a0c51ce0de754d095b59\",\"obligation_type\":\"receipt_valid\",\"satisfaction_ref\":\"sha256:40f107103cc1e26bee9d05f05a4d31febd82205b2dd2e78acd125124182dd2c5\"}],\"requests\":[{\"args\":{\"amount\":1250,\"channel\":\"email\"},\"capability_id\":\"capability.approvals\",\"cause\":{\"artifact_id\":\"sha256:487b5a9a4a7a780371b4bc2952099068a8207fc72e51adea776081771dcf9a79\",\"history_cursor\":-1,\"request_ordinal\":1,\"step_id\":\"S0001\"},\"operation\":\"submit\",\"request_id\":\"sha256:40f107103cc1e26bee9d05f05a4d31febd82205b2dd2e78acd125124182dd2c5\",\"request_ordinal\":1}],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"new\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"suspend\",\"emissions\":[]},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-202\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l2_rules_branching_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l2_evalir_rules_branching.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L2",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L2 rules branching fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"eval\",\"pass_count\":1,\"vectors\":[{\"actual_eval\":{\"control\":\"end\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"end\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"order\":{\"status\":\"open_case\"}}},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-213\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l2_rules_sexpr_branching_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l2_evalir_rules_sexpr_branching.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L2",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L2 rules sexpr fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"eval\",\"pass_count\":1,\"vectors\":[{\"actual_eval\":{\"control\":\"end\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"end\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"order\":{\"status\":\"open_case\"}}},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-215\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l2_join_obligations_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l2_evalir_join_obligations.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L2",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L2 join fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"eval\",\"pass_count\":3,\"vectors\":[{\"actual_eval\":{\"control\":\"suspend\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"new\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"suspend\",\"obligations\":[],\"requests\":[]},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-216\",\"verdict\":\"pass\"},{\"actual_eval\":{\"control\":\"end\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"end\",\"obligations\":[],\"requests\":[],\"state_out\":{\"order\":{\"status\":\"open_case\"}}},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-217\",\"verdict\":\"pass\"},{\"actual_eval\":{\"control\":\"end\",\"emissions\":[],\"obligations\":[],\"requests\":[],\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}}},\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_eval_expected\":{\"control\":\"end\",\"obligations\":[],\"requests\":[],\"state_out\":{\"order\":{\"status\":\"open_case\"}}},\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-218\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l2_artifact_pipeline_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l2_artifact_pipeline.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L2",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L2 artifact fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let expected_stdout = fs::read_to_string(fixture_path(
        "run_vectors_l2_artifact_pipeline_expected.json",
    ))
    .expect("read L2 artifact pipeline expected fixture");
    assert_eq!(stdout, expected_stdout);
}

#[test]
fn run_vectors_l3_proof_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l3_proof.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L3",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L3 fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"proof\",\"pass_count\":4,\"vectors\":[{\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-301\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"PROTOCOL.untrusted_signer\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"PROTOCOL.untrusted_signer\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"PROTOCOL.untrusted_signer\"],\"id\":\"V0-302\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-303\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"PROTOCOL.missing_receipt\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"PROTOCOL.missing_receipt\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"PROTOCOL.missing_receipt\"],\"id\":\"V0-304\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l4_capability_golden_json_is_deterministic() {
    let fixture = fixture_path("vectorset_v0_run_vectors_l4_capability.json");
    let output = cargo_bin_cmd!("portable-workflow")
        .args([
            "run-vectors",
            "--vectorset",
            fixture
                .to_str()
                .expect("fixture path should be valid UTF-8"),
            "--levels",
            "L4",
        ])
        .output()
        .expect("run portable-workflow run-vectors against L4 fixture");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_eq!(
        stdout,
        "{\"command\":\"run-vectors\",\"details\":{\"fail_count\":0,\"mode\":\"capability\",\"pass_count\":5,\"vectors\":[{\"actual_failure_codes\":[],\"actual_verdict\":\"pass\",\"expected_failure_codes\":[],\"expected_verdict\":\"pass\",\"failure_codes\":[],\"id\":\"V0-401\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"CAPABILITY.missing_required_capability\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"CAPABILITY.missing_required_capability\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"CAPABILITY.missing_required_capability\"],\"id\":\"V0-402\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"CAPABILITY.incompatible_version\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"CAPABILITY.incompatible_version\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"CAPABILITY.incompatible_version\"],\"id\":\"V0-403\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"CAPABILITY.constraint_violation\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"CAPABILITY.constraint_violation\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"CAPABILITY.constraint_violation\"],\"id\":\"V0-404\",\"verdict\":\"pass\"},{\"actual_failure_codes\":[\"CAPABILITY.untrusted_or_missing_trust_anchor\"],\"actual_verdict\":\"fail\",\"expected_failure_codes\":[\"CAPABILITY.untrusted_or_missing_trust_anchor\"],\"expected_verdict\":\"fail\",\"failure_codes\":[\"CAPABILITY.untrusted_or_missing_trust_anchor\"],\"id\":\"V0-405\",\"verdict\":\"pass\"}]},\"failure_codes\":[],\"schema_version\":\"portable_workflow.offline_tools.result.v0\",\"verdict\":\"pass\"}\n"
    );
}

#[test]
fn run_vectors_l1_resolves_paths_relative_to_vectorset_location_regardless_of_cwd() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let vectorset_dir = temp_dir.path().join("nested").join("vectors");
    fs::create_dir_all(&vectorset_dir).expect("create vectorset directory");

    let source_bundle = fixture_path("bundle_minimal_v0/valid_bundle");
    let destination_bundle = vectorset_dir
        .join("fixtures")
        .join("bundle_minimal_v0")
        .join("valid_bundle");
    copy_directory_recursive(&source_bundle, &destination_bundle);

    let vectorset_path = vectorset_dir.join("vectorset_relative.json");
    let vectorset_json = json!({
        "schema_version": "portable_workflow.vectorset.v0",
        "format_id": "portable_workflow.vectorset.v0",
        "vectors": [
            {
                "id": "V0-201",
                "levels": ["L1"],
                "inputs": {
                    "bundle": {
                        "path": "fixtures/bundle_minimal_v0/valid_bundle"
                    }
                },
                "expected": {
                    "verdict": "pass",
                    "failure_codes": []
                }
            }
        ]
    });
    fs::write(
        &vectorset_path,
        serde_json::to_string_pretty(&vectorset_json).expect("serialize vectorset fixture"),
    )
    .expect("write vectorset fixture");

    let detached_cwd = temp_dir.path().join("detached");
    fs::create_dir_all(&detached_cwd).expect("create detached cwd");
    let vectorset_path_str = vectorset_path
        .to_str()
        .expect("vectorset path should be valid UTF-8");

    let from_detached = cargo_bin_cmd!("portable-workflow")
        .current_dir(&detached_cwd)
        .args([
            "run-vectors",
            "--vectorset",
            vectorset_path_str,
            "--levels",
            "L1",
        ])
        .output()
        .expect("run portable-workflow run-vectors from detached cwd");
    let from_vectorset_parent = cargo_bin_cmd!("portable-workflow")
        .current_dir(&vectorset_dir)
        .args([
            "run-vectors",
            "--vectorset",
            vectorset_path_str,
            "--levels",
            "L1",
        ])
        .output()
        .expect("run portable-workflow run-vectors from vectorset directory");

    assert_eq!(from_detached.status.code(), Some(0));
    assert_eq!(from_vectorset_parent.status.code(), Some(0));
    assert_eq!(from_detached.stdout, from_vectorset_parent.stdout);

    let json: Value = serde_json::from_slice(&from_detached.stdout).expect("valid JSON output");
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["command"], "run-vectors");
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["failure_codes"], json!([]));
    assert_eq!(json["details"]["mode"], "validate");
    assert_eq!(json["details"]["pass_count"], 1);
    assert_eq!(json["details"]["fail_count"], 0);
}
