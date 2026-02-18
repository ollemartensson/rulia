use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn run_encode(path: &Path) -> Vec<u8> {
    let output = cargo_bin_cmd!("rulia")
        .args(["encode", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "encode failed: {:?}", output);
    output.stdout
}

#[test]
fn fmt_check_canonical_passes() {
    let path = fixture_path("canonical.rjl");
    cargo_bin_cmd!("rulia")
        .args(["fmt", "--check", path.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn fmt_check_noncanonical_fails() {
    let path = fixture_path("noncanonical.rjl");
    cargo_bin_cmd!("rulia")
        .args(["fmt", "--check", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("file is not canonical"));
}

#[test]
fn encode_decode_roundtrip() {
    let path = fixture_path("canonical.rjl");
    let expected = fs::read_to_string(&path).unwrap();

    let bytes = run_encode(&path);

    let tmp = TempDir::new().unwrap();
    let bin_path = tmp.path().join("value.rlb");
    fs::write(&bin_path, bytes).unwrap();

    let output = cargo_bin_cmd!("rulia")
        .args(["decode", bin_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "decode failed: {:?}", output);
    let decoded = String::from_utf8(output.stdout).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn framing_encode_decode_roundtrip() {
    let path = fixture_path("canonical.rjl");
    let payload1 = run_encode(&path);
    let payload2 = run_encode(&path);

    let tmp = TempDir::new().unwrap();
    let payload1_path = tmp.path().join("payload1.rlb");
    let payload2_path = tmp.path().join("payload2.rlb");
    fs::write(&payload1_path, &payload1).unwrap();
    fs::write(&payload2_path, &payload2).unwrap();

    let framed = cargo_bin_cmd!("rulia")
        .args([
            "frame",
            "encode",
            payload1_path.to_str().unwrap(),
            payload2_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(framed.status.success(), "frame encode failed: {:?}", framed);

    let framed_path = tmp.path().join("framed.bin");
    fs::write(&framed_path, &framed.stdout).unwrap();

    let out_dir = tmp.path().join("out");
    let decoded = cargo_bin_cmd!("rulia")
        .args([
            "frame",
            "decode",
            "--out-dir",
            out_dir.to_str().unwrap(),
            framed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        decoded.status.success(),
        "frame decode failed: {:?}",
        decoded
    );

    let digest1 = hex::encode(Sha256::digest(&payload1));
    let digest2 = hex::encode(Sha256::digest(&payload2));
    let expected_lines = vec![
        "frames=2".to_string(),
        format!("frame=1 len={} sha256={}", payload1.len(), digest1),
        format!("frame=2 len={} sha256={}", payload2.len(), digest2),
    ];
    let stdout = String::from_utf8(decoded.stdout).unwrap();
    let lines: Vec<String> = stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(lines, expected_lines);

    let out1 = out_dir.join("frame_000001.rlb");
    let out2 = out_dir.join("frame_000002.rlb");
    assert_eq!(fs::read(out1).unwrap(), payload1);
    assert_eq!(fs::read(out2).unwrap(), payload2);
}

fn assert_frame_decode_error(bytes: &[u8], expected: &str) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("framed.bin");
    fs::write(&path, bytes).unwrap();

    cargo_bin_cmd!("rulia")
        .args(["frame", "decode", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(expected));
}

#[test]
fn framing_rejects_zero_length() {
    assert_frame_decode_error(&[0, 0, 0, 0], "FRAMING_LENGTH_ZERO");
}

#[test]
fn framing_rejects_truncated_header() {
    assert_frame_decode_error(&[0x01, 0x02], "FRAMING_TRUNCATED_HEADER");
}

#[test]
fn framing_rejects_truncated_payload() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&[0x01, 0x02]);
    assert_frame_decode_error(&bytes, "FRAMING_TRUNCATED_PAYLOAD");
}

#[test]
fn framing_rejects_len_too_large() {
    let len = (MAX_FRAME_LEN as u32) + 1;
    let bytes = len.to_le_bytes();
    assert_frame_decode_error(&bytes, "FRAMING_LENGTH_EXCEEDS_LIMIT");
}
