use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use url::Url;

fn host_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[test]
fn tools_install_from_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let target = match host_target() {
        Some(target) => target,
        None => {
            eprintln!("skipping test: unsupported target");
            return Ok(());
        }
    };

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let archive_name = format!("rulia-tools-0.1.0-{target}.tar.gz");
    let archive_path = fixture_dir.join(archive_name);

    if !archive_path.is_file() {
        eprintln!("skipping test: missing fixture {archive_path:?}");
        return Ok(());
    }

    let digest = sha256_file(&archive_path)?;
    let tmp = TempDir::new()?;
    let manifest_path = tmp.path().join("manifest.json");
    let artifact_url = Url::from_file_path(&archive_path).unwrap();

    let manifest_json = format!(
        r#"{{"version":"0.1.0","artifacts":[{{"target":"{target}","file":"{artifact_url}","sha256":"{digest}","bins":["rulia","rulia-fmt","rulia-lsp"]}}]}}"#
    );
    fs::write(&manifest_path, manifest_json)?;

    let manifest_url = Url::from_file_path(&manifest_path).unwrap();
    let cache_dir = tmp.path().join("cache");

    let mut cmd = cargo_bin_cmd!("rulia");
    cmd.args([
        "tools",
        "install",
        "--manifest-url",
        manifest_url.as_str(),
        "--version",
        "0.1.0",
        "--cache-dir",
        cache_dir.to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(contains("rulia-lsp"))
    .stdout(contains("rulia-fmt"));

    let install_dir = cache_dir.join("tools").join("0.1.0").join(target);
    assert!(install_dir.join("bin").join("rulia").is_file());
    assert!(install_dir.join("bin").join("rulia-fmt").is_file());
    assert!(install_dir.join("bin").join("rulia-lsp").is_file());

    Ok(())
}
