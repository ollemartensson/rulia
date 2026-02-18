use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;
use url::Url;
use zip::read::ZipArchive;

const EXPECTED_BINS: [&str; 3] = ["rulia", "rulia-fmt", "rulia-lsp"];

#[derive(Debug, Error)]
pub enum ToolsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("unsupported target: {0}")]
    UnsupportedTarget(String),
    #[error("invalid manifest url: {0}")]
    InvalidManifestUrl(String),
    #[error("manifest download failed: {0}")]
    ManifestDownload(String),
    #[error("artifact download failed: {0}")]
    ArtifactDownload(String),
    #[error("manifest parse failed: {0}")]
    ManifestParse(String),
    #[error("manifest version {manifest} does not match requested {requested}")]
    ManifestVersionMismatch { manifest: String, requested: String },
    #[error("manifest contains no artifact for target {0}")]
    MissingArtifact(String),
    #[error("artifact url invalid: {0}")]
    InvalidArtifactUrl(String),
    #[error("artifact checksum mismatch (expected {expected}, got {actual})")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("archive type not supported for file {0}")]
    UnsupportedArchive(String),
    #[error("invalid archive entry: {0}")]
    InvalidArchiveEntry(String),
    #[error("unsupported archive entry type: {0}")]
    UnsupportedArchiveEntry(String),
    #[error("missing expected binary: {0}")]
    MissingBinary(String),
    #[error("invalid sha256 in manifest: {0}")]
    InvalidSha256(String),
    #[error("cache directory unavailable")]
    CacheDirUnavailable,
}

#[derive(Debug, Deserialize)]
struct ReleaseManifest {
    version: String,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug, Deserialize)]
struct ManifestArtifact {
    target: String,
    file: String,
    sha256: String,
    url: Option<String>,
}

pub struct InstallResult {
    pub lsp_path: PathBuf,
    pub fmt_path: PathBuf,
}

pub fn install_tools(
    manifest_url: &str,
    version: &str,
    cache_dir: Option<&Path>,
) -> Result<InstallResult, ToolsError> {
    let target =
        host_target_triple().ok_or_else(|| ToolsError::UnsupportedTarget(host_descriptor()))?;

    let manifest_url =
        Url::parse(manifest_url).map_err(|err| ToolsError::InvalidManifestUrl(err.to_string()))?;
    let manifest_bytes = download_manifest(&manifest_url)?;
    let manifest = parse_manifest(&manifest_bytes)?;

    if version != "latest" && manifest.version != version {
        return Err(ToolsError::ManifestVersionMismatch {
            manifest: manifest.version,
            requested: version.to_string(),
        });
    }

    let artifact = select_artifact(&manifest, target)
        .ok_or_else(|| ToolsError::MissingArtifact(target.to_string()))?;

    let resolved_version = if version == "latest" {
        manifest.version.as_str()
    } else {
        version
    };

    let cache_root = match cache_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_cache_dir()?,
    };
    fs::create_dir_all(&cache_root)?;

    let install_dir = cache_root.join("tools").join(resolved_version).join(target);

    let tmp_dir = Builder::new()
        .prefix(".rulia-tools-")
        .tempdir_in(&cache_root)?;
    let tmp_path = tmp_dir.path().to_path_buf();

    let archive_url = resolve_artifact_url(&manifest_url, artifact)?;
    let archive_name = archive_filename(&archive_url)
        .ok_or_else(|| ToolsError::UnsupportedArchive("unknown".to_string()))?;
    let archive_path = tmp_path.join(archive_name);
    let actual_sha = download_to_file_with_sha256(&archive_url, &archive_path)?;
    if !eq_hex(&actual_sha, &artifact.sha256) {
        let _ = fs::remove_file(&archive_path);
        return Err(ToolsError::ChecksumMismatch {
            expected: artifact.sha256.clone(),
            actual: actual_sha,
        });
    }

    extract_archive(&archive_path, &tmp_path, is_windows())?;
    fs::remove_file(&archive_path)?;

    ensure_expected_bins(&tmp_path)?;

    if install_dir.exists() {
        fs::remove_dir_all(&install_dir)?;
    }
    if let Some(parent) = install_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(&tmp_path, &install_dir)?;

    let bin_dir = install_dir.join("bin");
    let lsp_path = bin_dir.join(executable_name("rulia-lsp"));
    let fmt_path = bin_dir.join(executable_name("rulia-fmt"));

    Ok(InstallResult { lsp_path, fmt_path })
}

pub fn resolve_target_triple(os: &str, arch: &str) -> Option<&'static str> {
    let os = match os {
        "windows" | "win32" => "windows",
        "macos" | "darwin" => "darwin",
        "linux" => "linux",
        _ => return None,
    };

    let arch = match arch {
        "x86_64" | "x64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return None,
    };

    match (os, arch) {
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("darwin", "aarch64") => Some("aarch64-apple-darwin"),
        ("darwin", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        _ => None,
    }
}

fn host_target_triple() -> Option<&'static str> {
    resolve_target_triple(std::env::consts::OS, std::env::consts::ARCH)
}

fn host_descriptor() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn is_windows() -> bool {
    std::env::consts::OS == "windows"
}

fn default_cache_dir() -> Result<PathBuf, ToolsError> {
    let base = dirs::cache_dir().ok_or(ToolsError::CacheDirUnavailable)?;
    Ok(base.join("rulia"))
}

fn download_manifest(url: &Url) -> Result<Vec<u8>, ToolsError> {
    match url.scheme() {
        "file" => {
            let path = url
                .to_file_path()
                .map_err(|_| ToolsError::ManifestDownload("invalid file url".to_string()))?;
            Ok(fs::read(path)?)
        }
        "http" | "https" => {
            let agent = ureq::AgentBuilder::new().redirects(5).build();
            let response = agent
                .get(url.as_str())
                .call()
                .map_err(|err| ToolsError::ManifestDownload(err.to_string()))?;
            if response.status() != 200 {
                return Err(ToolsError::ManifestDownload(format!(
                    "HTTP {}",
                    response.status()
                )));
            }
            let mut reader = response.into_reader();
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .map_err(|err| ToolsError::ManifestDownload(err.to_string()))?;
            Ok(buf)
        }
        other => Err(ToolsError::ManifestDownload(format!(
            "unsupported scheme: {other}"
        ))),
    }
}

fn parse_manifest(bytes: &[u8]) -> Result<ReleaseManifest, ToolsError> {
    let manifest: ReleaseManifest =
        serde_json::from_slice(bytes).map_err(|err| ToolsError::ManifestParse(err.to_string()))?;

    if manifest.version.trim().is_empty() {
        return Err(ToolsError::ManifestParse(
            "manifest version must be non-empty".to_string(),
        ));
    }
    if manifest.artifacts.is_empty() {
        return Err(ToolsError::ManifestParse(
            "manifest artifacts must be non-empty".to_string(),
        ));
    }

    for artifact in &manifest.artifacts {
        if artifact.target.trim().is_empty()
            || artifact.file.trim().is_empty()
            || artifact.sha256.trim().is_empty()
        {
            return Err(ToolsError::ManifestParse(
                "manifest artifact fields must be non-empty".to_string(),
            ));
        }
        if let Some(url) = artifact.url.as_ref() {
            if url.trim().is_empty() {
                return Err(ToolsError::ManifestParse(
                    "manifest artifact url must be non-empty when provided".to_string(),
                ));
            }
        }
        if !valid_sha256_hex(&artifact.sha256) {
            return Err(ToolsError::InvalidSha256(artifact.sha256.clone()));
        }
    }

    Ok(manifest)
}

fn valid_sha256_hex(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return false;
    }
    trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn select_artifact<'a>(
    manifest: &'a ReleaseManifest,
    target: &str,
) -> Option<&'a ManifestArtifact> {
    manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.target == target)
}

fn resolve_artifact_url(
    manifest_url: &Url,
    artifact: &ManifestArtifact,
) -> Result<Url, ToolsError> {
    if let Some(url) = artifact.url.as_ref() {
        return Url::parse(url).map_err(|err| ToolsError::InvalidArtifactUrl(err.to_string()));
    }
    resolve_artifact_url_from_file(manifest_url, &artifact.file)
}

fn resolve_artifact_url_from_file(manifest_url: &Url, file: &str) -> Result<Url, ToolsError> {
    if file.starts_with("http://") || file.starts_with("https://") || file.starts_with("file://") {
        return Url::parse(file).map_err(|err| ToolsError::InvalidArtifactUrl(err.to_string()));
    }
    manifest_url
        .join(file)
        .map_err(|err| ToolsError::InvalidArtifactUrl(err.to_string()))
}

fn archive_filename(url: &Url) -> Option<&str> {
    url.path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|name| !name.is_empty())
}

fn download_to_file_with_sha256(url: &Url, dest: &Path) -> Result<String, ToolsError> {
    let mut output = File::create(dest)?;

    match url.scheme() {
        "file" => {
            let path = url
                .to_file_path()
                .map_err(|_| ToolsError::ArtifactDownload("invalid file url".to_string()))?;
            let mut input = File::open(path)?;
            let (digest, _) = copy_and_hash(&mut input, &mut output)?;
            Ok(digest)
        }
        "http" | "https" => {
            let agent = ureq::AgentBuilder::new().redirects(5).build();
            let response = agent
                .get(url.as_str())
                .call()
                .map_err(|err| ToolsError::ArtifactDownload(err.to_string()))?;
            if response.status() != 200 {
                return Err(ToolsError::ArtifactDownload(format!(
                    "HTTP {}",
                    response.status()
                )));
            }
            let mut reader = response.into_reader();
            let (digest, _) = copy_and_hash(&mut reader, &mut output)?;
            Ok(digest)
        }
        other => Err(ToolsError::ArtifactDownload(format!(
            "unsupported scheme: {other}"
        ))),
    }
}

fn copy_and_hash<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(String, u64), ToolsError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut total = 0u64;

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buf[..read])?;
        hasher.update(&buf[..read]);
        total += read as u64;
    }
    writer.flush()?;

    let digest = hex::encode(hasher.finalize());
    Ok((digest, total))
}

fn eq_hex(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn extract_archive(archive_path: &Path, dest: &Path, is_windows: bool) -> Result<(), ToolsError> {
    let filename = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();

    if filename.ends_with(".tar.gz") {
        extract_tar_gz(archive_path, dest, is_windows)
    } else if filename.ends_with(".zip") {
        extract_zip(archive_path, dest, is_windows)
    } else {
        Err(ToolsError::UnsupportedArchive(filename.to_string()))
    }
}

fn extract_tar_gz(archive_path: &Path, dest: &Path, is_windows: bool) -> Result<(), ToolsError> {
    let file = File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        let kind = if entry_type.is_dir() {
            EntryKind::Dir
        } else if entry_type.is_file() {
            EntryKind::File
        } else {
            return Err(ToolsError::UnsupportedArchiveEntry(
                entry.path()?.display().to_string(),
            ));
        };

        let path = entry.path()?;
        let components = normalized_components(&path)?;
        if components.is_empty() {
            continue;
        }
        validate_components(&components, kind, is_windows)?;
        let out_path = dest.join(path_from_components(&components));

        match kind {
            EntryKind::Dir => {
                fs::create_dir_all(&out_path)?;
            }
            EntryKind::File => {
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                entry.unpack(&out_path)?;
            }
        }
    }

    ensure_executables(dest)?;
    Ok(())
}

fn extract_zip(archive_path: &Path, dest: &Path, is_windows: bool) -> Result<(), ToolsError> {
    let file = File::open(archive_path)?;
    let mut archive =
        ZipArchive::new(file).map_err(|err| ToolsError::UnsupportedArchive(err.to_string()))?;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| ToolsError::UnsupportedArchive(err.to_string()))?;
        if is_zip_symlink(&entry) {
            return Err(ToolsError::UnsupportedArchiveEntry(
                entry.name().to_string(),
            ));
        }

        let normalized = entry.name().replace('\\', "/");
        let components = normalized_components(Path::new(&normalized))?;
        if components.is_empty() {
            continue;
        }
        let kind = if entry.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        validate_components(&components, kind, is_windows)?;
        let out_path = dest.join(path_from_components(&components));

        match kind {
            EntryKind::Dir => {
                fs::create_dir_all(&out_path)?;
            }
            EntryKind::File => {
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut output = File::create(&out_path)?;
                io::copy(&mut entry, &mut output)?;
            }
        }
    }

    ensure_executables(dest)?;
    Ok(())
}

fn ensure_expected_bins(dest: &Path) -> Result<(), ToolsError> {
    let bin_dir = dest.join("bin");
    for bin in EXPECTED_BINS {
        let path = bin_dir.join(executable_name(bin));
        if !path.is_file() {
            return Err(ToolsError::MissingBinary(path.display().to_string()));
        }
    }
    Ok(())
}

fn ensure_executables(dest: &Path) -> Result<(), ToolsError> {
    if is_windows() {
        return Ok(());
    }
    let bin_dir = dest.join("bin");
    for bin in EXPECTED_BINS {
        let path = bin_dir.join(bin);
        if path.is_file() {
            #[cfg(unix)]
            let mut perms = fs::metadata(&path)?.permissions();
            #[cfg(unix)]
            perms.set_mode(0o755);
            #[cfg(unix)]
            fs::set_permissions(&path, perms)?;
        }
    }
    Ok(())
}

fn executable_name(base: &str) -> String {
    if is_windows() {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

#[derive(Copy, Clone)]
enum EntryKind {
    File,
    Dir,
}

fn normalized_components(path: &Path) -> Result<Vec<String>, ToolsError> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let text = part
                    .to_str()
                    .ok_or_else(|| ToolsError::InvalidArchiveEntry(path.display().to_string()))?;
                if text.is_empty() {
                    return Err(ToolsError::InvalidArchiveEntry(path.display().to_string()));
                }
                components.push(text.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(ToolsError::InvalidArchiveEntry(path.display().to_string()))
            }
        }
    }
    Ok(components)
}

fn path_from_components(components: &[String]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    path
}

fn validate_components(
    components: &[String],
    kind: EntryKind,
    is_windows: bool,
) -> Result<(), ToolsError> {
    if components.len() == 1 {
        let name = &components[0];
        if name == "VERSION" || name.starts_with("LICENSE-") {
            if matches!(kind, EntryKind::Dir) {
                return Err(ToolsError::InvalidArchiveEntry(name.clone()));
            }
            return Ok(());
        }
        if name == "bin" && matches!(kind, EntryKind::Dir) {
            return Ok(());
        }
    }

    if components.len() == 2 && components[0] == "bin" {
        let filename = &components[1];
        if filename.is_empty() {
            return Err(ToolsError::InvalidArchiveEntry(components.join("/")));
        }
        if is_windows && !filename.ends_with(".exe") {
            return Err(ToolsError::InvalidArchiveEntry(components.join("/")));
        }
        if matches!(kind, EntryKind::Dir) {
            return Err(ToolsError::InvalidArchiveEntry(components.join("/")));
        }
        return Ok(());
    }

    Err(ToolsError::InvalidArchiveEntry(components.join("/")))
}

fn is_zip_symlink(file: &zip::read::ZipFile<'_>) -> bool {
    if let Some(mode) = file.unix_mode() {
        return (mode & 0o170000) == 0o120000;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_mapping_matches_vscode() {
        assert_eq!(
            resolve_target_triple("win32", "x64"),
            Some("x86_64-pc-windows-msvc")
        );
        assert_eq!(
            resolve_target_triple("darwin", "arm64"),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            resolve_target_triple("darwin", "x64"),
            Some("x86_64-apple-darwin")
        );
        assert_eq!(
            resolve_target_triple("linux", "x64"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(resolve_target_triple("linux", "arm64"), None);
    }

    #[test]
    fn sha256_streaming_matches_expected() {
        let data = b"rulia-stream";
        let mut reader = io::Cursor::new(data);
        let mut output = Vec::new();
        let (digest, total) = copy_and_hash(&mut reader, &mut output).unwrap();

        let expected = hex::encode(Sha256::digest(data));
        assert_eq!(digest, expected);
        assert_eq!(total, data.len() as u64);
        assert_eq!(output, data);
    }

    #[test]
    fn archive_path_validation() {
        let ok = [
            ("bin/rulia", EntryKind::File, false),
            ("bin/rulia-fmt", EntryKind::File, false),
            ("LICENSE-APACHE", EntryKind::File, false),
            ("VERSION", EntryKind::File, false),
            ("bin", EntryKind::Dir, false),
            ("bin/rulia.exe", EntryKind::File, true),
        ];
        for (path, kind, is_windows) in ok {
            let comps = normalized_components(Path::new(path)).unwrap();
            validate_components(&comps, kind, is_windows).unwrap();
        }

        let bad = [
            ("../bin/rulia", EntryKind::File, false),
            ("/bin/rulia", EntryKind::File, false),
            ("bin/../rulia", EntryKind::File, false),
            ("etc/passwd", EntryKind::File, false),
            ("bin", EntryKind::File, false),
            ("bin/rulia", EntryKind::File, true),
        ];
        for (path, kind, is_windows) in bad {
            let comps = normalized_components(Path::new(path));
            if let Ok(comps) = comps {
                assert!(validate_components(&comps, kind, is_windows).is_err());
            } else {
                assert!(comps.is_err());
            }
        }
    }
}
