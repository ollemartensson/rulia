# Releasing Rulia (v0)

This runbook produces deterministic, repeatable release artifacts for the CLI tools.

## Versioning

- Release version is derived from `Cargo.toml` at `[workspace.package].version`.
- Artifacts are placed under `dist/releases/<version>/<target>/`.
- Archive names follow: `rulia-tools-<version>-<target>.tar.gz|zip`.

## Supported targets (v0)

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu` (optional if you can build)
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

## Prerequisites

- Rust stable toolchain (edition 2021).
- Target toolchains installed via `rustup target add <triple>`.
- Native builds per platform (v0). Cross compilation is optional and not required.

## Deterministic release steps

1. Ensure a clean working tree (`git status -sb`).
2. Run tests:
   - `cargo test --workspace`
3. Build local release binaries for the host target:
   - `tools/release/build-local.sh`
4. Package the host target into an archive:
   - `tools/release/package.sh <version> <target>`
5. Generate checksums and manifest:
   - `tools/release/checksums.sh <version>`
6. Verify the archive contents contain expected binaries and ABI artifacts:
   - `bin/rulia`, `bin/rulia-fmt`, `bin/rulia-lsp` (or `.exe` on Windows)
   - `lib/librulia.so` (Linux), `lib/librulia.dylib` (macOS), or `lib/rulia.dll` (Windows)
   - `include/rulia_ffi_v1.h`
7. Create a GitHub Release and upload:
   - Archives (`rulia-tools-<version>-<target>.*`)
   - `SHA256SUMS`
   - `manifest.json`

## GCS release modes (v0)

Use these modes to publish artifacts to a GCS bucket for VS Code and CLI installers.

### Mode A: Public bucket (file-resolved artifacts)

1. Create a bucket (uniform access):
   - `gcloud storage buckets create gs://rulia-tools-<org>-<env> --location=europe-north1 --uniform-bucket-level-access`
2. Upload artifacts (repeat for each target archive):
   - `gcloud storage cp dist/releases/<version>/manifest.json gs://<bucket>/rulia/<version>/manifest.json`
   - `gcloud storage cp dist/releases/<version>/SHA256SUMS gs://<bucket>/rulia/<version>/SHA256SUMS`
   - `gcloud storage cp dist/releases/<version>/rulia-tools-<version>-<target>.* gs://<bucket>/rulia/<version>/`
3. Manifest URL format:
   - `https://storage.googleapis.com/<bucket>/rulia/<version>/manifest.json`

Installers resolve artifact downloads by combining the manifest URL directory with each artifact `file`.

If you want unauthenticated access, grant public viewer on the bucket:
`gcloud storage buckets add-iam-policy-binding gs://<bucket> --member=allUsers --role=roles/storage.objectViewer`

### Mode B: Private bucket (per-artifact signed URLs)

1. Upload artifacts to GCS as in Mode A.
2. Generate signed URLs for each artifact archive and publish a manifest that includes
   `url` per artifact (full download URL).
3. Use a signed or authenticated manifest URL:
   - `gcloud storage sign-url --duration=1h gs://<bucket>/rulia/<version>/manifest.json`

Signed URLs expire. When they do, regenerate the signed artifact URLs and re-publish the manifest.

## Outputs

Each target directory contains:
- `bin/` (binaries)
- `lib/` (ABI shared library)
- `include/` (C header)
- `LICENSE-APACHE`
- `LICENSE-MIT`
- `VERSION`

The archive includes only the files above (no build intermediates).

## Do not

- Do not package `node_modules` or any build caches.
- Do not embed machine-specific paths or timestamps in artifacts.
- Do not skip tests.

## Notes

- `tools/release/manifest.json` is a template reference. The generated manifest lives in
  `dist/releases/<version>/manifest.json`.
- The packaging script normalizes timestamps and file ordering to keep archives deterministic.
- The manifest `bins` list remains CLI-only; ABI libraries and headers are included in archives
  even though they are not listed in the manifest.
