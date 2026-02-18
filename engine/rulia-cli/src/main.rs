use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use rulia::{HashAlgorithm, Value};
use thiserror::Error;

mod tools_install;

const DEFAULT_MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "rulia", version, about = "Rulia CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print canonical text to stdout
    Fmt {
        /// Check whether the file is already canonical
        #[arg(long)]
        check: bool,
        /// Input file
        file: PathBuf,
    },
    /// Parse text and print canonical text to stdout
    Parse {
        /// Input file
        file: PathBuf,
    },
    /// Encode text to canonical binary
    Encode {
        /// Digest trailer algorithm
        #[arg(long, value_enum)]
        digest: Option<DigestAlgorithm>,
        /// Input file
        file: PathBuf,
    },
    /// Decode canonical binary and print canonical text
    Decode {
        /// Input file
        file: PathBuf,
    },
    /// Verify digest trailer, print algorithm + hex digest
    Verify {
        /// Input file
        file: PathBuf,
    },
    /// Stream framing v1 helpers
    Frame {
        #[command(subcommand)]
        command: FrameCommand,
    },
    /// Toolchain helpers
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum FrameCommand {
    /// Encode one or more binary payloads into a framed stream
    Encode {
        /// Binary payload files
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Decode a framed stream
    Decode {
        /// Framed input file
        file: PathBuf,
        /// Output directory for payloads
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ToolsCommand {
    /// Install the Rulia toolchain from a release manifest
    Install {
        /// Manifest URL (https or file URL)
        #[arg(long)]
        manifest_url: String,
        /// Toolchain version or 'latest'
        #[arg(long)]
        version: String,
        /// Optional cache directory
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Copy, Clone, Debug)]
#[clap(rename_all = "lower")]
enum DigestAlgorithm {
    Sha256,
    Blake3,
}

impl From<DigestAlgorithm> for HashAlgorithm {
    fn from(value: DigestAlgorithm) -> Self {
        match value {
            DigestAlgorithm::Sha256 => HashAlgorithm::Sha256,
            DigestAlgorithm::Blake3 => HashAlgorithm::Blake3,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Rulia(#[from] rulia::RuliaError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("file is not canonical: {0}")]
    NotCanonical(PathBuf),
    #[error("FRAMING_TRUNCATED_HEADER")]
    FramingTruncatedHeader,
    #[error("FRAMING_TRUNCATED_PAYLOAD")]
    FramingTruncatedPayload,
    #[error("FRAMING_LENGTH_EXCEEDS_LIMIT")]
    FramingLengthExceedsLimit,
    #[error("FRAMING_LENGTH_ZERO")]
    FramingLengthZero,
    #[error("FRAMING_MALFORMED_PAYLOAD")]
    FramingMalformedPayload,
    #[error("{0}")]
    InvalidOutputDir(String),
    #[error(transparent)]
    Tools(#[from] tools_install::ToolsError),
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Fmt { check, file } => cmd_fmt(&file, check),
        Commands::Parse { file } => cmd_parse(&file),
        Commands::Encode { digest, file } => cmd_encode(&file, digest),
        Commands::Decode { file } => cmd_decode(&file),
        Commands::Verify { file } => cmd_verify(&file),
        Commands::Frame { command } => match command {
            FrameCommand::Encode { files } => cmd_frame_encode(&files),
            FrameCommand::Decode { file, out_dir } => cmd_frame_decode(&file, out_dir.as_deref()),
        },
        Commands::Tools { command } => match command {
            ToolsCommand::Install {
                manifest_url,
                version,
                cache_dir,
            } => cmd_tools_install(&manifest_url, &version, cache_dir.as_deref()),
        },
    }
}

fn cmd_fmt(path: &Path, check: bool) -> Result<(), CliError> {
    let contents = fs::read_to_string(path)?;
    let value = parse_text_in_dir(&contents, path)?;
    let canonical = rulia::text::to_canonical_string(&value);

    if check {
        if contents == canonical {
            Ok(())
        } else {
            Err(CliError::NotCanonical(path.to_path_buf()))
        }
    } else {
        write_stdout(canonical.as_bytes())
    }
}

fn cmd_parse(path: &Path) -> Result<(), CliError> {
    let contents = fs::read_to_string(path)?;
    let value = parse_text_in_dir(&contents, path)?;
    let canonical = rulia::text::to_canonical_string(&value);
    write_stdout(canonical.as_bytes())
}

fn cmd_encode(path: &Path, digest: Option<DigestAlgorithm>) -> Result<(), CliError> {
    let contents = fs::read_to_string(path)?;
    let value = parse_text_in_dir(&contents, path)?;
    let bytes = match digest {
        Some(algorithm) => rulia::encode_with_digest_using(&value, algorithm.into())?.bytes,
        None => rulia::encode_canonical(&value)?,
    };
    write_stdout(&bytes)
}

fn cmd_decode(path: &Path) -> Result<(), CliError> {
    let bytes = fs::read(path)?;
    let value = rulia::decode_value(&bytes)?;
    let canonical = rulia::text::to_canonical_string(&value);
    write_stdout(canonical.as_bytes())
}

fn cmd_verify(path: &Path) -> Result<(), CliError> {
    let bytes = fs::read(path)?;
    let (algorithm, digest) = rulia::verify_digest(&bytes)?;
    println!("{} {}", algorithm.as_str(), hex::encode(digest));
    Ok(())
}

fn cmd_frame_encode(paths: &[PathBuf]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    for path in paths {
        let payload = fs::read(path)?;
        enforce_frame_len(payload.len())?;
        let len = payload.len() as u32;
        stdout.write_all(&len.to_le_bytes())?;
        stdout.write_all(&payload)?;
    }
    Ok(())
}

fn cmd_frame_decode(path: &Path, out_dir: Option<&Path>) -> Result<(), CliError> {
    if let Some(dir) = out_dir {
        if dir.exists() && !dir.is_dir() {
            return Err(CliError::InvalidOutputDir(format!(
                "output path is not a directory: {}",
                dir.display()
            )));
        }
        fs::create_dir_all(dir)?;
    }

    let bytes = fs::read(path)?;
    let mut offset = 0usize;
    let mut frames = Vec::new();
    let mut index = 0usize;

    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(CliError::FramingTruncatedHeader);
        }
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if len == 0 {
            return Err(CliError::FramingLengthZero);
        }
        if len > DEFAULT_MAX_FRAME_LEN {
            return Err(CliError::FramingLengthExceedsLimit);
        }
        if bytes.len() - offset < len {
            return Err(CliError::FramingTruncatedPayload);
        }

        let payload = &bytes[offset..offset + len];
        offset += len;

        if rulia::decode_value(payload).is_err() {
            return Err(CliError::FramingMalformedPayload);
        }

        index += 1;
        let digest = HashAlgorithm::Sha256.compute(payload);
        let digest_hex = hex::encode(digest);

        if let Some(dir) = out_dir {
            let filename = format!("frame_{:06}.rlb", index);
            let out_path = dir.join(filename);
            fs::write(out_path, payload)?;
        }

        frames.push((index, len, digest_hex));
    }

    println!("frames={}", frames.len());
    for (idx, len, digest) in frames {
        println!("frame={} len={} sha256={}", idx, len, digest);
    }

    Ok(())
}

fn cmd_tools_install(
    manifest_url: &str,
    version: &str,
    cache_dir: Option<&Path>,
) -> Result<(), CliError> {
    let result = tools_install::install_tools(manifest_url, version, cache_dir)?;
    println!("rulia-lsp {}", result.lsp_path.display());
    println!("rulia-fmt {}", result.fmt_path.display());
    Ok(())
}

fn parse_text_in_dir(contents: &str, path: &Path) -> Result<Value, CliError> {
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    Ok(rulia::text::parse_in_dir(contents, base_dir)?)
}

fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    Ok(())
}

fn enforce_frame_len(len: usize) -> Result<(), CliError> {
    if len == 0 {
        return Err(CliError::FramingLengthZero);
    }
    if len > DEFAULT_MAX_FRAME_LEN {
        return Err(CliError::FramingLengthExceedsLimit);
    }
    if len > u32::MAX as usize {
        return Err(CliError::FramingLengthExceedsLimit);
    }
    Ok(())
}
