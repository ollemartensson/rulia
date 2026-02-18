use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{error::ErrorKind, Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use rulia::{
    resolver_from_callback, HashAlgorithm, ParseOptions, ResolvedImport, RuliaError,
    Value as RuliaValue,
};
use serde_json::{Map, Number, Value};
use thiserror::Error;

#[path = "portable-workflow/workflow_artifact_subset_v0.rs"]
mod portable_workflow_artifact_subset_v0;
#[allow(dead_code)]
#[path = "portable-workflow/evalir_v0.rs"]
mod portable_workflow_evalir_v0;
#[path = "portable-workflow/kernel_expression_v0.rs"]
mod portable_workflow_kernel_expression_v0;
#[path = "portable-workflow/path_safety.rs"]
mod portable_workflow_path_safety;
#[path = "portable-workflow/request_identity_v0.rs"]
mod portable_workflow_request_identity_v0;
#[path = "portable-workflow/vectorset_v0.rs"]
mod portable_workflow_vectorset;

use portable_workflow_path_safety::{safe_relative_path, SafeRelativePathError};

const RESULT_SCHEMA_VERSION: &str = "portable_workflow.offline_tools.result.v0";
const BUNDLE_DIAGNOSTIC_CODE: &str = "portable_workflow.bundle_validate";
const BUNDLE_MANIFEST_FILENAME: &str = "manifest.rulia.bin";
const RECEIPT_SIGNATURE_DOMAIN: &str = "rulia:receipt:v0";
const RECEIPT_SIGNATURE_SCOPE: &str = "rulia_receipt_v0";
const FAILURE_CODE_ARTIFACT_IDENTITY: &str = "EVAL.E_ARTIFACT_IDENTITY";
const FAILURE_CODE_STATE_INVALID: &str = "EVAL.E_STATE_INVALID";
const FAILURE_CODE_STEP_CONTRACT: &str = "EVAL.E_STEP_CONTRACT";
const FAILURE_CODE_PROTOCOL_REQUEST_HASH_MISMATCH: &str = "PROTOCOL.request_hash_mismatch";
const FAILURE_CODE_PROTOCOL_UNTRUSTED_SIGNER: &str = "PROTOCOL.untrusted_signer";
const FAILURE_CODE_PROTOCOL_SIGNATURE_INVALID: &str = "PROTOCOL.signature_invalid";
const FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const FAILURE_CODE_PROTOCOL_MISSING_RECEIPT: &str = "PROTOCOL.missing_receipt";
const FAILURE_CODE_CAPABILITY_MISSING_REQUIRED: &str = "CAPABILITY.missing_required_capability";
const FAILURE_CODE_CAPABILITY_INCOMPATIBLE_VERSION: &str = "CAPABILITY.incompatible_version";
const FAILURE_CODE_CAPABILITY_CONSTRAINT_VIOLATION: &str = "CAPABILITY.constraint_violation";
const FAILURE_CODE_CAPABILITY_UNTRUSTED_OR_MISSING_TRUST_ANCHOR: &str =
    "CAPABILITY.untrusted_or_missing_trust_anchor";

#[derive(Parser, Debug)]
#[command(
    name = "portable-workflow",
    version,
    about = "Portable Workflow offline tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Compile(CompileArgs),
    Validate(ValidateArgs),
    Verify(VerifyArgs),
    #[command(name = "match-cap")]
    MatchCap(MatchCapArgs),
    #[command(name = "run-vectors")]
    RunVectors(RunVectorsArgs),
}

#[derive(Parser, Debug)]
struct CompileArgs {
    #[arg(long)]
    artifact: String,
    #[arg(long)]
    out: String,
    #[arg(long = "json-out")]
    json_out: Option<String>,
}

#[derive(Parser, Debug)]
struct ValidateArgs {
    #[arg(
        long = "level",
        value_enum,
        value_delimiter = ',',
        num_args = 1..,
        required_unless_present = "bundle"
    )]
    levels: Vec<ValidateLevel>,
    #[arg(long, required_unless_present = "bundle")]
    artifact: Option<String>,
    #[arg(long = "artifact-alt")]
    artifact_alt: Vec<String>,
    #[arg(long)]
    state: Option<String>,
    #[arg(long)]
    history: Option<String>,
    #[arg(long = "history-cursor")]
    history_cursor: Option<u64>,
    #[arg(long = "gamma-core")]
    gamma_core: Option<String>,
    #[arg(long = "gamma-cap")]
    gamma_cap: Option<String>,
    #[arg(long = "trigger-items")]
    trigger_items: Option<String>,
    #[arg(long)]
    bundle: Option<String>,
    #[arg(long = "json-out")]
    json_out: Option<String>,
}

#[derive(Parser, Debug)]
struct VerifyArgs {
    #[arg(long)]
    request: Option<String>,
    #[arg(long)]
    receipt: Option<String>,
    #[arg(long)]
    obligation: Option<String>,
    #[arg(long)]
    history: Option<String>,
    #[arg(long)]
    bundle: Option<String>,
    #[arg(long)]
    trust: String,
    #[arg(long = "json-out")]
    json_out: Option<String>,
}

#[derive(Parser, Debug)]
struct MatchCapArgs {
    #[arg(long, required_unless_present = "bundle", conflicts_with = "bundle")]
    requirements: Option<String>,
    #[arg(
        long = "gamma-cap",
        required_unless_present = "bundle",
        conflicts_with = "bundle"
    )]
    gamma_cap: Option<String>,
    #[arg(long, conflicts_with_all = ["requirements", "gamma_cap"])]
    bundle: Option<String>,
    #[arg(long = "json-out")]
    json_out: Option<String>,
}

#[derive(Parser, Debug)]
struct RunVectorsArgs {
    #[arg(long = "vectorset", alias = "vectors")]
    vectorset: String,
    #[arg(long)]
    bundle: Option<String>,
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        num_args = 1..,
        help = "Comma-separated levels (for example: --levels L0,L1). Defaults to L0."
    )]
    levels: Option<Vec<RunLevel>>,
    #[arg(long = "vector-id")]
    vector_ids: Vec<String>,
    #[arg(long = "json-out")]
    json_out: Option<String>,
    #[arg(long = "stop-on-first-fail")]
    stop_on_first_fail: bool,
    #[arg(
        long,
        value_enum,
        default_value_t = RunVectorsNormalize::None,
        help = "Deterministic output normalization profile."
    )]
    normalize: RunVectorsNormalize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ValidateLevel {
    #[value(name = "L0")]
    L0,
    #[value(name = "L1")]
    L1,
}

impl ValidateLevel {
    fn as_str(self) -> &'static str {
        match self {
            ValidateLevel::L0 => "L0",
            ValidateLevel::L1 => "L1",
        }
    }

    fn rank(self) -> u8 {
        match self {
            ValidateLevel::L0 => 0,
            ValidateLevel::L1 => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RunLevel {
    #[value(name = "L0")]
    L0,
    #[value(name = "L1")]
    L1,
    #[value(name = "L2")]
    L2,
    #[value(name = "L3")]
    L3,
    #[value(name = "L4")]
    L4,
}

impl RunLevel {
    fn as_str(self) -> &'static str {
        match self {
            RunLevel::L0 => "L0",
            RunLevel::L1 => "L1",
            RunLevel::L2 => "L2",
            RunLevel::L3 => "L3",
            RunLevel::L4 => "L4",
        }
    }

    fn rank(self) -> u8 {
        match self {
            RunLevel::L0 => 0,
            RunLevel::L1 => 1,
            RunLevel::L2 => 2,
            RunLevel::L3 => 3,
            RunLevel::L4 => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RunVectorsNormalize {
    #[value(name = "none")]
    None,
    #[value(name = "ci-v0")]
    CiV0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandName {
    Compile,
    Validate,
    Verify,
    MatchCap,
    RunVectors,
}

impl CommandName {
    fn as_str(self) -> &'static str {
        match self {
            CommandName::Compile => "compile",
            CommandName::Validate => "validate",
            CommandName::Verify => "verify",
            CommandName::MatchCap => "match-cap",
            CommandName::RunVectors => "run-vectors",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum Verdict {
    Pass,
    Fail,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
enum ExitCode {
    Pass = 0,
    Fail = 1,
    InvalidUsage = 2,
    #[allow(dead_code)]
    InputDecodeShape = 3,
    IoOrBundle = 4,
    Internal = 5,
}

impl ExitCode {
    fn from_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Pass => ExitCode::Pass,
            Verdict::Fail => ExitCode::Fail,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    InvalidUsage(#[from] clap::Error),
    #[error("{0}")]
    IoOrBundle(String),
    #[error("{0}")]
    Internal(String),
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            CliError::InvalidUsage(err) => match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::Pass,
                _ => ExitCode::InvalidUsage,
            },
            CliError::IoOrBundle(_) => ExitCode::IoOrBundle,
            CliError::Internal(_) => ExitCode::Internal,
        }
    }

    fn emit(self) {
        match self {
            CliError::InvalidUsage(err) => {
                let _ = err.print();
            }
            other => {
                eprintln!("{other}");
            }
        }
    }
}

struct CommandOutput {
    result: OfflineToolResult,
    json_out: Option<String>,
    run_vectors_normalize: Option<RunVectorsNormalize>,
}

#[derive(Clone, Debug)]
struct OfflineToolResult {
    command: CommandName,
    verdict: Verdict,
    failure_codes: Vec<String>,
    diagnostics: Vec<Value>,
    details: Option<Value>,
}

impl OfflineToolResult {
    fn with_verdict(
        command: CommandName,
        verdict: Verdict,
        failure_codes: Vec<String>,
        details: Option<Value>,
    ) -> Self {
        Self {
            command,
            verdict,
            failure_codes: order_failure_codes(failure_codes),
            diagnostics: Vec::new(),
            details,
        }
    }

    fn json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "schema_version".to_string(),
            Value::String(RESULT_SCHEMA_VERSION.to_string()),
        );
        map.insert(
            "command".to_string(),
            Value::String(self.command.as_str().to_string()),
        );
        map.insert(
            "verdict".to_string(),
            Value::String(self.verdict.as_str().to_string()),
        );

        let failure_codes = self
            .failure_codes
            .iter()
            .map(|code| Value::String(code.clone()))
            .collect();
        map.insert("failure_codes".to_string(), Value::Array(failure_codes));

        if !self.diagnostics.is_empty() {
            map.insert(
                "diagnostics".to_string(),
                Value::Array(self.diagnostics.clone()),
            );
        }
        if let Some(details) = &self.details {
            map.insert("details".to_string(), details.clone());
        }
        Value::Object(map)
    }
}

fn main() {
    let code = match run() {
        Ok(code) => code as i32,
        Err(err) => {
            let exit_code = err.exit_code() as i32;
            err.emit();
            exit_code
        }
    };
    std::process::exit(code);
}

fn run() -> Result<ExitCode, CliError> {
    let cli = Cli::try_parse()?;
    let output = execute(cli)?;
    let mut json_value = output.result.json_value();
    if let Some(normalize_mode) = output.run_vectors_normalize {
        normalize_run_vectors_output(normalize_mode, &mut json_value);
    }
    let json = serde_json::to_string(&json_value)
        .map_err(|err| CliError::Internal(format!("failed to serialize JSON result: {err}")))?;
    emit_json(&json, output.json_out.as_deref())?;
    Ok(ExitCode::from_verdict(output.result.verdict))
}

fn execute(cli: Cli) -> Result<CommandOutput, CliError> {
    match cli.command {
        Commands::Compile(args) => {
            let json_out = args.json_out.clone();
            Ok(CommandOutput {
                result: cmd_compile(args),
                json_out,
                run_vectors_normalize: None,
            })
        }
        Commands::Validate(args) => {
            let json_out = args.json_out.clone();
            Ok(CommandOutput {
                result: cmd_validate(args),
                json_out,
                run_vectors_normalize: None,
            })
        }
        Commands::Verify(args) => {
            let json_out = args.json_out.clone();
            Ok(CommandOutput {
                result: cmd_verify(args),
                json_out,
                run_vectors_normalize: None,
            })
        }
        Commands::MatchCap(args) => cmd_match_cap(args),
        Commands::RunVectors(args) => {
            let json_out = args.json_out.clone();
            let run_vectors_normalize = Some(args.normalize);
            Ok(CommandOutput {
                result: cmd_run_vectors(args),
                json_out,
                run_vectors_normalize,
            })
        }
    }
}

fn cmd_compile(args: CompileArgs) -> OfflineToolResult {
    let artifact_path = Path::new(args.artifact.as_str());
    let out_path = Path::new(args.out.as_str());

    let artifact_value = match load_workflow_artifact_value(artifact_path, None) {
        Ok(value) => value,
        Err(issue) => {
            let mut details = Map::new();
            details.insert(
                "artifact_path".to_string(),
                Value::String(artifact_path.display().to_string()),
            );
            details.insert(
                "primary_failure".to_string(),
                Value::String(FAILURE_CODE_STATE_INVALID.to_string()),
            );
            details.insert("schema_issue".to_string(), Value::String(issue));
            return OfflineToolResult::with_verdict(
                CommandName::Compile,
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                Some(Value::Object(details)),
            );
        }
    };

    let eval_ir = match portable_workflow_artifact_subset_v0::parse_and_compile_artifact_subset_v0(
        &artifact_value,
    ) {
        Ok(eval_ir) => eval_ir,
        Err(failure) => {
            let mut details = Map::new();
            details.insert(
                "artifact_path".to_string(),
                Value::String(artifact_path.display().to_string()),
            );
            if let Some(primary_failure) = failure.failure_codes.first() {
                details.insert(
                    "primary_failure".to_string(),
                    Value::String(primary_failure.clone()),
                );
            }
            details.insert(
                "issues".to_string(),
                Value::Array(failure.issues.into_iter().map(Value::String).collect()),
            );
            return OfflineToolResult::with_verdict(
                CommandName::Compile,
                Verdict::Fail,
                failure.failure_codes,
                Some(Value::Object(details)),
            );
        }
    };

    let mut eval_ir_json_value = match serde_json::to_value(&eval_ir) {
        Ok(value) => value,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "artifact_path".to_string(),
                Value::String(artifact_path.display().to_string()),
            );
            details.insert(
                "primary_failure".to_string(),
                Value::String(FAILURE_CODE_STATE_INVALID.to_string()),
            );
            details.insert(
                "schema_issue".to_string(),
                Value::String(format!("failed to serialize compiled EvalIR JSON: {err}")),
            );
            return OfflineToolResult::with_verdict(
                CommandName::Compile,
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                Some(Value::Object(details)),
            );
        }
    };
    strip_null_object_fields(&mut eval_ir_json_value);
    let eval_ir_json = match serde_json::to_string_pretty(&eval_ir_json_value) {
        Ok(json) => json,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "artifact_path".to_string(),
                Value::String(artifact_path.display().to_string()),
            );
            details.insert(
                "primary_failure".to_string(),
                Value::String(FAILURE_CODE_STATE_INVALID.to_string()),
            );
            details.insert(
                "schema_issue".to_string(),
                Value::String(format!("failed to serialize compiled EvalIR JSON: {err}")),
            );
            return OfflineToolResult::with_verdict(
                CommandName::Compile,
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                Some(Value::Object(details)),
            );
        }
    };

    if let Err(err) = fs::write(out_path, format!("{eval_ir_json}\n")) {
        let mut details = Map::new();
        details.insert(
            "artifact_path".to_string(),
            Value::String(artifact_path.display().to_string()),
        );
        details.insert(
            "out_path".to_string(),
            Value::String(out_path.display().to_string()),
        );
        details.insert(
            "primary_failure".to_string(),
            Value::String(FAILURE_CODE_STATE_INVALID.to_string()),
        );
        details.insert(
            "schema_issue".to_string(),
            Value::String(format!(
                "failed to write compiled EvalIR JSON '{}': {err}",
                out_path.display()
            )),
        );
        return OfflineToolResult::with_verdict(
            CommandName::Compile,
            Verdict::Fail,
            vec![FAILURE_CODE_STATE_INVALID.to_string()],
            Some(Value::Object(details)),
        );
    }

    let mut details = Map::new();
    details.insert(
        "artifact_path".to_string(),
        Value::String(artifact_path.display().to_string()),
    );
    details.insert(
        "entry_step_id".to_string(),
        Value::String(eval_ir.entry_step_id.clone()),
    );
    details.insert(
        "out_path".to_string(),
        Value::String(out_path.display().to_string()),
    );
    details.insert(
        "step_count".to_string(),
        Value::Number(Number::from(eval_ir.steps.len() as u64)),
    );

    OfflineToolResult::with_verdict(
        CommandName::Compile,
        Verdict::Pass,
        Vec::new(),
        Some(Value::Object(details)),
    )
}

fn cmd_validate(args: ValidateArgs) -> OfflineToolResult {
    if let Some(bundle_dir) = args.bundle.as_deref() {
        if let Some(bundle_artifact_path) = args.artifact.as_deref() {
            return validate_bundle_root_artifact(bundle_dir, bundle_artifact_path, &args.levels);
        }
        return validate_bundle(bundle_dir);
    }

    let artifact_path = match args.artifact.as_deref() {
        Some(path) => path,
        None => {
            return OfflineToolResult::with_verdict(
                CommandName::Validate,
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                None,
            )
        }
    };

    let levels = ordered_validate_levels(&args.levels);
    let mut aggregated_failure_codes = Vec::new();
    let mut artifact_hash: Option<String> = None;
    let mut level_results = Vec::new();
    for level in levels {
        let (verdict, failure_codes, level_artifact_hash) = match level {
            ValidateLevel::L0 => (
                Verdict::Fail,
                vec![FAILURE_CODE_STEP_CONTRACT.to_string()],
                None,
            ),
            ValidateLevel::L1 => validate_l1_artifact(Path::new(artifact_path)),
        };

        if artifact_hash.is_none() {
            artifact_hash = level_artifact_hash.clone();
        }

        let failure_codes = order_failure_codes(failure_codes);
        aggregated_failure_codes.extend(failure_codes.iter().cloned());

        let mut level_result = Map::new();
        level_result.insert(
            "failure_codes".to_string(),
            Value::Array(
                failure_codes
                    .iter()
                    .map(|code| Value::String(code.clone()))
                    .collect(),
            ),
        );
        level_result.insert(
            "level".to_string(),
            Value::String(level.as_str().to_string()),
        );
        level_result.insert(
            "verdict".to_string(),
            Value::String(verdict.as_str().to_string()),
        );
        if let Some(level_artifact_hash) = level_artifact_hash {
            level_result.insert(
                "artifact_hash".to_string(),
                Value::String(level_artifact_hash),
            );
        }
        level_results.push(Value::Object(level_result));
    }

    let failure_codes = order_failure_codes(aggregated_failure_codes);
    let verdict = if failure_codes.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail
    };

    let mut details = Map::new();
    if let Some(artifact_hash) = artifact_hash {
        details.insert("artifact_hash".to_string(), Value::String(artifact_hash));
    }
    details.insert("level_results".to_string(), Value::Array(level_results));

    OfflineToolResult::with_verdict(
        CommandName::Validate,
        verdict,
        failure_codes,
        Some(Value::Object(details)),
    )
}

fn validate_bundle_root_artifact(
    bundle_dir: &str,
    bundle_artifact_path: &str,
    levels: &[ValidateLevel],
) -> OfflineToolResult {
    let bundle_root = Path::new(bundle_dir);
    let artifact_path = match resolve_bundle_relative_path_with_context(
        bundle_root,
        bundle_artifact_path,
        "--artifact",
    ) {
        Ok(path) => path,
        Err(issue) => {
            let mut details = Map::new();
            details.insert(
                "bundle_path".to_string(),
                Value::String(bundle_root.display().to_string()),
            );
            details.insert(
                "artifact_path".to_string(),
                Value::String(bundle_artifact_path.to_string()),
            );
            details.insert(
                "primary_failure".to_string(),
                Value::String(FAILURE_CODE_STATE_INVALID.to_string()),
            );
            details.insert("schema_issue".to_string(), Value::String(issue));
            return OfflineToolResult::with_verdict(
                CommandName::Validate,
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                Some(Value::Object(details)),
            );
        }
    };

    let levels = if levels.is_empty() {
        vec![ValidateLevel::L1]
    } else {
        ordered_validate_levels(levels)
    };

    let mut aggregated_failure_codes = Vec::new();
    let mut artifact_hash: Option<String> = None;
    let mut level_results = Vec::new();
    for level in levels {
        let (verdict, failure_codes, level_artifact_hash) = match level {
            ValidateLevel::L0 => (
                Verdict::Fail,
                vec![FAILURE_CODE_STEP_CONTRACT.to_string()],
                None,
            ),
            ValidateLevel::L1 => {
                validate_l1_import_rooted_artifact(&artifact_path, Some(bundle_root))
            }
        };

        if artifact_hash.is_none() {
            artifact_hash = level_artifact_hash.clone();
        }

        let failure_codes = order_failure_codes(failure_codes);
        aggregated_failure_codes.extend(failure_codes.iter().cloned());

        let mut level_result = Map::new();
        level_result.insert(
            "failure_codes".to_string(),
            Value::Array(
                failure_codes
                    .iter()
                    .map(|code| Value::String(code.clone()))
                    .collect(),
            ),
        );
        level_result.insert(
            "level".to_string(),
            Value::String(level.as_str().to_string()),
        );
        level_result.insert(
            "verdict".to_string(),
            Value::String(verdict.as_str().to_string()),
        );
        if let Some(level_artifact_hash) = level_artifact_hash {
            level_result.insert(
                "artifact_hash".to_string(),
                Value::String(level_artifact_hash),
            );
        }
        level_results.push(Value::Object(level_result));
    }

    let failure_codes = order_failure_codes(aggregated_failure_codes);
    let verdict = if failure_codes.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail
    };

    let mut details = Map::new();
    details.insert(
        "artifact_path".to_string(),
        Value::String(bundle_artifact_path.to_string()),
    );
    details.insert(
        "bundle_path".to_string(),
        Value::String(bundle_root.display().to_string()),
    );
    if let Some(artifact_hash) = artifact_hash {
        details.insert("artifact_hash".to_string(), Value::String(artifact_hash));
    }
    details.insert("level_results".to_string(), Value::Array(level_results));

    OfflineToolResult::with_verdict(
        CommandName::Validate,
        verdict,
        failure_codes,
        Some(Value::Object(details)),
    )
}

#[derive(Debug)]
struct BundleArtifactRef {
    path: String,
    expected_hash: String,
}

#[derive(Debug)]
struct BundlePathRef {
    path: String,
    source_field: &'static str,
}

#[derive(Debug)]
struct BundleMatchCapRefs {
    requirements_ref: BundlePathRef,
    gamma_cap_ref: BundlePathRef,
}

fn validate_bundle(bundle_dir: &str) -> OfflineToolResult {
    let bundle_root = Path::new(bundle_dir);
    let manifest_path = bundle_root.join(BUNDLE_MANIFEST_FILENAME);
    let manifest_bytes = match fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "bundle_path".to_string(),
                Value::String(bundle_root.display().to_string()),
            );
            details.insert(
                "manifest_path".to_string(),
                Value::String(BUNDLE_MANIFEST_FILENAME.to_string()),
            );
            let message = if err.kind() == io::ErrorKind::NotFound {
                format!(
                    "required bundle manifest is missing: {}/{}",
                    bundle_root.display(),
                    BUNDLE_MANIFEST_FILENAME
                )
            } else {
                format!(
                    "failed reading bundle manifest '{}': {err}",
                    manifest_path.display()
                )
            };
            return bundle_failure_result(
                FAILURE_CODE_STATE_INVALID,
                Some(Value::Object(details)),
                Some(message),
            );
        }
    };

    let bundle_manifest_hash = sha256_prefixed(&manifest_bytes);

    let manifest_value = match rulia::decode_value(&manifest_bytes) {
        Ok(value) => value,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "bundle_manifest_hash".to_string(),
                Value::String(bundle_manifest_hash),
            );
            return bundle_failure_result(
                FAILURE_CODE_STATE_INVALID,
                Some(Value::Object(details)),
                Some(format!(
                    "failed to decode bundle manifest '{}': {err}",
                    manifest_path.display()
                )),
            );
        }
    };

    let artifact_ref = match decode_bundle_manifest_artifact_ref(&manifest_value) {
        Ok(artifact_ref) => artifact_ref,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "bundle_manifest_hash".to_string(),
                Value::String(bundle_manifest_hash),
            );
            return bundle_failure_result(
                FAILURE_CODE_STATE_INVALID,
                Some(Value::Object(details)),
                Some(format!("manifest decode unsupported: {err}")),
            );
        }
    };

    let artifact_path = match resolve_bundle_relative_path(bundle_root, &artifact_ref.path) {
        Ok(path) => path,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "artifact_path".to_string(),
                Value::String(artifact_ref.path.clone()),
            );
            details.insert(
                "bundle_manifest_hash".to_string(),
                Value::String(bundle_manifest_hash),
            );
            return bundle_failure_result(
                FAILURE_CODE_STATE_INVALID,
                Some(Value::Object(details)),
                Some(err),
            );
        }
    };

    let artifact_bytes = match fs::read(&artifact_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let mut details = Map::new();
            details.insert(
                "artifact_path".to_string(),
                Value::String(artifact_ref.path.clone()),
            );
            details.insert(
                "bundle_manifest_hash".to_string(),
                Value::String(bundle_manifest_hash),
            );
            return bundle_failure_result(
                FAILURE_CODE_STATE_INVALID,
                Some(Value::Object(details)),
                Some(format!(
                    "failed reading artifact bytes '{}': {err}",
                    artifact_path.display()
                )),
            );
        }
    };

    let artifact_hash = sha256_prefixed(&artifact_bytes);
    if artifact_hash != artifact_ref.expected_hash {
        let mut details = Map::new();
        details.insert("artifact_hash".to_string(), Value::String(artifact_hash));
        details.insert(
            "artifact_path".to_string(),
            Value::String(artifact_ref.path.clone()),
        );
        details.insert(
            "bundle_manifest_hash".to_string(),
            Value::String(bundle_manifest_hash),
        );
        details.insert(
            "expected_artifact_hash".to_string(),
            Value::String(artifact_ref.expected_hash),
        );
        return bundle_failure_result(
            FAILURE_CODE_ARTIFACT_IDENTITY,
            Some(Value::Object(details)),
            None,
        );
    }

    let mut details = Map::new();
    details.insert("artifact_hash".to_string(), Value::String(artifact_hash));
    details.insert(
        "artifact_path".to_string(),
        Value::String(artifact_ref.path),
    );
    details.insert(
        "bundle_manifest_hash".to_string(),
        Value::String(bundle_manifest_hash),
    );

    OfflineToolResult::with_verdict(
        CommandName::Validate,
        Verdict::Pass,
        Vec::new(),
        Some(Value::Object(details)),
    )
}

fn bundle_failure_result(
    failure_code: &str,
    details: Option<Value>,
    diagnostic_message: Option<String>,
) -> OfflineToolResult {
    let diagnostics = diagnostic_message
        .map(|message| {
            let mut diagnostic = Map::new();
            diagnostic.insert(
                "code".to_string(),
                Value::String(BUNDLE_DIAGNOSTIC_CODE.to_string()),
            );
            diagnostic.insert("message".to_string(), Value::String(message));
            diagnostic.insert("severity".to_string(), Value::String("error".to_string()));
            Value::Object(diagnostic)
        })
        .into_iter()
        .collect();

    OfflineToolResult {
        command: CommandName::Validate,
        verdict: Verdict::Fail,
        failure_codes: order_failure_codes(vec![failure_code.to_string()]),
        diagnostics,
        details,
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        hex::encode(HashAlgorithm::Sha256.compute(bytes))
    )
}

fn decode_bundle_manifest_artifact_ref(manifest: &RuliaValue) -> Result<BundleArtifactRef, String> {
    let root_entries = bundle_manifest_root_entries(manifest)?;
    let artifact_ref_value = map_get(
        root_entries,
        &["artifact_ref", "artifact/ref", "artifactRef"],
    )
    .ok_or_else(|| "manifest missing artifact_ref".to_string())?;
    let artifact_ref_entries = expect_map_entries(
        artifact_ref_value,
        "manifest artifact_ref must be a map value",
    )?;

    let path_value = map_get(artifact_ref_entries, &["path"])
        .ok_or_else(|| "manifest artifact_ref missing path".to_string())?;
    let path = expect_string(
        path_value,
        "manifest artifact_ref.path must be a string value",
    )?
    .to_string();

    let hash_value = map_get(artifact_ref_entries, &["hash"])
        .ok_or_else(|| "manifest artifact_ref missing hash".to_string())?;
    let expected_hash = decode_manifest_digest(hash_value)?;

    Ok(BundleArtifactRef {
        path,
        expected_hash,
    })
}

fn decode_bundle_manifest_match_cap_refs(
    manifest: &RuliaValue,
) -> Result<BundleMatchCapRefs, String> {
    let root_entries = bundle_manifest_root_entries(manifest)?;
    let requirements_ref = decode_manifest_path_ref(
        root_entries,
        &[
            "capability_requirements_ref",
            "capability_requirements/ref",
            "capabilityRequirementsRef",
            "requirements_ref",
            "requirements/ref",
            "requirementsRef",
        ],
        "capability_requirements_ref",
        "manifest capability_requirements_ref.path",
    )?
    .ok_or_else(|| "manifest missing capability_requirements_ref.path".to_string())?;

    let gamma_cap_ref = match decode_manifest_path_ref(
        root_entries,
        &["gamma_cap_ref", "gamma_cap/ref", "gammaCapRef"],
        "gamma_cap_ref",
        "manifest gamma_cap_ref.path",
    )? {
        Some(gamma_cap_ref) => gamma_cap_ref,
        None => decode_manifest_gamma_cap_snapshot_path(root_entries)?,
    };

    Ok(BundleMatchCapRefs {
        requirements_ref,
        gamma_cap_ref,
    })
}

fn bundle_manifest_root_entries(
    manifest: &RuliaValue,
) -> Result<&[(RuliaValue, RuliaValue)], String> {
    let RuliaValue::Tagged(tagged) = manifest else {
        return Err("root must be a tagged BundleManifestV0 value".to_string());
    };
    let tag_name = tagged.tag.as_str();
    if tag_name != "bundle_manifest_v0" {
        return Err(format!(
            "root tag must be 'bundle_manifest_v0', found '{tag_name}'"
        ));
    }

    expect_map_entries(
        tagged.value.as_ref(),
        "manifest tagged payload must be a map",
    )
}

fn decode_manifest_path_ref(
    root_entries: &[(RuliaValue, RuliaValue)],
    key_candidates: &[&str],
    field_name: &str,
    source_field: &'static str,
) -> Result<Option<BundlePathRef>, String> {
    let Some(value) = map_get(root_entries, key_candidates) else {
        return Ok(None);
    };

    let path = match value {
        RuliaValue::String(path) => path.clone(),
        _ => {
            let entries = expect_map_entries(
                value,
                format!("manifest {field_name} must be a map or string value").as_str(),
            )?;
            let path_value = map_get(entries, &["path"])
                .ok_or_else(|| format!("manifest {field_name} missing path"))?;
            expect_string(
                path_value,
                format!("manifest {field_name}.path must be a string value").as_str(),
            )?
            .to_string()
        }
    };

    Ok(Some(BundlePathRef { path, source_field }))
}

fn decode_manifest_gamma_cap_snapshot_path(
    root_entries: &[(RuliaValue, RuliaValue)],
) -> Result<BundlePathRef, String> {
    let gamma_cap_snapshots_value = map_get(
        root_entries,
        &[
            "gamma_cap_snapshots",
            "gamma_cap/snapshots",
            "gammaCapSnapshots",
        ],
    )
    .ok_or_else(|| "manifest missing gamma_cap_ref.path and gamma_cap_snapshots".to_string())?;
    let snapshots = expect_sequence_values(
        gamma_cap_snapshots_value,
        "manifest gamma_cap_snapshots must be vector/set",
    )?;
    if snapshots.is_empty() {
        return Err("manifest gamma_cap_snapshots must include at least one entry".to_string());
    }
    if snapshots.len() != 1 {
        return Err(
            "manifest gamma_cap_snapshots must include exactly one entry when gamma_cap_ref.path is absent"
                .to_string(),
        );
    }

    let snapshot_entries = expect_map_entries(
        snapshots
            .first()
            .expect("gamma_cap_snapshots length checked"),
        "manifest gamma_cap_snapshots[0] must be a map value",
    )?;
    let path_value = map_get(snapshot_entries, &["path"])
        .ok_or_else(|| "manifest gamma_cap_snapshots[0] missing path".to_string())?;
    let path = expect_string(
        path_value,
        "manifest gamma_cap_snapshots[0].path must be a string value",
    )?
    .to_string();

    Ok(BundlePathRef {
        path,
        source_field: "manifest gamma_cap_snapshots[0].path",
    })
}

fn expect_map_entries<'a>(
    value: &'a RuliaValue,
    message: &str,
) -> Result<&'a [(RuliaValue, RuliaValue)], String> {
    match value {
        RuliaValue::Map(entries) => Ok(entries.as_slice()),
        _ => Err(message.to_string()),
    }
}

fn expect_string<'a>(value: &'a RuliaValue, message: &str) -> Result<&'a str, String> {
    match value {
        RuliaValue::String(inner) => Ok(inner.as_str()),
        _ => Err(message.to_string()),
    }
}

fn decode_manifest_digest(value: &RuliaValue) -> Result<String, String> {
    match value {
        RuliaValue::Tagged(tagged) => {
            let tag_name = tagged.tag.as_str();
            if tag_name != "digest" {
                return Err(format!(
                    "manifest digest tag must be 'digest', found '{tag_name}'"
                ));
            }
            let digest_entries = expect_map_entries(
                tagged.value.as_ref(),
                "manifest digest payload must be a map",
            )?;
            let alg_value = map_get(digest_entries, &["alg"])
                .ok_or_else(|| "manifest digest missing alg".to_string())?;
            let algorithm = keyword_or_string(alg_value)
                .ok_or_else(|| "manifest digest alg must be keyword/string".to_string())?;
            if algorithm != "sha256" {
                return Err(format!(
                    "unsupported manifest digest algorithm '{algorithm}' (expected sha256)"
                ));
            }

            let hex_value = map_get(digest_entries, &["hex"])
                .ok_or_else(|| "manifest digest missing hex".to_string())?;
            let hex = expect_string(hex_value, "manifest digest hex must be a string")?;
            if !is_valid_sha256_hex(hex) {
                return Err(
                    "manifest digest hex must be 64 lowercase/uppercase hex characters".to_string(),
                );
            }
            Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
        }
        RuliaValue::String(value) => parse_prefixed_sha256(value).ok_or_else(|| {
            "manifest artifact_ref.hash string must use 'sha256:<64-hex>'".to_string()
        }),
        _ => Err("manifest artifact_ref.hash must be a Digest tagged value or string".to_string()),
    }
}

fn parse_prefixed_sha256(value: &str) -> Option<String> {
    let (algorithm, hex) = value.split_once(':')?;
    if algorithm != "sha256" || !is_valid_sha256_hex(hex) {
        return None;
    }
    Some(format!("sha256:{}", hex.to_ascii_lowercase()))
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn keyword_or_string(value: &RuliaValue) -> Option<String> {
    match value {
        RuliaValue::Keyword(keyword) => Some(keyword.as_symbol().as_str()),
        RuliaValue::String(value) => Some(value.to_string()),
        _ => None,
    }
}

fn map_get<'a>(
    entries: &'a [(RuliaValue, RuliaValue)],
    candidate_keys: &[&str],
) -> Option<&'a RuliaValue> {
    let normalized_candidates = candidate_keys
        .iter()
        .map(|candidate| normalized_lookup_key(candidate))
        .collect::<Vec<_>>();
    entries.iter().find_map(|(key, value)| {
        let key_name = match key {
            RuliaValue::Keyword(keyword) => keyword.as_symbol().as_str(),
            RuliaValue::String(raw) => raw.clone(),
            _ => return None,
        };
        let normalized_key = normalized_lookup_key(key_name.as_str());
        if normalized_candidates
            .iter()
            .any(|candidate_key| candidate_key == &normalized_key)
        {
            Some(value)
        } else {
            None
        }
    })
}

fn normalized_lookup_key(value: &str) -> String {
    value.replace(['/', '-'], "_")
}

fn resolve_bundle_relative_path(
    bundle_root: &Path,
    relative_path: &str,
) -> Result<std::path::PathBuf, String> {
    resolve_bundle_relative_path_with_context(
        bundle_root,
        relative_path,
        "manifest artifact_ref.path",
    )
}

fn resolve_bundle_relative_path_with_context(
    bundle_root: &Path,
    relative_path: &str,
    field_path: &str,
) -> Result<std::path::PathBuf, String> {
    if relative_path.is_empty() {
        return Err(format!("{field_path} must be non-empty"));
    }
    let relative = safe_relative_path(relative_path).map_err(|error| match error {
        SafeRelativePathError::BackslashSeparator => {
            format!("{field_path} must use bundle-relative POSIX separators")
        }
        SafeRelativePathError::AbsolutePath => {
            format!("{field_path} must be bundle-relative")
        }
        SafeRelativePathError::ForbiddenSegments => {
            format!("{field_path} '{relative_path}' contains forbidden path segments")
        }
        SafeRelativePathError::InvalidRelativePath => {
            format!("{field_path} '{relative_path}' is not a valid bundle-relative file path")
        }
    })?;

    Ok(bundle_root.join(relative))
}

fn validate_l1_artifact(artifact_path: &Path) -> (Verdict, Vec<String>, Option<String>) {
    if should_resolve_imports_for_artifact(artifact_path, false) {
        return validate_l1_import_rooted_artifact(artifact_path, None);
    }

    let artifact_bytes = match fs::read(artifact_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                None,
            );
        }
    };

    if artifact_bytes.is_empty() {
        return (
            Verdict::Fail,
            vec![FAILURE_CODE_ARTIFACT_IDENTITY.to_string()],
            None,
        );
    }

    let digest = HashAlgorithm::Sha256.compute(&artifact_bytes);
    let artifact_hash = format!("sha256:{}", hex::encode(digest));
    (Verdict::Pass, Vec::new(), Some(artifact_hash))
}

fn validate_l1_import_rooted_artifact(
    artifact_path: &Path,
    bundle_root: Option<&Path>,
) -> (Verdict, Vec<String>, Option<String>) {
    let artifact_value = match load_workflow_artifact_value(artifact_path, bundle_root) {
        Ok(value) => value,
        Err(_) => {
            return (
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                None,
            );
        }
    };
    let canonical_bytes = match rulia::encode_canonical(&artifact_value) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                Verdict::Fail,
                vec![FAILURE_CODE_STATE_INVALID.to_string()],
                None,
            );
        }
    };
    let digest = HashAlgorithm::Sha256.compute(&canonical_bytes);
    let artifact_hash = format!("sha256:{}", hex::encode(digest));
    (Verdict::Pass, Vec::new(), Some(artifact_hash))
}

fn should_resolve_imports_for_artifact(path: &Path, bundle_root_mode: bool) -> bool {
    bundle_root_mode
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension == "rjl" || extension == "rulia")
}

#[derive(Debug)]
struct ParsedDigestValue {
    algorithm: HashAlgorithm,
    hex: String,
}

impl ParsedDigestValue {
    fn prefixed(&self) -> String {
        format!("{}:{}", self.algorithm.as_str(), self.hex)
    }
}

#[derive(Debug)]
struct ParsedReceiptV0 {
    request_hash: ParsedDigestValue,
    signer_key_id: String,
    signature_alg: String,
    scope: String,
    signature: Vec<u8>,
    signing_body_bytes: Vec<u8>,
}

#[derive(Debug)]
struct ParsedReceiptValidObligationV0 {
    request_hash: ParsedDigestValue,
}

#[derive(Debug)]
struct TrustAnchorSet {
    public_keys: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug)]
struct HistoryReceiptCandidate {
    history_index: u64,
    source_path: String,
    canonical_receipt_hash: String,
    parsed_receipt: ParsedReceiptV0,
}

#[derive(Debug, Clone)]
struct ObligationHistoryReceiptV0 {
    history_index: u64,
    source_path: String,
    canonical_receipt_hash: String,
    request_hash: String,
    signer_key_id: Option<String>,
    signature_valid: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct ObligationTrustContextV0 {
    // `None` means unsigned/hash-only satisfaction mode.
    trusted_signer_keys: Option<BTreeSet<String>>,
}

#[derive(Debug, Clone)]
struct ObligationSatisfactionResultV0 {
    satisfied: bool,
    failure_codes: Vec<String>,
    matched_receipt_count: usize,
    verified_receipt_index: Option<u64>,
    verified_receipt_path: Option<String>,
}

#[derive(Debug)]
struct ReceiptVerificationResult {
    failure_codes: Vec<String>,
    signature_valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyMode {
    Receipt,
    Obligation,
}

fn cmd_verify(args: VerifyArgs) -> OfflineToolResult {
    let mode = match resolve_verify_mode(&args) {
        Ok(mode) => mode,
        Err(issue) => {
            let mut details = Map::new();
            details.insert("mode".to_string(), Value::String("verify".to_string()));
            return verify_schema_failure(details, issue);
        }
    };
    match mode {
        VerifyMode::Receipt => cmd_verify_receipt(&args),
        VerifyMode::Obligation => cmd_verify_obligation(&args),
    }
}

fn resolve_verify_mode(args: &VerifyArgs) -> Result<VerifyMode, String> {
    let obligation_input_present =
        args.obligation.is_some() || args.history.is_some() || args.bundle.is_some();
    if obligation_input_present {
        if args.obligation.is_none() {
            return Err("--obligation is required when using --history/--bundle".to_string());
        }
        if args.history.is_some() == args.bundle.is_some() {
            return Err(
                "exactly one of --history or --bundle is required for obligation verification"
                    .to_string(),
            );
        }
        if args.request.is_some() || args.receipt.is_some() {
            return Err(
                "--request and --receipt are not allowed when verifying --obligation".to_string(),
            );
        }
        return Ok(VerifyMode::Obligation);
    }

    if args.request.is_none() || args.receipt.is_none() {
        return Err("--request and --receipt are required for receipt verification".to_string());
    }
    Ok(VerifyMode::Receipt)
}

fn cmd_verify_receipt(args: &VerifyArgs) -> OfflineToolResult {
    let mut details = Map::new();
    details.insert("mode".to_string(), Value::String("receipt".to_string()));

    let request_path = args
        .request
        .as_deref()
        .expect("receipt mode must include --request");
    let request_value = match load_rulia_value(Path::new(request_path), "request") {
        Ok(value) => value,
        Err(issue) => return verify_schema_failure(details, issue),
    };
    if let Err(issue) = validate_request_v0(&request_value) {
        return verify_schema_failure(details, issue);
    }

    let receipt_path = args
        .receipt
        .as_deref()
        .expect("receipt mode must include --receipt");
    let receipt_value = match load_rulia_value(Path::new(receipt_path), "receipt") {
        Ok(value) => value,
        Err(issue) => return verify_schema_failure(details, issue),
    };
    let parsed_receipt = match parse_receipt_v0(&receipt_value) {
        Ok(parsed) => parsed,
        Err(issue) => return verify_schema_failure(details, issue),
    };

    let trust_anchors = match load_trust_anchors(Path::new(args.trust.as_str())) {
        Ok(anchors) => anchors,
        Err(issue) => return verify_schema_failure(details, issue),
    };

    details.insert(
        "receipt_request_hash".to_string(),
        Value::String(parsed_receipt.request_hash.prefixed()),
    );
    details.insert(
        "receipt_signature_alg".to_string(),
        Value::String(parsed_receipt.signature_alg.clone()),
    );
    details.insert(
        "signer_key_id".to_string(),
        Value::String(parsed_receipt.signer_key_id.clone()),
    );
    details.insert(
        "trust_anchor_count".to_string(),
        Value::Number(Number::from(trust_anchors.public_keys.len() as u64)),
    );

    let computed_request_hash =
        match hash_canonical_prefixed(&request_value, parsed_receipt.request_hash.algorithm) {
            Ok(hash) => hash,
            Err(issue) => return verify_schema_failure(details, issue),
        };
    details.insert(
        "request_hash".to_string(),
        Value::String(computed_request_hash.clone()),
    );

    let verification = verify_receipt_against_expected_hash(
        &parsed_receipt,
        &computed_request_hash,
        &trust_anchors,
    );
    details.insert(
        "signature_valid".to_string(),
        Value::Bool(verification.signature_valid),
    );

    let failure_codes = verification.failure_codes;
    let verdict = if failure_codes.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    if let Some(primary_failure) = failure_codes.first() {
        details.insert(
            "primary_failure".to_string(),
            Value::String(primary_failure.clone()),
        );
    }

    OfflineToolResult::with_verdict(
        CommandName::Verify,
        verdict,
        failure_codes,
        Some(Value::Object(details)),
    )
}

fn cmd_verify_obligation(args: &VerifyArgs) -> OfflineToolResult {
    let mut details = Map::new();
    details.insert("mode".to_string(), Value::String("obligation".to_string()));

    let obligation_path = args
        .obligation
        .as_deref()
        .expect("obligation mode must include --obligation");
    let obligation_value = match load_rulia_value(Path::new(obligation_path), "obligation") {
        Ok(value) => value,
        Err(issue) => return verify_schema_failure(details, issue),
    };
    let parsed_obligation = match parse_receipt_valid_obligation_v0(&obligation_value) {
        Ok(parsed) => parsed,
        Err(issue) => return verify_schema_failure(details, issue),
    };
    let expected_request_hash = parsed_obligation.request_hash.prefixed();
    details.insert(
        "obligation_type".to_string(),
        Value::String("receipt_valid".to_string()),
    );
    details.insert(
        "obligation_request_hash".to_string(),
        Value::String(expected_request_hash.clone()),
    );

    let trust_anchors = match load_trust_anchors(Path::new(args.trust.as_str())) {
        Ok(anchors) => anchors,
        Err(issue) => return verify_schema_failure(details, issue),
    };
    details.insert(
        "trust_anchor_count".to_string(),
        Value::Number(Number::from(trust_anchors.public_keys.len() as u64)),
    );
    let history_source = args
        .history
        .as_deref()
        .map(str::to_owned)
        .or_else(|| {
            args.bundle
                .as_deref()
                .map(|bundle| format!("{bundle}/history"))
        })
        .unwrap_or_else(|| "history".to_string());
    details.insert("history_source".to_string(), Value::String(history_source));

    let history_receipts = match collect_history_receipt_candidates(args) {
        Ok(candidates) => candidates,
        Err(issue) => return verify_schema_failure(details, issue),
    };
    details.insert(
        "history_receipt_count".to_string(),
        Value::Number(Number::from(history_receipts.len() as u64)),
    );
    let obligation_history = history_receipts
        .iter()
        .map(|candidate| {
            let signer_key_id = candidate.parsed_receipt.signer_key_id.clone();
            let signature_valid = trust_anchors
                .public_keys
                .get(&signer_key_id)
                .map(|public_key| verify_receipt_signature(&candidate.parsed_receipt, public_key));
            ObligationHistoryReceiptV0 {
                history_index: candidate.history_index,
                source_path: candidate.source_path.clone(),
                canonical_receipt_hash: candidate.canonical_receipt_hash.clone(),
                request_hash: candidate.parsed_receipt.request_hash.prefixed(),
                signer_key_id: Some(signer_key_id),
                signature_valid,
            }
        })
        .collect::<Vec<_>>();
    let trust_context = ObligationTrustContextV0 {
        trusted_signer_keys: Some(trust_anchors.public_keys.keys().cloned().collect()),
    };
    let satisfaction =
        obligation_is_satisfied(&expected_request_hash, &obligation_history, &trust_context);
    details.insert(
        "matching_receipt_count".to_string(),
        Value::Number(Number::from(satisfaction.matched_receipt_count as u64)),
    );

    if satisfaction.satisfied {
        details.insert(
            "satisfaction".to_string(),
            Value::String("satisfied".to_string()),
        );
        if let Some(history_index) = satisfaction.verified_receipt_index {
            details.insert(
                "verified_receipt_index".to_string(),
                Value::Number(Number::from(history_index)),
            );
        }
        if let Some(path) = satisfaction.verified_receipt_path {
            details.insert("verified_receipt_path".to_string(), Value::String(path));
        }
        return OfflineToolResult::with_verdict(
            CommandName::Verify,
            Verdict::Pass,
            Vec::new(),
            Some(Value::Object(details)),
        );
    }

    let failure_codes = satisfaction.failure_codes;
    details.insert(
        "satisfaction".to_string(),
        Value::String("unsatisfied".to_string()),
    );
    if let Some(primary_failure) = failure_codes.first() {
        details.insert(
            "primary_failure".to_string(),
            Value::String(primary_failure.clone()),
        );
    }

    OfflineToolResult::with_verdict(
        CommandName::Verify,
        Verdict::Fail,
        failure_codes,
        Some(Value::Object(details)),
    )
}

fn obligation_is_satisfied(
    expected_request_hash: &str,
    history_receipts: &[ObligationHistoryReceiptV0],
    trust_context: &ObligationTrustContextV0,
) -> ObligationSatisfactionResultV0 {
    let mut matching_receipts = history_receipts
        .iter()
        .filter(|candidate| candidate.request_hash == expected_request_hash)
        .collect::<Vec<_>>();
    matching_receipts.sort_by(|left, right| {
        left.history_index.cmp(&right.history_index).then_with(|| {
            left.canonical_receipt_hash
                .cmp(&right.canonical_receipt_hash)
        })
    });

    let matched_receipt_count = matching_receipts.len();
    if matching_receipts.is_empty() {
        return ObligationSatisfactionResultV0 {
            satisfied: false,
            failure_codes: vec![FAILURE_CODE_PROTOCOL_MISSING_RECEIPT.to_string()],
            matched_receipt_count,
            verified_receipt_index: None,
            verified_receipt_path: None,
        };
    }

    // Deterministic unsigned mode for L2 evaluator fixtures: if trust anchors are absent,
    // satisfaction is request-hash based only and does not enforce signature fields.
    if trust_context.trusted_signer_keys.is_none() {
        let first = matching_receipts
            .first()
            .expect("matching_receipts is non-empty");
        return ObligationSatisfactionResultV0 {
            satisfied: true,
            failure_codes: Vec::new(),
            matched_receipt_count,
            verified_receipt_index: Some(first.history_index),
            verified_receipt_path: Some(first.source_path.clone()),
        };
    }

    let trusted_signer_keys = trust_context
        .trusted_signer_keys
        .as_ref()
        .expect("checked is_some above");
    let mut aggregated_failure_codes = Vec::new();
    for candidate in matching_receipts {
        let mut candidate_failures = Vec::new();

        let signer_key_id = candidate.signer_key_id.as_deref();
        let signer_trusted = signer_key_id
            .map(|key_id| trusted_signer_keys.contains(key_id))
            .unwrap_or(false);
        if !signer_trusted {
            candidate_failures.push(FAILURE_CODE_PROTOCOL_UNTRUSTED_SIGNER.to_string());
        }
        if signer_trusted && candidate.signature_valid != Some(true) {
            candidate_failures.push(FAILURE_CODE_PROTOCOL_SIGNATURE_INVALID.to_string());
        }

        if candidate_failures.is_empty() {
            return ObligationSatisfactionResultV0 {
                satisfied: true,
                failure_codes: Vec::new(),
                matched_receipt_count,
                verified_receipt_index: Some(candidate.history_index),
                verified_receipt_path: Some(candidate.source_path.clone()),
            };
        }

        aggregated_failure_codes.extend(candidate_failures);
    }

    ObligationSatisfactionResultV0 {
        satisfied: false,
        failure_codes: order_failure_codes(aggregated_failure_codes),
        matched_receipt_count,
        verified_receipt_index: None,
        verified_receipt_path: None,
    }
}

fn collect_history_receipt_candidates(
    args: &VerifyArgs,
) -> Result<Vec<HistoryReceiptCandidate>, String> {
    if let Some(history_dir) = args.history.as_deref() {
        return load_history_receipt_candidates(Path::new(history_dir), false);
    }

    let bundle_root = Path::new(
        args.bundle
            .as_deref()
            .expect("obligation mode must include --bundle or --history"),
    );
    let bundle_metadata = fs::metadata(bundle_root).map_err(|err| {
        format!(
            "failed to read bundle directory '{}': {err}",
            bundle_root.display()
        )
    })?;
    if !bundle_metadata.is_dir() {
        return Err(format!(
            "bundle path '{}' must be a directory",
            bundle_root.display()
        ));
    }
    load_history_receipt_candidates(&bundle_root.join("history"), true)
}

fn load_history_receipt_candidates(
    history_dir: &Path,
    allow_missing_dir: bool,
) -> Result<Vec<HistoryReceiptCandidate>, String> {
    let metadata = match fs::metadata(history_dir) {
        Ok(metadata) => metadata,
        Err(err) => {
            if allow_missing_dir && err.kind() == io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(format!(
                "failed to read history directory '{}': {err}",
                history_dir.display()
            ));
        }
    };
    if !metadata.is_dir() {
        return Err(format!(
            "history path '{}' must be a directory",
            history_dir.display()
        ));
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(history_dir).map_err(|err| {
        format!(
            "failed to list history directory '{}': {err}",
            history_dir.display()
        )
    })? {
        let entry = entry.map_err(|err| {
            format!(
                "failed to read history directory '{}': {err}",
                history_dir.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "failed to inspect history entry '{}': {err}",
                entry.path().display()
            )
        })?;
        if file_type.is_file() {
            files.push(entry.path());
        }
    }
    files.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));

    let mut candidates = Vec::new();
    for file in files {
        let Some(file_name) = file.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(history_index) = parse_history_receipt_file_index(file_name) else {
            continue;
        };

        let receipt_value = load_rulia_value(&file, "history receipt")?;
        let parsed_receipt = parse_receipt_v0(&receipt_value)?;
        let canonical_receipt_hash =
            hash_canonical_prefixed(&receipt_value, HashAlgorithm::Sha256)?;
        candidates.push(HistoryReceiptCandidate {
            history_index,
            source_path: file.display().to_string(),
            canonical_receipt_hash,
            parsed_receipt,
        });
    }

    candidates.sort_by(|left, right| {
        left.history_index.cmp(&right.history_index).then_with(|| {
            left.canonical_receipt_hash
                .cmp(&right.canonical_receipt_hash)
        })
    });
    Ok(candidates)
}

fn parse_history_receipt_file_index(file_name: &str) -> Option<u64> {
    let index_str = file_name.strip_suffix(".receipt.rulia.bin")?;
    if index_str.len() != 20 || !index_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    index_str.parse().ok()
}

fn verify_receipt_against_expected_hash(
    parsed_receipt: &ParsedReceiptV0,
    expected_request_hash: &str,
    trust_anchors: &TrustAnchorSet,
) -> ReceiptVerificationResult {
    let mut failure_codes = Vec::new();
    if expected_request_hash != parsed_receipt.request_hash.prefixed() {
        failure_codes.push(FAILURE_CODE_PROTOCOL_REQUEST_HASH_MISMATCH.to_string());
    }

    let trusted_public_key = trust_anchors.public_keys.get(&parsed_receipt.signer_key_id);
    if trusted_public_key.is_none() {
        failure_codes.push(FAILURE_CODE_PROTOCOL_UNTRUSTED_SIGNER.to_string());
    }

    let signature_valid = trusted_public_key
        .map(|public_key| verify_receipt_signature(parsed_receipt, public_key))
        .unwrap_or(false);
    if trusted_public_key.is_some() && !signature_valid {
        failure_codes.push(FAILURE_CODE_PROTOCOL_SIGNATURE_INVALID.to_string());
    }

    ReceiptVerificationResult {
        failure_codes: order_failure_codes(failure_codes),
        signature_valid,
    }
}

fn verify_schema_failure(mut details: Map<String, Value>, issue: String) -> OfflineToolResult {
    details.insert(
        "primary_failure".to_string(),
        Value::String(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH.to_string()),
    );
    details.insert("schema_issue".to_string(), Value::String(issue));

    OfflineToolResult::with_verdict(
        CommandName::Verify,
        Verdict::Fail,
        vec![FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH.to_string()],
        Some(Value::Object(details)),
    )
}

fn load_rulia_value(path: &Path, label: &str) -> Result<RuliaValue, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read {label} '{}': {err}", path.display()))?;
    rulia::decode_value(&bytes)
        .map_err(|err| format!("failed to decode {label} '{}': {err}", path.display()))
}

fn load_workflow_artifact_value(
    artifact_path: &Path,
    bundle_root: Option<&Path>,
) -> Result<RuliaValue, String> {
    if !should_resolve_imports_for_artifact(artifact_path, bundle_root.is_some()) {
        return load_rulia_value(artifact_path, "workflow artifact");
    }

    let source = fs::read_to_string(artifact_path).map_err(|err| {
        format!(
            "failed to read workflow artifact '{}': {err}",
            artifact_path.display()
        )
    })?;
    let artifact_base_dir = artifact_path.parent().map(|path| path.to_path_buf());
    let bundle_root = bundle_root.map(|path| path.to_path_buf());
    let import_resolver = resolver_from_callback(move |base_dir, import_path| {
        resolve_artifact_import(
            base_dir,
            import_path,
            artifact_base_dir.as_deref(),
            bundle_root.as_deref(),
        )
    });
    let options = ParseOptions {
        import_resolver: Some(import_resolver),
        ..ParseOptions::deterministic()
    };
    let parse_base_dir = artifact_path.parent().unwrap_or(Path::new("."));
    rulia::text::parse_in_dir_with_options(&source, parse_base_dir, options).map_err(|err| {
        format!(
            "failed to parse workflow artifact '{}': {err}",
            artifact_path.display()
        )
    })
}

fn resolve_artifact_import(
    base_dir: Option<&Path>,
    import_path: &str,
    artifact_base_dir: Option<&Path>,
    bundle_root: Option<&Path>,
) -> rulia::RuliaResult<ResolvedImport> {
    let resolved_path = if let Some(bundle_root) = bundle_root {
        let relative = safe_relative_path(import_path).map_err(|error| match error {
            SafeRelativePathError::BackslashSeparator => RuliaError::Parse(
                "import path must use bundle-relative POSIX separators".to_string(),
            ),
            SafeRelativePathError::AbsolutePath => {
                RuliaError::Parse("import path must be bundle-relative".to_string())
            }
            SafeRelativePathError::ForbiddenSegments => RuliaError::Parse(format!(
                "import path '{import_path}' contains forbidden path segments"
            )),
            SafeRelativePathError::InvalidRelativePath => {
                RuliaError::Parse(format!("import path '{import_path}' is not valid"))
            }
        })?;

        let base = base_dir
            .filter(|path| path.starts_with(bundle_root))
            .or_else(|| artifact_base_dir.filter(|path| path.starts_with(bundle_root)))
            .unwrap_or(bundle_root);
        let resolved_path = base.join(relative);
        if !resolved_path.starts_with(bundle_root) {
            return Err(RuliaError::Parse(format!(
                "import path '{import_path}' escapes bundle root"
            )));
        }
        resolved_path
    } else {
        let import_path = Path::new(import_path);
        if import_path.is_absolute() {
            import_path.to_path_buf()
        } else if let Some(base_dir) = base_dir {
            base_dir.join(import_path)
        } else if let Some(artifact_base_dir) = artifact_base_dir {
            artifact_base_dir.join(import_path)
        } else {
            PathBuf::from(import_path)
        }
    };

    let bytes = fs::read(&resolved_path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            RuliaError::Parse(format!("import not found: {import_path}"))
        } else {
            RuliaError::Parse(format!(
                "failed to read import '{}': {err}",
                resolved_path.display()
            ))
        }
    })?;
    let contents = String::from_utf8(bytes)
        .map_err(|_| RuliaError::Parse("import is not valid utf-8".into()))?;
    let origin = resolved_path
        .parent()
        .unwrap_or(Path::new("."))
        .display()
        .to_string();
    Ok(ResolvedImport { origin, contents })
}

fn validate_request_v0(value: &RuliaValue) -> Result<(), String> {
    let request_entries = tagged_entries(
        value,
        "request_v0",
        "request root must be RequestV0 tagged value",
    )?;
    validate_format_field(
        request_entries,
        "rulia_request_v0",
        "request format must be :rulia_request_v0",
    )
}

fn parse_receipt_v0(value: &RuliaValue) -> Result<ParsedReceiptV0, String> {
    let receipt_entries = tagged_entries(
        value,
        "receipt_v0",
        "receipt root must be ReceiptV0 tagged value",
    )?;
    validate_format_field(
        receipt_entries,
        "rulia_receipt_v0",
        "receipt format must be :rulia_receipt_v0",
    )?;

    let request_hash_value = map_get(receipt_entries, &["request_hash"])
        .ok_or_else(|| "receipt missing request_hash".to_string())?;
    let request_hash = parse_digest_value(request_hash_value)?;

    let attestation_value = map_get(receipt_entries, &["attestation"])
        .ok_or_else(|| "receipt missing attestation".to_string())?;
    let attestation_entries =
        expect_map_entries(attestation_value, "receipt attestation must be map")?;

    let signer_key_id_value = map_get(attestation_entries, &["signer_key_id"])
        .ok_or_else(|| "receipt attestation missing signer_key_id".to_string())?;
    let signer_key_id = expect_string(
        signer_key_id_value,
        "receipt attestation signer_key_id must be string",
    )?
    .to_string();

    let signature_alg_value = map_get(attestation_entries, &["signature_alg"])
        .ok_or_else(|| "receipt attestation missing signature_alg".to_string())?;
    let signature_alg = keyword_or_string(signature_alg_value)
        .ok_or_else(|| "receipt attestation signature_alg must be keyword/string".to_string())?;

    let scope_value = map_get(attestation_entries, &["scope"])
        .ok_or_else(|| "receipt attestation missing scope".to_string())?;
    let scope = keyword_or_string(scope_value)
        .ok_or_else(|| "receipt attestation scope must be keyword/string".to_string())?;

    let signature_value = map_get(attestation_entries, &["sig"])
        .ok_or_else(|| "receipt attestation missing sig".to_string())?;
    let signature = match signature_value {
        RuliaValue::Bytes(bytes) => bytes.clone(),
        _ => return Err("receipt attestation sig must be bytes".to_string()),
    };

    let signing_body_bytes = canonical_receipt_signing_body(value)?;

    Ok(ParsedReceiptV0 {
        request_hash,
        signer_key_id,
        signature_alg,
        scope,
        signature,
        signing_body_bytes,
    })
}

fn parse_receipt_valid_obligation_v0(
    value: &RuliaValue,
) -> Result<ParsedReceiptValidObligationV0, String> {
    let obligation_entries = tagged_entries(
        value,
        "obligation_v0",
        "obligation root must be ObligationV0 tagged value",
    )?;
    validate_format_field(
        obligation_entries,
        "rulia_obligation_v0",
        "obligation format must be :rulia_obligation_v0",
    )?;

    let obligation_type_value = map_get(obligation_entries, &["obligation_type"])
        .ok_or_else(|| "obligation missing obligation_type".to_string())?;
    let obligation_type = keyword_or_string(obligation_type_value)
        .ok_or_else(|| "obligation obligation_type must be keyword/string".to_string())?;
    if obligation_type != "receipt_valid" {
        return Err("obligation obligation_type must be :receipt_valid".to_string());
    }

    let params_value = map_get(obligation_entries, &["params"])
        .ok_or_else(|| "obligation missing params".to_string())?;
    let params_entries = expect_map_entries(params_value, "obligation params must be map")?;
    let request_hash_value = map_get(params_entries, &["request_hash"])
        .ok_or_else(|| "obligation params missing request_hash".to_string())?;
    let request_hash = parse_digest_value(request_hash_value)?;

    Ok(ParsedReceiptValidObligationV0 { request_hash })
}

fn tagged_entries<'a>(
    value: &'a RuliaValue,
    expected_tag: &str,
    message: &str,
) -> Result<&'a [(RuliaValue, RuliaValue)], String> {
    let RuliaValue::Tagged(tagged) = value else {
        return Err(message.to_string());
    };
    if tagged.tag.as_str() != expected_tag {
        return Err(message.to_string());
    }
    expect_map_entries(tagged.value.as_ref(), message)
}

fn validate_format_field(
    entries: &[(RuliaValue, RuliaValue)],
    expected_format: &str,
    message: &str,
) -> Result<(), String> {
    let format_value = map_get(entries, &["format"]).ok_or_else(|| message.to_string())?;
    let actual = keyword_or_string(format_value).ok_or_else(|| message.to_string())?;
    let normalized_actual = actual.replace(['/', '-'], "_");
    let normalized_expected = expected_format.replace(['/', '-'], "_");
    if normalized_actual != normalized_expected {
        return Err(message.to_string());
    }
    Ok(())
}

fn parse_digest_value(value: &RuliaValue) -> Result<ParsedDigestValue, String> {
    match value {
        RuliaValue::Tagged(tagged) => {
            if tagged.tag.as_str() != "digest" {
                return Err("digest value must use Digest(...) shape".to_string());
            }
            let digest_entries = expect_map_entries(
                tagged.value.as_ref(),
                "digest value must be map with alg and hex",
            )?;
            let alg_value = map_get(digest_entries, &["alg"])
                .ok_or_else(|| "digest missing alg".to_string())?;
            let algorithm_name = keyword_or_string(alg_value)
                .ok_or_else(|| "digest alg must be keyword/string".to_string())?;
            let algorithm = parse_hash_algorithm(&algorithm_name)
                .ok_or_else(|| format!("unsupported digest algorithm '{algorithm_name}'"))?;

            let hex_value = map_get(digest_entries, &["hex"])
                .ok_or_else(|| "digest missing hex".to_string())?;
            let hex = expect_string(hex_value, "digest hex must be a string")?;
            if !is_valid_digest_hex(hex) {
                return Err("digest hex must be 64 hexadecimal characters".to_string());
            }
            Ok(ParsedDigestValue {
                algorithm,
                hex: hex.to_ascii_lowercase(),
            })
        }
        RuliaValue::String(raw) => parse_prefixed_digest(raw)
            .ok_or_else(|| "digest string must use '<alg>:<64-hex>' format".to_string()),
        _ => Err("digest value must be Digest(...) or '<alg>:<hex>' string".to_string()),
    }
}

fn parse_prefixed_digest(value: &str) -> Option<ParsedDigestValue> {
    let (algorithm_name, hex) = value.split_once(':')?;
    let algorithm = parse_hash_algorithm(algorithm_name)?;
    if !is_valid_digest_hex(hex) {
        return None;
    }
    Some(ParsedDigestValue {
        algorithm,
        hex: hex.to_ascii_lowercase(),
    })
}

fn parse_hash_algorithm(value: &str) -> Option<HashAlgorithm> {
    match value {
        "sha256" => Some(HashAlgorithm::Sha256),
        "blake3" => Some(HashAlgorithm::Blake3),
        _ => None,
    }
}

fn is_valid_digest_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_receipt_signing_body(receipt: &RuliaValue) -> Result<Vec<u8>, String> {
    let mut signing_body = receipt.clone();
    let RuliaValue::Tagged(tagged) = &mut signing_body else {
        return Err("receipt root must be tagged value".to_string());
    };
    if tagged.tag.as_str() != "receipt_v0" {
        return Err("receipt root tag must be receipt_v0".to_string());
    }
    let RuliaValue::Map(receipt_entries) = tagged.value.as_mut() else {
        return Err("receipt payload must be map".to_string());
    };
    let attestation_value = map_get_mut(receipt_entries, &["attestation"])
        .ok_or_else(|| "receipt missing attestation".to_string())?;
    let RuliaValue::Map(attestation_entries) = attestation_value else {
        return Err("receipt attestation must be map".to_string());
    };
    let signature_value = map_get_mut(attestation_entries, &["sig"])
        .ok_or_else(|| "receipt attestation missing sig".to_string())?;
    *signature_value = RuliaValue::Bytes(Vec::new());

    rulia::encode_canonical(&signing_body)
        .map_err(|err| format!("failed to canonicalize receipt signing body: {err}"))
}

fn map_get_mut<'a>(
    entries: &'a mut [(RuliaValue, RuliaValue)],
    candidate_keys: &[&str],
) -> Option<&'a mut RuliaValue> {
    let normalized_candidates = candidate_keys
        .iter()
        .map(|candidate| normalized_lookup_key(candidate))
        .collect::<Vec<_>>();
    entries.iter_mut().find_map(|(key, value)| {
        let key_name = match key {
            RuliaValue::Keyword(keyword) => keyword.as_symbol().as_str(),
            RuliaValue::String(raw) => raw.clone(),
            _ => return None,
        };
        let normalized_key = normalized_lookup_key(key_name.as_str());
        if normalized_candidates
            .iter()
            .any(|candidate_key| candidate_key == &normalized_key)
        {
            Some(value)
        } else {
            None
        }
    })
}

fn hash_canonical_prefixed(value: &RuliaValue, algorithm: HashAlgorithm) -> Result<String, String> {
    let canonical_bytes = rulia::encode_canonical(value)
        .map_err(|err| format!("failed to canonicalize request: {err}"))?;
    Ok(format!(
        "{}:{}",
        algorithm.as_str(),
        hex::encode(algorithm.compute(&canonical_bytes))
    ))
}

fn load_trust_anchors(trust_dir: &Path) -> Result<TrustAnchorSet, String> {
    let metadata = fs::metadata(trust_dir).map_err(|err| {
        format!(
            "failed to read trust-anchor directory '{}': {err}",
            trust_dir.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "trust-anchor path '{}' must be a directory",
            trust_dir.display()
        ));
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(trust_dir).map_err(|err| {
        format!(
            "failed to list trust-anchor directory '{}': {err}",
            trust_dir.display()
        )
    })? {
        let entry = entry.map_err(|err| {
            format!(
                "failed to read trust-anchor directory '{}': {err}",
                trust_dir.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "failed to inspect trust-anchor entry '{}': {err}",
                entry.path().display()
            )
        })?;
        if file_type.is_file() {
            files.push(entry.path());
        }
    }
    files.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));

    let mut public_keys = BTreeMap::new();
    for file in files {
        let key_id = trust_anchor_key_id_from_path(&file)?;
        let public_key = load_trust_anchor_public_key(&file)?;
        if public_keys.insert(key_id.clone(), public_key).is_some() {
            return Err(format!("duplicate trust anchor key id '{key_id}'"));
        }
    }

    Ok(TrustAnchorSet { public_keys })
}

fn trust_anchor_key_id_from_path(path: &Path) -> Result<String, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("trust-anchor path '{}' is not valid UTF-8", path.display()))?;

    let key_id = if let Some(prefix) = file_name.strip_suffix(".pub.rulia.bin") {
        prefix
    } else if let Some(prefix) = file_name.strip_suffix(".pub") {
        prefix
    } else if let Some(prefix) = file_name.strip_suffix(".rulia.bin") {
        prefix
    } else {
        file_name
    };

    if key_id.is_empty() {
        return Err(format!(
            "trust-anchor file '{}' has an empty key id",
            path.display()
        ));
    }
    Ok(key_id.to_string())
}

fn load_trust_anchor_public_key(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read trust-anchor '{}': {err}", path.display()))?;
    if bytes.len() == 32 {
        return Ok(bytes);
    }

    if let Ok(text) = std::str::from_utf8(&bytes) {
        let trimmed = text.trim();
        if is_valid_digest_hex(trimmed) {
            return hex::decode(trimmed.to_ascii_lowercase()).map_err(|err| {
                format!(
                    "failed to decode hex trust-anchor public key '{}': {err}",
                    path.display()
                )
            });
        }
    }

    let value = rulia::decode_value(&bytes).map_err(|_| {
        format!(
            "trust-anchor '{}' must be 32 raw bytes, 64-hex string, or canonical Rulia key value",
            path.display()
        )
    })?;
    parse_trust_anchor_public_key_value(&value).ok_or_else(|| {
        format!(
            "trust-anchor '{}' missing supported public key field",
            path.display()
        )
    })
}

fn parse_trust_anchor_public_key_value(value: &RuliaValue) -> Option<Vec<u8>> {
    let map_entries = match value {
        RuliaValue::Map(entries) => Some(entries.as_slice()),
        RuliaValue::Tagged(tagged) => match tagged.value.as_ref() {
            RuliaValue::Map(entries) => Some(entries.as_slice()),
            _ => None,
        },
        _ => None,
    }?;

    let public_key = map_get(
        map_entries,
        &["public_key", "public_key_bytes", "key_bytes"],
    )?;
    match public_key {
        RuliaValue::Bytes(bytes) => {
            if bytes.len() == 32 {
                Some(bytes.clone())
            } else {
                None
            }
        }
        RuliaValue::String(hex_value) => {
            if !is_valid_digest_hex(hex_value) {
                return None;
            }
            hex::decode(hex_value).ok()
        }
        _ => None,
    }
}

fn verify_receipt_signature(parsed_receipt: &ParsedReceiptV0, public_key: &[u8]) -> bool {
    if parsed_receipt.scope != RECEIPT_SIGNATURE_SCOPE {
        return false;
    }
    if parsed_receipt.signature_alg != "ed25519" {
        return false;
    }
    verify_ed25519_signature(
        public_key,
        &receipt_signature_input(&parsed_receipt.signing_body_bytes),
        &parsed_receipt.signature,
    )
}

fn receipt_signature_input(signing_body_bytes: &[u8]) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + 1 + signing_body_bytes.len());
    input.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN.as_bytes());
    input.push(0);
    input.extend_from_slice(signing_body_bytes);
    input
}

fn verify_ed25519_signature(public_key: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let public_key_bytes: [u8; 32] = match public_key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = match Ed25519Signature::from_slice(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    verifying_key.verify_strict(message, &signature).is_ok()
}

fn cmd_match_cap(args: MatchCapArgs) -> Result<CommandOutput, CliError> {
    let result = match args.bundle.as_deref() {
        Some(bundle_dir) => evaluate_match_capability_from_bundle(bundle_dir),
        None => {
            let requirements_path = args
                .requirements
                .as_deref()
                .expect("clap requires --requirements when --bundle is absent");
            let gamma_cap_path = args
                .gamma_cap
                .as_deref()
                .expect("clap requires --gamma-cap when --bundle is absent");
            evaluate_match_capability_from_paths(
                Path::new(requirements_path),
                Path::new(gamma_cap_path),
            )
        }
    };
    Ok(CommandOutput {
        result,
        json_out: args.json_out,
        run_vectors_normalize: None,
    })
}

fn evaluate_match_capability_from_bundle(bundle_dir: &str) -> OfflineToolResult {
    let bundle_root = Path::new(bundle_dir);
    let manifest_path = bundle_root.join(BUNDLE_MANIFEST_FILENAME);
    let manifest_value = match load_rulia_value(&manifest_path, "bundle manifest") {
        Ok(value) => value,
        Err(issue) => return match_cap_schema_failure(issue),
    };

    let refs = match decode_bundle_manifest_match_cap_refs(&manifest_value) {
        Ok(refs) => refs,
        Err(issue) => {
            return match_cap_schema_failure(format!("manifest decode unsupported: {issue}"))
        }
    };

    let requirements_path = match resolve_bundle_relative_path_with_context(
        bundle_root,
        &refs.requirements_ref.path,
        refs.requirements_ref.source_field,
    ) {
        Ok(path) => path,
        Err(issue) => return match_cap_schema_failure(issue),
    };
    let gamma_cap_path = match resolve_bundle_relative_path_with_context(
        bundle_root,
        &refs.gamma_cap_ref.path,
        refs.gamma_cap_ref.source_field,
    ) {
        Ok(path) => path,
        Err(issue) => return match_cap_schema_failure(issue),
    };

    evaluate_match_capability_from_paths(&requirements_path, &gamma_cap_path)
}

fn evaluate_match_capability_from_paths(
    requirements_path: &Path,
    gamma_cap_path: &Path,
) -> OfflineToolResult {
    let requirements_value = match load_rulia_value(requirements_path, "capability requirements") {
        Ok(value) => value,
        Err(issue) => return match_cap_schema_failure(issue),
    };
    let requirements = match parse_capability_requirements_v0(&requirements_value) {
        Ok(requirements) => requirements,
        Err(issue) => return match_cap_schema_failure(issue),
    };

    let gamma_cap_value = match load_rulia_value(gamma_cap_path, "gamma_cap") {
        Ok(value) => value,
        Err(issue) => return match_cap_schema_failure(issue),
    };
    let gamma_cap_snapshot = match parse_gamma_cap_snapshot_v0(&gamma_cap_value) {
        Ok(snapshot) => snapshot,
        Err(issue) => return match_cap_schema_failure(issue),
    };

    evaluate_match_capability(&requirements, &gamma_cap_snapshot)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequiredAbsencePolicyV0 {
    Reject,
    Suspend,
}

#[derive(Clone, Debug)]
struct CapabilityRequirementsV0 {
    required_absence_policy: RequiredAbsencePolicyV0,
    required: Vec<CapabilityRequirementV0>,
    optional: Vec<CapabilityRequirementV0>,
}

#[derive(Clone, Debug)]
struct CapabilityRequirementV0 {
    requirement_id: String,
    alternatives: Vec<CapabilityAlternativeV0>,
    required_operations: Vec<RequiredOperationV0>,
    required_constraints: ConstraintPolicyV0,
    required_trust_anchors: RequiredTrustAnchorsV0,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CapabilityAlternativeV0 {
    capability_id: String,
    capability_version: String,
    capability_config_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct RequiredOperationV0 {
    operation: String,
    semantics_ref: String,
}

#[derive(Clone, Debug)]
struct GammaCapSnapshotV0 {
    capabilities: Vec<CapabilityEntryV0>,
}

#[derive(Clone, Debug)]
struct CapabilityEntryV0 {
    capability_id: String,
    capability_version: String,
    capability_config_hash: String,
    operations: Vec<CapabilityOperationV0>,
    constraints: ConstraintPolicyV0,
    trust_anchors: CapabilityTrustAnchorsV0,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CapabilityOperationV0 {
    operation: String,
    semantics_ref: String,
}

#[derive(Clone, Debug, Default)]
struct ConstraintPolicyV0 {
    fields: BTreeMap<String, ConstraintFieldValueV0>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConstraintFieldValueV0 {
    Set(BTreeSet<String>),
    Max(u64),
    Bool(bool),
    Raw(RuliaValue),
}

#[derive(Clone, Debug, Default)]
struct RequiredTrustAnchorsV0 {
    signer_keys_any_of: BTreeSet<String>,
    signer_keys_all_of: BTreeSet<String>,
    allowed_signature_algs: BTreeSet<String>,
    required_cert_roots: BTreeSet<String>,
    cert_roots_any_of: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
struct CapabilityTrustAnchorsV0 {
    trusted_signer_keys: BTreeSet<String>,
    trusted_cert_roots: BTreeSet<String>,
    allowed_signature_algs: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityFailureCategoryV0 {
    MissingRequiredCapability,
    IncompatibleVersion,
    ConstraintViolation,
    UntrustedOrMissingTrustAnchor,
}

impl CapabilityFailureCategoryV0 {
    fn rank(self) -> usize {
        match self {
            CapabilityFailureCategoryV0::MissingRequiredCapability => 1,
            CapabilityFailureCategoryV0::IncompatibleVersion => 2,
            CapabilityFailureCategoryV0::ConstraintViolation => 4,
            CapabilityFailureCategoryV0::UntrustedOrMissingTrustAnchor => 5,
        }
    }

    fn code(self) -> &'static str {
        match self {
            CapabilityFailureCategoryV0::MissingRequiredCapability => {
                FAILURE_CODE_CAPABILITY_MISSING_REQUIRED
            }
            CapabilityFailureCategoryV0::IncompatibleVersion => {
                FAILURE_CODE_CAPABILITY_INCOMPATIBLE_VERSION
            }
            CapabilityFailureCategoryV0::ConstraintViolation => {
                FAILURE_CODE_CAPABILITY_CONSTRAINT_VIOLATION
            }
            CapabilityFailureCategoryV0::UntrustedOrMissingTrustAnchor => {
                FAILURE_CODE_CAPABILITY_UNTRUSTED_OR_MISSING_TRUST_ANCHOR
            }
        }
    }
}

#[derive(Clone, Debug)]
struct RequirementMatchV0 {
    requirement_id: String,
    alternative: CapabilityAlternativeV0,
}

#[derive(Clone, Debug)]
struct RequirementUnmetV0 {
    requirement_id: String,
    failure_category: CapabilityFailureCategoryV0,
    alternative: CapabilityAlternativeV0,
}

enum RequirementOutcomeV0 {
    Matched(RequirementMatchV0),
    Unmet(RequirementUnmetV0),
}

fn evaluate_match_capability(
    requirements: &CapabilityRequirementsV0,
    gamma_cap_snapshot: &GammaCapSnapshotV0,
) -> OfflineToolResult {
    let mut matched_required = Vec::new();
    let mut matched_optional = Vec::new();
    let mut unmet_required = Vec::new();
    let mut unmet_optional = Vec::new();

    for requirement in &requirements.required {
        match evaluate_requirement(requirement, gamma_cap_snapshot) {
            RequirementOutcomeV0::Matched(matched) => matched_required.push(matched),
            RequirementOutcomeV0::Unmet(unmet) => unmet_required.push(unmet),
        }
    }
    for requirement in &requirements.optional {
        match evaluate_requirement(requirement, gamma_cap_snapshot) {
            RequirementOutcomeV0::Matched(matched) => matched_optional.push(matched),
            RequirementOutcomeV0::Unmet(unmet) => unmet_optional.push(unmet),
        }
    }

    unmet_required.sort_by(compare_requirement_unmet);
    unmet_optional.sort_by(compare_requirement_unmet);
    matched_required.sort_by(compare_requirement_match);
    matched_optional.sort_by(compare_requirement_match);

    let status = if unmet_required.is_empty() {
        if unmet_optional.is_empty() {
            "accepted"
        } else {
            "accepted_with_soft_gaps"
        }
    } else if requirements.required_absence_policy == RequiredAbsencePolicyV0::Suspend {
        "suspend"
    } else {
        "reject"
    };

    let verdict = if status == "accepted" || status == "accepted_with_soft_gaps" {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let failure_codes = if verdict == Verdict::Fail {
        unmet_required
            .iter()
            .map(|unmet| unmet.failure_category.code().to_string())
            .collect()
    } else {
        Vec::new()
    };

    let mut details = Map::new();
    details.insert("status".to_string(), Value::String(status.to_string()));
    details.insert(
        "matched_required".to_string(),
        Value::Array(
            matched_required
                .iter()
                .map(requirement_match_to_json)
                .collect(),
        ),
    );
    details.insert(
        "matched_optional".to_string(),
        Value::Array(
            matched_optional
                .iter()
                .map(requirement_match_to_json)
                .collect(),
        ),
    );
    details.insert(
        "unmet_required".to_string(),
        Value::Array(
            unmet_required
                .iter()
                .map(requirement_unmet_to_json)
                .collect(),
        ),
    );
    details.insert(
        "unmet_optional".to_string(),
        Value::Array(
            unmet_optional
                .iter()
                .map(requirement_unmet_to_json)
                .collect(),
        ),
    );
    if let Some(primary_failure) = unmet_required.first() {
        details.insert(
            "primary_failure".to_string(),
            Value::String(primary_failure.failure_category.code().to_string()),
        );
    }

    OfflineToolResult::with_verdict(
        CommandName::MatchCap,
        verdict,
        failure_codes,
        Some(Value::Object(details)),
    )
}

fn evaluate_requirement(
    requirement: &CapabilityRequirementV0,
    gamma_cap_snapshot: &GammaCapSnapshotV0,
) -> RequirementOutcomeV0 {
    let mut alternative_failures = Vec::new();
    for alternative in &requirement.alternatives {
        match evaluate_alternative(requirement, alternative, gamma_cap_snapshot) {
            Ok(()) => {
                return RequirementOutcomeV0::Matched(RequirementMatchV0 {
                    requirement_id: requirement.requirement_id.clone(),
                    alternative: alternative.clone(),
                });
            }
            Err(failure_category) => alternative_failures.push((failure_category, alternative)),
        }
    }

    let (failure_category, alternative) = alternative_failures
        .into_iter()
        .min_by(
            |(left_failure, left_alternative), (right_failure, right_alternative)| {
                left_failure
                    .rank()
                    .cmp(&right_failure.rank())
                    .then_with(|| compare_alternative_tuple(left_alternative, right_alternative))
            },
        )
        .expect("requirement alternatives must be non-empty");

    RequirementOutcomeV0::Unmet(RequirementUnmetV0 {
        requirement_id: requirement.requirement_id.clone(),
        failure_category,
        alternative: alternative.clone(),
    })
}

fn compare_requirement_unmet(left: &RequirementUnmetV0, right: &RequirementUnmetV0) -> Ordering {
    left.requirement_id
        .cmp(&right.requirement_id)
        .then_with(|| {
            left.failure_category
                .rank()
                .cmp(&right.failure_category.rank())
        })
        .then_with(|| compare_alternative_tuple(&left.alternative, &right.alternative))
}

fn compare_requirement_match(left: &RequirementMatchV0, right: &RequirementMatchV0) -> Ordering {
    left.requirement_id
        .cmp(&right.requirement_id)
        .then_with(|| compare_alternative_tuple(&left.alternative, &right.alternative))
}

fn evaluate_alternative(
    requirement: &CapabilityRequirementV0,
    alternative: &CapabilityAlternativeV0,
    gamma_cap_snapshot: &GammaCapSnapshotV0,
) -> Result<(), CapabilityFailureCategoryV0> {
    let id_matches: Vec<&CapabilityEntryV0> = gamma_cap_snapshot
        .capabilities
        .iter()
        .filter(|entry| entry.capability_id == alternative.capability_id)
        .collect();
    if id_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::MissingRequiredCapability);
    }

    let version_matches: Vec<&CapabilityEntryV0> = id_matches
        .into_iter()
        .filter(|entry| entry.capability_version == alternative.capability_version)
        .collect();
    if version_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::IncompatibleVersion);
    }

    let mut config_matches: Vec<&CapabilityEntryV0> =
        if let Some(required_hash) = &alternative.capability_config_hash {
            version_matches
                .into_iter()
                .filter(|entry| &entry.capability_config_hash == required_hash)
                .collect()
        } else {
            version_matches
        };
    if config_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::IncompatibleVersion);
    }

    config_matches.sort_by(|left, right| {
        left.capability_id
            .cmp(&right.capability_id)
            .then_with(|| left.capability_version.cmp(&right.capability_version))
            .then_with(|| {
                left.capability_config_hash
                    .cmp(&right.capability_config_hash)
            })
    });

    let operation_matches: Vec<&CapabilityEntryV0> = config_matches
        .iter()
        .copied()
        .filter(|entry| operations_compatible(&requirement.required_operations, &entry.operations))
        .collect();
    if operation_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::ConstraintViolation);
    }

    let constraint_matches: Vec<&CapabilityEntryV0> = operation_matches
        .iter()
        .copied()
        .filter(|entry| {
            constraints_compatible(&requirement.required_constraints, &entry.constraints)
        })
        .collect();
    if constraint_matches.is_empty() {
        return Err(CapabilityFailureCategoryV0::ConstraintViolation);
    }

    let trusted = constraint_matches.iter().any(|entry| {
        trust_anchors_compatible(&requirement.required_trust_anchors, &entry.trust_anchors)
    });
    if !trusted {
        return Err(CapabilityFailureCategoryV0::UntrustedOrMissingTrustAnchor);
    }

    Ok(())
}

fn compare_alternative_tuple(
    left: &CapabilityAlternativeV0,
    right: &CapabilityAlternativeV0,
) -> Ordering {
    left.capability_id
        .cmp(&right.capability_id)
        .then_with(|| left.capability_version.cmp(&right.capability_version))
        .then_with(|| {
            left.capability_config_hash
                .cmp(&right.capability_config_hash)
        })
}

fn operations_compatible(
    required_operations: &[RequiredOperationV0],
    environment_operations: &[CapabilityOperationV0],
) -> bool {
    required_operations.iter().all(|required_operation| {
        environment_operations.iter().any(|environment_operation| {
            required_operation.operation == environment_operation.operation
                && required_operation.semantics_ref == environment_operation.semantics_ref
        })
    })
}

fn constraints_compatible(
    required_constraints: &ConstraintPolicyV0,
    environment_constraints: &ConstraintPolicyV0,
) -> bool {
    required_constraints
        .fields
        .iter()
        .all(|(field_name, required_value)| {
            let Some(environment_value) = environment_constraints.fields.get(field_name) else {
                return false;
            };
            constraint_field_compatible(required_value, environment_value)
        })
}

fn constraint_field_compatible(
    required_value: &ConstraintFieldValueV0,
    environment_value: &ConstraintFieldValueV0,
) -> bool {
    match (required_value, environment_value) {
        (
            ConstraintFieldValueV0::Set(required_set),
            ConstraintFieldValueV0::Set(environment_set),
        ) => required_set.is_subset(environment_set),
        (
            ConstraintFieldValueV0::Max(required_max),
            ConstraintFieldValueV0::Max(environment_max),
        ) => required_max <= environment_max,
        (ConstraintFieldValueV0::Bool(required), ConstraintFieldValueV0::Bool(environment)) => {
            !required || *environment
        }
        (ConstraintFieldValueV0::Raw(required), ConstraintFieldValueV0::Raw(environment)) => {
            required == environment
        }
        _ => false,
    }
}

fn trust_anchors_compatible(
    required_trust_anchors: &RequiredTrustAnchorsV0,
    environment_trust_anchors: &CapabilityTrustAnchorsV0,
) -> bool {
    if !required_trust_anchors
        .signer_keys_all_of
        .is_subset(&environment_trust_anchors.trusted_signer_keys)
    {
        return false;
    }
    if !required_trust_anchors.signer_keys_any_of.is_empty()
        && required_trust_anchors
            .signer_keys_any_of
            .is_disjoint(&environment_trust_anchors.trusted_signer_keys)
    {
        return false;
    }
    if !required_trust_anchors
        .allowed_signature_algs
        .is_subset(&environment_trust_anchors.allowed_signature_algs)
    {
        return false;
    }
    if !required_trust_anchors
        .required_cert_roots
        .is_subset(&environment_trust_anchors.trusted_cert_roots)
    {
        return false;
    }
    if !required_trust_anchors.cert_roots_any_of.is_empty()
        && required_trust_anchors
            .cert_roots_any_of
            .is_disjoint(&environment_trust_anchors.trusted_cert_roots)
    {
        return false;
    }
    true
}

fn parse_capability_requirements_v0(
    value: &RuliaValue,
) -> Result<CapabilityRequirementsV0, String> {
    let entries = tagged_entries(
        value,
        "capability_requirements_v0",
        "requirements root must be CapabilityRequirementsV0 tagged value",
    )?;
    validate_format_field(
        entries,
        "rulia_capability_requirements_v0",
        "requirements format must be :rulia_capability_requirements_v0",
    )?;

    let required_absence_policy_value = map_get(
        entries,
        &[
            "required_absence_policy",
            "required/absence/policy",
            "requiredAbsencePolicy",
        ],
    )
    .ok_or_else(|| "requirements missing required_absence_policy".to_string())?;
    let required_absence_policy = keyword_or_string(required_absence_policy_value)
        .ok_or_else(|| "requirements required_absence_policy must be keyword/string".to_string())
        .and_then(|value| match value.as_str() {
            "reject" => Ok(RequiredAbsencePolicyV0::Reject),
            "suspend" => Ok(RequiredAbsencePolicyV0::Suspend),
            _ => {
                Err("requirements required_absence_policy must be :reject or :suspend".to_string())
            }
        })?;

    let required_value = map_get(entries, &["required"])
        .ok_or_else(|| "requirements missing required list".to_string())?;
    let mut required = parse_requirement_list(required_value, "required")?;
    required.sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));

    let optional_value = map_get(entries, &["optional"])
        .ok_or_else(|| "requirements missing optional list".to_string())?;
    let mut optional = parse_requirement_list(optional_value, "optional")?;
    optional.sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));

    let mut seen_requirement_ids = BTreeSet::new();
    for requirement in required.iter().chain(optional.iter()) {
        if !seen_requirement_ids.insert(requirement.requirement_id.clone()) {
            return Err(format!(
                "requirements include duplicate requirement_id '{}'",
                requirement.requirement_id
            ));
        }
    }

    Ok(CapabilityRequirementsV0 {
        required_absence_policy,
        required,
        optional,
    })
}

fn parse_requirement_list(
    value: &RuliaValue,
    scope_name: &str,
) -> Result<Vec<CapabilityRequirementV0>, String> {
    let items = expect_sequence_values(value, "requirements list must be vector/set")?;
    let mut requirements = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        requirements.push(parse_capability_requirement_v0(
            item,
            &format!("{scope_name}[{index}]"),
        )?);
    }
    Ok(requirements)
}

fn parse_capability_requirement_v0(
    value: &RuliaValue,
    context: &str,
) -> Result<CapabilityRequirementV0, String> {
    let entries = expect_map_entries(value, "requirement must be map value")?;
    let requirement_id_value = map_get(
        entries,
        &["requirement_id", "requirement/id", "requirementId"],
    )
    .ok_or_else(|| format!("{context} missing requirement_id"))?;
    let requirement_id = expect_string(
        requirement_id_value,
        format!("{context} requirement_id must be string").as_str(),
    )?
    .to_string();

    let alternatives_value = map_get(entries, &["alternatives"])
        .ok_or_else(|| format!("{context} missing alternatives"))?;
    let alternatives_values = expect_sequence_values(
        alternatives_value,
        "requirement alternatives must be vector/set",
    )?;
    if alternatives_values.is_empty() {
        return Err(format!("{context} alternatives must be non-empty"));
    }
    let mut alternatives = Vec::with_capacity(alternatives_values.len());
    for (index, alternative_value) in alternatives_values.iter().enumerate() {
        alternatives.push(parse_capability_alternative_v0(
            alternative_value,
            &format!("{context}.alternatives[{index}]"),
        )?);
    }
    alternatives.sort_by(compare_alternative_tuple);
    alternatives.dedup();

    let required_operations = parse_required_operations_v0(
        map_get(
            entries,
            &[
                "required_operations",
                "required/operations",
                "requiredOperations",
            ],
        ),
        context,
    )?;
    let required_constraints = parse_constraint_policy_v0(
        map_get(
            entries,
            &[
                "required_constraints",
                "required/constraints",
                "requiredConstraints",
            ],
        ),
        context,
    )?;
    let required_trust_anchors = parse_required_trust_anchors_v0(
        map_get(
            entries,
            &[
                "required_trust_anchors",
                "required/trust/anchors",
                "requiredTrustAnchors",
            ],
        ),
        context,
    )?;

    Ok(CapabilityRequirementV0 {
        requirement_id,
        alternatives,
        required_operations,
        required_constraints,
        required_trust_anchors,
    })
}

fn parse_capability_alternative_v0(
    value: &RuliaValue,
    context: &str,
) -> Result<CapabilityAlternativeV0, String> {
    let entries = expect_map_entries(value, "capability alternative must be map value")?;
    let capability_id = expect_string(
        map_get(entries, &["capability_id", "capability/id", "capabilityId"])
            .ok_or_else(|| format!("{context} missing capability_id"))?,
        format!("{context} capability_id must be string").as_str(),
    )?
    .to_string();
    let capability_version = expect_string(
        map_get(
            entries,
            &[
                "capability_version",
                "capability/version",
                "capabilityVersion",
            ],
        )
        .ok_or_else(|| format!("{context} missing capability_version"))?,
        format!("{context} capability_version must be string").as_str(),
    )?
    .to_string();
    let capability_config_hash = match map_get(
        entries,
        &[
            "capability_config_hash",
            "capability/config/hash",
            "capabilityConfigHash",
            "config_hash",
            "config/hash",
            "configHash",
        ],
    ) {
        Some(RuliaValue::Nil) | None => None,
        Some(value) => Some(parse_digest_value(value)?.prefixed()),
    };

    Ok(CapabilityAlternativeV0 {
        capability_id,
        capability_version,
        capability_config_hash,
    })
}

fn parse_required_operations_v0(
    value: Option<&RuliaValue>,
    context: &str,
) -> Result<Vec<RequiredOperationV0>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if matches!(value, RuliaValue::Nil) {
        return Ok(Vec::new());
    }
    let items = expect_sequence_values(value, "required_operations must be vector/set")?;
    let mut required_operations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let entries = expect_map_entries(item, "required operation entry must be map")?;
        let operation_value = map_get(entries, &["operation"])
            .ok_or_else(|| format!("{context} required_operations[{index}] missing operation"))?;
        let operation = keyword_string_or_symbol(operation_value).ok_or_else(|| {
            format!("{context} required_operations[{index}] operation must be keyword/string")
        })?;
        let semantics_ref_value =
            map_get(entries, &["semantics_ref", "semantics/ref", "semanticsRef"]).ok_or_else(
                || format!("{context} required_operations[{index}] missing semantics_ref"),
            )?;
        let semantics_ref = parse_digest_value(semantics_ref_value)?.prefixed();
        required_operations.push(RequiredOperationV0 {
            operation,
            semantics_ref,
        });
    }
    required_operations.sort();
    required_operations.dedup();
    Ok(required_operations)
}

fn parse_gamma_cap_snapshot_v0(value: &RuliaValue) -> Result<GammaCapSnapshotV0, String> {
    let entries = tagged_entries(
        value,
        "gamma_cap_snapshot_v0",
        "gamma_cap root must be GammaCapSnapshotV0 tagged value",
    )?;
    validate_format_field(
        entries,
        "rulia_gamma_cap_snapshot_v0",
        "gamma_cap format must be :rulia_gamma_cap_snapshot_v0",
    )?;
    let schema_version_value = map_get(
        entries,
        &["schema_version", "schema/version", "schemaVersion"],
    )
    .ok_or_else(|| "gamma_cap missing schema_version".to_string())?;
    let schema_version = expect_string(
        schema_version_value,
        "gamma_cap schema_version must be string",
    )?;
    if schema_version != "v0" {
        return Err("gamma_cap schema_version must be 'v0'".to_string());
    }

    let capabilities_value = map_get(entries, &["capabilities"])
        .ok_or_else(|| "gamma_cap missing capabilities".to_string())?;
    let capability_values = expect_sequence_values(
        capabilities_value,
        "gamma_cap capabilities must be vector/set",
    )?;
    let mut capabilities = Vec::with_capacity(capability_values.len());
    for (index, capability_value) in capability_values.iter().enumerate() {
        capabilities.push(parse_capability_entry_v0(
            capability_value,
            &format!("capabilities[{index}]"),
        )?);
    }
    capabilities.sort_by(|left, right| {
        left.capability_id
            .cmp(&right.capability_id)
            .then_with(|| left.capability_version.cmp(&right.capability_version))
            .then_with(|| {
                left.capability_config_hash
                    .cmp(&right.capability_config_hash)
            })
    });

    let mut seen_tuples = BTreeSet::new();
    for capability in &capabilities {
        let tuple = (
            capability.capability_id.clone(),
            capability.capability_version.clone(),
            capability.capability_config_hash.clone(),
        );
        if !seen_tuples.insert(tuple) {
            return Err(format!(
                "gamma_cap includes duplicate capability tuple '{}@{}#{}'",
                capability.capability_id,
                capability.capability_version,
                capability.capability_config_hash
            ));
        }
    }

    Ok(GammaCapSnapshotV0 { capabilities })
}

fn parse_capability_entry_v0(
    value: &RuliaValue,
    context: &str,
) -> Result<CapabilityEntryV0, String> {
    let entries = tagged_entries(
        value,
        "capability_entry_v0",
        "capability entry must be CapabilityEntryV0 tagged value",
    )?;
    let capability_id = expect_string(
        map_get(entries, &["capability_id", "capability/id", "capabilityId"])
            .ok_or_else(|| format!("{context} missing capability_id"))?,
        format!("{context} capability_id must be string").as_str(),
    )?
    .to_string();
    let capability_version = expect_string(
        map_get(
            entries,
            &[
                "capability_version",
                "capability/version",
                "capabilityVersion",
            ],
        )
        .ok_or_else(|| format!("{context} missing capability_version"))?,
        format!("{context} capability_version must be string").as_str(),
    )?
    .to_string();
    let capability_config_hash = parse_digest_value(
        map_get(
            entries,
            &[
                "capability_config_hash",
                "capability/config/hash",
                "capabilityConfigHash",
            ],
        )
        .ok_or_else(|| format!("{context} missing capability_config_hash"))?,
    )?
    .prefixed();

    let operations = parse_capability_operations_v0(
        map_get(entries, &["operations"]).ok_or_else(|| format!("{context} missing operations"))?,
        context,
    )?;
    let constraints = parse_constraint_policy_v0(map_get(entries, &["constraints"]), context)?;
    let trust_anchors = parse_capability_trust_anchors_v0(
        map_get(entries, &["trust_anchors", "trust/anchors", "trustAnchors"]),
        context,
    )?;

    Ok(CapabilityEntryV0 {
        capability_id,
        capability_version,
        capability_config_hash,
        operations,
        constraints,
        trust_anchors,
    })
}

fn parse_capability_operations_v0(
    value: &RuliaValue,
    context: &str,
) -> Result<Vec<CapabilityOperationV0>, String> {
    let items = expect_sequence_values(value, "capability operations must be vector/set")?;
    let mut operations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let entries = expect_map_entries(item, "capability operation entry must be map")?;
        let operation = keyword_string_or_symbol(
            map_get(entries, &["operation"])
                .ok_or_else(|| format!("{context} operations[{index}] missing operation"))?,
        )
        .ok_or_else(|| format!("{context} operations[{index}] operation must be keyword/string"))?;
        let semantics_ref = parse_digest_value(
            map_get(entries, &["semantics_ref", "semantics/ref", "semanticsRef"])
                .ok_or_else(|| format!("{context} operations[{index}] missing semantics_ref"))?,
        )?
        .prefixed();
        operations.push(CapabilityOperationV0 {
            operation,
            semantics_ref,
        });
    }
    operations.sort();
    operations.dedup();
    Ok(operations)
}

fn parse_constraint_policy_v0(
    value: Option<&RuliaValue>,
    context: &str,
) -> Result<ConstraintPolicyV0, String> {
    let Some(value) = value else {
        return Ok(ConstraintPolicyV0::default());
    };
    if matches!(value, RuliaValue::Nil) {
        return Ok(ConstraintPolicyV0::default());
    }
    let entries = expect_map_entries(value, "constraints must be map value")?;
    let mut fields = BTreeMap::new();
    for (key, field_value) in entries {
        let key_name = map_key_name(key)
            .ok_or_else(|| format!("{context} constraints keys must be keyword/string"))?;
        let parsed_field = parse_constraint_field_value(&key_name, field_value)?;
        if fields.insert(key_name.clone(), parsed_field).is_some() {
            return Err(format!(
                "{context} constraints include duplicate key '{key_name}'"
            ));
        }
    }
    Ok(ConstraintPolicyV0 { fields })
}

fn parse_constraint_field_value(
    field_name: &str,
    value: &RuliaValue,
) -> Result<ConstraintFieldValueV0, String> {
    if field_name.ends_with("allowlist") || field_name.ends_with("allow/list") {
        return Ok(ConstraintFieldValueV0::Set(parse_string_set(
            value,
            "constraint allowlist field must be vector/set",
        )?));
    }
    if field_name.starts_with("max_") || field_name.starts_with("max/") {
        return Ok(ConstraintFieldValueV0::Max(parse_u64_value(
            value,
            "constraint max field must be unsigned integer",
        )?));
    }
    if field_name.starts_with("allow_") || field_name.starts_with("allow/") {
        return match value {
            RuliaValue::Bool(boolean_value) => Ok(ConstraintFieldValueV0::Bool(*boolean_value)),
            _ => Err("constraint allow_* field must be bool".to_string()),
        };
    }

    match value {
        RuliaValue::Vector(_) | RuliaValue::Set(_) => {
            Ok(ConstraintFieldValueV0::Set(parse_string_set(
                value,
                "constraint vector/set field must contain scalar values",
            )?))
        }
        RuliaValue::Bool(boolean_value) => Ok(ConstraintFieldValueV0::Bool(*boolean_value)),
        RuliaValue::UInt(_) | RuliaValue::Int(_) => {
            Ok(ConstraintFieldValueV0::Max(parse_u64_value(
                value,
                "constraint numeric field must be non-negative integer",
            )?))
        }
        _ => Ok(ConstraintFieldValueV0::Raw(value.clone())),
    }
}

fn parse_required_trust_anchors_v0(
    value: Option<&RuliaValue>,
    context: &str,
) -> Result<RequiredTrustAnchorsV0, String> {
    let Some(value) = value else {
        return Ok(RequiredTrustAnchorsV0::default());
    };
    if matches!(value, RuliaValue::Nil) {
        return Ok(RequiredTrustAnchorsV0::default());
    }
    let entries = expect_map_entries(value, "required_trust_anchors must be map value")?;

    let signer_keys_any_of = map_get(
        entries,
        &[
            "signer_keys_any_of",
            "signer/keys/any/of",
            "signerKeysAnyOf",
        ],
    )
    .map(|value| {
        parse_string_set(
            value,
            "required_trust_anchors signer_keys_any_of must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();
    let signer_keys_all_of = map_get(
        entries,
        &[
            "signer_keys_all_of",
            "signer/keys/all/of",
            "signerKeysAllOf",
        ],
    )
    .map(|value| {
        parse_string_set(
            value,
            "required_trust_anchors signer_keys_all_of must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();
    let allowed_signature_algs = map_get(
        entries,
        &[
            "allowed_signature_algs",
            "allowed/signature/algs",
            "allowedSignatureAlgs",
        ],
    )
    .map(|value| {
        parse_string_set(
            value,
            "required_trust_anchors allowed_signature_algs must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();
    let required_cert_roots = map_get(
        entries,
        &[
            "required_cert_roots",
            "required/cert/roots",
            "requiredCertRoots",
        ],
    )
    .map(|value| {
        parse_digest_set(
            value,
            "required_trust_anchors required_cert_roots must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();
    let cert_roots_any_of = map_get(
        entries,
        &["cert_roots_any_of", "cert/roots/any/of", "certRootsAnyOf"],
    )
    .map(|value| {
        parse_digest_set(
            value,
            "required_trust_anchors cert_roots_any_of must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();

    if signer_keys_any_of.is_empty()
        && signer_keys_all_of.is_empty()
        && allowed_signature_algs.is_empty()
        && required_cert_roots.is_empty()
        && cert_roots_any_of.is_empty()
        && !entries.is_empty()
    {
        let _ = context;
    }

    Ok(RequiredTrustAnchorsV0 {
        signer_keys_any_of,
        signer_keys_all_of,
        allowed_signature_algs,
        required_cert_roots,
        cert_roots_any_of,
    })
}

fn parse_capability_trust_anchors_v0(
    value: Option<&RuliaValue>,
    _context: &str,
) -> Result<CapabilityTrustAnchorsV0, String> {
    let Some(value) = value else {
        return Ok(CapabilityTrustAnchorsV0::default());
    };
    if matches!(value, RuliaValue::Nil) {
        return Ok(CapabilityTrustAnchorsV0::default());
    }
    let entries = expect_map_entries(value, "trust_anchors must be map value")?;

    let trusted_signer_keys = map_get(
        entries,
        &[
            "trusted_signer_keys",
            "trusted/signer/keys",
            "trustedSignerKeys",
        ],
    )
    .map(|value| {
        parse_string_set(
            value,
            "trust_anchors trusted_signer_keys must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();
    let trusted_cert_roots = map_get(
        entries,
        &[
            "trusted_cert_roots",
            "trusted/cert/roots",
            "trustedCertRoots",
        ],
    )
    .map(|value| parse_digest_set(value, "trust_anchors trusted_cert_roots must be vector/set"))
    .transpose()?
    .unwrap_or_default();
    let allowed_signature_algs = map_get(
        entries,
        &[
            "allowed_signature_algs",
            "allowed/signature/algs",
            "allowedSignatureAlgs",
        ],
    )
    .map(|value| {
        parse_string_set(
            value,
            "trust_anchors allowed_signature_algs must be vector/set",
        )
    })
    .transpose()?
    .unwrap_or_default();

    Ok(CapabilityTrustAnchorsV0 {
        trusted_signer_keys,
        trusted_cert_roots,
        allowed_signature_algs,
    })
}

fn parse_string_set(value: &RuliaValue, message: &str) -> Result<BTreeSet<String>, String> {
    let items = expect_sequence_values(value, message)?;
    let mut set = BTreeSet::new();
    for item in items {
        set.insert(
            keyword_string_or_symbol(item)
                .ok_or_else(|| format!("{message}: entries must be keyword/string/symbol"))?,
        );
    }
    Ok(set)
}

fn parse_digest_set(value: &RuliaValue, message: &str) -> Result<BTreeSet<String>, String> {
    let items = expect_sequence_values(value, message)?;
    let mut set = BTreeSet::new();
    for item in items {
        set.insert(parse_digest_value(item)?.prefixed());
    }
    Ok(set)
}

fn parse_u64_value(value: &RuliaValue, message: &str) -> Result<u64, String> {
    match value {
        RuliaValue::UInt(value) => Ok(*value),
        RuliaValue::Int(value) if *value >= 0 => Ok(*value as u64),
        _ => Err(message.to_string()),
    }
}

fn expect_sequence_values<'a>(
    value: &'a RuliaValue,
    message: &str,
) -> Result<&'a [RuliaValue], String> {
    match value {
        RuliaValue::Vector(items) => Ok(items.as_slice()),
        RuliaValue::Set(items) => Ok(items.as_slice()),
        _ => Err(message.to_string()),
    }
}

fn map_key_name(key: &RuliaValue) -> Option<String> {
    match key {
        RuliaValue::Keyword(keyword) => Some(keyword.as_symbol().as_str()),
        RuliaValue::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn keyword_string_or_symbol(value: &RuliaValue) -> Option<String> {
    match value {
        RuliaValue::Keyword(keyword) => Some(keyword.as_symbol().as_str()),
        RuliaValue::String(value) => Some(value.clone()),
        RuliaValue::Symbol(symbol) => Some(symbol.as_str()),
        _ => None,
    }
}

fn requirement_match_to_json(matched: &RequirementMatchV0) -> Value {
    let mut map = Map::new();
    map.insert(
        "requirement_id".to_string(),
        Value::String(matched.requirement_id.clone()),
    );
    map.insert(
        "selected_alternative".to_string(),
        alternative_to_json(&matched.alternative),
    );
    Value::Object(map)
}

fn requirement_unmet_to_json(unmet: &RequirementUnmetV0) -> Value {
    let mut map = Map::new();
    map.insert(
        "requirement_id".to_string(),
        Value::String(unmet.requirement_id.clone()),
    );
    map.insert(
        "failure_category".to_string(),
        Value::String(unmet.failure_category.code().to_string()),
    );
    map.insert(
        "selected_alternative".to_string(),
        alternative_to_json(&unmet.alternative),
    );
    Value::Object(map)
}

fn alternative_to_json(alternative: &CapabilityAlternativeV0) -> Value {
    let mut map = Map::new();
    map.insert(
        "capability_id".to_string(),
        Value::String(alternative.capability_id.clone()),
    );
    map.insert(
        "capability_version".to_string(),
        Value::String(alternative.capability_version.clone()),
    );
    match &alternative.capability_config_hash {
        Some(hash) => {
            map.insert(
                "capability_config_hash".to_string(),
                Value::String(hash.clone()),
            );
        }
        None => {
            map.insert("capability_config_hash".to_string(), Value::Null);
        }
    }
    Value::Object(map)
}

fn match_cap_schema_failure(issue: String) -> OfflineToolResult {
    let mut details = Map::new();
    details.insert("status".to_string(), Value::String("reject".to_string()));
    details.insert(
        "primary_failure".to_string(),
        Value::String(FAILURE_CODE_CAPABILITY_CONSTRAINT_VIOLATION.to_string()),
    );
    details.insert("schema_issue".to_string(), Value::String(issue));

    OfflineToolResult::with_verdict(
        CommandName::MatchCap,
        Verdict::Fail,
        vec![FAILURE_CODE_CAPABILITY_CONSTRAINT_VIOLATION.to_string()],
        Some(Value::Object(details)),
    )
}

fn cmd_run_vectors(args: RunVectorsArgs) -> OfflineToolResult {
    let requested_levels = requested_run_levels(args.levels.as_deref());
    let mode = run_vectors_mode(&requested_levels).to_string();
    let vectorset_directory = Path::new(&args.vectorset)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let vectorset = match portable_workflow_vectorset::load_vectorset_v0(&args.vectorset) {
        Ok(vectorset) => vectorset,
        Err(load_failure) => {
            let mut details = run_vectors_details_base(&mode);
            details.insert(
                "loader_issues".to_string(),
                Value::Array(
                    load_failure
                        .issues
                        .iter()
                        .map(|issue| Value::String(issue.clone()))
                        .collect(),
                ),
            );
            return OfflineToolResult::with_verdict(
                CommandName::RunVectors,
                Verdict::Fail,
                load_failure.failure_codes,
                Some(Value::Object(details)),
            );
        }
    };

    let requested_ids = ordered_vector_ids(&args.vector_ids);
    let mut selected_vectors = vectorset
        .vectors
        .iter()
        .filter(|vector| {
            vector_matches_requested_levels(vector, &requested_levels)
                && (requested_ids.is_empty() || requested_ids.binary_search(&vector.id).is_ok())
        })
        .collect::<Vec<_>>();
    selected_vectors.sort_by(|left, right| left.id.cmp(&right.id));
    if selected_vectors.is_empty() {
        return OfflineToolResult::with_verdict(
            CommandName::RunVectors,
            Verdict::Fail,
            vec![FAILURE_CODE_STEP_CONTRACT.to_string()],
            Some(Value::Object(run_vectors_details_base(&mode))),
        );
    }

    let mut vector_results = Vec::new();
    let mut pass_count = 0u64;
    let mut fail_count = 0u64;
    let mut aggregated_failure_codes = Vec::new();

    for vector in selected_vectors {
        let executes_l3 = requested_levels.contains(&RunLevel::L3)
            && vector
                .levels
                .iter()
                .any(|level| level == RunLevel::L3.as_str());
        let executes_l1 = requested_levels.contains(&RunLevel::L1)
            && vector
                .levels
                .iter()
                .any(|level| level == RunLevel::L1.as_str());
        let executes_l2 = requested_levels.contains(&RunLevel::L2)
            && vector
                .levels
                .iter()
                .any(|level| level == RunLevel::L2.as_str());
        let executes_l4 = requested_levels.contains(&RunLevel::L4)
            && vector
                .levels
                .iter()
                .any(|level| level == RunLevel::L4.as_str());

        let (verdict, failure_codes, extra_fields) = if executes_l3 {
            let actual = run_vector_l3_proof(vector, &vectorset_directory);
            let expected_verdict = vector.expected.verdict.as_str();
            let expected_failure_codes = vector.expected.failure_codes.as_slice();
            let matches_expected = actual.verdict.as_str() == expected_verdict
                && actual.failure_codes.as_slice() == expected_failure_codes;
            let verdict = if matches_expected {
                Verdict::Pass
            } else {
                Verdict::Fail
            };

            let mut extra_fields = Map::new();
            extra_fields.insert(
                "actual_verdict".to_string(),
                Value::String(actual.verdict.as_str().to_string()),
            );
            extra_fields.insert(
                "actual_failure_codes".to_string(),
                Value::Array(
                    actual
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            extra_fields.insert(
                "expected_verdict".to_string(),
                Value::String(vector.expected.verdict.clone()),
            );
            extra_fields.insert(
                "expected_failure_codes".to_string(),
                Value::Array(
                    vector
                        .expected
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            (verdict, actual.failure_codes, Some(extra_fields))
        } else if executes_l4 {
            let actual = run_vector_l4_capability(vector, &vectorset_directory);
            let expected_verdict = vector.expected.verdict.as_str();
            let expected_failure_codes = vector.expected.failure_codes.as_slice();
            let matches_expected = actual.verdict.as_str() == expected_verdict
                && actual.failure_codes.as_slice() == expected_failure_codes;
            let verdict = if matches_expected {
                Verdict::Pass
            } else {
                Verdict::Fail
            };

            let mut extra_fields = Map::new();
            extra_fields.insert(
                "actual_verdict".to_string(),
                Value::String(actual.verdict.as_str().to_string()),
            );
            extra_fields.insert(
                "actual_failure_codes".to_string(),
                Value::Array(
                    actual
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            extra_fields.insert(
                "expected_verdict".to_string(),
                Value::String(vector.expected.verdict.clone()),
            );
            extra_fields.insert(
                "expected_failure_codes".to_string(),
                Value::Array(
                    vector
                        .expected
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            (verdict, actual.failure_codes, Some(extra_fields))
        } else if executes_l2 {
            let actual = run_vector_l2_eval(vector, &vectorset_directory);
            let expected_verdict = vector.expected.verdict.as_str();
            let expected_failure_codes = vector.expected.failure_codes.as_slice();
            let matches_eval_expected = matches_expected_eval_subset(
                vector.expected.eval_expected.as_ref(),
                actual.eval_result.as_ref(),
            );
            let matches_expected = actual.verdict.as_str() == expected_verdict
                && actual.failure_codes.as_slice() == expected_failure_codes
                && matches_eval_expected;
            let verdict = if matches_expected {
                Verdict::Pass
            } else {
                Verdict::Fail
            };

            let mut extra_fields = Map::new();
            if let Some(actual_eval) = actual.eval_result.clone() {
                extra_fields.insert("actual_eval".to_string(), actual_eval);
            }
            extra_fields.insert(
                "actual_verdict".to_string(),
                Value::String(actual.verdict.as_str().to_string()),
            );
            extra_fields.insert(
                "actual_failure_codes".to_string(),
                Value::Array(
                    actual
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            if let Some(expected_eval) = vector.expected.eval_expected.as_ref() {
                extra_fields.insert(
                    "expected_eval_expected".to_string(),
                    eval_expected_to_json(expected_eval),
                );
            }
            extra_fields.insert(
                "expected_verdict".to_string(),
                Value::String(vector.expected.verdict.clone()),
            );
            extra_fields.insert(
                "expected_failure_codes".to_string(),
                Value::Array(
                    vector
                        .expected
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            (verdict, actual.failure_codes, Some(extra_fields))
        } else if executes_l1 {
            let actual = run_vector_l1_validation(vector, &vectorset_directory);
            let expected_verdict = vector.expected.verdict.as_str();
            let expected_failure_codes = vector.expected.failure_codes.as_slice();
            let matches_expected = actual.verdict.as_str() == expected_verdict
                && actual.failure_codes.as_slice() == expected_failure_codes;
            let verdict = if matches_expected {
                Verdict::Pass
            } else {
                Verdict::Fail
            };

            let mut extra_fields = Map::new();
            extra_fields.insert(
                "actual_verdict".to_string(),
                Value::String(actual.verdict.as_str().to_string()),
            );
            extra_fields.insert(
                "actual_failure_codes".to_string(),
                Value::Array(
                    actual
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            extra_fields.insert(
                "expected_verdict".to_string(),
                Value::String(vector.expected.verdict.clone()),
            );
            extra_fields.insert(
                "expected_failure_codes".to_string(),
                Value::Array(
                    vector
                        .expected
                        .failure_codes
                        .iter()
                        .map(|code| Value::String(code.clone()))
                        .collect(),
                ),
            );
            (verdict, actual.failure_codes, Some(extra_fields))
        } else {
            let (verdict, failure_codes) = if vector.expected.verdict == Verdict::Fail.as_str() {
                let codes = order_failure_codes(vector.expected.failure_codes.clone());
                (Verdict::Fail, codes)
            } else {
                (Verdict::Pass, Vec::new())
            };
            (verdict, failure_codes, None)
        };

        let mut vector_result = Map::new();
        vector_result.insert(
            "failure_codes".to_string(),
            Value::Array(
                failure_codes
                    .iter()
                    .map(|code| Value::String(code.clone()))
                    .collect(),
            ),
        );
        vector_result.insert("id".to_string(), Value::String(vector.id.clone()));
        vector_result.insert(
            "verdict".to_string(),
            Value::String(verdict.as_str().to_string()),
        );
        if let Some(extra_fields) = extra_fields {
            for (key, value) in extra_fields {
                vector_result.insert(key, value);
            }
        }
        vector_results.push(Value::Object(vector_result));

        if verdict == Verdict::Pass {
            pass_count += 1;
        } else {
            fail_count += 1;
            aggregated_failure_codes.extend(failure_codes);
            if args.stop_on_first_fail {
                break;
            }
        }
    }

    let mut details = run_vectors_details_base(&mode);
    details.insert(
        "fail_count".to_string(),
        Value::Number(Number::from(fail_count)),
    );
    details.insert(
        "pass_count".to_string(),
        Value::Number(Number::from(pass_count)),
    );
    details.insert("vectors".to_string(), Value::Array(vector_results));

    let (overall_verdict, failure_codes) = if fail_count > 0 {
        (Verdict::Fail, order_failure_codes(aggregated_failure_codes))
    } else {
        (Verdict::Pass, Vec::new())
    };

    OfflineToolResult::with_verdict(
        CommandName::RunVectors,
        overall_verdict,
        failure_codes,
        Some(Value::Object(details)),
    )
}

#[derive(Debug)]
struct VectorActualResult {
    verdict: Verdict,
    failure_codes: Vec<String>,
    eval_result: Option<Value>,
}

fn run_vector_l1_validation(
    vector: &portable_workflow_vectorset::VectorV0,
    vectorset_directory: &Path,
) -> VectorActualResult {
    let artifact_path = vector_input_path(vector.inputs.artifact.as_ref());
    let bundle_path = vector_input_path(vector.inputs.bundle.as_ref());

    match (artifact_path, bundle_path) {
        (Some(artifact_path), None) => {
            let resolved_path =
                match resolve_vectorset_relative_path(vectorset_directory, artifact_path) {
                    Ok(path) => path,
                    Err(_) => return vector_state_invalid_result(),
                };
            let (verdict, failure_codes, _) = validate_l1_artifact(&resolved_path);
            VectorActualResult {
                verdict,
                failure_codes: order_failure_codes(failure_codes),
                eval_result: None,
            }
        }
        (None, Some(bundle_path)) => {
            let resolved_path =
                match resolve_vectorset_relative_path(vectorset_directory, bundle_path) {
                    Ok(path) => path,
                    Err(_) => return vector_state_invalid_result(),
                };
            let resolved_path = resolved_path.to_string_lossy().into_owned();
            let result = validate_bundle(&resolved_path);
            VectorActualResult {
                verdict: result.verdict,
                failure_codes: order_failure_codes(result.failure_codes),
                eval_result: None,
            }
        }
        _ => vector_state_invalid_result(),
    }
}

fn run_vector_l2_eval(
    vector: &portable_workflow_vectorset::VectorV0,
    vectorset_directory: &Path,
) -> VectorActualResult {
    let eval_ir_path = vector_input_path(vector.inputs.eval_ir.as_ref());
    let artifact_path = vector_input_path(vector.inputs.artifact.as_ref());
    let initial_state_path = vector_input_path(vector.inputs.initial_state.as_ref());
    let history_prefix_path = vector_input_path(vector.inputs.history.as_ref());
    let gamma_core_path = vector_input_path(vector.inputs.gamma_core.as_ref());

    let Some(initial_state_path) = initial_state_path else {
        return vector_state_invalid_result();
    };

    let eval_ir_json = match (eval_ir_path, artifact_path) {
        (Some(eval_ir_path), None) => match read_vector_json(vectorset_directory, eval_ir_path) {
            Ok(content) => content,
            Err(_) => return vector_state_invalid_result(),
        },
        (None, Some(artifact_path)) => {
            match compile_vector_l2_eval_ir_json_from_artifact(vectorset_directory, artifact_path) {
                Ok(content) => content,
                Err(failure_codes) => {
                    return VectorActualResult {
                        verdict: Verdict::Fail,
                        failure_codes: order_failure_codes(failure_codes),
                        eval_result: None,
                    };
                }
            }
        }
        _ => return vector_state_invalid_result(),
    };

    let initial_state_json = match read_vector_json(vectorset_directory, initial_state_path) {
        Ok(content) => content,
        Err(_) => return vector_state_invalid_result(),
    };
    let history_prefix_json = match history_prefix_path {
        Some(path) => match read_vector_json(vectorset_directory, path) {
            Ok(content) => Some(content),
            Err(_) => return vector_state_invalid_result(),
        },
        None => None,
    };
    let gamma_core_json = match gamma_core_path {
        Some(path) => match read_vector_json(vectorset_directory, path) {
            Ok(content) => Some(content),
            Err(_) => return vector_state_invalid_result(),
        },
        None => None,
    };

    let run_input = match portable_workflow_evalir_v0::parse_eval_run_input_v0(
        &eval_ir_json,
        &initial_state_json,
        history_prefix_json.as_deref(),
        gamma_core_json.as_deref(),
    ) {
        Ok(input) => input,
        Err(errors) => {
            return VectorActualResult {
                verdict: Verdict::Fail,
                failure_codes: order_failure_codes(errors),
                eval_result: None,
            }
        }
    };

    let eval_result = portable_workflow_evalir_v0::evaluate_eval_ir_v0(run_input);
    let eval_result_json = eval_result_to_json(&eval_result);
    let evaluator_failed = eval_result.control == portable_workflow_evalir_v0::EvalControlV0::Error
        || !eval_result.errors.is_empty();
    let failure_codes = if evaluator_failed {
        if eval_result.errors.is_empty() {
            vec![FAILURE_CODE_STEP_CONTRACT.to_string()]
        } else {
            order_failure_codes(eval_result.errors)
        }
    } else {
        Vec::new()
    };

    VectorActualResult {
        verdict: if evaluator_failed {
            Verdict::Fail
        } else {
            Verdict::Pass
        },
        failure_codes,
        eval_result: Some(eval_result_json),
    }
}

fn compile_vector_l2_eval_ir_json_from_artifact(
    vectorset_directory: &Path,
    relative_artifact_path: &str,
) -> Result<String, Vec<String>> {
    let artifact_path =
        resolve_vectorset_relative_path(vectorset_directory, relative_artifact_path)
            .map_err(|_| vec![FAILURE_CODE_STATE_INVALID.to_string()])?;
    let artifact_value = load_workflow_artifact_value(&artifact_path, None)
        .map_err(|_| vec![FAILURE_CODE_STATE_INVALID.to_string()])?;
    let eval_ir =
        portable_workflow_artifact_subset_v0::parse_and_compile_artifact_subset_v0(&artifact_value)
            .map_err(|failure| failure.failure_codes)?;
    serde_json::to_string(&eval_ir).map_err(|_| vec![FAILURE_CODE_STATE_INVALID.to_string()])
}

fn read_vector_json(vectorset_directory: &Path, relative_path: &str) -> Result<String, ()> {
    let resolved_path =
        resolve_vectorset_relative_path(vectorset_directory, relative_path).map_err(|_| ())?;
    fs::read_to_string(&resolved_path).map_err(|_| ())
}

fn eval_result_to_json(result: &portable_workflow_evalir_v0::EvalRunResultV0) -> Value {
    let mut eval_json = Map::new();
    eval_json.insert(
        "control".to_string(),
        Value::String(eval_control_to_str(result.control).to_string()),
    );
    eval_json.insert("state_out".to_string(), result.state_out.clone());
    eval_json.insert(
        "emissions".to_string(),
        Value::Array(result.emissions.clone()),
    );
    eval_json.insert(
        "requests".to_string(),
        serde_json::to_value(&result.requests).expect("EvalRequestV0 should serialize"),
    );
    eval_json.insert(
        "obligations".to_string(),
        serde_json::to_value(&result.obligations).expect("EvalObligationV0 should serialize"),
    );
    Value::Object(eval_json)
}

fn eval_control_to_str(control: portable_workflow_evalir_v0::EvalControlV0) -> &'static str {
    match control {
        portable_workflow_evalir_v0::EvalControlV0::Continue => "continue",
        portable_workflow_evalir_v0::EvalControlV0::Suspend => "suspend",
        portable_workflow_evalir_v0::EvalControlV0::End => "end",
        portable_workflow_evalir_v0::EvalControlV0::Error => "error",
    }
}

fn eval_expected_to_json(expected: &portable_workflow_vectorset::EvalExpectedV0) -> Value {
    let mut map = Map::new();
    if let Some(control) = expected.control.as_ref() {
        map.insert("control".to_string(), Value::String(control.clone()));
    }
    if let Some(state_out) = expected.state_out.as_ref() {
        map.insert("state_out".to_string(), state_out.clone());
    }
    if let Some(emissions) = expected.emissions.as_ref() {
        map.insert("emissions".to_string(), emissions.clone());
    }
    if let Some(requests) = expected.requests.as_ref() {
        map.insert("requests".to_string(), requests.clone());
    }
    if let Some(obligations) = expected.obligations.as_ref() {
        map.insert("obligations".to_string(), obligations.clone());
    }
    Value::Object(map)
}

fn value_matches_subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(expected_map), Value::Object(actual_map)) => {
            expected_map.iter().all(|(key, expected_value)| {
                actual_map
                    .get(key)
                    .is_some_and(|actual_value| value_matches_subset(expected_value, actual_value))
            })
        }
        (Value::Array(expected_items), Value::Array(actual_items)) => {
            expected_items.len() == actual_items.len()
                && expected_items.iter().zip(actual_items.iter()).all(
                    |(expected_item, actual_item)| value_matches_subset(expected_item, actual_item),
                )
        }
        _ => expected == actual,
    }
}

fn eval_field_matches_subset(
    actual_map: &Map<String, Value>,
    field: &str,
    expected: &Value,
) -> bool {
    actual_map
        .get(field)
        .is_some_and(|actual_value| value_matches_subset(expected, actual_value))
}

fn matches_expected_eval_subset(
    expected: Option<&portable_workflow_vectorset::EvalExpectedV0>,
    actual: Option<&Value>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(actual) = actual else {
        return false;
    };
    let Some(actual_map) = actual.as_object() else {
        return false;
    };

    if let Some(control) = expected.control.as_ref() {
        if !eval_field_matches_subset(actual_map, "control", &Value::String(control.clone())) {
            return false;
        }
    }
    if let Some(state_out) = expected.state_out.as_ref() {
        if !eval_field_matches_subset(actual_map, "state_out", state_out) {
            return false;
        }
    }
    if let Some(emissions) = expected.emissions.as_ref() {
        if !eval_field_matches_subset(actual_map, "emissions", emissions) {
            return false;
        }
    }
    if let Some(requests) = expected.requests.as_ref() {
        if !eval_field_matches_subset(actual_map, "requests", requests) {
            return false;
        }
    }
    if let Some(obligations) = expected.obligations.as_ref() {
        if !eval_field_matches_subset(actual_map, "obligations", obligations) {
            return false;
        }
    }

    true
}

fn run_vector_l3_proof(
    vector: &portable_workflow_vectorset::VectorV0,
    vectorset_directory: &Path,
) -> VectorActualResult {
    let request_path = vector_input_path(vector.inputs.request.as_ref());
    let receipt_path = vector_input_path(vector.inputs.receipt.as_ref());
    let trust_path = vector_input_path(vector.inputs.trust.as_ref());
    let obligation_path = vector_input_path(vector.inputs.obligation.as_ref());
    let history_path = vector_input_path(vector.inputs.history.as_ref());
    let bundle_path = vector_input_path(vector.inputs.bundle.as_ref());

    let Some(trust_path) = trust_path else {
        return vector_state_invalid_result();
    };
    let trust_path = match resolve_vectorset_relative_path(vectorset_directory, trust_path) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => return vector_state_invalid_result(),
    };

    if let Some(obligation_path) = obligation_path {
        if request_path.is_some() || receipt_path.is_some() {
            return vector_state_invalid_result();
        }
        if history_path.is_some() == bundle_path.is_some() {
            return vector_state_invalid_result();
        }
        let obligation_path =
            match resolve_vectorset_relative_path(vectorset_directory, obligation_path) {
                Ok(path) => path.to_string_lossy().into_owned(),
                Err(_) => return vector_state_invalid_result(),
            };
        let history_path = match history_path {
            Some(path) => match resolve_vectorset_relative_path(vectorset_directory, path) {
                Ok(path) => Some(path.to_string_lossy().into_owned()),
                Err(_) => return vector_state_invalid_result(),
            },
            None => None,
        };
        let bundle_path = match bundle_path {
            Some(path) => match resolve_vectorset_relative_path(vectorset_directory, path) {
                Ok(path) => Some(path.to_string_lossy().into_owned()),
                Err(_) => return vector_state_invalid_result(),
            },
            None => None,
        };

        let verify_args = VerifyArgs {
            request: None,
            receipt: None,
            obligation: Some(obligation_path),
            history: history_path,
            bundle: bundle_path,
            trust: trust_path,
            json_out: None,
        };
        let result = cmd_verify_obligation(&verify_args);
        return VectorActualResult {
            verdict: result.verdict,
            failure_codes: order_failure_codes(result.failure_codes),
            eval_result: None,
        };
    }

    if history_path.is_some() || bundle_path.is_some() {
        return vector_state_invalid_result();
    }
    let (Some(request_path), Some(receipt_path)) = (request_path, receipt_path) else {
        return vector_state_invalid_result();
    };

    let request_path = match resolve_vectorset_relative_path(vectorset_directory, request_path) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => return vector_state_invalid_result(),
    };
    let receipt_path = match resolve_vectorset_relative_path(vectorset_directory, receipt_path) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => return vector_state_invalid_result(),
    };

    let verify_args = VerifyArgs {
        request: Some(request_path),
        receipt: Some(receipt_path),
        obligation: None,
        history: None,
        bundle: None,
        trust: trust_path,
        json_out: None,
    };
    let result = cmd_verify_receipt(&verify_args);
    VectorActualResult {
        verdict: result.verdict,
        failure_codes: order_failure_codes(result.failure_codes),
        eval_result: None,
    }
}

fn run_vector_l4_capability(
    vector: &portable_workflow_vectorset::VectorV0,
    vectorset_directory: &Path,
) -> VectorActualResult {
    let requirements_path = vector_input_path(vector.inputs.requirements.as_ref());
    let gamma_cap_path = vector_input_path(vector.inputs.gamma_cap.as_ref());
    let (Some(requirements_path), Some(gamma_cap_path)) = (requirements_path, gamma_cap_path)
    else {
        return vector_state_invalid_result();
    };

    let requirements_path =
        match resolve_vectorset_relative_path(vectorset_directory, requirements_path) {
            Ok(path) => path,
            Err(_) => return vector_state_invalid_result(),
        };
    let gamma_cap_path = match resolve_vectorset_relative_path(vectorset_directory, gamma_cap_path)
    {
        Ok(path) => path,
        Err(_) => return vector_state_invalid_result(),
    };

    let result = evaluate_match_capability_from_paths(&requirements_path, &gamma_cap_path);
    VectorActualResult {
        verdict: result.verdict,
        failure_codes: result.failure_codes,
        eval_result: None,
    }
}

fn vector_state_invalid_result() -> VectorActualResult {
    VectorActualResult {
        verdict: Verdict::Fail,
        failure_codes: vec![FAILURE_CODE_STATE_INVALID.to_string()],
        eval_result: None,
    }
}

fn vector_input_path(input: Option<&portable_workflow_vectorset::PathInputV0>) -> Option<&str> {
    input
        .and_then(|value| value.path.as_deref())
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

fn resolve_vectorset_relative_path(
    vectorset_directory: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    let relative = safe_relative_path(relative_path).map_err(|error| match error {
        SafeRelativePathError::BackslashSeparator => {
            "vector input path must use vectorset-relative POSIX separators".to_string()
        }
        SafeRelativePathError::AbsolutePath => {
            "vector input path must be vectorset-relative".to_string()
        }
        SafeRelativePathError::ForbiddenSegments => {
            format!("vector input path '{relative_path}' contains forbidden path segments")
        }
        SafeRelativePathError::InvalidRelativePath => {
            format!(
                "vector input path '{relative_path}' is not a valid vectorset-relative file path"
            )
        }
    })?;

    Ok(vectorset_directory.join(relative))
}

fn requested_run_levels(levels: Option<&[RunLevel]>) -> Vec<RunLevel> {
    match levels {
        Some(levels) if !levels.is_empty() => ordered_run_levels(levels),
        _ => vec![RunLevel::L0],
    }
}

fn run_vectors_mode(requested_levels: &[RunLevel]) -> &'static str {
    if requested_levels.contains(&RunLevel::L3) {
        "proof"
    } else if requested_levels.contains(&RunLevel::L4) {
        "capability"
    } else if requested_levels.contains(&RunLevel::L2) {
        "eval"
    } else if requested_levels.contains(&RunLevel::L1) {
        "validate"
    } else {
        "structure_only"
    }
}

fn normalize_run_vectors_output(mode: RunVectorsNormalize, output: &mut Value) {
    if mode != RunVectorsNormalize::CiV0 {
        return;
    }
    drop_l2_eval_internal_ids(output);
}

fn drop_l2_eval_internal_ids(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                drop_l2_eval_internal_ids(item);
            }
        }
        Value::Object(map) => {
            map.remove("request_id");
            map.remove("obligation_id");
            map.remove("satisfaction_ref");
            for entry in map.values_mut() {
                drop_l2_eval_internal_ids(entry);
            }
        }
        _ => {}
    }
}

fn strip_null_object_fields(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                strip_null_object_fields(item);
            }
        }
        Value::Object(map) => {
            let keys = map.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                let should_remove = map.get(&key).is_some_and(Value::is_null);
                if should_remove {
                    map.remove(&key);
                } else if let Some(entry) = map.get_mut(&key) {
                    strip_null_object_fields(entry);
                }
            }
        }
        _ => {}
    }
}

fn run_vectors_details_base(mode: &str) -> Map<String, Value> {
    let mut details = Map::new();
    details.insert("fail_count".to_string(), Value::Number(Number::from(0u64)));
    details.insert("mode".to_string(), Value::String(mode.to_string()));
    details.insert("pass_count".to_string(), Value::Number(Number::from(0u64)));
    details.insert("vectors".to_string(), Value::Array(Vec::new()));
    details
}

fn vector_matches_requested_levels(
    vector: &portable_workflow_vectorset::VectorV0,
    requested_levels: &[RunLevel],
) -> bool {
    vector.levels.iter().any(|vector_level| {
        requested_levels
            .iter()
            .any(|requested_level| vector_level == requested_level.as_str())
    })
}

fn emit_json(json: &str, json_out: Option<&str>) -> Result<(), CliError> {
    if let Some(path) = json_out {
        if path != "-" {
            fs::write(Path::new(path), format!("{json}\n")).map_err(|err| {
                CliError::IoOrBundle(format!("failed to write --json-out '{path}': {err}"))
            })?;
        }
    }

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(json.as_bytes())
        .map_err(|err| CliError::IoOrBundle(format!("failed writing JSON to stdout: {err}")))?;
    stdout.write_all(b"\n").map_err(|err| {
        CliError::IoOrBundle(format!("failed writing JSON newline to stdout: {err}"))
    })?;
    Ok(())
}

fn order_failure_codes(codes: Vec<String>) -> Vec<String> {
    let mut ordered = codes;
    ordered.sort_by(|left, right| compare_failure_codes(left, right));
    ordered.dedup();
    ordered
}

fn compare_failure_codes(left: &str, right: &str) -> Ordering {
    let (left_ns, left_leaf) = split_failure_code(left);
    let (right_ns, right_leaf) = split_failure_code(right);

    namespace_rank(left_ns)
        .cmp(&namespace_rank(right_ns))
        .then_with(|| {
            namespace_local_rank(left_ns, left_leaf)
                .cmp(&namespace_local_rank(right_ns, right_leaf))
        })
        .then_with(|| left.cmp(right))
}

fn split_failure_code(code: &str) -> (&str, &str) {
    if let Some((namespace, leaf)) = code.split_once('.') {
        (namespace, leaf)
    } else {
        ("", code)
    }
}

fn namespace_rank(namespace: &str) -> usize {
    match namespace {
        "KERNEL" => 1,
        "EVAL" => 2,
        "PROTOCOL" => 3,
        "CAPABILITY" => 4,
        _ => usize::MAX,
    }
}

fn namespace_local_rank(namespace: &str, leaf: &str) -> usize {
    match namespace {
        "EVAL" => ranked_leaf(
            leaf,
            &[
                "E_ARTIFACT_IDENTITY",
                "E_STEP_IDENTITY",
                "E_STATE_INVALID",
                "E_HISTORY_CURSOR",
                "E_CONTEXT_SNAPSHOT_MISSING",
                "E_CONTEXT_SNAPSHOT_MISMATCH",
                "E_TRIGGER_ITEM_INVALID",
                "E_STEP_CONTRACT",
                "E_REQUEST_CANONICALIZATION",
            ],
        ),
        "PROTOCOL" => ranked_leaf(
            leaf,
            &[
                "unknown_capability",
                "request_hash_mismatch",
                "untrusted_signer",
                "signature_invalid",
                "schema_mismatch",
                "policy_violation",
                "payload_hash_mismatch",
                "missing_receipt",
                "outcome_disallowed",
                "missing_event_type",
                "correlation_mismatch",
                "invalid_correlation_rule",
                "missing_timer_evidence",
                "timer_untrusted",
                "timer_time_invalid",
                "timer_before_deadline",
            ],
        ),
        "CAPABILITY" => ranked_leaf(
            leaf,
            &[
                "missing_required_capability",
                "incompatible_version",
                "incompatible_config_hash",
                "constraint_violation",
                "untrusted_or_missing_trust_anchor",
            ],
        ),
        _ => usize::MAX,
    }
}

fn ranked_leaf(leaf: &str, order: &[&str]) -> usize {
    order
        .iter()
        .position(|candidate| *candidate == leaf)
        .map(|idx| idx + 1)
        .unwrap_or(usize::MAX)
}

fn ordered_validate_levels(levels: &[ValidateLevel]) -> Vec<ValidateLevel> {
    let mut unique = levels.to_vec();
    unique.sort_by_key(|level| level.rank());
    unique.dedup();
    unique
}

fn ordered_run_levels(levels: &[RunLevel]) -> Vec<RunLevel> {
    let mut unique = levels.to_vec();
    unique.sort_by_key(|level| level.rank());
    unique.dedup();
    unique
}

fn ordered_vector_ids(ids: &[String]) -> Vec<String> {
    let mut unique = ids.to_vec();
    unique.sort();
    unique.dedup();
    unique
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::json;

    use super::{
        matches_expected_eval_subset, normalize_run_vectors_output, order_failure_codes,
        portable_workflow_vectorset, RunVectorsNormalize, RESULT_SCHEMA_VERSION,
    };

    #[test]
    fn orders_failure_codes_by_registry_priority_and_deduplicates() {
        let ordered = order_failure_codes(vec![
            "CAPABILITY.constraint_violation".to_string(),
            "PROTOCOL.signature_invalid".to_string(),
            "EVAL.E_STEP_CONTRACT".to_string(),
            "EVAL.E_ARTIFACT_IDENTITY".to_string(),
            "PROTOCOL.request_hash_mismatch".to_string(),
            "CAPABILITY.missing_required_capability".to_string(),
            "EVAL.E_ARTIFACT_IDENTITY".to_string(),
        ]);

        assert_eq!(
            ordered,
            vec![
                "EVAL.E_ARTIFACT_IDENTITY",
                "EVAL.E_STEP_CONTRACT",
                "PROTOCOL.request_hash_mismatch",
                "PROTOCOL.signature_invalid",
                "CAPABILITY.missing_required_capability",
                "CAPABILITY.constraint_violation",
            ]
        );
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn vectorset_loader_accepts_valid_fixture() {
        let path = fixture_path("vectorset_v0_valid_minimal.json");
        let vectorset =
            portable_workflow_vectorset::load_vectorset_v0(path.to_string_lossy().as_ref());

        assert!(vectorset.is_ok());
    }

    #[test]
    fn vectorset_loader_accepts_l2_evalir_fixture() {
        let path = fixture_path("vectorset_v0_run_vectors_l2_evalir_plan.json");
        let vectorset =
            portable_workflow_vectorset::load_vectorset_v0(path.to_string_lossy().as_ref());

        assert!(vectorset.is_ok());
    }

    #[test]
    fn vectorset_loader_accepts_l2_artifact_fixture() {
        let path = fixture_path("vectorset_v0_run_vectors_l2_artifact_pipeline.json");
        let vectorset =
            portable_workflow_vectorset::load_vectorset_v0(path.to_string_lossy().as_ref());

        assert!(vectorset.is_ok());
    }

    #[test]
    fn vectorset_loader_accepts_l2_join_fixture() {
        let path = fixture_path("vectorset_v0_run_vectors_l2_evalir_join_obligations.json");
        let vectorset =
            portable_workflow_vectorset::load_vectorset_v0(path.to_string_lossy().as_ref());

        assert!(vectorset.is_ok());
    }

    #[test]
    fn vectorset_loader_reports_deterministic_failure_codes_for_invalid_fixture() {
        let path = fixture_path("vectorset_v0_invalid_multi.yaml");
        let error = portable_workflow_vectorset::load_vectorset_v0(path.to_string_lossy().as_ref())
            .expect_err("fixture should fail structural validation");

        assert_eq!(
            error.failure_codes,
            vec![
                "EVAL.E_STEP_IDENTITY",
                "EVAL.E_STATE_INVALID",
                "EVAL.E_STEP_CONTRACT",
            ]
        );
        assert!(
            error.issues.len() >= 3,
            "expected multiple structural issues, got {:?}",
            error.issues
        );
    }

    #[test]
    fn vectorset_loader_rejects_forbidden_l1_input_paths() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let vectorset_path = temp_dir.path().join("vectorset_invalid_paths.json");
        let absolute_bundle = fixture_path("bundle_minimal_v0/valid_bundle")
            .canonicalize()
            .expect("canonicalize fixture path");
        let absolute_trust = fixture_path("l3_proof_v0/trust/trusted")
            .canonicalize()
            .expect("canonicalize trust fixture path");
        let absolute_requirements = fixture_path("match_cap_v0/pass/requirements.rulia.bin")
            .canonicalize()
            .expect("canonicalize requirements fixture path");
        let vectorset_json = json!({
            "schema_version": "portable_workflow.vectorset.v0",
            "format_id": "portable_workflow.vectorset.v0",
            "vectors": [
                {
                    "id": "V0-100",
                    "levels": ["L1"],
                    "inputs": { "bundle": { "path": "fixtures/../bundle_minimal_v0/valid_bundle" } },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                },
                {
                    "id": "V0-101",
                    "levels": ["L1"],
                    "inputs": { "bundle": { "path": "fixtures\\bundle_minimal_v0\\valid_bundle" } },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                },
                {
                    "id": "V0-102",
                    "levels": ["L1"],
                    "inputs": { "bundle": { "path": absolute_bundle.to_string_lossy().to_string() } },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                },
                {
                    "id": "V0-103",
                    "levels": ["L3"],
                    "inputs": {
                        "request": { "path": "l3_proof_v0/request.rulia.bin" },
                        "receipt": { "path": "l3_proof_v0/receipt.valid.rulia.bin" },
                        "trust": { "path": absolute_trust.to_string_lossy().to_string() }
                    },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                },
                {
                    "id": "V0-104",
                    "levels": ["L4"],
                    "inputs": {
                        "requirements": { "path": absolute_requirements.to_string_lossy().to_string() },
                        "gamma_cap": { "path": "match_cap_v0/pass/gamma_cap.rulia.bin" }
                    },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                }
            ]
        });
        fs::write(
            &vectorset_path,
            serde_json::to_string_pretty(&vectorset_json).expect("serialize vectorset fixture"),
        )
        .expect("write vectorset fixture");

        let error = portable_workflow_vectorset::load_vectorset_v0(
            vectorset_path.to_string_lossy().as_ref(),
        )
        .expect_err("vectorset with forbidden paths should fail");

        assert_eq!(error.failure_codes, vec!["EVAL.E_STATE_INVALID"]);
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[0].inputs.bundle.path")),
            "expected traversal-path validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[1].inputs.bundle.path")),
            "expected separator validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[2].inputs.bundle.path")),
            "expected absolute-path validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[3].inputs.trust.path")),
            "expected L3 trust-path validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[4].inputs.requirements.path")),
            "expected L4 requirements-path validation issue, got {:?}",
            error.issues
        );
    }

    #[test]
    fn vectorset_loader_rejects_forbidden_l2_input_paths() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let vectorset_path = temp_dir.path().join("vectorset_invalid_l2_paths.json");
        let absolute_gamma_core = fixture_path("l2_evalir_v0/gamma_core_main.json")
            .canonicalize()
            .expect("canonicalize gamma core fixture path");

        let vectorset_json = json!({
            "schema_version": "portable_workflow.vectorset.v0",
            "format_id": "portable_workflow.vectorset.v0",
            "vectors": [
                {
                    "id": "V0-120",
                    "levels": ["L2"],
                    "inputs": {
                        "eval_ir": { "path": "l2_evalir_v0/../evalir_assign_emit_end.json" },
                        "initial_state": { "path": "l2_evalir_v0\\initial_state_base.json" },
                        "gamma_core": { "path": absolute_gamma_core.to_string_lossy().to_string() }
                    },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                },
                {
                    "id": "V0-121",
                    "levels": ["L2"],
                    "inputs": {
                        "artifact": { "path": "workflow_artifact_v0_subset\\artifact_assign_emit_end.rulia.bin" },
                        "initial_state": { "path": "l2_evalir_v0/initial_state_base.json" }
                    },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                }
            ]
        });

        fs::write(
            &vectorset_path,
            serde_json::to_string_pretty(&vectorset_json).expect("serialize vectorset fixture"),
        )
        .expect("write vectorset fixture");

        let error = portable_workflow_vectorset::load_vectorset_v0(
            vectorset_path.to_string_lossy().as_ref(),
        )
        .expect_err("vectorset with forbidden L2 paths should fail");

        assert_eq!(error.failure_codes, vec!["EVAL.E_STATE_INVALID"]);
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[0].inputs.eval_ir.path")),
            "expected eval_ir path validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[0].inputs.initial_state.path")),
            "expected initial_state path validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[0].inputs.gamma_core.path")),
            "expected gamma_core path validation issue, got {:?}",
            error.issues
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("vectors[1].inputs.artifact.path")),
            "expected artifact path validation issue, got {:?}",
            error.issues
        );
    }

    #[test]
    fn vectorset_loader_enforces_l2_eval_ir_or_artifact_exclusivity() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let vectorset_path = temp_dir
            .path()
            .join("vectorset_invalid_l2_source_selection.json");
        let vectorset_json = json!({
            "schema_version": "portable_workflow.vectorset.v0",
            "format_id": "portable_workflow.vectorset.v0",
            "vectors": [
                {
                    "id": "V0-122",
                    "levels": ["L2"],
                    "inputs": {
                        "initial_state": { "path": "l2_evalir_v0/initial_state_base.json" }
                    },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                },
                {
                    "id": "V0-123",
                    "levels": ["L2"],
                    "inputs": {
                        "eval_ir": { "path": "l2_evalir_v0/evalir_assign_emit_end.json" },
                        "artifact": { "path": "workflow_artifact_v0_subset/artifact_assign_emit_end.rulia.bin" },
                        "initial_state": { "path": "l2_evalir_v0/initial_state_base.json" }
                    },
                    "expected": { "verdict": "pass", "failure_codes": [] }
                }
            ]
        });

        fs::write(
            &vectorset_path,
            serde_json::to_string_pretty(&vectorset_json).expect("serialize vectorset fixture"),
        )
        .expect("write vectorset fixture");

        let error = portable_workflow_vectorset::load_vectorset_v0(
            vectorset_path.to_string_lossy().as_ref(),
        )
        .expect_err("vectorset with invalid L2 source selection should fail");

        assert_eq!(error.failure_codes, vec!["EVAL.E_STATE_INVALID"]);
        assert!(
            error.issues.iter().any(|issue| issue.contains("vectors[0] with level L2 must include exactly one of inputs.eval_ir.path or inputs.artifact.path")),
            "expected missing L2 source issue, got {:?}",
            error.issues
        );
        assert!(
            error.issues.iter().any(|issue| issue.contains("vectors[1] with level L2 must not set both inputs.eval_ir.path and inputs.artifact.path")),
            "expected dual L2 source issue, got {:?}",
            error.issues
        );
    }

    #[test]
    fn eval_expected_subset_allows_partial_request_and_obligation_assertions() {
        let expected = portable_workflow_vectorset::EvalExpectedV0 {
            control: Some("suspend".to_string()),
            state_out: None,
            emissions: Some(json!([])),
            requests: Some(json!([{}])),
            obligations: Some(json!([{"obligation_type": "receipt_valid"}])),
        };
        let actual = json!({
            "control": "suspend",
            "state_out": {"metrics": {"request_count": 0}},
            "emissions": [],
            "requests": [{
                "request_ordinal": 1,
                "request_id": "sha256:request-id",
                "capability_id": "capability.approvals",
                "operation": "submit",
                "args": {"amount": 1250},
                "cause": {
                    "artifact_id": "sha256:artifact-id",
                    "step_id": "S0001",
                    "request_ordinal": 1,
                    "history_cursor": -1
                }
            }],
            "obligations": [{
                "obligation_id": "sha256:obligation-id",
                "obligation_type": "receipt_valid",
                "satisfaction_ref": "sha256:request-id"
            }]
        });

        assert!(matches_expected_eval_subset(Some(&expected), Some(&actual)));
    }

    #[test]
    fn eval_expected_subset_rejects_count_or_type_mismatches() {
        let expected = portable_workflow_vectorset::EvalExpectedV0 {
            control: Some("suspend".to_string()),
            state_out: None,
            emissions: Some(json!([])),
            requests: Some(json!([{}])),
            obligations: Some(json!([{"obligation_type": "receipt_valid"}])),
        };
        let wrong_obligation_type = json!({
            "control": "suspend",
            "emissions": [],
            "requests": [{}],
            "obligations": [{"obligation_type": "not_receipt_valid"}]
        });
        let wrong_request_count = json!({
            "control": "suspend",
            "emissions": [],
            "requests": [{}, {}],
            "obligations": [{"obligation_type": "receipt_valid"}]
        });

        assert!(!matches_expected_eval_subset(
            Some(&expected),
            Some(&wrong_obligation_type)
        ));
        assert!(!matches_expected_eval_subset(
            Some(&expected),
            Some(&wrong_request_count)
        ));
    }

    #[test]
    fn run_vectors_ci_v0_normalization_drops_l2_eval_internal_ids_recursively() {
        let mut output = json!({
            "schema_version": RESULT_SCHEMA_VERSION,
            "command": "run-vectors",
            "details": {
                "vectors": [
                    {
                        "id": "V0-202",
                        "actual_eval": {
                            "requests": [
                                {
                                    "request_id": "sha256:r1",
                                    "request_ordinal": 1
                                },
                                {
                                    "request_id": "sha256:r2",
                                    "request_ordinal": 2
                                }
                            ],
                            "obligations": [
                                {
                                    "obligation_id": "sha256:o1",
                                    "obligation_type": "receipt_valid",
                                    "satisfaction_ref": "sha256:r1"
                                }
                            ]
                        }
                    }
                ],
                "normalized_eval_fragment": {
                    "requests": [
                        {
                            "request_id": "sha256:r3",
                            "request_ordinal": 3
                        }
                    ],
                    "obligations": [
                        {
                            "obligation_id": "sha256:o2",
                            "obligation_type": "receipt_valid",
                            "satisfaction_ref": "sha256:r3"
                        }
                    ]
                }
            }
        });

        normalize_run_vectors_output(RunVectorsNormalize::CiV0, &mut output);

        assert_eq!(
            output,
            json!({
                "schema_version": RESULT_SCHEMA_VERSION,
                "command": "run-vectors",
                "details": {
                    "vectors": [
                        {
                            "id": "V0-202",
                            "actual_eval": {
                                "requests": [
                                    {
                                        "request_ordinal": 1
                                    },
                                    {
                                        "request_ordinal": 2
                                    }
                                ],
                                "obligations": [
                                    {
                                        "obligation_type": "receipt_valid"
                                    }
                                ]
                            }
                        }
                    ],
                    "normalized_eval_fragment": {
                        "requests": [
                            {
                                "request_ordinal": 3
                            }
                        ],
                        "obligations": [
                            {
                                "obligation_type": "receipt_valid"
                            }
                        ]
                    }
                }
            })
        );
    }
}
