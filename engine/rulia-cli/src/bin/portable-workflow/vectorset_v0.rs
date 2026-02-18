use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use super::portable_workflow_path_safety::{safe_relative_path, SafeRelativePathError};

const VECTORSET_SCHEMA_VERSION: &str = "portable_workflow.vectorset.v0";
const ENUM_REGISTRY_DOC: &str = "docs/design/PORTABLE_WORKFLOW_ENUM_REGISTRY_V0.md";

const FAILURE_CODE_STATE_INVALID: &str = "EVAL.E_STATE_INVALID";
const FAILURE_CODE_STEP_IDENTITY: &str = "EVAL.E_STEP_IDENTITY";
const FAILURE_CODE_STEP_CONTRACT: &str = "EVAL.E_STEP_CONTRACT";

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct VectorSetV0 {
    #[serde(default)]
    pub(crate) schema_version: Option<String>,
    #[serde(default)]
    pub(crate) format_id: Option<String>,
    #[serde(default)]
    pub(crate) vectors: Vec<VectorV0>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct VectorV0 {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) levels: Vec<String>,
    #[serde(default)]
    pub(crate) inputs: InputsV0,
    #[serde(default)]
    pub(crate) expected: ExpectedV0,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct InputsV0 {
    #[serde(default)]
    pub(crate) artifact: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) bundle: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) eval_ir: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) initial_state: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) requirements: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) gamma_core: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) gamma_cap: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) request: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) receipt: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) trust: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) obligation: Option<PathInputV0>,
    #[serde(default)]
    pub(crate) history: Option<PathInputV0>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct PathInputV0 {
    #[serde(default)]
    pub(crate) path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ExpectedV0 {
    #[serde(default)]
    pub(crate) verdict: String,
    #[serde(default)]
    pub(crate) failure_codes: Vec<String>,
    #[serde(default)]
    pub(crate) ordering_rule: Option<OrderingRuleV0>,
    #[serde(default)]
    pub(crate) eval_expected: Option<EvalExpectedV0>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct EvalExpectedV0 {
    #[serde(default)]
    pub(crate) control: Option<String>,
    #[serde(default)]
    pub(crate) state_out: Option<Value>,
    #[serde(default)]
    pub(crate) emissions: Option<Value>,
    #[serde(default)]
    pub(crate) requests: Option<Value>,
    #[serde(default)]
    pub(crate) obligations: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct OrderingRuleV0 {
    #[serde(default)]
    pub(crate) registry_doc: String,
    #[serde(default)]
    pub(crate) section: String,
    #[serde(default)]
    pub(crate) rule_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct VectorSetLoadFailure {
    pub(crate) failure_codes: Vec<String>,
    pub(crate) issues: Vec<String>,
}

impl VectorSetLoadFailure {
    fn single(failure_code: &'static str, issue: String) -> Self {
        Self {
            failure_codes: super::order_failure_codes(vec![failure_code.to_string()]),
            issues: vec![issue],
        }
    }

    fn from_issues(issues: Vec<ValidationIssue>) -> Self {
        Self {
            failure_codes: super::order_failure_codes(
                issues
                    .iter()
                    .map(|issue| issue.failure_code.to_string())
                    .collect(),
            ),
            issues: issues.into_iter().map(|issue| issue.message).collect(),
        }
    }
}

pub(crate) fn load_vectorset_v0(path: &str) -> Result<VectorSetV0, VectorSetLoadFailure> {
    let vectorset_path = Path::new(path);
    let input = fs::read_to_string(vectorset_path).map_err(|err| {
        VectorSetLoadFailure::single(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "failed to read vectorset '{}': {err}",
                vectorset_path.display()
            ),
        )
    })?;

    let vectorset = parse_vectorset(vectorset_path, &input)
        .map_err(|issue| VectorSetLoadFailure::single(FAILURE_CODE_STATE_INVALID, issue))?;

    let issues = validate_vectorset(&vectorset);
    if issues.is_empty() {
        Ok(vectorset)
    } else {
        Err(VectorSetLoadFailure::from_issues(issues))
    }
}

fn parse_vectorset(path: &Path, input: &str) -> Result<VectorSetV0, String> {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    match extension.as_deref() {
        Some("json") => parse_json(path, input),
        Some("yaml") | Some("yml") => parse_yaml(path, input),
        _ => parse_json(path, input).or_else(|json_err| {
            parse_yaml(path, input).map_err(|yaml_err| {
                format!(
                    "failed to parse vectorset '{}'; json error: {json_err}; yaml error: {yaml_err}",
                    path.display()
                )
            })
        }),
    }
}

fn parse_json(path: &Path, input: &str) -> Result<VectorSetV0, String> {
    serde_json::from_str(input)
        .map_err(|err| format!("failed to parse vectorset JSON '{}': {err}", path.display()))
}

fn parse_yaml(path: &Path, input: &str) -> Result<VectorSetV0, String> {
    serde_yaml::from_str(input)
        .map_err(|err| format!("failed to parse vectorset YAML '{}': {err}", path.display()))
}

#[derive(Debug)]
struct ValidationIssue {
    failure_code: &'static str,
    message: String,
}

fn validation_issue(code: &'static str, message: String) -> ValidationIssue {
    ValidationIssue {
        failure_code: code,
        message,
    }
}

fn validate_vectorset(vectorset: &VectorSetV0) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    match vectorset.schema_version.as_deref().map(str::trim) {
        Some(VECTORSET_SCHEMA_VERSION) => {}
        Some(actual) => issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectorset schema_version must be '{VECTORSET_SCHEMA_VERSION}', found '{actual}'"
            ),
        )),
        None => issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            "vectorset schema_version is required".to_string(),
        )),
    }

    if let Some(format_id) = vectorset.format_id.as_deref().map(str::trim) {
        if format_id != VECTORSET_SCHEMA_VERSION {
            issues.push(validation_issue(
                FAILURE_CODE_STATE_INVALID,
                format!(
                    "vectorset format_id must be '{VECTORSET_SCHEMA_VERSION}', found '{format_id}'"
                ),
            ));
        }
    }

    if vectorset.vectors.is_empty() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            "vectorset must include at least one vector".to_string(),
        ));
    }

    for (index, vector) in vectorset.vectors.iter().enumerate() {
        validate_vector(index, vector, &mut issues);
    }

    issues
}

fn validate_vector(index: usize, vector: &VectorV0, issues: &mut Vec<ValidationIssue>) {
    if !is_valid_vector_id(&vector.id) {
        issues.push(validation_issue(
            FAILURE_CODE_STEP_IDENTITY,
            format!(
                "vectors[{index}].id must match '^V0-[0-9]{{3}}$', found '{}'",
                vector.id
            ),
        ));
    }

    if vector.levels.is_empty() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!("vectors[{index}].levels must include at least one level"),
        ));
    }
    for level in &vector.levels {
        if !is_valid_level(level) {
            issues.push(validation_issue(
                FAILURE_CODE_STATE_INVALID,
                format!(
                    "vectors[{index}].levels contains invalid level '{level}' (allowed: L0..L4)"
                ),
            ));
        }
    }

    validate_expected(index, &vector.expected, issues);
    validate_l1_inputs(index, vector, issues);
    validate_l2_inputs(index, vector, issues);
    validate_l3_inputs(index, vector, issues);
    validate_l4_inputs(index, vector, issues);
}

fn validate_expected(index: usize, expected: &ExpectedV0, issues: &mut Vec<ValidationIssue>) {
    match expected.verdict.as_str() {
        "pass" => {
            if !expected.failure_codes.is_empty() {
                issues.push(validation_issue(
                    FAILURE_CODE_STEP_CONTRACT,
                    format!(
                        "vectors[{index}].expected.failure_codes must be empty when verdict='pass'"
                    ),
                ));
            }
        }
        "fail" => {
            if expected.failure_codes.is_empty() {
                issues.push(validation_issue(
                    FAILURE_CODE_STEP_CONTRACT,
                    format!(
                        "vectors[{index}].expected.failure_codes must be non-empty when verdict='fail'"
                    ),
                ));
            }
        }
        _ => issues.push(validation_issue(
            FAILURE_CODE_STEP_CONTRACT,
            format!(
                "vectors[{index}].expected.verdict must be 'pass' or 'fail', found '{}'",
                expected.verdict
            ),
        )),
    }

    for (failure_index, failure_code) in expected.failure_codes.iter().enumerate() {
        if !is_valid_namespaced_failure_code(failure_code) {
            issues.push(validation_issue(
                FAILURE_CODE_STEP_CONTRACT,
                format!(
                    "vectors[{index}].expected.failure_codes[{failure_index}] must be a non-empty namespaced enum id"
                ),
            ));
        }
    }

    let requires_ordering_rule = expected.verdict == "fail";
    if requires_ordering_rule || expected.ordering_rule.is_some() {
        match expected.ordering_rule.as_ref() {
            Some(rule) => {
                if rule.registry_doc.trim().is_empty()
                    || rule.section.trim().is_empty()
                    || rule.rule_id.trim().is_empty()
                {
                    issues.push(validation_issue(
                        FAILURE_CODE_STEP_CONTRACT,
                        format!("vectors[{index}].expected.ordering_rule fields must be non-empty"),
                    ));
                }

                if rule.registry_doc.trim() != ENUM_REGISTRY_DOC {
                    issues.push(validation_issue(
                        FAILURE_CODE_STEP_CONTRACT,
                        format!(
                            "vectors[{index}].expected.ordering_rule.registry_doc must be '{ENUM_REGISTRY_DOC}'"
                        ),
                    ));
                }

                if !references_enum_registry_ordering_section(&rule.section) {
                    issues.push(validation_issue(
                        FAILURE_CODE_STEP_CONTRACT,
                        format!(
                            "vectors[{index}].expected.ordering_rule.section must reference an enum-registry ordering section"
                        ),
                    ));
                }
            }
            None => issues.push(validation_issue(
                FAILURE_CODE_STEP_CONTRACT,
                format!("vectors[{index}].expected.ordering_rule is required when verdict='fail'"),
            )),
        }
    }

    if let Some(eval_expected) = expected.eval_expected.as_ref() {
        if let Some(control) = eval_expected.control.as_deref() {
            if !matches!(control.trim(), "continue" | "suspend" | "end" | "error") {
                issues.push(validation_issue(
                    FAILURE_CODE_STEP_CONTRACT,
                    format!(
                        "vectors[{index}].expected.eval_expected.control must be one of continue|suspend|end|error"
                    ),
                ));
            }
        }
    }
}

fn validate_l1_inputs(index: usize, vector: &VectorV0, issues: &mut Vec<ValidationIssue>) {
    if !vector.levels.iter().any(|level| level == "L1") {
        return;
    }

    let artifact_path = path_field(vector.inputs.artifact.as_ref());
    let bundle_path = path_field(vector.inputs.bundle.as_ref());

    if artifact_path.is_none() && bundle_path.is_none() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L1 must include one of inputs.artifact.path or inputs.bundle.path"
            ),
        ));
        return;
    }

    if artifact_path.is_some() && bundle_path.is_some() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L1 must not set both inputs.artifact.path and inputs.bundle.path"
            ),
        ));
    }

    if let Some(artifact_path) = artifact_path {
        validate_vector_input_path(index, "inputs.artifact.path", artifact_path, issues);
    }
    if let Some(bundle_path) = bundle_path {
        validate_vector_input_path(index, "inputs.bundle.path", bundle_path, issues);
    }
}

fn validate_l2_inputs(index: usize, vector: &VectorV0, issues: &mut Vec<ValidationIssue>) {
    if !vector.levels.iter().any(|level| level == "L2") {
        return;
    }

    let eval_ir_path = path_field(vector.inputs.eval_ir.as_ref());
    let artifact_path = path_field(vector.inputs.artifact.as_ref());
    let initial_state_path = path_field(vector.inputs.initial_state.as_ref());
    let history_path = path_field(vector.inputs.history.as_ref());
    let gamma_core_path = path_field(vector.inputs.gamma_core.as_ref());
    let has_l3 = vector.levels.iter().any(|level| level == "L3");

    if let Some(eval_ir_path) = eval_ir_path {
        validate_vector_input_path(index, "inputs.eval_ir.path", eval_ir_path, issues);
    }
    if let Some(initial_state_path) = initial_state_path {
        validate_vector_input_path(
            index,
            "inputs.initial_state.path",
            initial_state_path,
            issues,
        );
    }
    if let Some(artifact_path) = artifact_path {
        validate_vector_input_path(index, "inputs.artifact.path", artifact_path, issues);
    }
    if let Some(history_path) = history_path {
        if !has_l3 {
            validate_vector_input_path(index, "inputs.history.path", history_path, issues);
        }
    }
    if let Some(gamma_core_path) = gamma_core_path {
        validate_vector_input_path(index, "inputs.gamma_core.path", gamma_core_path, issues);
    }

    if eval_ir_path.is_none() && artifact_path.is_none() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L2 must include exactly one of inputs.eval_ir.path or inputs.artifact.path"
            ),
        ));
    }

    if eval_ir_path.is_some() && artifact_path.is_some() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L2 must not set both inputs.eval_ir.path and inputs.artifact.path"
            ),
        ));
    }

    if initial_state_path.is_none() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!("vectors[{index}] with level L2 must include inputs.initial_state.path"),
        ));
    }
}

fn validate_l3_inputs(index: usize, vector: &VectorV0, issues: &mut Vec<ValidationIssue>) {
    if !vector.levels.iter().any(|level| level == "L3") {
        return;
    }

    let request_path = path_field(vector.inputs.request.as_ref());
    let receipt_path = path_field(vector.inputs.receipt.as_ref());
    let trust_path = path_field(vector.inputs.trust.as_ref());
    let obligation_path = path_field(vector.inputs.obligation.as_ref());
    let history_path = path_field(vector.inputs.history.as_ref());
    let bundle_path = path_field(vector.inputs.bundle.as_ref());

    if let Some(request_path) = request_path {
        validate_vector_input_path(index, "inputs.request.path", request_path, issues);
    }
    if let Some(receipt_path) = receipt_path {
        validate_vector_input_path(index, "inputs.receipt.path", receipt_path, issues);
    }
    if let Some(trust_path) = trust_path {
        validate_vector_input_path(index, "inputs.trust.path", trust_path, issues);
    }
    if let Some(obligation_path) = obligation_path {
        validate_vector_input_path(index, "inputs.obligation.path", obligation_path, issues);
    }
    if let Some(history_path) = history_path {
        validate_vector_input_path(index, "inputs.history.path", history_path, issues);
    }
    if let Some(bundle_path) = bundle_path {
        validate_vector_input_path(index, "inputs.bundle.path", bundle_path, issues);
    }

    if trust_path.is_none() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!("vectors[{index}] with level L3 must include inputs.trust.path"),
        ));
    }

    let has_request_or_receipt = request_path.is_some() || receipt_path.is_some();
    let has_receipt_mode_inputs = request_path.is_some() && receipt_path.is_some();
    let has_obligation_mode_inputs = obligation_path.is_some();

    if has_request_or_receipt && !has_receipt_mode_inputs {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L3 receipt verification must include both inputs.request.path and inputs.receipt.path"
            ),
        ));
    }

    if !has_receipt_mode_inputs && !has_obligation_mode_inputs {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L3 must include either receipt inputs (inputs.request.path + inputs.receipt.path) or obligation inputs (inputs.obligation.path)"
            ),
        ));
    }

    if has_receipt_mode_inputs && has_obligation_mode_inputs {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L3 must not mix receipt inputs with obligation inputs"
            ),
        ));
    }

    if has_receipt_mode_inputs && (history_path.is_some() || bundle_path.is_some()) {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L3 receipt verification must not set inputs.history.path or inputs.bundle.path"
            ),
        ));
    }

    if has_obligation_mode_inputs && history_path.is_some() == bundle_path.is_some() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "vectors[{index}] with level L3 obligation verification must include exactly one of inputs.history.path or inputs.bundle.path"
            ),
        ));
    }
}

fn validate_l4_inputs(index: usize, vector: &VectorV0, issues: &mut Vec<ValidationIssue>) {
    if !vector.levels.iter().any(|level| level == "L4") {
        return;
    }

    let requirements_path = path_field(vector.inputs.requirements.as_ref());
    let gamma_cap_path = path_field(vector.inputs.gamma_cap.as_ref());

    if let Some(requirements_path) = requirements_path {
        validate_vector_input_path(index, "inputs.requirements.path", requirements_path, issues);
    }
    if let Some(gamma_cap_path) = gamma_cap_path {
        validate_vector_input_path(index, "inputs.gamma_cap.path", gamma_cap_path, issues);
    }

    if requirements_path.is_none() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!("vectors[{index}] with level L4 must include inputs.requirements.path"),
        ));
    }
    if gamma_cap_path.is_none() {
        issues.push(validation_issue(
            FAILURE_CODE_STATE_INVALID,
            format!("vectors[{index}] with level L4 must include inputs.gamma_cap.path"),
        ));
    }
}

fn path_field(input: Option<&PathInputV0>) -> Option<&str> {
    input
        .and_then(|value| value.path.as_deref())
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

fn validate_vector_input_path(
    index: usize,
    field_name: &str,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Err(error) = safe_relative_path(path) {
        let message = match error {
            SafeRelativePathError::BackslashSeparator => {
                format!(
                    "vectors[{index}].{field_name} must use vectorset-relative POSIX separators"
                )
            }
            SafeRelativePathError::AbsolutePath => {
                format!("vectors[{index}].{field_name} must be vectorset-relative")
            }
            SafeRelativePathError::ForbiddenSegments => {
                format!("vectors[{index}].{field_name} '{path}' contains forbidden path segments")
            }
            SafeRelativePathError::InvalidRelativePath => format!(
                "vectors[{index}].{field_name} '{path}' is not a valid vectorset-relative file path"
            ),
        };
        issues.push(validation_issue(FAILURE_CODE_STATE_INVALID, message));
    }
}

fn is_valid_vector_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 6
        && bytes.starts_with(b"V0-")
        && bytes[3].is_ascii_digit()
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
}

fn is_valid_level(level: &str) -> bool {
    matches!(level, "L0" | "L1" | "L2" | "L3" | "L4")
}

fn is_valid_namespaced_failure_code(code: &str) -> bool {
    if code.trim().is_empty() {
        return false;
    }

    if let Some((namespace, leaf_code)) = code.split_once('.') {
        if leaf_code.is_empty() {
            return false;
        }

        matches!(namespace, "KERNEL" | "EVAL" | "PROTOCOL" | "CAPABILITY")
    } else {
        false
    }
}

fn references_enum_registry_ordering_section(section: &str) -> bool {
    if section.trim().is_empty() {
        return false;
    }

    let normalized = section.to_ascii_lowercase();
    normalized.contains("ordering")
        && (normalized.contains("eval")
            || normalized.contains("protocol")
            || normalized.contains("capability")
            || normalized.contains("multi-failure")
            || normalized.contains("global ordering key"))
}
