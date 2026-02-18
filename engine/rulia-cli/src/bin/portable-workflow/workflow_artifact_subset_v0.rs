use std::collections::{BTreeMap, BTreeSet};

use rulia::Value as RuliaValue;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use super::portable_workflow_evalir_v0::{EvalIrV0, EvalStepV0};
use super::portable_workflow_request_identity_v0::{
    compute_args_hash_v0, compute_request_key_v0, RequestSeedV0 as RequestIdentitySeedV0,
    REQUEST_ORDINAL_BASE_V0,
};

const WORKFLOW_ARTIFACT_TAG: &str = "workflow_artifact_v0";
const WORKFLOW_ARTIFACT_VERSION: &str = "v0";
const EVAL_IR_FORMAT_ID: &str = "portable_workflow.eval_ir.v0";
const EVAL_IR_VERSION: &str = "v0";
const FAILURE_CODE_STATE_INVALID: &str = "EVAL.E_STATE_INVALID";
const FAILURE_CODE_STEP_IDENTITY: &str = "EVAL.E_STEP_IDENTITY";
const FAILURE_CODE_STEP_CONTRACT: &str = "EVAL.E_STEP_CONTRACT";
const FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const MAX_DERIVED_STEP_COUNT: usize = 9999;

#[derive(Debug, Clone)]
pub(crate) struct ArtifactCompileFailure {
    pub(crate) failure_codes: Vec<String>,
    pub(crate) issues: Vec<String>,
}

impl ArtifactCompileFailure {
    fn single(failure_code: &'static str, issue: String) -> Self {
        Self {
            failure_codes: super::order_failure_codes(vec![failure_code.to_string()]),
            issues: vec![issue],
        }
    }
}

#[derive(Debug)]
struct WorkflowArtifactSubsetV0 {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    version: String,
    steps: Vec<WorkflowArtifactStepV0>,
}

#[derive(Debug)]
enum WorkflowArtifactStepV0 {
    Assign {
        name: Option<String>,
        path: String,
        value: Value,
    },
    Emit {
        name: Option<String>,
        emission: Value,
    },
    Request {
        name: Option<String>,
        capability_id: String,
        operation: String,
        args: Value,
    },
    JoinObligationsV0 {
        name: Option<String>,
        source: JoinObligationsSourceV0,
        policy: JoinPolicyV0,
    },
    End {
        name: Option<String>,
    },
}

#[derive(Debug)]
enum RouteTargetRefV0 {
    StepName(String),
    StepOrdinal(usize),
}

#[derive(Debug, Clone, Copy)]
enum JoinPolicyV0 {
    AllOf,
    AnyOf,
}

#[derive(Debug)]
enum JoinObligationsSourceV0 {
    Inline(Vec<Value>),
    WaitForSteps(Vec<RouteTargetRefV0>),
}

impl WorkflowArtifactStepV0 {
    fn name(&self) -> Option<&str> {
        match self {
            WorkflowArtifactStepV0::Assign { name, .. }
            | WorkflowArtifactStepV0::Emit { name, .. }
            | WorkflowArtifactStepV0::Request { name, .. }
            | WorkflowArtifactStepV0::JoinObligationsV0 { name, .. }
            | WorkflowArtifactStepV0::End { name } => name.as_deref(),
        }
    }
}

impl JoinPolicyV0 {
    fn as_evalir_value(self) -> Option<String> {
        match self {
            JoinPolicyV0::AllOf => None,
            JoinPolicyV0::AnyOf => Some("any_of".to_string()),
        }
    }
}

pub(crate) fn parse_and_compile_artifact_subset_v0(
    value: &RuliaValue,
) -> Result<EvalIrV0, ArtifactCompileFailure> {
    let artifact_hash = compute_artifact_hash(value).map_err(|issue| {
        ArtifactCompileFailure::single(
            FAILURE_CODE_STATE_INVALID,
            format!("failed to derive artifact hash for request identity: {issue}"),
        )
    })?;
    let artifact = parse_workflow_artifact_subset_v0(value)?;
    compile_workflow_artifact_subset_v0(&artifact, artifact_hash)
}

fn parse_workflow_artifact_subset_v0(
    value: &RuliaValue,
) -> Result<WorkflowArtifactSubsetV0, ArtifactCompileFailure> {
    let RuliaValue::Tagged(tagged) = value else {
        return Err(ArtifactCompileFailure::single(
            FAILURE_CODE_STATE_INVALID,
            "artifact root must be WorkflowArtifactV0 tagged value".to_string(),
        ));
    };
    if tagged.tag.as_str() != WORKFLOW_ARTIFACT_TAG {
        return Err(ArtifactCompileFailure::single(
            FAILURE_CODE_STATE_INVALID,
            format!(
                "artifact root tag must be '{WORKFLOW_ARTIFACT_TAG}', found '{}'",
                tagged.tag
            ),
        ));
    }

    let root_entries = expect_map_entries(
        tagged.value.as_ref(),
        "artifact payload must be map with id, version, and steps",
    )
    .map_err(|issue| ArtifactCompileFailure::single(FAILURE_CODE_STATE_INVALID, issue))?;
    let root_fields = strict_field_map(root_entries, &["id", "version", "steps"], "artifact")
        .map_err(|issue| ArtifactCompileFailure::single(FAILURE_CODE_STATE_INVALID, issue))?;

    let id = expect_non_empty_string(
        root_fields
            .get("id")
            .expect("required id field must exist after strict field map"),
        "artifact.id must be a non-empty string",
    )
    .map_err(|issue| ArtifactCompileFailure::single(FAILURE_CODE_STATE_INVALID, issue))?;
    let version = expect_non_empty_string(
        root_fields
            .get("version")
            .expect("required version field must exist after strict field map"),
        "artifact.version must be a non-empty string",
    )
    .map_err(|issue| ArtifactCompileFailure::single(FAILURE_CODE_STATE_INVALID, issue))?;
    if version != WORKFLOW_ARTIFACT_VERSION {
        return Err(ArtifactCompileFailure::single(
            FAILURE_CODE_STATE_INVALID,
            format!("artifact.version must be '{WORKFLOW_ARTIFACT_VERSION}', found '{version}'"),
        ));
    }

    let steps_value = root_fields
        .get("steps")
        .expect("required steps field must exist after strict field map");
    let steps_values = expect_vector_values(
        steps_value,
        "artifact.steps must be an ordered vector of workflow steps",
    )
    .map_err(|issue| ArtifactCompileFailure::single(FAILURE_CODE_STATE_INVALID, issue))?;
    if steps_values.is_empty() {
        return Err(ArtifactCompileFailure::single(
            FAILURE_CODE_STEP_IDENTITY,
            "artifact.steps must include at least one step".to_string(),
        ));
    }
    if steps_values.len() > MAX_DERIVED_STEP_COUNT {
        return Err(ArtifactCompileFailure::single(
            FAILURE_CODE_STEP_IDENTITY,
            format!(
                "artifact.steps length {} exceeds max derived step count {MAX_DERIVED_STEP_COUNT}",
                steps_values.len()
            ),
        ));
    }

    let mut steps = Vec::with_capacity(steps_values.len());
    let mut seen_step_names = BTreeSet::new();
    for (index, step_value) in steps_values.iter().enumerate() {
        let step = parse_step(step_value, index).map_err(|issue| {
            ArtifactCompileFailure::single(
                issue.failure_code,
                format!("artifact.steps[{index}] {}", issue.message),
            )
        })?;
        if let Some(step_name) = step.name() {
            if !seen_step_names.insert(step_name.to_string()) {
                return Err(ArtifactCompileFailure::single(
                    FAILURE_CODE_STEP_IDENTITY,
                    format!("artifact.steps[{index}] duplicate step name '{step_name}'"),
                ));
            }
        }
        steps.push(step);
    }

    Ok(WorkflowArtifactSubsetV0 { id, version, steps })
}

fn compile_workflow_artifact_subset_v0(
    artifact: &WorkflowArtifactSubsetV0,
    artifact_hash: String,
) -> Result<EvalIrV0, ArtifactCompileFailure> {
    let step_count = artifact.steps.len();
    let mut step_name_to_index = BTreeMap::new();
    for (index, step) in artifact.steps.iter().enumerate() {
        if let Some(name) = step.name() {
            if step_name_to_index.insert(name.to_string(), index).is_some() {
                return Err(ArtifactCompileFailure::single(
                    FAILURE_CODE_STEP_IDENTITY,
                    format!("duplicate step name '{name}'"),
                ));
            }
        }
    }

    let mut request_hash_by_step_index = BTreeMap::new();
    let mut request_args_is_dynamic_by_step_index = BTreeMap::new();
    for (index, artifact_step) in artifact.steps.iter().enumerate() {
        let WorkflowArtifactStepV0::Request { args, .. } = artifact_step else {
            continue;
        };
        let args_is_dynamic =
            super::portable_workflow_kernel_expression_v0::payload_contains_expression_json(args)
                .map_err(|issue| {
                    ArtifactCompileFailure::single(
                        FAILURE_CODE_STEP_CONTRACT,
                        format!(
                            "request step at index {index} has invalid expression payload shape: {issue}"
                        ),
                    )
                })?;
        request_args_is_dynamic_by_step_index.insert(index, args_is_dynamic);
        if args_is_dynamic {
            continue;
        }

        let request_step_id = derived_step_id(index).ok_or_else(|| {
            ArtifactCompileFailure::single(
                FAILURE_CODE_STEP_IDENTITY,
                format!("derived step id is invalid at index {index}"),
            )
        })?;
        let args_hash = compute_args_hash_v0(args).map_err(|issue| {
            ArtifactCompileFailure::single(
                FAILURE_CODE_STEP_CONTRACT,
                format!(
                    "request step '{request_step_id}' failed to canonicalize request args: {issue}"
                ),
            )
        })?;
        let seed = RequestIdentitySeedV0 {
            artifact_hash: artifact_hash.clone(),
            step_id: request_step_id.clone(),
            request_ordinal: REQUEST_ORDINAL_BASE_V0,
            args_hash,
            history_cursor: None,
            process_id: None,
        };
        let request_hash = compute_request_key_v0(&seed).map_err(|issue| {
            ArtifactCompileFailure::single(
                FAILURE_CODE_STEP_CONTRACT,
                format!(
                    "request step '{request_step_id}' failed to canonicalize request seed: {issue}"
                ),
            )
        })?;
        request_hash_by_step_index.insert(index, request_hash);
    }

    let mut end_step_count = 0usize;
    let mut eval_steps = Vec::with_capacity(step_count);

    for (index, artifact_step) in artifact.steps.iter().enumerate() {
        let step_id = derived_step_id(index).ok_or_else(|| {
            ArtifactCompileFailure::single(
                FAILURE_CODE_STEP_IDENTITY,
                format!("derived step id is invalid at index {index}"),
            )
        })?;
        let next_step_id = if index + 1 < step_count {
            Some(derived_step_id(index + 1).expect("next step id must exist within max bound"))
        } else {
            None
        };

        let eval_step = match artifact_step {
            WorkflowArtifactStepV0::Assign { path, value, .. } => {
                if next_step_id.is_none() {
                    return Err(ArtifactCompileFailure::single(
                        FAILURE_CODE_STEP_CONTRACT,
                        "assign step cannot be terminal; terminal step must be end".to_string(),
                    ));
                }
                EvalStepV0 {
                    step_id,
                    op: "assign".to_string(),
                    path: Some(path.clone()),
                    value: Some(value.clone()),
                    emission: None,
                    capability_id: None,
                    operation: None,
                    args: None,
                    next_step_id,
                    obligations: None,
                    policy: None,
                    on_timeout: None,
                    rules: None,
                    rules_sexpr: None,
                    routes: None,
                }
            }
            WorkflowArtifactStepV0::Emit { emission, .. } => {
                if next_step_id.is_none() {
                    return Err(ArtifactCompileFailure::single(
                        FAILURE_CODE_STEP_CONTRACT,
                        "emit step cannot be terminal; terminal step must be end".to_string(),
                    ));
                }
                EvalStepV0 {
                    step_id,
                    op: "emit".to_string(),
                    path: None,
                    value: None,
                    emission: Some(emission.clone()),
                    capability_id: None,
                    operation: None,
                    args: None,
                    next_step_id,
                    obligations: None,
                    policy: None,
                    on_timeout: None,
                    rules: None,
                    rules_sexpr: None,
                    routes: None,
                }
            }
            WorkflowArtifactStepV0::Request {
                capability_id,
                operation,
                args,
                ..
            } => {
                if next_step_id.is_none() {
                    return Err(ArtifactCompileFailure::single(
                        FAILURE_CODE_STEP_CONTRACT,
                        "request step cannot be terminal; terminal step must be end".to_string(),
                    ));
                }
                EvalStepV0 {
                    step_id,
                    op: "request".to_string(),
                    path: None,
                    value: None,
                    emission: None,
                    capability_id: Some(capability_id.clone()),
                    operation: Some(operation.clone()),
                    args: Some(args.clone()),
                    next_step_id,
                    obligations: None,
                    policy: None,
                    on_timeout: None,
                    rules: None,
                    rules_sexpr: None,
                    routes: None,
                }
            }
            WorkflowArtifactStepV0::JoinObligationsV0 { source, policy, .. } => {
                if next_step_id.is_none() {
                    return Err(ArtifactCompileFailure::single(
                        FAILURE_CODE_STEP_CONTRACT,
                        "join_obligations_v0 step cannot be terminal; terminal step must be end"
                            .to_string(),
                    ));
                }
                let obligations = match source {
                    JoinObligationsSourceV0::Inline(obligations) => obligations.clone(),
                    JoinObligationsSourceV0::WaitForSteps(step_refs) => {
                        let mut obligations = Vec::with_capacity(step_refs.len());
                        for step_ref in step_refs {
                            let target_index = resolve_route_target_index(
                                step_ref,
                                &step_name_to_index,
                                step_count,
                            )
                            .map_err(|issue| {
                                ArtifactCompileFailure::single(
                                    FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH,
                                    format!("join_obligations_v0 wait_for_steps {issue}"),
                                )
                            })?;
                            let target_step_id = derived_step_id(target_index).ok_or_else(|| {
                                ArtifactCompileFailure::single(
                                    FAILURE_CODE_STEP_IDENTITY,
                                    format!(
                                        "join_obligations_v0 wait_for_steps resolved to invalid target index {target_index}"
                                    ),
                                )
                            })?;
                            let Some(request_hash) = request_hash_by_step_index.get(&target_index)
                            else {
                                if request_args_is_dynamic_by_step_index
                                    .get(&target_index)
                                    .copied()
                                    .unwrap_or(false)
                                {
                                    return Err(ArtifactCompileFailure::single(
                                        FAILURE_CODE_STEP_CONTRACT,
                                        format!(
                                            "join_obligations_v0 wait_for_steps target '{target_step_id}' uses request args derived from state expressions, which cannot be precomputed for deterministic join obligations"
                                        ),
                                    ));
                                }
                                return Err(ArtifactCompileFailure::single(
                                    FAILURE_CODE_STEP_CONTRACT,
                                    format!(
                                        "join_obligations_v0 wait_for_steps target '{target_step_id}' must resolve to a request step"
                                    ),
                                ));
                            };
                            obligations.push(receipt_valid_obligation(request_hash));
                        }
                        obligations
                    }
                };

                EvalStepV0 {
                    step_id,
                    op: "join_obligations_v0".to_string(),
                    path: None,
                    value: None,
                    emission: None,
                    capability_id: None,
                    operation: None,
                    args: None,
                    next_step_id,
                    obligations: Some(obligations),
                    policy: policy.as_evalir_value(),
                    on_timeout: None,
                    rules: None,
                    rules_sexpr: None,
                    routes: None,
                }
            }
            WorkflowArtifactStepV0::End { .. } => {
                end_step_count += 1;
                if index + 1 != step_count {
                    return Err(ArtifactCompileFailure::single(
                        FAILURE_CODE_STEP_CONTRACT,
                        "end step must be the final step".to_string(),
                    ));
                }
                EvalStepV0 {
                    step_id,
                    op: "end".to_string(),
                    path: None,
                    value: None,
                    emission: None,
                    capability_id: None,
                    operation: None,
                    args: None,
                    next_step_id: None,
                    obligations: None,
                    policy: None,
                    on_timeout: None,
                    rules: None,
                    rules_sexpr: None,
                    routes: None,
                }
            }
        };
        eval_steps.push(eval_step);
    }

    if end_step_count != 1 {
        return Err(ArtifactCompileFailure::single(
            FAILURE_CODE_STEP_CONTRACT,
            "artifact must contain exactly one end step".to_string(),
        ));
    }

    Ok(EvalIrV0 {
        format_id: EVAL_IR_FORMAT_ID.to_string(),
        ir_version: EVAL_IR_VERSION.to_string(),
        artifact_hash: Some(artifact_hash),
        entry_step_id: derived_step_id(0).expect("non-empty steps must yield S0001"),
        steps: eval_steps,
    })
}

fn derived_step_id(index: usize) -> Option<String> {
    if index >= MAX_DERIVED_STEP_COUNT {
        return None;
    }
    Some(format!("S{:04}", index + 1))
}

fn resolve_route_target_index(
    target_ref: &RouteTargetRefV0,
    step_name_to_index: &BTreeMap<String, usize>,
    step_count: usize,
) -> Result<usize, String> {
    match target_ref {
        RouteTargetRefV0::StepName(name) => step_name_to_index
            .get(name)
            .copied()
            .ok_or_else(|| format!("references unknown step name '{name}'")),
        RouteTargetRefV0::StepOrdinal(ordinal) => {
            if *ordinal == 0 || *ordinal > step_count {
                Err(format!(
                    "references out-of-range ordinal {ordinal} (valid range is 1..={step_count})"
                ))
            } else {
                Ok(ordinal - 1)
            }
        }
    }
}

fn compute_artifact_hash(value: &RuliaValue) -> Result<String, String> {
    let canonical_bytes = rulia::encode_canonical(value)
        .map_err(|err| format!("failed to canonicalize artifact: {err}"))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(&canonical_bytes))
    ))
}

fn receipt_valid_obligation(request_hash: &str) -> Value {
    let mut params = Map::new();
    params.insert(
        "request_hash".to_string(),
        Value::String(request_hash.to_string()),
    );

    let mut obligation = Map::new();
    obligation.insert(
        "format".to_string(),
        Value::String("rulia_obligation_v0".to_string()),
    );
    obligation.insert(
        "obligation_type".to_string(),
        Value::String("receipt_valid".to_string()),
    );
    obligation.insert("params".to_string(), Value::Object(params));
    Value::Object(obligation)
}

#[derive(Debug)]
struct StepIssue {
    failure_code: &'static str,
    message: String,
}

fn parse_step(value: &RuliaValue, index: usize) -> Result<WorkflowArtifactStepV0, StepIssue> {
    let entries =
        expect_map_entries(value, "step must be a map").map_err(StepIssue::state_invalid)?;

    let op_value = map_get_unique(entries, "op")
        .map_err(StepIssue::state_invalid)?
        .ok_or_else(|| StepIssue::step_contract("step must include op"))?;
    let op = keyword_or_string(op_value)
        .ok_or_else(|| StepIssue::state_invalid("step op must be keyword or string".to_string()))?;
    let op = normalize_key_name(op.as_str());

    match op.as_str() {
        "assign" => parse_assign_step(entries),
        "emit" => parse_emit_step(entries),
        "request" => parse_request_step(entries),
        "join_obligations_v0" => parse_join_obligations_step(entries),
        "end" => parse_end_step(entries, index),
        _ => Err(StepIssue::step_contract(format!(
            "unsupported step op '{op}' (allowed: assign|emit|request|join_obligations_v0|end)"
        ))),
    }
}

fn parse_assign_step(
    entries: &[(RuliaValue, RuliaValue)],
) -> Result<WorkflowArtifactStepV0, StepIssue> {
    let fields =
        strict_field_map_with_optional(entries, &["op", "path", "value"], &["name"], "assign step")
            .map_err(StepIssue::state_invalid)?;
    let name = parse_optional_step_name(&fields).map_err(StepIssue::step_contract)?;
    let path = expect_non_empty_string(
        fields
            .get("path")
            .expect("assign path must exist after strict field map"),
        "assign path must be a non-empty string",
    )
    .map_err(StepIssue::step_contract)?;
    let value = rulia_value_to_json(
        fields
            .get("value")
            .expect("assign value must exist after strict field map"),
    )
    .map_err(StepIssue::step_contract)?;
    Ok(WorkflowArtifactStepV0::Assign { name, path, value })
}

fn parse_emit_step(
    entries: &[(RuliaValue, RuliaValue)],
) -> Result<WorkflowArtifactStepV0, StepIssue> {
    let fields =
        strict_field_map_with_optional(entries, &["op", "emission"], &["name"], "emit step")
            .map_err(StepIssue::state_invalid)?;
    let name = parse_optional_step_name(&fields).map_err(StepIssue::step_contract)?;
    let emission = rulia_value_to_json(
        fields
            .get("emission")
            .expect("emit emission must exist after strict field map"),
    )
    .map_err(StepIssue::step_contract)?;
    Ok(WorkflowArtifactStepV0::Emit { name, emission })
}

fn parse_request_step(
    entries: &[(RuliaValue, RuliaValue)],
) -> Result<WorkflowArtifactStepV0, StepIssue> {
    let fields = strict_field_map_with_optional(
        entries,
        &["op", "capability_id", "operation", "args"],
        &["name"],
        "request step",
    )
    .map_err(StepIssue::state_invalid)?;
    let name = parse_optional_step_name(&fields).map_err(StepIssue::step_contract)?;
    let capability_id = expect_non_empty_string(
        fields
            .get("capability_id")
            .expect("request capability_id must exist after strict field map"),
        "request capability_id must be a non-empty string",
    )
    .map_err(StepIssue::step_contract)?;
    let operation = expect_non_empty_string(
        fields
            .get("operation")
            .expect("request operation must exist after strict field map"),
        "request operation must be a non-empty string",
    )
    .map_err(StepIssue::step_contract)?;
    let args = rulia_value_to_json(
        fields
            .get("args")
            .expect("request args must exist after strict field map"),
    )
    .map_err(StepIssue::step_contract)?;
    Ok(WorkflowArtifactStepV0::Request {
        name,
        capability_id,
        operation,
        args,
    })
}

fn parse_join_obligations_step(
    entries: &[(RuliaValue, RuliaValue)],
) -> Result<WorkflowArtifactStepV0, StepIssue> {
    let fields = strict_field_map_with_optional(
        entries,
        &["op"],
        &["name", "obligations", "wait_for_steps", "policy"],
        "join_obligations_v0 step",
    )
    .map_err(StepIssue::state_invalid)?;
    let name = parse_optional_step_name(&fields).map_err(StepIssue::step_contract)?;

    let obligations_value = fields.get("obligations");
    let wait_for_steps_value = fields.get("wait_for_steps");
    let source = match (obligations_value, wait_for_steps_value) {
        (Some(obligations_value), None) => {
            let obligation_values = expect_vector_values(
                obligations_value,
                "join_obligations_v0 obligations must be a non-empty vector",
            )
            .map_err(StepIssue::protocol_schema_mismatch)?;
            if obligation_values.is_empty() {
                return Err(StepIssue::protocol_schema_mismatch(
                    "join_obligations_v0 obligations must be a non-empty vector".to_string(),
                ));
            }
            let mut obligations = Vec::with_capacity(obligation_values.len());
            for obligation in obligation_values {
                obligations.push(
                    rulia_value_to_json(obligation).map_err(StepIssue::protocol_schema_mismatch)?,
                );
            }
            JoinObligationsSourceV0::Inline(obligations)
        }
        (None, Some(wait_for_steps_value)) => {
            let ref_values = expect_vector_values(
                wait_for_steps_value,
                "join_obligations_v0 wait_for_steps must be a non-empty vector",
            )
            .map_err(StepIssue::protocol_schema_mismatch)?;
            if ref_values.is_empty() {
                return Err(StepIssue::protocol_schema_mismatch(
                    "join_obligations_v0 wait_for_steps must be a non-empty vector".to_string(),
                ));
            }
            let mut refs = Vec::with_capacity(ref_values.len());
            for step_ref in ref_values {
                refs.push(
                    parse_wait_for_step_ref(step_ref)
                        .map_err(StepIssue::protocol_schema_mismatch)?,
                );
            }
            JoinObligationsSourceV0::WaitForSteps(refs)
        }
        (Some(_), Some(_)) => {
            return Err(StepIssue::protocol_schema_mismatch(
                "join_obligations_v0 step must include exactly one of obligations or wait_for_steps"
                    .to_string(),
            ));
        }
        (None, None) => {
            return Err(StepIssue::protocol_schema_mismatch(
                "join_obligations_v0 step must include exactly one of obligations or wait_for_steps"
                    .to_string(),
            ));
        }
    };

    let policy = parse_join_policy(fields.get("policy").copied())?;

    Ok(WorkflowArtifactStepV0::JoinObligationsV0 {
        name,
        source,
        policy,
    })
}

fn parse_wait_for_step_ref(value: &RuliaValue) -> Result<RouteTargetRefV0, String> {
    match value {
        RuliaValue::String(name) if !name.trim().is_empty() => {
            Ok(RouteTargetRefV0::StepName(name.trim().to_string()))
        }
        RuliaValue::UInt(ordinal) => {
            let ordinal = usize::try_from(*ordinal).map_err(|_| {
                format!("wait_for_steps ordinal {ordinal} exceeds supported range")
            })?;
            if ordinal == 0 {
                return Err("wait_for_steps ordinal must be >= 1".to_string());
            }
            Ok(RouteTargetRefV0::StepOrdinal(ordinal))
        }
        RuliaValue::Int(ordinal) => {
            if *ordinal <= 0 {
                return Err("wait_for_steps ordinal must be >= 1".to_string());
            }
            let ordinal = usize::try_from(*ordinal).map_err(|_| {
                format!("wait_for_steps ordinal {ordinal} exceeds supported range")
            })?;
            Ok(RouteTargetRefV0::StepOrdinal(ordinal))
        }
        _ => Err(
            "join_obligations_v0 wait_for_steps entries must be non-empty step name strings or positive ordinals"
                .to_string(),
        ),
    }
}

fn parse_join_policy(value: Option<&RuliaValue>) -> Result<JoinPolicyV0, StepIssue> {
    let Some(value) = value else {
        return Ok(JoinPolicyV0::AllOf);
    };
    let policy = keyword_or_string(value).ok_or_else(|| {
        StepIssue::protocol_schema_mismatch(
            "join_obligations_v0 policy must be a string policy ('all_of' or 'any_of')".to_string(),
        )
    })?;
    match policy.trim() {
        "all_of" | "all-of" => Ok(JoinPolicyV0::AllOf),
        "any_of" | "any-of" => Ok(JoinPolicyV0::AnyOf),
        _ => Err(StepIssue::protocol_schema_mismatch(
            "join_obligations_v0 policy must be 'all_of' or 'any_of'".to_string(),
        )),
    }
}

fn parse_end_step(
    entries: &[(RuliaValue, RuliaValue)],
    _index: usize,
) -> Result<WorkflowArtifactStepV0, StepIssue> {
    let fields = strict_field_map_with_optional(entries, &["op"], &["name"], "end step")
        .map_err(StepIssue::state_invalid)?;
    let name = parse_optional_step_name(&fields).map_err(StepIssue::step_contract)?;
    Ok(WorkflowArtifactStepV0::End { name })
}

fn parse_optional_step_name(
    fields: &BTreeMap<String, &RuliaValue>,
) -> Result<Option<String>, String> {
    let Some(name_value) = fields.get("name") else {
        return Ok(None);
    };
    expect_non_empty_string(name_value, "step name must be a non-empty string").map(Some)
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

fn expect_vector_values<'a>(
    value: &'a RuliaValue,
    message: &str,
) -> Result<&'a [RuliaValue], String> {
    match value {
        RuliaValue::Vector(values) => Ok(values.as_slice()),
        _ => Err(message.to_string()),
    }
}

fn strict_field_map<'a>(
    entries: &'a [(RuliaValue, RuliaValue)],
    required_fields: &[&str],
    context: &str,
) -> Result<BTreeMap<String, &'a RuliaValue>, String> {
    strict_field_map_with_optional(entries, required_fields, &[], context)
}

fn strict_field_map_with_optional<'a>(
    entries: &'a [(RuliaValue, RuliaValue)],
    required_fields: &[&str],
    optional_fields: &[&str],
    context: &str,
) -> Result<BTreeMap<String, &'a RuliaValue>, String> {
    let allowed = required_fields
        .iter()
        .chain(optional_fields.iter())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut fields = BTreeMap::new();

    for (key, value) in entries {
        let field_name = map_key_name(key)
            .ok_or_else(|| format!("{context} keys must be keyword/string names"))?;
        if !allowed.contains(field_name.as_str()) {
            return Err(format!("{context} includes unknown field '{field_name}'"));
        }
        if fields.insert(field_name.clone(), value).is_some() {
            return Err(format!("{context} includes duplicate field '{field_name}'"));
        }
    }

    for required in required_fields {
        if !fields.contains_key(*required) {
            return Err(format!("{context} missing required field '{required}'"));
        }
    }
    Ok(fields)
}

fn map_get_unique<'a>(
    entries: &'a [(RuliaValue, RuliaValue)],
    field_name: &str,
) -> Result<Option<&'a RuliaValue>, String> {
    let mut value = None;
    for (key, candidate_value) in entries {
        let Some(candidate_name) = map_key_name(key) else {
            continue;
        };
        if candidate_name != field_name {
            continue;
        }
        if value.is_some() {
            return Err(format!("step includes duplicate field '{field_name}'"));
        }
        value = Some(candidate_value);
    }
    Ok(value)
}

fn map_key_name(key: &RuliaValue) -> Option<String> {
    match key {
        RuliaValue::Keyword(keyword) => {
            let raw = keyword.as_symbol().as_str();
            Some(normalize_key_name(raw.as_str()))
        }
        RuliaValue::String(value) => Some(normalize_key_name(value)),
        _ => None,
    }
}

fn normalize_key_name(value: &str) -> String {
    value.replace(['/', '-'], "_")
}

fn expect_non_empty_string(value: &RuliaValue, message: &str) -> Result<String, String> {
    match value {
        RuliaValue::String(inner) if !inner.trim().is_empty() => Ok(inner.clone()),
        _ => Err(message.to_string()),
    }
}

fn keyword_or_string(value: &RuliaValue) -> Option<String> {
    match value {
        RuliaValue::Keyword(keyword) => Some(keyword.as_symbol().as_str()),
        RuliaValue::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn rulia_value_to_json(value: &RuliaValue) -> Result<Value, String> {
    match value {
        RuliaValue::Nil => Ok(Value::Null),
        RuliaValue::Bool(boolean) => Ok(Value::Bool(*boolean)),
        RuliaValue::Int(number) => Ok(Value::Number(Number::from(*number))),
        RuliaValue::UInt(number) => Ok(Value::Number(Number::from(*number))),
        RuliaValue::Float32(number) => number_to_json(f64::from(number.into_inner())),
        RuliaValue::Float64(number) => number_to_json(number.into_inner()),
        RuliaValue::String(string) => Ok(Value::String(string.clone())),
        RuliaValue::Vector(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(rulia_value_to_json(item)?);
            }
            Ok(Value::Array(out))
        }
        RuliaValue::Map(entries) => {
            let mut canonical = BTreeMap::new();
            for (key, map_value) in entries {
                let Some(key_name) = map_key_name(key) else {
                    return Err("map keys must be keyword/string for JSON conversion".to_string());
                };
                let json_value = rulia_value_to_json(map_value)?;
                if canonical.insert(key_name.clone(), json_value).is_some() {
                    return Err(format!("duplicate JSON object key '{key_name}'"));
                }
            }
            let mut object = Map::new();
            for (key, json_value) in canonical {
                object.insert(key, json_value);
            }
            Ok(Value::Object(object))
        }
        _ => Err(format!(
            "value kind '{}' is unsupported in workflow artifact subset JSON payloads",
            value.kind()
        )),
    }
}

fn number_to_json(value: f64) -> Result<Value, String> {
    let Some(number) = Number::from_f64(value) else {
        return Err("float values must be finite".to_string());
    };
    Ok(Value::Number(number))
}

impl StepIssue {
    fn state_invalid(message: impl Into<String>) -> Self {
        Self {
            failure_code: FAILURE_CODE_STATE_INVALID,
            message: message.into(),
        }
    }

    fn step_contract(message: impl Into<String>) -> Self {
        Self {
            failure_code: FAILURE_CODE_STEP_CONTRACT,
            message: message.into(),
        }
    }

    fn protocol_schema_mismatch(message: impl Into<String>) -> Self {
        Self {
            failure_code: FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use rulia::{Keyword, Symbol, TaggedValue};
    use serde_json::json;

    use super::parse_and_compile_artifact_subset_v0;

    fn kw(name: &str) -> rulia::Value {
        rulia::Value::Keyword(Keyword::simple(name))
    }

    fn tagged_workflow_artifact_v0(value: rulia::Value) -> rulia::Value {
        rulia::Value::Tagged(TaggedValue::new(
            Symbol::simple("workflow_artifact_v0"),
            value,
        ))
    }

    fn root_with_steps(steps: Vec<rulia::Value>) -> rulia::Value {
        tagged_workflow_artifact_v0(rulia::Value::Map(vec![
            (kw("id"), rulia::Value::String("wf.test".to_string())),
            (kw("version"), rulia::Value::String("v0".to_string())),
            (kw("steps"), rulia::Value::Vector(steps)),
        ]))
    }

    fn fixture_path(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(path)
    }

    #[test]
    fn compiles_assign_emit_end_shape() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (kw("op"), kw("assign")),
                (kw("path"), rulia::Value::String("order.status".to_string())),
                (kw("value"), rulia::Value::String("active".to_string())),
            ]),
            rulia::Value::Map(vec![
                (kw("op"), kw("emit")),
                (
                    kw("emission"),
                    rulia::Value::Map(vec![
                        (kw("kind"), rulia::Value::String("audit".to_string())),
                        (
                            kw("event"),
                            rulia::Value::String("order_activated".to_string()),
                        ),
                    ]),
                ),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let eval_ir = parse_and_compile_artifact_subset_v0(&artifact).expect("compile artifact");
        assert_eq!(eval_ir.entry_step_id, "S0001");
        assert_eq!(eval_ir.steps.len(), 3);
        assert_eq!(eval_ir.steps[0].step_id, "S0001");
        assert_eq!(eval_ir.steps[0].op, "assign");
        assert_eq!(eval_ir.steps[0].next_step_id.as_deref(), Some("S0002"));
        assert_eq!(eval_ir.steps[1].op, "emit");
        assert_eq!(eval_ir.steps[2].op, "end");
    }

    #[test]
    fn compiles_request_with_deterministic_payload_order() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (kw("op"), kw("request")),
                (
                    kw("capability_id"),
                    rulia::Value::String("capability.approvals".to_string()),
                ),
                (kw("operation"), rulia::Value::String("submit".to_string())),
                (
                    kw("args"),
                    rulia::Value::Map(vec![
                        (kw("channel"), rulia::Value::String("email".to_string())),
                        (kw("amount"), rulia::Value::UInt(1250)),
                    ]),
                ),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let eval_ir = parse_and_compile_artifact_subset_v0(&artifact).expect("compile artifact");
        assert_eq!(eval_ir.steps[0].op, "request");
        assert_eq!(
            eval_ir.steps[0].args,
            Some(json!({
                "amount": 1250,
                "channel": "email",
            }))
        );
    }

    #[test]
    fn compiles_assign_and_request_with_expression_payloads() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (kw("op"), kw("assign")),
                (
                    kw("path"),
                    rulia::Value::String("order.risk_class".to_string()),
                ),
                (
                    kw("value"),
                    rulia::Value::Map(vec![
                        (
                            rulia::Value::String("$fn".to_string()),
                            rulia::Value::String("state".to_string()),
                        ),
                        (
                            kw("body"),
                            rulia::Value::Map(vec![
                                (
                                    rulia::Value::String("$expr".to_string()),
                                    rulia::Value::String("state_get".to_string()),
                                ),
                                (kw("path"), rulia::Value::String("order.amount".to_string())),
                            ]),
                        ),
                    ]),
                ),
            ]),
            rulia::Value::Map(vec![
                (kw("op"), kw("request")),
                (
                    kw("capability_id"),
                    rulia::Value::String("capability.approvals".to_string()),
                ),
                (kw("operation"), rulia::Value::String("submit".to_string())),
                (
                    kw("args"),
                    rulia::Value::Map(vec![
                        (
                            kw("amount"),
                            rulia::Value::Map(vec![
                                (
                                    rulia::Value::String("$expr".to_string()),
                                    rulia::Value::String("state_get".to_string()),
                                ),
                                (kw("path"), rulia::Value::String("order.amount".to_string())),
                            ]),
                        ),
                        (kw("channel"), rulia::Value::String("email".to_string())),
                    ]),
                ),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let eval_ir = parse_and_compile_artifact_subset_v0(&artifact).expect("compile artifact");
        assert_eq!(
            eval_ir.steps[0].value,
            Some(json!({
                "$fn": "state",
                "body": {
                    "$expr": "state_get",
                    "path": "order.amount"
                }
            }))
        );
        assert_eq!(
            eval_ir.steps[1].args,
            Some(json!({
                "amount": {
                    "$expr": "state_get",
                    "path": "order.amount"
                },
                "channel": "email"
            }))
        );
    }

    #[test]
    fn compiles_assign_with_if_expression_for_native_branch_logic() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (kw("op"), kw("assign")),
                (kw("path"), rulia::Value::String("order.status".to_string())),
                (
                    kw("value"),
                    rulia::Value::Map(vec![
                        (
                            rulia::Value::String("$expr".to_string()),
                            rulia::Value::String("if".to_string()),
                        ),
                        (
                            kw("cond"),
                            rulia::Value::Map(vec![
                                (
                                    rulia::Value::String("$expr".to_string()),
                                    rulia::Value::String(">=".to_string()),
                                ),
                                (
                                    kw("left"),
                                    rulia::Value::Map(vec![
                                        (
                                            rulia::Value::String("$expr".to_string()),
                                            rulia::Value::String("state_get".to_string()),
                                        ),
                                        (
                                            kw("path"),
                                            rulia::Value::String("order.amount".to_string()),
                                        ),
                                    ]),
                                ),
                                (kw("right"), rulia::Value::Int(80)),
                            ]),
                        ),
                        (kw("then"), rulia::Value::String("open_case".to_string())),
                        (kw("else"), rulia::Value::String("wait_docs".to_string())),
                    ]),
                ),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let eval_ir = parse_and_compile_artifact_subset_v0(&artifact).expect("compile artifact");
        assert_eq!(eval_ir.steps[0].op, "assign");
        assert_eq!(
            eval_ir.steps[0].value,
            Some(json!({
                "$expr": "if",
                "cond": {
                    "$expr": ">=",
                    "left": {
                        "$expr": "state_get",
                        "path": "order.amount"
                    },
                    "right": 80
                },
                "then": "open_case",
                "else": "wait_docs"
            }))
        );
    }

    #[test]
    fn join_wait_for_steps_rejects_dynamic_request_args() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (
                    kw("name"),
                    rulia::Value::String("approval_request".to_string()),
                ),
                (kw("op"), kw("request")),
                (
                    kw("capability_id"),
                    rulia::Value::String("capability.approvals".to_string()),
                ),
                (kw("operation"), rulia::Value::String("submit".to_string())),
                (
                    kw("args"),
                    rulia::Value::Map(vec![
                        (
                            kw("amount"),
                            rulia::Value::Map(vec![
                                (
                                    rulia::Value::String("$expr".to_string()),
                                    rulia::Value::String("state_get".to_string()),
                                ),
                                (kw("path"), rulia::Value::String("order.amount".to_string())),
                            ]),
                        ),
                        (kw("channel"), rulia::Value::String("email".to_string())),
                    ]),
                ),
            ]),
            rulia::Value::Map(vec![
                (kw("op"), kw("join_obligations_v0")),
                (
                    kw("wait_for_steps"),
                    rulia::Value::Vector(vec![rulia::Value::String(
                        "approval_request".to_string(),
                    )]),
                ),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let error =
            parse_and_compile_artifact_subset_v0(&artifact).expect_err("artifact should fail");
        assert_eq!(error.failure_codes, vec!["EVAL.E_STEP_CONTRACT"]);
        assert!(error.issues[0].contains("derived from state expressions"));
    }

    #[test]
    fn rejects_legacy_choose_rules_v0_steps_with_contract_error() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (kw("name"), rulia::Value::String("route_start".to_string())),
                (kw("op"), kw("choose_rules_v0")),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let error =
            parse_and_compile_artifact_subset_v0(&artifact).expect_err("artifact should fail");
        assert_eq!(error.failure_codes, vec!["EVAL.E_STEP_CONTRACT"]);
        assert!(error.issues[0].contains("unsupported step op 'choose_rules_v0'"));
    }

    #[test]
    fn rejects_non_terminal_end_step() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let error =
            parse_and_compile_artifact_subset_v0(&artifact).expect_err("artifact should fail");
        assert_eq!(error.failure_codes, vec!["EVAL.E_STEP_CONTRACT"]);
    }

    #[test]
    fn rejects_join_step_with_invalid_one_of_payload() {
        let artifact = root_with_steps(vec![
            rulia::Value::Map(vec![
                (kw("op"), kw("join_obligations_v0")),
                (
                    kw("obligations"),
                    rulia::Value::Vector(vec![rulia::Value::Map(vec![
                        (
                            kw("format"),
                            rulia::Value::String("rulia_obligation_v0".to_string()),
                        ),
                        (
                            kw("obligation_type"),
                            rulia::Value::String("receipt_valid".to_string()),
                        ),
                        (
                            kw("params"),
                            rulia::Value::Map(vec![(
                                kw("request_hash"),
                                rulia::Value::String(
                                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                        .to_string(),
                                ),
                            )]),
                        ),
                    ])]),
                ),
                (
                    kw("wait_for_steps"),
                    rulia::Value::Vector(vec![rulia::Value::String(
                        "approval_request".to_string(),
                    )]),
                ),
            ]),
            rulia::Value::Map(vec![(kw("op"), kw("end"))]),
        ]);

        let error =
            parse_and_compile_artifact_subset_v0(&artifact).expect_err("artifact should fail");
        assert_eq!(error.failure_codes, vec!["PROTOCOL.schema_mismatch"]);
    }

    #[test]
    fn legacy_join_fixture_is_compatibility_gated_on_choose_rules_v0() {
        let artifact_path =
            fixture_path("workflow_artifact_v0_subset/artifact_join_wait_for_request.rulia.bin");
        let artifact_bytes = fs::read(&artifact_path).expect("read artifact fixture");
        let artifact_value = rulia::decode_value(&artifact_bytes).expect("decode artifact fixture");

        let error = parse_and_compile_artifact_subset_v0(&artifact_value)
            .expect_err("artifact should fail");
        assert_eq!(error.failure_codes, vec!["EVAL.E_STEP_CONTRACT"]);
        assert!(error.issues[0].contains("unsupported step op 'choose_rules_v0'"));
    }

    #[test]
    fn run_vectors_l2_artifact_pipeline_join_fixture_is_compatibility_gated() {
        let vectorset_path =
            fixture_path("vectorset_v0_run_vectors_l2_artifact_pipeline_join_obligations.json");
        let vectorset = crate::portable_workflow_vectorset::load_vectorset_v0(
            vectorset_path
                .to_str()
                .expect("vectorset path should be valid UTF-8"),
        )
        .expect("load vectorset fixture");
        let vectorset_directory = vectorset_path
            .parent()
            .expect("vectorset fixture should have a parent directory");
        let vector = vectorset
            .vectors
            .iter()
            .find(|candidate| candidate.id == "V0-219")
            .expect("vectorset should contain V0-219");

        let actual = crate::run_vector_l2_eval(vector, vectorset_directory);
        assert_eq!(actual.verdict, crate::Verdict::Fail);
        assert_eq!(actual.failure_codes, vec!["EVAL.E_STEP_CONTRACT"]);
        assert!(actual.eval_result.is_none());
    }
}
