use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use rulia::{Keyword, Value as RuliaCanonicalValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::portable_workflow_request_identity_v0::{
    compute_args_hash_v0, compute_request_key_v0, RequestSeedV0 as RequestIdentitySeedV0,
    REQUEST_ORDINAL_BASE_V0,
};

const EVAL_IR_FORMAT_ID: &str = "portable_workflow.eval_ir.v0";
const EVAL_IR_VERSION: &str = "v0";
const FAILURE_CODE_STEP_IDENTITY: &str = "EVAL.E_STEP_IDENTITY";
const FAILURE_CODE_STATE_INVALID: &str = "EVAL.E_STATE_INVALID";
const FAILURE_CODE_STEP_CONTRACT: &str = "EVAL.E_STEP_CONTRACT";
const FAILURE_CODE_REQUEST_CANONICALIZATION: &str = "EVAL.E_REQUEST_CANONICALIZATION";
const FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH: &str = "PROTOCOL.schema_mismatch";
const FAILURE_CODE_UNBOUND_VAR: &str = "EVAL.unbound_var";
const FAILURE_CODE_TYPE_MISMATCH: &str = "EVAL.type_mismatch";
const FAILURE_CODE_FORBIDDEN_FEATURE: &str = "EVAL.forbidden_feature";
const FAILURE_CODE_NO_MATCH: &str = "EVAL.no_match";
const FAILURE_CODE_AMBIGUOUS_MATCH: &str = "EVAL.ambiguous_match";
const OBLIGATION_TYPE_RECEIPT_VALID: &str = "receipt_valid";
const MAX_RULES_SEXPR_BYTES: usize = 64 * 1024;
const MAX_RULES_SEXPR_TOKENS: usize = 20_000;
const MAX_RULES_SEXPR_FACTS: usize = 1_000;
const MAX_RULES_SEXPR_RULES: usize = 1_000;
const MAX_RULES_SEXPR_BODY_TERMS_PER_RULE: usize = 100;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct EvalIrV0 {
    pub(crate) format_id: String,
    pub(crate) ir_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_hash: Option<String>,
    pub(crate) entry_step_id: String,
    pub(crate) steps: Vec<EvalStepV0>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct EvalStepV0 {
    pub(crate) step_id: String,
    #[serde(alias = "kind")]
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<Value>,
    #[serde(default)]
    pub(crate) emission: Option<Value>,
    #[serde(default)]
    pub(crate) capability_id: Option<String>,
    #[serde(default)]
    pub(crate) operation: Option<String>,
    #[serde(default)]
    pub(crate) args: Option<Value>,
    #[serde(default)]
    pub(crate) next_step_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) obligations: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) on_timeout: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "rules_program"
    )]
    pub(crate) rules: Option<RulesProgramV0>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rules_sexpr: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) routes: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RulesProgramV0 {
    #[serde(default)]
    pub(crate) facts: Vec<Value>,
    #[serde(default)]
    pub(crate) rules: Vec<RulesRuleV0>,
    pub(crate) query: Value,
    #[serde(default)]
    pub(crate) selection: Option<String>,
    #[serde(default)]
    pub(crate) on_no_match: Option<Value>,
    #[serde(default)]
    pub(crate) on_ambiguous: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RulesRuleV0 {
    pub(crate) head: Value,
    #[serde(default)]
    pub(crate) body: Vec<Value>,
}

#[derive(Debug, Clone)]
pub(crate) struct EvalRunInputV0 {
    pub(crate) eval_ir: EvalIrV0,
    pub(crate) initial_state: Value,
    pub(crate) history_prefix: Option<Value>,
    pub(crate) gamma_core: Option<Value>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvalControlV0 {
    Continue,
    Suspend,
    End,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EvalRunResultV0 {
    pub(crate) control: EvalControlV0,
    pub(crate) state_out: Value,
    pub(crate) emissions: Vec<Value>,
    pub(crate) requests: Vec<EvalRequestV0>,
    pub(crate) obligations: Vec<EvalObligationV0>,
    pub(crate) errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EvalRequestV0 {
    pub(crate) request_ordinal: u64,
    pub(crate) request_id: String,
    pub(crate) capability_id: String,
    pub(crate) operation: String,
    pub(crate) args: Value,
    pub(crate) cause: EvalRequestCauseV0,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EvalRequestCauseV0 {
    pub(crate) artifact_id: String,
    pub(crate) step_id: String,
    pub(crate) request_ordinal: u64,
    pub(crate) history_cursor: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EvalObligationV0 {
    pub(crate) obligation_id: String,
    pub(crate) obligation_type: String,
    pub(crate) satisfaction_ref: String,
}

#[derive(Debug, Serialize)]
struct ObligationSeedV0<'a> {
    artifact_id: &'a str,
    step_id: &'a str,
    request_id: &'a str,
    obligation_type: &'a str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum JoinPolicyV0 {
    AllOf,
    AnyOf,
}

pub(crate) fn parse_eval_run_input_v0(
    eval_ir_json: &str,
    initial_state_json: &str,
    history_prefix_json: Option<&str>,
    gamma_core_json: Option<&str>,
) -> Result<EvalRunInputV0, Vec<String>> {
    let mut errors = Vec::new();

    let eval_ir = match serde_json::from_str::<EvalIrV0>(eval_ir_json) {
        Ok(eval_ir) => Some(eval_ir),
        Err(_) => {
            errors.push(FAILURE_CODE_STATE_INVALID.to_string());
            None
        }
    };

    let initial_state = match serde_json::from_str::<Value>(initial_state_json) {
        Ok(initial_state) => Some(initial_state),
        Err(_) => {
            errors.push(FAILURE_CODE_STATE_INVALID.to_string());
            None
        }
    };

    let history_prefix = match history_prefix_json {
        Some(raw) => match serde_json::from_str::<Value>(raw) {
            Ok(value) => Some(Some(value)),
            Err(_) => {
                errors.push(FAILURE_CODE_STATE_INVALID.to_string());
                None
            }
        },
        None => Some(None),
    };

    let gamma_core = match gamma_core_json {
        Some(raw) => match serde_json::from_str::<Value>(raw) {
            Ok(value) => Some(Some(value)),
            Err(_) => {
                errors.push(FAILURE_CODE_STATE_INVALID.to_string());
                None
            }
        },
        None => Some(None),
    };

    if !errors.is_empty() {
        return Err(super::order_failure_codes(errors));
    }

    Ok(EvalRunInputV0 {
        eval_ir: eval_ir.expect("eval_ir is present after parse success"),
        initial_state: initial_state.expect("initial_state is present after parse success"),
        history_prefix: history_prefix.expect("history_prefix is present after parse success"),
        gamma_core: gamma_core.expect("gamma_core is present after parse success"),
    })
}

pub(crate) fn evaluate_eval_ir_v0(input: EvalRunInputV0) -> EvalRunResultV0 {
    let mut result = EvalRunResultV0 {
        control: EvalControlV0::Continue,
        state_out: input.initial_state,
        emissions: Vec::new(),
        requests: Vec::new(),
        obligations: Vec::new(),
        errors: Vec::new(),
    };

    let validation_errors = validate_eval_ir_v0(&input.eval_ir);
    if !validation_errors.is_empty() {
        result.control = EvalControlV0::Error;
        result.errors = super::order_failure_codes(validation_errors);
        return result;
    }

    let step_index: BTreeMap<_, _> = input
        .eval_ir
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step))
        .collect();

    let artifact_hash = match input.eval_ir.artifact_hash.clone() {
        Some(artifact_hash) => artifact_hash,
        None => match digest_json(&input.eval_ir) {
            Ok(artifact_hash) => artifact_hash,
            Err(_) => {
                result.control = EvalControlV0::Error;
                result
                    .errors
                    .push(FAILURE_CODE_REQUEST_CANONICALIZATION.to_string());
                result.errors = super::order_failure_codes(result.errors);
                return result;
            }
        },
    };

    let history_cursor = history_cursor_from_prefix(input.history_prefix.as_ref());
    let max_steps = max_steps_from_gamma_core(input.gamma_core.as_ref());
    let mut current_step_id = input.eval_ir.entry_step_id.clone();

    for _ in 0..max_steps {
        let Some(step) = step_index.get(current_step_id.as_str()) else {
            mark_eval_error(&mut result, FAILURE_CODE_STEP_IDENTITY);
            return result;
        };

        match step.op.as_str() {
            "assign" => {
                let path = match step.path.as_deref() {
                    Some(path) => path,
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };
                let value = match step.value.clone() {
                    Some(value) => value,
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };
                let value = match super::portable_workflow_kernel_expression_v0::resolve_payload_against_state_json(
                    &value,
                    &result.state_out,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };

                if apply_assign(&mut result.state_out, path, value).is_err() {
                    mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                    return result;
                }

                current_step_id = match step.next_step_id.as_ref() {
                    Some(next_step_id) => next_step_id.clone(),
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_IDENTITY);
                        return result;
                    }
                };
            }
            "emit" => {
                let emission = match step.emission.clone() {
                    Some(emission) => emission,
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };

                result.emissions.push(emission);
                current_step_id = match step.next_step_id.as_ref() {
                    Some(next_step_id) => next_step_id.clone(),
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_IDENTITY);
                        return result;
                    }
                };
            }
            "request" => {
                let capability_id = match step.capability_id.as_deref() {
                    Some(capability_id) => capability_id,
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };
                let operation = match step.operation.as_deref() {
                    Some(operation) => operation,
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };
                let args = match step.args.clone() {
                    Some(args) => args,
                    None => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };
                let args = match super::portable_workflow_kernel_expression_v0::resolve_payload_against_state_json(
                    &args,
                    &result.state_out,
                ) {
                    Ok(args) => args,
                    Err(_) => {
                        mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                        return result;
                    }
                };

                let request_ordinal = REQUEST_ORDINAL_BASE_V0;
                let args_hash = match compute_args_hash_v0(&args) {
                    Ok(args_hash) => args_hash,
                    Err(_) => {
                        mark_eval_error(&mut result, FAILURE_CODE_REQUEST_CANONICALIZATION);
                        return result;
                    }
                };
                let request_seed = RequestIdentitySeedV0 {
                    artifact_hash: artifact_hash.clone(),
                    step_id: step.step_id.clone(),
                    request_ordinal,
                    args_hash,
                    history_cursor: None,
                    process_id: None,
                };
                let request_id = match compute_request_key_v0(&request_seed) {
                    Ok(request_id) => request_id,
                    Err(_) => {
                        mark_eval_error(&mut result, FAILURE_CODE_REQUEST_CANONICALIZATION);
                        return result;
                    }
                };

                let obligation_seed = ObligationSeedV0 {
                    artifact_id: &artifact_hash,
                    step_id: &step.step_id,
                    request_id: &request_id,
                    obligation_type: OBLIGATION_TYPE_RECEIPT_VALID,
                };
                let obligation_id = match digest_json(&obligation_seed) {
                    Ok(obligation_id) => obligation_id,
                    Err(_) => {
                        mark_eval_error(&mut result, FAILURE_CODE_REQUEST_CANONICALIZATION);
                        return result;
                    }
                };

                result.requests.push(EvalRequestV0 {
                    request_ordinal,
                    request_id: request_id.clone(),
                    capability_id: capability_id.to_string(),
                    operation: operation.to_string(),
                    args,
                    cause: EvalRequestCauseV0 {
                        artifact_id: artifact_hash.clone(),
                        step_id: step.step_id.clone(),
                        request_ordinal,
                        history_cursor,
                    },
                });
                result.obligations.push(EvalObligationV0 {
                    obligation_id,
                    obligation_type: OBLIGATION_TYPE_RECEIPT_VALID.to_string(),
                    satisfaction_ref: request_id,
                });
                result.control = EvalControlV0::Suspend;
                return result;
            }
            "choose_rules_v0" => {
                let next_step_id = match evaluate_choose_rules_step(step) {
                    Ok(next_step_id) => next_step_id,
                    Err(failure_code) => {
                        mark_eval_error(&mut result, failure_code);
                        return result;
                    }
                };
                current_step_id = next_step_id;
            }
            "join_obligations_v0" => {
                let join_step = match parse_join_step_v0(step) {
                    Ok(join_step) => join_step,
                    Err(failure_code) => {
                        mark_eval_error(&mut result, failure_code);
                        return result;
                    }
                };
                let history_receipts =
                    match parse_evalir_history_receipts(input.history_prefix.as_ref()) {
                        Ok(receipts) => receipts,
                        Err(failure_code) => {
                            mark_eval_error(&mut result, failure_code);
                            return result;
                        }
                    };
                let trust_context = match parse_evalir_join_trust_context(input.gamma_core.as_ref())
                {
                    Ok(context) => context,
                    Err(failure_code) => {
                        mark_eval_error(&mut result, failure_code);
                        return result;
                    }
                };

                let aggregate_satisfied = match join_step.policy {
                    JoinPolicyV0::AllOf => join_step.obligations.iter().all(|request_hash| {
                        super::obligation_is_satisfied(
                            request_hash,
                            &history_receipts,
                            &trust_context,
                        )
                        .satisfied
                    }),
                    JoinPolicyV0::AnyOf => join_step.obligations.iter().any(|request_hash| {
                        super::obligation_is_satisfied(
                            request_hash,
                            &history_receipts,
                            &trust_context,
                        )
                        .satisfied
                    }),
                };

                if !aggregate_satisfied {
                    result.control = EvalControlV0::Suspend;
                    return result;
                }

                current_step_id = join_step.next_step_id;
            }
            "end" => {
                result.control = EvalControlV0::End;
                return result;
            }
            _ => {
                mark_eval_error(&mut result, FAILURE_CODE_STEP_CONTRACT);
                return result;
            }
        }
    }

    result
}

fn mark_eval_error(result: &mut EvalRunResultV0, code: &'static str) {
    result.control = EvalControlV0::Error;
    result.errors.push(code.to_string());
    result.errors = super::order_failure_codes(std::mem::take(&mut result.errors));
}

fn validate_eval_ir_v0(eval_ir: &EvalIrV0) -> Vec<String> {
    let mut errors = Vec::new();

    if eval_ir.format_id != EVAL_IR_FORMAT_ID {
        errors.push(FAILURE_CODE_STATE_INVALID.to_string());
    }
    if eval_ir.ir_version != EVAL_IR_VERSION {
        errors.push(FAILURE_CODE_STATE_INVALID.to_string());
    }
    if eval_ir.steps.is_empty() {
        errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
        return super::order_failure_codes(errors);
    }

    let mut step_ids = Vec::new();
    let mut seen_step_ids = BTreeSet::new();
    let mut end_count = 0usize;

    for step in &eval_ir.steps {
        step_ids.push(step.step_id.as_str());

        if !is_valid_step_id(&step.step_id) {
            errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
        }
        if !seen_step_ids.insert(step.step_id.clone()) {
            errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
        }

        if step.op == "end" {
            end_count += 1;
        }

        match step.op.as_str() {
            "assign" => {
                if step.path.as_deref().map(str::trim).unwrap_or("").is_empty() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if step.value.is_none() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if step.next_step_id.is_none() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
            }
            "emit" => {
                if step.emission.is_none() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if step.next_step_id.is_none() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
            }
            "request" => {
                if step
                    .capability_id
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if step
                    .operation
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if step.args.is_none() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if step.next_step_id.is_none() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
            }
            "choose_rules_v0" => {
                if step.next_step_id.is_some() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
                if let Some(routes) = step.routes.as_ref() {
                    if routes.is_empty() {
                        errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                    }
                } else {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }

                match compile_rules_program_from_step(step) {
                    Ok(_) => {}
                    Err(code) => errors.push(code.to_string()),
                }
            }
            "join_obligations_v0" => {
                if parse_join_step_v0(step).is_err() {
                    errors.push(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH.to_string());
                }
            }
            "end" => {
                if step.next_step_id.is_some() {
                    errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
                }
            }
            _ => {
                errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
            }
        }
    }

    if !step_ids.windows(2).all(|window| window[0] < window[1]) {
        errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
    }

    if let Some(first_step_id) = step_ids.first() {
        if eval_ir.entry_step_id != *first_step_id {
            errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
        }
    }

    if !seen_step_ids.contains(&eval_ir.entry_step_id) {
        errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
    }

    if end_count != 1 {
        errors.push(FAILURE_CODE_STEP_CONTRACT.to_string());
    }

    for step in &eval_ir.steps {
        let successors = match collect_successor_step_ids(step) {
            Ok(successors) => successors,
            Err(code) => {
                errors.push(code.to_string());
                continue;
            }
        };

        for next_step_id in successors {
            if !seen_step_ids.contains(&next_step_id) {
                errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
                continue;
            }
            if next_step_id <= step.step_id {
                errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
            }
        }
    }

    let step_index: BTreeMap<_, _> = eval_ir
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step))
        .collect();
    let mut visited = BTreeSet::new();
    let mut frontier = vec![eval_ir.entry_step_id.clone()];

    while let Some(step_id) = frontier.pop() {
        if !visited.insert(step_id.clone()) {
            continue;
        }

        let Some(step) = step_index.get(step_id.as_str()) else {
            errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
            continue;
        };

        let mut successors = match collect_successor_step_ids(step) {
            Ok(successors) => successors,
            Err(code) => {
                errors.push(code.to_string());
                continue;
            }
        };
        successors.reverse();
        for successor in successors {
            if !visited.contains(&successor) {
                frontier.push(successor);
            }
        }
    }

    if visited.len() != eval_ir.steps.len() {
        errors.push(FAILURE_CODE_STEP_IDENTITY.to_string());
    }

    super::order_failure_codes(errors)
}

fn is_valid_step_id(step_id: &str) -> bool {
    step_id.len() == 5
        && step_id.as_bytes()[0] == b'S'
        && step_id.as_bytes()[1..]
            .iter()
            .all(|byte| byte.is_ascii_digit())
}

fn collect_successor_step_ids(step: &EvalStepV0) -> Result<Vec<String>, &'static str> {
    match step.op.as_str() {
        "assign" | "emit" | "request" => step
            .next_step_id
            .as_ref()
            .map(|next| vec![next.clone()])
            .ok_or(FAILURE_CODE_STEP_CONTRACT),
        "join_obligations_v0" => step
            .next_step_id
            .as_ref()
            .map(|next| vec![next.clone()])
            .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
        "choose_rules_v0" => {
            let routes = step.routes.as_ref().ok_or(FAILURE_CODE_STEP_CONTRACT)?;
            if routes.is_empty() {
                return Err(FAILURE_CODE_STEP_CONTRACT);
            }
            let mut successors = routes.values().cloned().collect::<Vec<_>>();
            successors.sort();
            successors.dedup();
            Ok(successors)
        }
        "end" => Ok(Vec::new()),
        _ => Err(FAILURE_CODE_STEP_CONTRACT),
    }
}

#[derive(Debug, Clone)]
struct ParsedJoinStepV0 {
    obligations: Vec<String>,
    policy: JoinPolicyV0,
    next_step_id: String,
}

fn parse_join_step_v0(step: &EvalStepV0) -> Result<ParsedJoinStepV0, &'static str> {
    let obligations_value = step
        .obligations
        .as_ref()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    if obligations_value.is_empty() {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let mut obligations = Vec::with_capacity(obligations_value.len());
    for obligation in obligations_value {
        obligations.push(parse_join_obligation_request_hash(obligation)?);
    }
    let policy = parse_join_policy_v0(step.policy.as_deref())?;
    if step.on_timeout.is_some() {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    let next_step_id = step
        .next_step_id
        .clone()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;

    Ok(ParsedJoinStepV0 {
        obligations,
        policy,
        next_step_id,
    })
}

fn parse_join_policy_v0(policy: Option<&str>) -> Result<JoinPolicyV0, &'static str> {
    let Some(policy) = policy else {
        return Ok(JoinPolicyV0::AllOf);
    };
    match policy.trim().trim_start_matches(':') {
        "all_of" => Ok(JoinPolicyV0::AllOf),
        "any_of" => Ok(JoinPolicyV0::AnyOf),
        _ => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_join_obligation_request_hash(obligation: &Value) -> Result<String, &'static str> {
    let obligation_entries = obligation
        .as_object()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;

    let format = obligation_entries
        .get("format")
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    let normalized_format = format
        .trim_start_matches(':')
        .replace(['/', '-'], "_")
        .to_ascii_lowercase();
    if normalized_format != "rulia_obligation_v0" {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let obligation_type = obligation_entries
        .get("obligation_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .map(|value| value.trim_start_matches(':'))
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    if obligation_type != OBLIGATION_TYPE_RECEIPT_VALID {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let params = obligation_entries
        .get("params")
        .and_then(Value::as_object)
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    let request_hash_value = params
        .get("request_hash")
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    parse_json_digest(request_hash_value).ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)
}

fn parse_json_digest(value: &Value) -> Option<String> {
    match value {
        Value::String(raw) => {
            let (algorithm_name, hex) = raw.trim().split_once(':')?;
            let algorithm =
                super::parse_hash_algorithm(algorithm_name.trim().trim_start_matches(':'))?;
            if !super::is_valid_digest_hex(hex) {
                return None;
            }
            Some(format!(
                "{}:{}",
                algorithm.as_str(),
                hex.to_ascii_lowercase()
            ))
        }
        Value::Object(entries) => {
            let algorithm_name = entries
                .get("alg")
                .or_else(|| entries.get("algorithm"))
                .and_then(Value::as_str)?
                .trim()
                .trim_start_matches(':');
            let algorithm = super::parse_hash_algorithm(algorithm_name)?;
            let hex = entries.get("hex").and_then(Value::as_str)?.trim();
            if !super::is_valid_digest_hex(hex) {
                return None;
            }
            Some(format!(
                "{}:{}",
                algorithm.as_str(),
                hex.to_ascii_lowercase()
            ))
        }
        _ => None,
    }
}

fn parse_evalir_history_receipts(
    history_prefix: Option<&Value>,
) -> Result<Vec<super::ObligationHistoryReceiptV0>, &'static str> {
    let Some(history_prefix) = history_prefix else {
        return Ok(Vec::new());
    };
    let Some(items_value) = history_prefix.get("items") else {
        return Ok(Vec::new());
    };
    let items = items_value
        .as_array()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;

    let mut receipts = Vec::new();
    for (index, item) in items.iter().enumerate() {
        if let Some(receipt) = parse_evalir_history_receipt(item, index)? {
            receipts.push(receipt);
        }
    }

    Ok(receipts)
}

fn parse_evalir_history_receipt(
    item: &Value,
    index: usize,
) -> Result<Option<super::ObligationHistoryReceiptV0>, &'static str> {
    let item_entries = item
        .as_object()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;

    let receipt_value = if let Some(receipt) = item_entries.get("receipt") {
        receipt
    } else if item_entries.contains_key("request_hash") {
        item
    } else {
        return Ok(None);
    };
    let receipt_entries = receipt_value
        .as_object()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    let request_hash = parse_json_digest(
        receipt_entries
            .get("request_hash")
            .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?,
    )
    .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    let signer_key_id = receipt_entries
        .get("signer_key_id")
        .and_then(Value::as_str)
        .or_else(|| {
            receipt_entries
                .get("attestation")
                .and_then(Value::as_object)
                .and_then(|attestation| attestation.get("signer_key_id"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let signature_valid = receipt_entries
        .get("signature_valid")
        .and_then(Value::as_bool)
        .or_else(|| {
            receipt_entries
                .get("attestation")
                .and_then(Value::as_object)
                .and_then(|attestation| attestation.get("signature_valid"))
                .and_then(Value::as_bool)
        });

    Ok(Some(super::ObligationHistoryReceiptV0 {
        history_index: index as u64,
        source_path: format!("history_prefix.items[{index}]"),
        canonical_receipt_hash: digest_json(receipt_value)
            .map_err(|_| FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?,
        request_hash,
        signer_key_id,
        signature_valid,
    }))
}

fn parse_evalir_join_trust_context(
    gamma_core: Option<&Value>,
) -> Result<super::ObligationTrustContextV0, &'static str> {
    let Some(gamma_core) = gamma_core else {
        return Ok(super::ObligationTrustContextV0 {
            trusted_signer_keys: None,
        });
    };

    // Deterministic strategy for M8.2: consume trust anchors only from explicit signer-key
    // arrays in `gamma_core`. If none are present, fall back to unsigned/hash-only checks.
    let signer_keys = gamma_core
        .get("trusted_signer_keys")
        .or_else(|| gamma_core.get("trust_signer_keys"))
        .or_else(|| {
            gamma_core
                .get("trust")
                .and_then(Value::as_object)
                .and_then(|trust| trust.get("trusted_signer_keys"))
        })
        .or_else(|| {
            gamma_core
                .get("trust")
                .and_then(Value::as_object)
                .and_then(|trust| trust.get("signer_keys"))
        });

    match signer_keys {
        None => Ok(super::ObligationTrustContextV0 {
            trusted_signer_keys: None,
        }),
        Some(value) => {
            let keys = value
                .as_array()
                .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .map(str::trim)
                        .filter(|candidate| !candidate.is_empty())
                        .map(str::to_string)
                        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;

            Ok(super::ObligationTrustContextV0 {
                trusted_signer_keys: Some(keys),
            })
        }
    }
}

fn apply_assign(state: &mut Value, path: &str, value: Value) -> Result<(), ()> {
    let segments = path.split('.').map(str::trim).collect::<Vec<_>>();

    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(());
    }

    // v0 assign semantics: dot-path object write where missing/non-object intermediates
    // are replaced with empty objects before writing the leaf value.
    assign_segments(state, &segments, value);
    Ok(())
}

fn assign_segments(state: &mut Value, segments: &[&str], value: Value) {
    if segments.len() == 1 {
        if !state.is_object() {
            *state = Value::Object(Map::new());
        }
        if let Value::Object(map) = state {
            map.insert(segments[0].to_string(), value);
        }
        return;
    }

    if !state.is_object() {
        *state = Value::Object(Map::new());
    }

    let next = match state {
        Value::Object(map) => map
            .entry(segments[0].to_string())
            .or_insert_with(|| Value::Object(Map::new())),
        _ => unreachable!(),
    };

    if !next.is_object() {
        *next = Value::Object(Map::new());
    }

    assign_segments(next, &segments[1..], value);
}

fn history_cursor_from_prefix(history_prefix: Option<&Value>) -> i64 {
    history_prefix
        .and_then(|prefix| prefix.get("cursor"))
        .and_then(|cursor| cursor.as_i64())
        .unwrap_or(-1)
}

fn max_steps_from_gamma_core(gamma_core: Option<&Value>) -> usize {
    let from_gamma = gamma_core
        .and_then(|gamma| gamma.get("max_steps"))
        .and_then(|value| value.as_u64())
        .map(|value| value as usize)
        .filter(|value| *value > 0);

    // Deterministic default batch limit until policy wiring is added in M4.3.
    from_gamma.unwrap_or(10)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let canonical_bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(&canonical_bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

#[derive(Debug, Clone)]
enum RulesSExprNode {
    List(Vec<RulesSExprNode>),
    Token(String),
    String(String),
    Number(String),
    Bool(bool),
    Variable(String),
}

struct RulesSExprParser<'a> {
    input: &'a [u8],
    cursor: usize,
    token_count: usize,
}

impl<'a> RulesSExprParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            cursor: 0,
            token_count: 0,
        }
    }

    fn parse_program(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.skip_insignificant();
        let node = self.parse_expr()?;
        self.skip_insignificant();
        if self.cursor != self.input.len() {
            return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
        }
        Ok(node)
    }

    fn parse_expr(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.skip_insignificant();
        let Some(byte) = self.peek() else {
            return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
        };

        match byte {
            b'(' => self.parse_list(),
            b'"' => self.parse_string(),
            b')' => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
            _ => self.parse_atom(),
        }
    }

    fn parse_list(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.consume(b'(')?;
        self.record_token()?;
        let mut items = Vec::new();

        loop {
            self.skip_insignificant();
            let Some(byte) = self.peek() else {
                return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
            };
            if byte == b')' {
                self.cursor += 1;
                self.record_token()?;
                break;
            }
            items.push(self.parse_expr()?);
        }

        Ok(RulesSExprNode::List(items))
    }

    fn parse_string(&mut self) -> Result<RulesSExprNode, &'static str> {
        self.consume(b'"')?;
        self.record_token()?;
        let mut parsed = String::new();

        loop {
            if self.cursor >= self.input.len() {
                return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
            }

            let remaining = std::str::from_utf8(&self.input[self.cursor..])
                .map_err(|_| FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
            let mut chars = remaining.chars();
            let current = chars.next().ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
            self.cursor += current.len_utf8();

            match current {
                '"' => break,
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
                    };
                    self.cursor += 1;
                    let translated = match escaped {
                        b'\\' => '\\',
                        b'"' => '"',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
                    };
                    parsed.push(translated);
                }
                _ => parsed.push(current),
            }
        }

        Ok(RulesSExprNode::String(parsed))
    }

    fn parse_atom(&mut self) -> Result<RulesSExprNode, &'static str> {
        let start = self.cursor;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'#') {
                break;
            }
            self.cursor += 1;
        }

        if self.cursor == start {
            return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
        }

        let token = std::str::from_utf8(&self.input[start..self.cursor])
            .map_err(|_| FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
        self.record_token()?;

        if token == "true" {
            return Ok(RulesSExprNode::Bool(true));
        }
        if token == "false" {
            return Ok(RulesSExprNode::Bool(false));
        }
        if let Some(variable_name) = parse_rules_sexpr_variable_token(token) {
            return Ok(RulesSExprNode::Variable(variable_name));
        }
        if is_rules_sexpr_number_token(token) {
            return Ok(RulesSExprNode::Number(token.to_string()));
        }
        Ok(RulesSExprNode::Token(token.to_string()))
    }

    fn skip_insignificant(&mut self) {
        loop {
            while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                self.cursor += 1;
            }
            if self.peek() == Some(b'#') {
                while let Some(byte) = self.peek() {
                    self.cursor += 1;
                    if byte == b'\n' {
                        break;
                    }
                }
                continue;
            }
            break;
        }
    }

    fn consume(&mut self, expected: u8) -> Result<(), &'static str> {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            Ok(())
        } else {
            Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)
        }
    }

    fn record_token(&mut self) -> Result<(), &'static str> {
        self.token_count = self
            .token_count
            .checked_add(1)
            .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
        if self.token_count > MAX_RULES_SEXPR_TOKENS {
            return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }
}

fn parse_rules_sexpr_variable_token(token: &str) -> Option<String> {
    let name = token.strip_prefix('?')?;
    if !is_rules_sexpr_identifier(name) {
        return None;
    }
    Some(name.to_string())
}

fn is_rules_sexpr_identifier(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_rules_sexpr_number_token(token: &str) -> bool {
    token.bytes().any(|byte| byte.is_ascii_digit()) && token.parse::<serde_json::Number>().is_ok()
}

fn parse_rules_sexpr_program(source: &str) -> Result<RulesProgramV0, &'static str> {
    if source.len() > MAX_RULES_SEXPR_BYTES {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let mut parser = RulesSExprParser::new(source);
    let root = parser.parse_program()?;
    let root_items = rules_sexpr_expect_list(&root)?;
    if root_items.len() < 2 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token(&root_items[0], "rules-sexpr-v0")?;

    let mut facts = None;
    let mut rules = None;
    let mut query = None;
    let mut routing = None;

    for clause in &root_items[1..] {
        let clause_items = rules_sexpr_expect_list(clause)?;
        if clause_items.is_empty() {
            return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
        }
        let clause_name = rules_sexpr_expect_token(&clause_items[0])?;
        match clause_name {
            "facts" => {
                if facts.is_some() {
                    return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
                }
                facts = Some(parse_rules_sexpr_facts_clause(clause_items)?);
            }
            "rules" => {
                if rules.is_some() {
                    return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
                }
                rules = Some(parse_rules_sexpr_rules_clause(clause_items)?);
            }
            "query" => {
                if query.is_some() {
                    return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
                }
                query = Some(parse_rules_sexpr_query_clause(clause_items)?);
            }
            "routing_policy" => {
                if routing.is_some() {
                    return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
                }
                routing = Some(parse_rules_sexpr_routing_clause(clause_items)?);
            }
            _ => return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
        }
    }

    let (on_no_match, on_ambiguous) = routing.ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    normalize_rules_program_v0(RulesProgramV0 {
        facts: facts.ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?,
        rules: rules.ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?,
        query: query.ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?,
        selection: Some("canonical-first".to_string()),
        on_no_match: Some(on_no_match),
        on_ambiguous: Some(on_ambiguous),
    })
}

fn rules_sexpr_expect_list(node: &RulesSExprNode) -> Result<&[RulesSExprNode], &'static str> {
    match node {
        RulesSExprNode::List(items) => Ok(items),
        _ => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn rules_sexpr_expect_token(node: &RulesSExprNode) -> Result<&str, &'static str> {
    match node {
        RulesSExprNode::Token(token) => Ok(token.as_str()),
        _ => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn rules_sexpr_expect_exact_token(
    node: &RulesSExprNode,
    expected: &str,
) -> Result<(), &'static str> {
    if rules_sexpr_expect_token(node)? == expected {
        Ok(())
    } else {
        Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)
    }
}

fn parse_rules_sexpr_facts_clause(items: &[RulesSExprNode]) -> Result<Vec<Value>, &'static str> {
    let fact_count = items.len().saturating_sub(1);
    if fact_count > MAX_RULES_SEXPR_FACTS {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let mut facts = Vec::with_capacity(fact_count);
    for fact in &items[1..] {
        facts.push(parse_rules_sexpr_pattern(fact, false)?);
    }
    Ok(facts)
}

fn parse_rules_sexpr_rules_clause(
    items: &[RulesSExprNode],
) -> Result<Vec<RulesRuleV0>, &'static str> {
    let rule_count = items.len().saturating_sub(1);
    if rule_count > MAX_RULES_SEXPR_RULES {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let mut rules = Vec::with_capacity(rule_count);
    for rule in &items[1..] {
        rules.push(parse_rules_sexpr_rule(rule)?);
    }
    Ok(rules)
}

fn parse_rules_sexpr_rule(node: &RulesSExprNode) -> Result<RulesRuleV0, &'static str> {
    let items = rules_sexpr_expect_list(node)?;
    if items.len() < 3 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    let body_term_count = items.len().saturating_sub(2);
    if body_term_count > MAX_RULES_SEXPR_BODY_TERMS_PER_RULE {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token(&items[0], ":-")?;

    let head = parse_rules_sexpr_pattern(&items[1], true)?;
    let mut body = Vec::with_capacity(body_term_count);
    for item in &items[2..] {
        body.push(parse_rules_sexpr_body_item(item)?);
    }

    Ok(RulesRuleV0 { head, body })
}

fn parse_rules_sexpr_body_item(node: &RulesSExprNode) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list(node)?;
    if items.is_empty() {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    if let Ok(op) = rules_sexpr_expect_token(&items[0]) {
        if is_builtin_operator(op) {
            return parse_rules_sexpr_builtin(op, items);
        }
    }
    parse_rules_sexpr_pattern(node, true)
}

fn parse_rules_sexpr_builtin(op: &str, items: &[RulesSExprNode]) -> Result<Value, &'static str> {
    if items.len() != 3 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    let left = parse_rules_sexpr_term(&items[1], true, FAILURE_CODE_FORBIDDEN_FEATURE)?;

    let right = if op == "in" {
        let set_items =
            rules_sexpr_expect_list(&items[2]).map_err(|_| FAILURE_CODE_TYPE_MISMATCH)?;
        if set_items.is_empty() {
            return Err(FAILURE_CODE_TYPE_MISMATCH);
        }
        rules_sexpr_expect_exact_token(&set_items[0], "set")
            .map_err(|_| FAILURE_CODE_TYPE_MISMATCH)?;
        let mut values = Vec::with_capacity(set_items.len().saturating_sub(1));
        for member in &set_items[1..] {
            values.push(parse_rules_sexpr_literal_set_member(member)?);
        }
        Value::Array(values)
    } else {
        parse_rules_sexpr_term(&items[2], true, FAILURE_CODE_FORBIDDEN_FEATURE)?
    };

    Ok(Value::Array(vec![
        Value::String(op.to_string()),
        left,
        right,
    ]))
}

fn parse_rules_sexpr_literal_set_member(node: &RulesSExprNode) -> Result<Value, &'static str> {
    match node {
        RulesSExprNode::Variable(_) => Err(FAILURE_CODE_TYPE_MISMATCH),
        RulesSExprNode::List(_) => Err(FAILURE_CODE_TYPE_MISMATCH),
        _ => parse_rules_sexpr_term(node, false, FAILURE_CODE_TYPE_MISMATCH),
    }
}

fn parse_rules_sexpr_query_clause(items: &[RulesSExprNode]) -> Result<Value, &'static str> {
    if items.len() != 2 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    parse_rules_sexpr_pattern(&items[1], true)
}

fn parse_rules_sexpr_routing_clause(
    items: &[RulesSExprNode],
) -> Result<(Value, String), &'static str> {
    if items.len() != 4 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    parse_rules_sexpr_route_predicate(&items[1])?;
    let on_no_match = parse_rules_sexpr_no_match_policy(&items[2])?;
    let on_ambiguous = parse_rules_sexpr_ambiguous_policy(&items[3])?;
    Ok((on_no_match, on_ambiguous))
}

fn parse_rules_sexpr_route_predicate(node: &RulesSExprNode) -> Result<(), &'static str> {
    let items = rules_sexpr_expect_list(node)?;
    if items.len() != 2 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token(&items[0], "route_predicate")?;
    rules_sexpr_expect_exact_token(&items[1], "route")?;
    Ok(())
}

fn parse_rules_sexpr_no_match_policy(node: &RulesSExprNode) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list(node)?;
    if items.len() != 2 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token(&items[0], "no_match_policy")?;

    if let Ok(token) = rules_sexpr_expect_token(&items[1]) {
        if token == "error" {
            return Ok(Value::String("error".to_string()));
        }
    }

    let default_items = rules_sexpr_expect_list(&items[1])?;
    if default_items.len() != 2 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token(&default_items[0], "default")?;
    let route_token = rules_sexpr_expect_token(&default_items[1])?;
    if !is_rules_sexpr_identifier(route_token) {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    let mut object = Map::new();
    object.insert(
        "default".to_string(),
        Value::String(format!(":{route_token}")),
    );
    Ok(Value::Object(object))
}

fn parse_rules_sexpr_ambiguous_policy(node: &RulesSExprNode) -> Result<String, &'static str> {
    let items = rules_sexpr_expect_list(node)?;
    if items.len() != 2 {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }
    rules_sexpr_expect_exact_token(&items[0], "ambiguous_policy")?;
    match rules_sexpr_expect_token(&items[1])? {
        "allow_multiple" => Ok("choose-first".to_string()),
        "error" => Ok("error".to_string()),
        _ => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
    }
}

fn parse_rules_sexpr_pattern(
    node: &RulesSExprNode,
    allow_variables: bool,
) -> Result<Value, &'static str> {
    let items = rules_sexpr_expect_list(node)?;
    if items.is_empty() {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let predicate = rules_sexpr_expect_token(&items[0])?;
    if !is_rules_sexpr_identifier(predicate) {
        return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    let mut pattern = Vec::with_capacity(items.len());
    pattern.push(Value::String(predicate.to_string()));
    for term in &items[1..] {
        pattern.push(parse_rules_sexpr_term(
            term,
            allow_variables,
            FAILURE_CODE_FORBIDDEN_FEATURE,
        )?);
    }

    Ok(Value::Array(pattern))
}

fn parse_rules_sexpr_term(
    node: &RulesSExprNode,
    allow_variables: bool,
    nested_term_error: &'static str,
) -> Result<Value, &'static str> {
    match node {
        RulesSExprNode::Variable(name) => {
            if allow_variables {
                Ok(Value::String(format!("?{name}")))
            } else {
                Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)
            }
        }
        RulesSExprNode::String(value) => Ok(Value::String(value.clone())),
        RulesSExprNode::Number(number) => {
            let parsed_number: serde_json::Number = number
                .parse()
                .map_err(|_| FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
            Ok(Value::Number(parsed_number))
        }
        RulesSExprNode::Bool(value) => Ok(Value::Bool(*value)),
        RulesSExprNode::Token(token) => {
            if !is_rules_sexpr_identifier(token) {
                return Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
            }
            Ok(Value::String(format!(":{token}")))
        }
        RulesSExprNode::List(_) => Err(nested_term_error),
    }
}

fn normalize_rules_program_v0(program: RulesProgramV0) -> Result<RulesProgramV0, &'static str> {
    let mut fact_entries = Vec::with_capacity(program.facts.len());
    for fact in &program.facts {
        fact_entries.push((rules_json_sort_key(fact)?, fact.clone()));
    }
    fact_entries.sort_by(|left, right| left.0.cmp(&right.0));
    fact_entries.dedup_by(|left, right| left.0 == right.0);

    let mut rule_entries = Vec::with_capacity(program.rules.len());
    for rule in &program.rules {
        rule_entries.push((rules_json_sort_key(rule)?, rule.clone()));
    }
    rule_entries.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(RulesProgramV0 {
        facts: fact_entries.into_iter().map(|(_, value)| value).collect(),
        rules: rule_entries.into_iter().map(|(_, value)| value).collect(),
        query: program.query,
        selection: Some("canonical-first".to_string()),
        on_no_match: program.on_no_match,
        on_ambiguous: program.on_ambiguous,
    })
}

fn rules_json_sort_key<T: Serialize>(value: &T) -> Result<String, &'static str> {
    serde_json::to_string(value).map_err(|_| FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum RulesLiteral {
    Atom(String),
    String(String),
    Number(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RulesTerm {
    Var(String),
    Lit(RulesLiteral),
}

#[derive(Debug, Clone)]
struct PredicatePatternV0 {
    predicate: String,
    args: Vec<RulesTerm>,
}

#[derive(Debug, Clone)]
enum RuleBodyItemV0 {
    Predicate(PredicatePatternV0),
    Builtin(BuiltinCallV0),
}

#[derive(Debug, Clone)]
struct BuiltinCallV0 {
    op: BuiltinOpV0,
    left: RulesTerm,
    right: BuiltinRhsV0,
}

#[derive(Debug, Clone)]
enum BuiltinRhsV0 {
    Term(RulesTerm),
    LiteralSet(Vec<RulesLiteral>),
}

#[derive(Debug, Clone, Copy)]
enum BuiltinOpV0 {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    In,
}

#[derive(Debug, Clone)]
struct CompiledRuleV0 {
    head: PredicatePatternV0,
    body: Vec<RuleBodyItemV0>,
    sort_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroundFactV0 {
    predicate: String,
    args: Vec<RulesLiteral>,
}

#[derive(Debug, Clone, Copy)]
enum SelectionPolicyV0 {
    CanonicalFirst,
}

#[derive(Debug, Clone)]
enum NoMatchPolicyV0 {
    Error,
    DefaultRoute(String),
}

#[derive(Debug, Clone, Copy)]
enum AmbiguousPolicyV0 {
    Error,
    ChooseFirst,
}

#[derive(Debug, Clone)]
struct CompiledRulesProgramV0 {
    facts: BTreeSet<GroundFactV0>,
    rules: Vec<CompiledRuleV0>,
    query: PredicatePatternV0,
    selection: SelectionPolicyV0,
    no_match: NoMatchPolicyV0,
    ambiguous: AmbiguousPolicyV0,
}

type RuleBindingsV0 = BTreeMap<String, RulesLiteral>;

fn evaluate_choose_rules_step(step: &EvalStepV0) -> Result<String, &'static str> {
    let routes = step.routes.as_ref().ok_or(FAILURE_CODE_STEP_CONTRACT)?;
    if routes.is_empty() {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }
    let program = compile_rules_program_from_step(step)?;
    let selected_route = evaluate_rules_program_v0(&program)?;
    routes
        .get(&selected_route)
        .cloned()
        .ok_or(FAILURE_CODE_NO_MATCH)
}

fn compile_rules_program_from_step(
    step: &EvalStepV0,
) -> Result<CompiledRulesProgramV0, &'static str> {
    let rules_program = parse_rules_program_from_step(step)?;
    compile_rules_program_v0(&rules_program)
}

fn parse_rules_program_from_step(step: &EvalStepV0) -> Result<RulesProgramV0, &'static str> {
    match (step.rules.as_ref(), step.rules_sexpr.as_ref()) {
        (Some(_), Some(_)) => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
        (None, None) => Err(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH),
        (Some(rules_program), None) => Ok(rules_program.clone()),
        (None, Some(rules_sexpr)) => parse_rules_sexpr_program_from_value(rules_sexpr),
    }
}

fn parse_rules_sexpr_program_from_value(value: &Value) -> Result<RulesProgramV0, &'static str> {
    let source = value
        .as_str()
        .ok_or(FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH)?;
    parse_rules_sexpr_program(source)
}

fn compile_rules_program_v0(
    program: &RulesProgramV0,
) -> Result<CompiledRulesProgramV0, &'static str> {
    let selection = parse_selection_policy(program.selection.as_deref())?;
    let no_match = parse_no_match_policy(program.on_no_match.as_ref())?;
    let ambiguous = parse_ambiguous_policy(program.on_ambiguous.as_deref())?;

    let mut facts = BTreeSet::new();
    let mut arities = BTreeMap::new();
    for fact_value in &program.facts {
        let fact = parse_ground_fact_v0(fact_value)?;
        register_predicate_arity(&mut arities, &fact.predicate, fact.args.len())?;
        facts.insert(fact);
    }

    let mut rules = Vec::new();
    for rule in &program.rules {
        let compiled_rule = parse_rule_v0(rule)?;
        register_predicate_arity(
            &mut arities,
            &compiled_rule.head.predicate,
            compiled_rule.head.args.len(),
        )?;
        for item in &compiled_rule.body {
            if let RuleBodyItemV0::Predicate(pattern) = item {
                register_predicate_arity(&mut arities, &pattern.predicate, pattern.args.len())?;
            }
        }
        validate_rule_variable_safety(&compiled_rule)?;
        rules.push(compiled_rule);
    }

    let query = parse_predicate_pattern_v0(&program.query)?;
    register_predicate_arity(&mut arities, &query.predicate, query.args.len())?;
    if query.args.len() != 1 {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }

    let topo_rank = rule_topo_ranks_v0(&rules)?;
    rules.sort_by(|left, right| {
        let left_rank = *topo_rank
            .get(left.head.predicate.as_str())
            .expect("head predicate rank must exist");
        let right_rank = *topo_rank
            .get(right.head.predicate.as_str())
            .expect("head predicate rank must exist");
        left_rank
            .cmp(&right_rank)
            .then_with(|| left.sort_key.cmp(&right.sort_key))
    });

    Ok(CompiledRulesProgramV0 {
        facts,
        rules,
        query,
        selection,
        no_match,
        ambiguous,
    })
}

fn parse_selection_policy(value: Option<&str>) -> Result<SelectionPolicyV0, &'static str> {
    match value.map(str::trim) {
        None | Some("") | Some("canonical-first") | Some("canonical_first") => {
            Ok(SelectionPolicyV0::CanonicalFirst)
        }
        _ => Err(FAILURE_CODE_STEP_CONTRACT),
    }
}

fn parse_no_match_policy(value: Option<&Value>) -> Result<NoMatchPolicyV0, &'static str> {
    let Some(value) = value else {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    };
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed == "error" {
                Ok(NoMatchPolicyV0::Error)
            } else {
                Ok(NoMatchPolicyV0::DefaultRoute(parse_route_atom(trimmed)?))
            }
        }
        Value::Object(object) => {
            if object
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "error")
            {
                return Ok(NoMatchPolicyV0::Error);
            }

            if let Some(default_value) = object
                .get("default")
                .or_else(|| object.get("route"))
                .or_else(|| object.get("default_route"))
            {
                return Ok(NoMatchPolicyV0::DefaultRoute(parse_route_atom_value(
                    default_value,
                )?));
            }

            Err(FAILURE_CODE_STEP_CONTRACT)
        }
        _ => Err(FAILURE_CODE_TYPE_MISMATCH),
    }
}

fn parse_ambiguous_policy(value: Option<&str>) -> Result<AmbiguousPolicyV0, &'static str> {
    let Some(value) = value.map(str::trim) else {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    };
    match value {
        "error" => Ok(AmbiguousPolicyV0::Error),
        "choose-first" | "allow_multiple" => Ok(AmbiguousPolicyV0::ChooseFirst),
        _ => Err(FAILURE_CODE_STEP_CONTRACT),
    }
}

fn parse_ground_fact_v0(value: &Value) -> Result<GroundFactV0, &'static str> {
    let items = value.as_array().ok_or(FAILURE_CODE_STEP_CONTRACT)?;
    if items.is_empty() {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }

    let predicate = parse_predicate_name(&items[0])?;
    let mut args = Vec::with_capacity(items.len().saturating_sub(1));
    for item in &items[1..] {
        let term = parse_term_v0(item)?;
        match term {
            RulesTerm::Var(_) => return Err(FAILURE_CODE_STEP_CONTRACT),
            RulesTerm::Lit(literal) => args.push(literal),
        }
    }

    Ok(GroundFactV0 { predicate, args })
}

fn parse_rule_v0(rule: &RulesRuleV0) -> Result<CompiledRuleV0, &'static str> {
    let head = parse_predicate_pattern_v0(&rule.head)?;
    let mut body = Vec::with_capacity(rule.body.len());
    for item in &rule.body {
        body.push(parse_rule_body_item_v0(item)?);
    }
    let sort_key = format_rule_sort_key(&head, &body);
    Ok(CompiledRuleV0 {
        head,
        body,
        sort_key,
    })
}

fn parse_rule_body_item_v0(value: &Value) -> Result<RuleBodyItemV0, &'static str> {
    if contains_negation_token(value) {
        return Err(FAILURE_CODE_FORBIDDEN_FEATURE);
    }

    let items = value.as_array().ok_or(FAILURE_CODE_STEP_CONTRACT)?;
    if items.is_empty() {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }
    let token = items[0].as_str().ok_or(FAILURE_CODE_STEP_CONTRACT)?.trim();
    if is_builtin_operator(token) {
        return parse_builtin_call_v0(items).map(RuleBodyItemV0::Builtin);
    }

    Ok(RuleBodyItemV0::Predicate(parse_predicate_pattern_v0(
        value,
    )?))
}

fn parse_builtin_call_v0(items: &[Value]) -> Result<BuiltinCallV0, &'static str> {
    if items.len() != 3 {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }
    let op = parse_builtin_operator(items[0].as_str().ok_or(FAILURE_CODE_STEP_CONTRACT)?)?;
    let left = parse_term_v0(&items[1])?;

    let right = match op {
        BuiltinOpV0::In => {
            let rhs_items = items[2].as_array().ok_or(FAILURE_CODE_TYPE_MISMATCH)?;
            let mut literals = Vec::with_capacity(rhs_items.len());
            for rhs_item in rhs_items {
                match parse_term_v0(rhs_item)? {
                    RulesTerm::Var(_) => return Err(FAILURE_CODE_TYPE_MISMATCH),
                    RulesTerm::Lit(literal) => literals.push(literal),
                }
            }
            BuiltinRhsV0::LiteralSet(literals)
        }
        _ => BuiltinRhsV0::Term(parse_term_v0(&items[2])?),
    };

    Ok(BuiltinCallV0 { op, left, right })
}

fn parse_predicate_pattern_v0(value: &Value) -> Result<PredicatePatternV0, &'static str> {
    let items = value.as_array().ok_or(FAILURE_CODE_STEP_CONTRACT)?;
    if items.is_empty() {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }
    let predicate = parse_predicate_name(&items[0])?;
    let mut args = Vec::with_capacity(items.len().saturating_sub(1));
    for item in &items[1..] {
        args.push(parse_term_v0(item)?);
    }
    Ok(PredicatePatternV0 { predicate, args })
}

fn parse_predicate_name(value: &Value) -> Result<String, &'static str> {
    let token = value.as_str().ok_or(FAILURE_CODE_STEP_CONTRACT)?.trim();
    if token.is_empty() || token.starts_with('?') || token.starts_with(':') {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }
    if token.chars().any(char::is_whitespace) {
        return Err(FAILURE_CODE_STEP_CONTRACT);
    }
    if is_builtin_operator(token)
        || is_negation_operator(token)
        || looks_like_function_symbol(token)
    {
        return Err(FAILURE_CODE_FORBIDDEN_FEATURE);
    }
    Ok(token.to_string())
}

fn parse_term_v0(value: &Value) -> Result<RulesTerm, &'static str> {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if let Some(variable) = parse_variable_name(trimmed) {
                return Ok(RulesTerm::Var(variable));
            }
            if looks_like_function_symbol(trimmed) {
                return Err(FAILURE_CODE_FORBIDDEN_FEATURE);
            }
            if is_route_atom_format(trimmed) {
                return Ok(RulesTerm::Lit(RulesLiteral::Atom(trimmed.to_string())));
            }
            Ok(RulesTerm::Lit(RulesLiteral::String(raw.clone())))
        }
        Value::Number(number) => Ok(RulesTerm::Lit(RulesLiteral::Number(number.to_string()))),
        Value::Bool(flag) => Ok(RulesTerm::Lit(RulesLiteral::Bool(*flag))),
        Value::Array(_) | Value::Object(_) => Err(FAILURE_CODE_FORBIDDEN_FEATURE),
        Value::Null => Err(FAILURE_CODE_STEP_CONTRACT),
    }
}

fn parse_variable_name(raw: &str) -> Option<String> {
    let name = raw.strip_prefix('?')?;
    if name.is_empty() {
        return None;
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(name.to_string())
}

fn parse_route_atom(raw: &str) -> Result<String, &'static str> {
    if is_route_atom_format(raw) {
        Ok(raw.to_string())
    } else {
        Err(FAILURE_CODE_TYPE_MISMATCH)
    }
}

fn parse_route_atom_value(value: &Value) -> Result<String, &'static str> {
    let raw = value.as_str().ok_or(FAILURE_CODE_TYPE_MISMATCH)?;
    parse_route_atom(raw.trim())
}

fn is_route_atom_format(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() > 1
        && trimmed.starts_with(':')
        && !trimmed.chars().any(char::is_whitespace)
        && !looks_like_function_symbol(trimmed)
}

fn is_negation_operator(token: &str) -> bool {
    let normalized = token.trim().to_ascii_lowercase();
    normalized == "not" || normalized.starts_with("not(")
}

fn contains_negation_token(value: &Value) -> bool {
    match value {
        Value::String(token) => is_negation_operator(token),
        Value::Array(items) => items
            .first()
            .and_then(Value::as_str)
            .is_some_and(is_negation_operator),
        Value::Object(object) => {
            object.contains_key("not")
                || object
                    .get("negated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn looks_like_function_symbol(token: &str) -> bool {
    let trimmed = token.trim();
    let Some(open_index) = trimmed.find('(') else {
        return false;
    };
    if !trimmed.ends_with(')') || open_index == 0 {
        return false;
    }
    trimmed[..open_index]
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_builtin_operator(token: &str) -> bool {
    matches!(token, "=" | "!=" | "<" | "<=" | ">" | ">=" | "in")
}

fn parse_builtin_operator(token: &str) -> Result<BuiltinOpV0, &'static str> {
    match token.trim() {
        "=" => Ok(BuiltinOpV0::Eq),
        "!=" => Ok(BuiltinOpV0::NotEq),
        "<" => Ok(BuiltinOpV0::Lt),
        "<=" => Ok(BuiltinOpV0::LtEq),
        ">" => Ok(BuiltinOpV0::Gt),
        ">=" => Ok(BuiltinOpV0::GtEq),
        "in" => Ok(BuiltinOpV0::In),
        _ => Err(FAILURE_CODE_FORBIDDEN_FEATURE),
    }
}

fn register_predicate_arity(
    arities: &mut BTreeMap<String, usize>,
    predicate: &str,
    arity: usize,
) -> Result<(), &'static str> {
    match arities.get(predicate) {
        Some(existing) if *existing != arity => Err(FAILURE_CODE_STEP_CONTRACT),
        Some(_) => Ok(()),
        None => {
            arities.insert(predicate.to_string(), arity);
            Ok(())
        }
    }
}

fn validate_rule_variable_safety(rule: &CompiledRuleV0) -> Result<(), &'static str> {
    let mut vars_in_predicates = BTreeSet::new();
    for item in &rule.body {
        if let RuleBodyItemV0::Predicate(pattern) = item {
            collect_variables_from_pattern(pattern, &mut vars_in_predicates);
        }
    }
    for variable in variables_in_terms(&rule.head.args) {
        if !vars_in_predicates.contains(&variable) {
            return Err(FAILURE_CODE_UNBOUND_VAR);
        }
    }

    let mut bound_before_builtin = BTreeSet::new();
    for item in &rule.body {
        match item {
            RuleBodyItemV0::Predicate(pattern) => {
                collect_variables_from_pattern(pattern, &mut bound_before_builtin);
            }
            RuleBodyItemV0::Builtin(builtin) => {
                let mut builtin_vars = BTreeSet::new();
                collect_variables_from_builtin(builtin, &mut builtin_vars);
                for variable in builtin_vars {
                    if !bound_before_builtin.contains(&variable) {
                        return Err(FAILURE_CODE_UNBOUND_VAR);
                    }
                }
            }
        }
    }

    Ok(())
}

fn collect_variables_from_pattern(pattern: &PredicatePatternV0, variables: &mut BTreeSet<String>) {
    for term in &pattern.args {
        if let RulesTerm::Var(name) = term {
            variables.insert(name.clone());
        }
    }
}

fn collect_variables_from_builtin(builtin: &BuiltinCallV0, variables: &mut BTreeSet<String>) {
    collect_variables_from_term(&builtin.left, variables);
    match &builtin.right {
        BuiltinRhsV0::Term(term) => collect_variables_from_term(term, variables),
        BuiltinRhsV0::LiteralSet(_) => {}
    }
}

fn collect_variables_from_term(term: &RulesTerm, variables: &mut BTreeSet<String>) {
    if let RulesTerm::Var(name) = term {
        variables.insert(name.clone());
    }
}

fn variables_in_terms(terms: &[RulesTerm]) -> BTreeSet<String> {
    let mut variables = BTreeSet::new();
    for term in terms {
        collect_variables_from_term(term, &mut variables);
    }
    variables
}

fn rule_topo_ranks_v0(rules: &[CompiledRuleV0]) -> Result<BTreeMap<String, usize>, &'static str> {
    let mut head_predicates = BTreeSet::new();
    for rule in rules {
        head_predicates.insert(rule.head.predicate.clone());
    }

    let mut adjacency: BTreeMap<String, BTreeSet<String>> = head_predicates
        .iter()
        .cloned()
        .map(|predicate| (predicate, BTreeSet::new()))
        .collect();
    let mut indegree: BTreeMap<String, usize> = head_predicates
        .iter()
        .cloned()
        .map(|predicate| (predicate, 0usize))
        .collect();

    for rule in rules {
        let head = rule.head.predicate.clone();
        for item in &rule.body {
            if let RuleBodyItemV0::Predicate(pattern) = item {
                if head_predicates.contains(&pattern.predicate)
                    && adjacency
                        .get_mut(&head)
                        .expect("head predicate adjacency must exist")
                        .insert(pattern.predicate.clone())
                {
                    *indegree
                        .get_mut(&pattern.predicate)
                        .expect("body head predicate indegree must exist") += 1;
                }
            }
        }
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(predicate, degree)| (*degree == 0).then_some(predicate.clone()))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(head_predicates.len());

    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        order.push(next.clone());
        if let Some(children) = adjacency.get(&next) {
            for child in children {
                let degree = indegree
                    .get_mut(child)
                    .expect("child predicate indegree must exist");
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }

    if order.len() != head_predicates.len() {
        return Err(FAILURE_CODE_FORBIDDEN_FEATURE);
    }

    Ok(order
        .into_iter()
        .enumerate()
        .map(|(rank, predicate)| (predicate, rank))
        .collect())
}

fn format_rule_sort_key(head: &PredicatePatternV0, body: &[RuleBodyItemV0]) -> String {
    let mut key = String::new();
    key.push_str("head:");
    key.push_str(&format_pattern(head));
    key.push_str("|body:");
    for (index, item) in body.iter().enumerate() {
        if index > 0 {
            key.push(',');
        }
        key.push_str(&format_body_item(item));
    }
    key
}

fn format_pattern(pattern: &PredicatePatternV0) -> String {
    let args = pattern
        .args
        .iter()
        .map(format_term)
        .collect::<Vec<_>>()
        .join(",");
    format!("{}({args})", pattern.predicate)
}

fn format_body_item(item: &RuleBodyItemV0) -> String {
    match item {
        RuleBodyItemV0::Predicate(pattern) => format!("pred:{}", format_pattern(pattern)),
        RuleBodyItemV0::Builtin(call) => {
            let right = match &call.right {
                BuiltinRhsV0::Term(term) => format_term(term),
                BuiltinRhsV0::LiteralSet(set) => format!(
                    "{{{}}}",
                    set.iter().map(format_literal).collect::<Vec<_>>().join(",")
                ),
            };
            format!(
                "builtin:{}({},{right})",
                format_builtin_op(call.op),
                format_term(&call.left)
            )
        }
    }
}

fn format_term(term: &RulesTerm) -> String {
    match term {
        RulesTerm::Var(name) => format!("?{name}"),
        RulesTerm::Lit(literal) => format_literal(literal),
    }
}

fn format_literal(literal: &RulesLiteral) -> String {
    match literal {
        RulesLiteral::Atom(atom) => format!("atom:{atom}"),
        RulesLiteral::String(string) => format!("str:{string:?}"),
        RulesLiteral::Number(number) => format!("num:{number}"),
        RulesLiteral::Bool(flag) => format!("bool:{flag}"),
    }
}

fn format_builtin_op(op: BuiltinOpV0) -> &'static str {
    match op {
        BuiltinOpV0::Eq => "=",
        BuiltinOpV0::NotEq => "!=",
        BuiltinOpV0::Lt => "<",
        BuiltinOpV0::LtEq => "<=",
        BuiltinOpV0::Gt => ">",
        BuiltinOpV0::GtEq => ">=",
        BuiltinOpV0::In => "in",
    }
}

fn evaluate_rules_program_v0(program: &CompiledRulesProgramV0) -> Result<String, &'static str> {
    let mut idb = BTreeSet::new();
    for rule in &program.rules {
        let derived = evaluate_rule_once_v0(rule, &program.facts, &idb)?;
        idb.extend(derived);
    }

    let route_candidates = evaluate_query_routes_v0(&program.query, &program.facts, &idb)?;
    if route_candidates.is_empty() {
        return match &program.no_match {
            NoMatchPolicyV0::Error => Err(FAILURE_CODE_NO_MATCH),
            NoMatchPolicyV0::DefaultRoute(route) => Ok(route.clone()),
        };
    }

    if route_candidates.len() > 1 && matches!(program.ambiguous, AmbiguousPolicyV0::Error) {
        return Err(FAILURE_CODE_AMBIGUOUS_MATCH);
    }

    match program.selection {
        SelectionPolicyV0::CanonicalFirst => {
            let mut sorted = route_candidates;
            sorted.sort_by(|left, right| compare_route_atoms(left, right));
            sorted.into_iter().next().ok_or(FAILURE_CODE_NO_MATCH)
        }
    }
}

fn evaluate_rule_once_v0(
    rule: &CompiledRuleV0,
    edb: &BTreeSet<GroundFactV0>,
    idb: &BTreeSet<GroundFactV0>,
) -> Result<BTreeSet<GroundFactV0>, &'static str> {
    let mut bindings = vec![RuleBindingsV0::new()];
    for item in &rule.body {
        bindings = match item {
            RuleBodyItemV0::Predicate(pattern) => {
                evaluate_predicate_body_item_v0(pattern, &bindings, edb, idb)
            }
            RuleBodyItemV0::Builtin(call) => evaluate_builtin_body_item_v0(call, &bindings)?,
        };
        if bindings.is_empty() {
            break;
        }
    }

    let mut derived = BTreeSet::new();
    for binding in &bindings {
        derived.insert(instantiate_head_fact_v0(&rule.head, binding)?);
    }
    Ok(derived)
}

fn evaluate_predicate_body_item_v0(
    pattern: &PredicatePatternV0,
    bindings: &[RuleBindingsV0],
    edb: &BTreeSet<GroundFactV0>,
    idb: &BTreeSet<GroundFactV0>,
) -> Vec<RuleBindingsV0> {
    let mut next_bindings = Vec::new();
    for binding in bindings {
        for fact in edb.iter().chain(idb.iter()) {
            if let Some(merged) = unify_pattern_with_fact_v0(pattern, fact, binding) {
                next_bindings.push(merged);
            }
        }
    }
    next_bindings
}

fn unify_pattern_with_fact_v0(
    pattern: &PredicatePatternV0,
    fact: &GroundFactV0,
    bindings: &RuleBindingsV0,
) -> Option<RuleBindingsV0> {
    if pattern.predicate != fact.predicate || pattern.args.len() != fact.args.len() {
        return None;
    }

    let mut merged = bindings.clone();
    for (term, literal) in pattern.args.iter().zip(&fact.args) {
        match term {
            RulesTerm::Var(name) => {
                if let Some(bound) = merged.get(name) {
                    if bound != literal {
                        return None;
                    }
                } else {
                    merged.insert(name.clone(), literal.clone());
                }
            }
            RulesTerm::Lit(expected) => {
                if expected != literal {
                    return None;
                }
            }
        }
    }

    Some(merged)
}

fn evaluate_builtin_body_item_v0(
    builtin: &BuiltinCallV0,
    bindings: &[RuleBindingsV0],
) -> Result<Vec<RuleBindingsV0>, &'static str> {
    let mut next_bindings = Vec::new();
    for binding in bindings {
        if evaluate_builtin_call_v0(builtin, binding)? {
            next_bindings.push(binding.clone());
        }
    }
    Ok(next_bindings)
}

fn evaluate_builtin_call_v0(
    builtin: &BuiltinCallV0,
    bindings: &RuleBindingsV0,
) -> Result<bool, &'static str> {
    let left = resolve_term_v0(&builtin.left, bindings)?;

    match builtin.op {
        BuiltinOpV0::Eq => {
            let right = resolve_builtin_rhs_term_v0(&builtin.right, bindings)?;
            comparable_equals_v0(&left, &right)
        }
        BuiltinOpV0::NotEq => {
            let right = resolve_builtin_rhs_term_v0(&builtin.right, bindings)?;
            comparable_equals_v0(&left, &right).map(|matches| !matches)
        }
        BuiltinOpV0::Lt | BuiltinOpV0::LtEq | BuiltinOpV0::Gt | BuiltinOpV0::GtEq => {
            let right = resolve_builtin_rhs_term_v0(&builtin.right, bindings)?;
            let ordering = compare_numeric_literals_v0(&left, &right)?;
            Ok(match builtin.op {
                BuiltinOpV0::Lt => ordering == Ordering::Less,
                BuiltinOpV0::LtEq => ordering == Ordering::Less || ordering == Ordering::Equal,
                BuiltinOpV0::Gt => ordering == Ordering::Greater,
                BuiltinOpV0::GtEq => ordering == Ordering::Greater || ordering == Ordering::Equal,
                BuiltinOpV0::Eq | BuiltinOpV0::NotEq | BuiltinOpV0::In => unreachable!(),
            })
        }
        BuiltinOpV0::In => {
            let BuiltinRhsV0::LiteralSet(set_members) = &builtin.right else {
                return Err(FAILURE_CODE_TYPE_MISMATCH);
            };
            for member in set_members {
                if comparable_equals_v0(&left, member)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn resolve_builtin_rhs_term_v0(
    right: &BuiltinRhsV0,
    bindings: &RuleBindingsV0,
) -> Result<RulesLiteral, &'static str> {
    match right {
        BuiltinRhsV0::Term(term) => resolve_term_v0(term, bindings),
        BuiltinRhsV0::LiteralSet(_) => Err(FAILURE_CODE_TYPE_MISMATCH),
    }
}

fn resolve_term_v0(
    term: &RulesTerm,
    bindings: &RuleBindingsV0,
) -> Result<RulesLiteral, &'static str> {
    match term {
        RulesTerm::Var(name) => bindings.get(name).cloned().ok_or(FAILURE_CODE_UNBOUND_VAR),
        RulesTerm::Lit(literal) => Ok(literal.clone()),
    }
}

fn comparable_equals_v0(left: &RulesLiteral, right: &RulesLiteral) -> Result<bool, &'static str> {
    match (left, right) {
        (RulesLiteral::Bool(left), RulesLiteral::Bool(right)) => Ok(left == right),
        (RulesLiteral::String(left), RulesLiteral::String(right)) => Ok(left == right),
        (RulesLiteral::Atom(left), RulesLiteral::Atom(right)) => Ok(left == right),
        (RulesLiteral::Number(_), RulesLiteral::Number(_)) => {
            Ok(compare_numeric_literals_v0(left, right)? == Ordering::Equal)
        }
        _ => Err(FAILURE_CODE_TYPE_MISMATCH),
    }
}

fn compare_numeric_literals_v0(
    left: &RulesLiteral,
    right: &RulesLiteral,
) -> Result<Ordering, &'static str> {
    let RulesLiteral::Number(left_number) = left else {
        return Err(FAILURE_CODE_TYPE_MISMATCH);
    };
    let RulesLiteral::Number(right_number) = right else {
        return Err(FAILURE_CODE_TYPE_MISMATCH);
    };

    let left_value = parse_number_for_builtin_v0(left_number)?;
    let right_value = parse_number_for_builtin_v0(right_number)?;
    left_value
        .partial_cmp(&right_value)
        .ok_or(FAILURE_CODE_TYPE_MISMATCH)
}

fn parse_number_for_builtin_v0(raw: &str) -> Result<f64, &'static str> {
    raw.parse::<f64>().map_err(|_| FAILURE_CODE_TYPE_MISMATCH)
}

fn instantiate_head_fact_v0(
    head: &PredicatePatternV0,
    bindings: &RuleBindingsV0,
) -> Result<GroundFactV0, &'static str> {
    let mut args = Vec::with_capacity(head.args.len());
    for term in &head.args {
        args.push(match term {
            RulesTerm::Var(name) => bindings
                .get(name)
                .cloned()
                .ok_or(FAILURE_CODE_UNBOUND_VAR)?,
            RulesTerm::Lit(literal) => literal.clone(),
        });
    }
    Ok(GroundFactV0 {
        predicate: head.predicate.clone(),
        args,
    })
}

fn evaluate_query_routes_v0(
    query: &PredicatePatternV0,
    edb: &BTreeSet<GroundFactV0>,
    idb: &BTreeSet<GroundFactV0>,
) -> Result<Vec<String>, &'static str> {
    let mut route_candidates = BTreeSet::new();
    for fact in edb.iter().chain(idb.iter()) {
        if let Some(bindings) = unify_pattern_with_fact_v0(query, fact, &RuleBindingsV0::new()) {
            let route_term = query
                .args
                .first()
                .expect("query arity validated as exactly one");
            let literal = resolve_term_v0(route_term, &bindings)?;
            let RulesLiteral::Atom(route_atom) = literal else {
                return Err(FAILURE_CODE_TYPE_MISMATCH);
            };
            route_candidates.insert(route_atom);
        }
    }
    Ok(route_candidates.into_iter().collect())
}

fn compare_route_atoms(left: &str, right: &str) -> Ordering {
    let left_canonical = canonical_route_atom_bytes(left);
    let right_canonical = canonical_route_atom_bytes(right);

    match (left_canonical, right_canonical) {
        (Some(left_bytes), Some(right_bytes)) => {
            left_bytes.cmp(&right_bytes).then_with(|| left.cmp(right))
        }
        _ => left.cmp(right),
    }
}

fn canonical_route_atom_bytes(route_atom: &str) -> Option<Vec<u8>> {
    if !is_route_atom_format(route_atom) {
        return None;
    }
    let canonical_value = RuliaCanonicalValue::Keyword(Keyword::parse(route_atom));
    rulia::encode_canonical(&canonical_value).ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::json;

    use super::{
        compile_rules_program_v0, evaluate_eval_ir_v0, evaluate_rules_program_v0,
        parse_eval_run_input_v0, parse_rules_sexpr_program, RulesProgramV0,
        FAILURE_CODE_AMBIGUOUS_MATCH, FAILURE_CODE_FORBIDDEN_FEATURE,
        FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH, FAILURE_CODE_UNBOUND_VAR, MAX_RULES_SEXPR_BYTES,
        MAX_RULES_SEXPR_TOKENS,
    };

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("l2_evalir_v0")
            .join(name)
    }

    fn fixture_contents(name: &str) -> String {
        fs::read_to_string(fixture_path(name)).expect("read fixture")
    }

    fn rules_sexpr_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("rules_sexpr_v0")
            .join(name)
    }

    fn rules_sexpr_fixture_contents(name: &str) -> String {
        fs::read_to_string(rules_sexpr_fixture_path(name)).expect("read rules sexpr fixture")
    }

    #[test]
    fn evalir_assign_emit_end_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_assign_emit_end.json"),
            &fixture_contents("initial_state_base.json"),
            None,
            None,
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"end\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"active\"}},\"emissions\":[{\"event\":\"order_activated\",\"kind\":\"audit\"}],\"requests\":[],\"obligations\":[],\"errors\":[]}"
        );
    }

    #[test]
    fn evalir_request_suspend_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_request_suspend.json"),
            &fixture_contents("initial_state_base.json"),
            Some(&fixture_contents("history_prefix_empty.json")),
            Some(&fixture_contents("gamma_core_main.json")),
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"suspend\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"new\"}},\"emissions\":[],\"requests\":[{\"request_ordinal\":1,\"request_id\":\"sha256:40f107103cc1e26bee9d05f05a4d31febd82205b2dd2e78acd125124182dd2c5\",\"capability_id\":\"capability.approvals\",\"operation\":\"submit\",\"args\":{\"amount\":1250,\"channel\":\"email\"},\"cause\":{\"artifact_id\":\"sha256:487b5a9a4a7a780371b4bc2952099068a8207fc72e51adea776081771dcf9a79\",\"step_id\":\"S0001\",\"request_ordinal\":1,\"history_cursor\":-1}}],\"obligations\":[{\"obligation_id\":\"sha256:54e86a294e74a4656d0923a8c702527c0ee045c9a1e8a0c51ce0de754d095b59\",\"obligation_type\":\"receipt_valid\",\"satisfaction_ref\":\"sha256:40f107103cc1e26bee9d05f05a4d31febd82205b2dd2e78acd125124182dd2c5\"}],\"errors\":[]}"
        );
    }

    #[test]
    fn evalir_assign_and_request_expression_payloads_resolve_from_state() {
        let eval_ir = json!({
            "format_id": "portable_workflow.eval_ir.v0",
            "ir_version": "v0",
            "artifact_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "entry_step_id": "S0001",
            "steps": [
                {
                    "step_id": "S0001",
                    "op": "assign",
                    "path": "order.risk_class",
                    "value": {
                        "$fn": "state",
                        "body": {
                            "$expr": "if",
                            "cond": {
                                "$expr": ">=",
                                "left": {"$expr": "state_get", "path": "order.amount"},
                                "right": 1000
                            },
                            "then": "high",
                            "else": "standard"
                        }
                    },
                    "next_step_id": "S0002"
                },
                {
                    "step_id": "S0002",
                    "op": "request",
                    "capability_id": "capability.approvals",
                    "operation": "submit",
                    "args": {
                        "amount": {"$expr": "state_get", "path": "order.amount"},
                        "channel": "email",
                        "risk_class": {"$expr": "state_get", "path": "order.risk_class"}
                    },
                    "next_step_id": "S0003"
                },
                {
                    "step_id": "S0003",
                    "op": "end"
                }
            ]
        });
        let state = json!({
            "order": {
                "amount": 1250,
                "risk_class": "unset"
            }
        });

        let input = parse_eval_run_input_v0(
            &eval_ir.to_string(),
            &state.to_string(),
            Some(&fixture_contents("history_prefix_empty.json")),
            Some(&fixture_contents("gamma_core_main.json")),
        )
        .expect("parse eval run input");
        let result = evaluate_eval_ir_v0(input);

        assert_eq!(result.control, super::EvalControlV0::Suspend);
        assert_eq!(result.state_out["order"]["risk_class"], json!("high"));
        assert_eq!(result.requests.len(), 1);
        assert_eq!(result.requests[0].args["amount"], json!(1250));
        assert_eq!(result.requests[0].args["risk_class"], json!("high"));
    }

    #[test]
    fn evalir_expression_payloads_are_deterministic_across_reruns() {
        let eval_ir = json!({
            "format_id": "portable_workflow.eval_ir.v0",
            "ir_version": "v0",
            "artifact_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "entry_step_id": "S0001",
            "steps": [
                {
                    "step_id": "S0001",
                    "op": "assign",
                    "path": "order.risk_class",
                    "value": {
                        "$fn": "state",
                        "body": {
                            "$expr": "if",
                            "cond": {
                                "$expr": ">=",
                                "left": {"$expr": "state_get", "path": "order.amount"},
                                "right": 1000
                            },
                            "then": "high",
                            "else": "standard"
                        }
                    },
                    "next_step_id": "S0002"
                },
                {
                    "step_id": "S0002",
                    "op": "request",
                    "capability_id": "capability.approvals",
                    "operation": "submit",
                    "args": {
                        "amount": {"$expr": "state_get", "path": "order.amount"},
                        "channel": "email",
                        "risk_class": {"$expr": "state_get", "path": "order.risk_class"}
                    },
                    "next_step_id": "S0003"
                },
                {
                    "step_id": "S0003",
                    "op": "end"
                }
            ]
        });
        let state = json!({
            "order": {
                "amount": 1250,
                "risk_class": "unset"
            }
        });
        let history = fixture_contents("history_prefix_empty.json");
        let gamma = fixture_contents("gamma_core_main.json");

        let first_input = parse_eval_run_input_v0(
            &eval_ir.to_string(),
            &state.to_string(),
            Some(&history),
            Some(&gamma),
        )
        .expect("parse first eval run input");
        let second_input = parse_eval_run_input_v0(
            &eval_ir.to_string(),
            &state.to_string(),
            Some(&history),
            Some(&gamma),
        )
        .expect("parse second eval run input");

        let first = evaluate_eval_ir_v0(first_input);
        let second = evaluate_eval_ir_v0(second_input);

        let first_bytes =
            serde_json::to_vec(&first).expect("serialize first eval run result deterministically");
        let second_bytes = serde_json::to_vec(&second)
            .expect("serialize second eval run result deterministically");
        assert_eq!(first_bytes, second_bytes);
    }

    #[test]
    fn evalir_choose_rules_branch_end_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_choose_rules_branch.json"),
            &fixture_contents("initial_state_base.json"),
            None,
            None,
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"end\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}},\"emissions\":[],\"requests\":[],\"obligations\":[],\"errors\":[]}"
        );
    }

    #[test]
    fn evalir_choose_rules_branch_with_rules_sexpr_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_choose_rules_branch_sexpr.json"),
            &fixture_contents("initial_state_base.json"),
            None,
            None,
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"end\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}},\"emissions\":[],\"requests\":[],\"obligations\":[],\"errors\":[]}"
        );
    }

    #[test]
    fn evalir_join_all_of_missing_suspends_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_join_all_of_missing.json"),
            &fixture_contents("initial_state_base.json"),
            Some(&fixture_contents("history_prefix_join_one_receipt.json")),
            Some(&fixture_contents("gamma_core_main.json")),
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"suspend\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"new\"}},\"emissions\":[],\"requests\":[],\"obligations\":[],\"errors\":[]}"
        );
    }

    #[test]
    fn evalir_join_all_of_satisfied_reaches_end_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_join_all_of_satisfied.json"),
            &fixture_contents("initial_state_base.json"),
            Some(&fixture_contents("history_prefix_join_two_receipts.json")),
            Some(&fixture_contents("gamma_core_main.json")),
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"end\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}},\"emissions\":[],\"requests\":[],\"obligations\":[],\"errors\":[]}"
        );
    }

    #[test]
    fn evalir_join_any_of_satisfied_reaches_end_golden() {
        let input = parse_eval_run_input_v0(
            &fixture_contents("evalir_join_any_of_satisfied.json"),
            &fixture_contents("initial_state_base.json"),
            Some(&fixture_contents("history_prefix_join_one_receipt.json")),
            Some(&fixture_contents("gamma_core_main.json")),
        )
        .expect("parse eval run input");

        let result = evaluate_eval_ir_v0(input);
        let actual = serde_json::to_string(&result).expect("serialize result to JSON");

        assert_eq!(
            actual,
            "{\"control\":\"end\",\"state_out\":{\"metrics\":{\"request_count\":0},\"order\":{\"id\":\"ORD-1000\",\"status\":\"open_case\"}},\"emissions\":[],\"requests\":[],\"obligations\":[],\"errors\":[]}"
        );
    }

    #[test]
    fn join_step_invalid_policy_maps_to_schema_mismatch() {
        let input = parse_eval_run_input_v0(
            r#"{
                "format_id": "portable_workflow.eval_ir.v0",
                "ir_version": "v0",
                "entry_step_id": "S0001",
                "steps": [
                    {
                        "step_id": "S0001",
                        "op": "join_obligations_v0",
                        "obligations": [
                            {
                                "format": "rulia_obligation_v0",
                                "obligation_type": "receipt_valid",
                                "params": {
                                    "request_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                }
                            }
                        ],
                        "policy": "invalid_policy",
                        "next_step_id": "S0002"
                    },
                    {
                        "step_id": "S0002",
                        "op": "end"
                    }
                ]
            }"#,
            &fixture_contents("initial_state_base.json"),
            Some(&fixture_contents("history_prefix_join_one_receipt.json")),
            Some(&fixture_contents("gamma_core_main.json")),
        )
        .expect("input should parse");

        let result = evaluate_eval_ir_v0(input);
        assert_eq!(result.control, super::EvalControlV0::Error);
        assert_eq!(
            result.errors,
            vec![FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH.to_string()]
        );
    }

    #[test]
    fn rules_sexpr_001_desugars_risk_routing_to_canonical_rules_program() {
        let sexpr = rules_sexpr_fixture_contents("risk_routing_open_case.sx");
        let actual_program = parse_rules_sexpr_program(&sexpr).expect("sugar parse must succeed");
        let expected_program: RulesProgramV0 = serde_json::from_str(
            r#"{
                "facts": [
                    ["doc_complete", "case-001", true],
                    ["risk_score", "case-001", 82]
                ],
                "rules": [
                    {
                        "head": ["route", ":open_case"],
                        "body": [
                            ["risk_score", "?case", "?score"],
                            [">=", "?score", 80],
                            ["doc_complete", "?case", true]
                        ]
                    },
                    {
                        "head": ["route", ":wait_docs"],
                        "body": [
                            ["doc_complete", "?case", false]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": {
                    "default": ":wait_docs"
                },
                "on_ambiguous": "choose-first"
            }"#,
        )
        .expect("expected canonical program must parse");

        let actual_value =
            serde_json::to_value(actual_program).expect("serialize actual canonical program");
        let expected_value =
            serde_json::to_value(expected_program).expect("serialize expected canonical program");
        assert_eq!(actual_value, expected_value);
    }

    #[test]
    fn rules_sexpr_002_desugars_allowlist_routing_to_canonical_rules_program() {
        let sexpr = rules_sexpr_fixture_contents("allowlist_routing_wait_docs.sx");
        let actual_program = parse_rules_sexpr_program(&sexpr).expect("sugar parse must succeed");
        let expected_program: RulesProgramV0 = serde_json::from_str(
            r#"{
                "facts": [
                    ["country", "case-002", "SE"],
                    ["doc_status", "case-002", "missing_income_proof"]
                ],
                "rules": [
                    {
                        "head": ["route", ":open_case"],
                        "body": [
                            ["country", "?case", "?c"],
                            ["in", "?c", ["US", "CA", "SE"]],
                            ["doc_status", "?case", "complete"]
                        ]
                    },
                    {
                        "head": ["route", ":wait_docs"],
                        "body": [
                            ["country", "?case", "?c"],
                            ["in", "?c", ["US", "CA", "SE"]],
                            ["doc_status", "?case", "missing_income_proof"]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": {
                    "default": ":wait_docs"
                },
                "on_ambiguous": "choose-first"
            }"#,
        )
        .expect("expected canonical program must parse");

        let actual_value =
            serde_json::to_value(actual_program).expect("serialize actual canonical program");
        let expected_value =
            serde_json::to_value(expected_program).expect("serialize expected canonical program");
        assert_eq!(actual_value, expected_value);
    }

    #[test]
    fn rules_sexpr_003_unbound_head_var_maps_to_unbound_var() {
        let sexpr = rules_sexpr_fixture_contents("unbound_var_failure.sx");
        let program = parse_rules_sexpr_program(&sexpr).expect("sugar parse must succeed");
        let error = compile_rules_program_v0(&program).expect_err("RULES-SEXPR-003 must fail");
        assert_eq!(error, FAILURE_CODE_UNBOUND_VAR);
    }

    #[test]
    fn rules_sexpr_004_oversized_input_maps_to_schema_mismatch() {
        let oversized_comment = "x".repeat(MAX_RULES_SEXPR_BYTES + 1);
        let sexpr = format!(
            "#{}\n(rules-sexpr-v0 (facts) (rules) (query (route ?r)) (routing_policy (route_predicate route) (no_match_policy error) (ambiguous_policy allow_multiple)))",
            oversized_comment
        );

        let error =
            parse_rules_sexpr_program(&sexpr).expect_err("oversized RulesSExpr source must fail");
        assert_eq!(error, FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    #[test]
    fn rules_sexpr_005_token_explosion_maps_to_schema_mismatch() {
        let exploded_terms = "a ".repeat(MAX_RULES_SEXPR_TOKENS + 256);
        let sexpr = format!(
            "(rules-sexpr-v0 (facts (f {exploded_terms})) (rules (:- (route ok) (f ?x))) (query (route ?r)) (routing_policy (route_predicate route) (no_match_policy error) (ambiguous_policy allow_multiple)))"
        );
        assert!(
            sexpr.len() <= MAX_RULES_SEXPR_BYTES,
            "token explosion fixture must stay below byte limit"
        );

        let error = parse_rules_sexpr_program(&sexpr).expect_err("token explosion must fail");
        assert_eq!(error, FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH);
    }

    #[test]
    fn rules_step_requires_exactly_one_rules_payload_form() {
        let input = parse_eval_run_input_v0(
            r#"{
                "format_id": "portable_workflow.eval_ir.v0",
                "ir_version": "v0",
                "entry_step_id": "S0001",
                "steps": [
                    {
                        "step_id": "S0001",
                        "op": "choose_rules_v0",
                        "rules_program": {
                            "facts": [["risk_score", "case-001", 82]],
                            "rules": [
                                {
                                    "head": ["route", ":open_case"],
                                    "body": [["risk_score", "?case", "?score"], [">=", "?score", 80]]
                                }
                            ],
                            "query": ["route", "?r"],
                            "selection": "canonical-first",
                            "on_no_match": "error",
                            "on_ambiguous": "choose-first"
                        },
                        "rules_sexpr": "(rules-sexpr-v0 (facts) (rules) (query (route ?r)) (routing_policy (route_predicate route) (no_match_policy error) (ambiguous_policy allow_multiple)))",
                        "routes": {
                            ":open_case": "S0002"
                        }
                    },
                    {
                        "step_id": "S0002",
                        "op": "end"
                    }
                ]
            }"#,
            r#"{}"#,
            None,
            None,
        )
        .expect("input should parse");

        let result = evaluate_eval_ir_v0(input);
        assert_eq!(result.control, super::EvalControlV0::Error);
        assert_eq!(
            result.errors,
            vec![FAILURE_CODE_PROTOCOL_SCHEMA_MISMATCH.to_string()]
        );
    }

    fn evaluate_rules(program_json: &str) -> Result<String, String> {
        let program: RulesProgramV0 =
            serde_json::from_str(program_json).expect("rules program fixture must parse");
        let compiled = compile_rules_program_v0(&program).map_err(|code| code.to_string())?;
        evaluate_rules_program_v0(&compiled).map_err(|code| code.to_string())
    }

    #[test]
    fn rules_001_threshold_routes_to_open_case() {
        let route = evaluate_rules(
            r#"{
                "facts": [
                    ["risk_score", "case-001", 82],
                    ["doc_complete", "case-001", true]
                ],
                "rules": [
                    {
                        "head": ["route", ":open_case"],
                        "body": [
                            ["risk_score", "?case", "?score"],
                            [">=", "?score", 80],
                            ["doc_complete", "?case", true]
                        ]
                    },
                    {
                        "head": ["route", ":wait_docs"],
                        "body": [
                            ["doc_complete", "?case", false]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": "error",
                "on_ambiguous": "choose-first"
            }"#,
        )
        .expect("RULES-001 must evaluate");
        assert_eq!(route, ":open_case");
    }

    #[test]
    fn rules_002_allowlist_routes_to_wait_docs() {
        let route = evaluate_rules(
            r#"{
                "facts": [
                    ["country", "case-002", "SE"],
                    ["doc_status", "case-002", "missing_income_proof"]
                ],
                "rules": [
                    {
                        "head": ["route", ":wait_docs"],
                        "body": [
                            ["country", "?case", "?c"],
                            ["in", "?c", ["US", "CA", "SE"]],
                            ["doc_status", "?case", "missing_income_proof"]
                        ]
                    },
                    {
                        "head": ["route", ":open_case"],
                        "body": [
                            ["country", "?case", "?c"],
                            ["in", "?c", ["US", "CA", "SE"]],
                            ["doc_status", "?case", "complete"]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": "error",
                "on_ambiguous": "choose-first"
            }"#,
        )
        .expect("RULES-002 must evaluate");
        assert_eq!(route, ":wait_docs");
    }

    #[test]
    fn rules_003_ambiguous_policy_error_returns_ambiguous_match() {
        let error = evaluate_rules(
            r#"{
                "facts": [
                    ["risk_score", "case-003", 75]
                ],
                "rules": [
                    {
                        "head": ["route", ":open_case"],
                        "body": [
                            ["risk_score", "?case", "?score"],
                            [">=", "?score", 70]
                        ]
                    },
                    {
                        "head": ["route", ":wait_docs"],
                        "body": [
                            ["risk_score", "?case", "?score"],
                            [">=", "?score", 70]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": "error",
                "on_ambiguous": "error"
            }"#,
        )
        .expect_err("RULES-003 must fail");
        assert_eq!(error, FAILURE_CODE_AMBIGUOUS_MATCH);
    }

    #[test]
    fn rules_005_negation_is_forbidden_feature() {
        let error = evaluate_rules(
            r#"{
                "facts": [
                    ["doc_complete", "case-005", false]
                ],
                "rules": [
                    {
                        "head": ["route", ":open_case"],
                        "body": [
                            ["doc_complete", "?case", "?ok"],
                            ["not", ["=", "?ok", false]]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": "error",
                "on_ambiguous": "error"
            }"#,
        )
        .expect_err("RULES-005 must fail");
        assert_eq!(error, FAILURE_CODE_FORBIDDEN_FEATURE);
    }

    #[test]
    fn rules_006_unbound_head_var_is_rejected() {
        let error = evaluate_rules(
            r#"{
                "facts": [
                    ["risk_score", "case-006", 91]
                ],
                "rules": [
                    {
                        "head": ["route", "?r"],
                        "body": [
                            ["risk_score", "case-006", "?score"],
                            [">", "?score", 70]
                        ]
                    }
                ],
                "query": ["route", "?r"],
                "selection": "canonical-first",
                "on_no_match": "error",
                "on_ambiguous": "choose-first"
            }"#,
        )
        .expect_err("RULES-006 must fail");
        assert_eq!(error, FAILURE_CODE_UNBOUND_VAR);
    }
}
