use std::cmp::Ordering;

use num_traits::ToPrimitive;

use crate::{RuliaError, RuliaResult, Value};

const EXPR_FIELD: &str = "$expr";
const FUNCTION_FIELD: &str = "$fn";
const FUNCTION_BODY_FIELD: &str = "body";

/// Resolve a workflow kernel payload against deterministic state.
///
/// Supported payload markers:
/// - `{"$expr": "..."}` expression nodes
/// - `{"$fn": "state", "body": ...}` unary function payloads invoked with state
///
/// Non-marker maps/vectors are resolved recursively so nested expression markers are supported.
pub fn evaluate_kernel_expression_payload(payload: &Value, state: &Value) -> RuliaResult<Value> {
    resolve_payload(payload, state)
}

/// Returns true when a payload contains kernel expression markers.
pub fn payload_contains_kernel_expression(payload: &Value) -> bool {
    match payload {
        Value::Map(entries) => {
            if map_get(entries, EXPR_FIELD).is_some() || map_get(entries, FUNCTION_FIELD).is_some()
            {
                return true;
            }
            entries
                .iter()
                .any(|(_, value)| payload_contains_kernel_expression(value))
        }
        Value::Vector(items) | Value::Set(items) => {
            items.iter().any(payload_contains_kernel_expression)
        }
        Value::Tagged(tagged) => payload_contains_kernel_expression(tagged.value.as_ref()),
        Value::Annotated(annotation) => {
            payload_contains_kernel_expression(annotation.value.as_ref())
        }
        _ => false,
    }
}

fn resolve_payload(payload: &Value, state: &Value) -> RuliaResult<Value> {
    match payload {
        Value::Map(entries) => {
            if map_get(entries, FUNCTION_FIELD).is_some() {
                return evaluate_function_payload(entries, state);
            }
            if map_get(entries, EXPR_FIELD).is_some() {
                return evaluate_expression_payload(entries, state);
            }

            let mut resolved = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                resolved.push((key.clone(), resolve_payload(value, state)?));
            }
            Ok(Value::Map(resolved))
        }
        Value::Vector(items) => {
            let mut resolved = Vec::with_capacity(items.len());
            for item in items {
                resolved.push(resolve_payload(item, state)?);
            }
            Ok(Value::Vector(resolved))
        }
        Value::Set(items) => {
            let mut resolved = Vec::with_capacity(items.len());
            for item in items {
                resolved.push(resolve_payload(item, state)?);
            }
            Ok(Value::Set(resolved))
        }
        Value::Tagged(tagged) => resolve_payload(tagged.value.as_ref(), state),
        Value::Annotated(annotation) => resolve_payload(annotation.value.as_ref(), state),
        _ => Ok(payload.clone()),
    }
}

fn evaluate_function_payload(entries: &[(Value, Value)], state: &Value) -> RuliaResult<Value> {
    ensure_allowed_keys(
        entries,
        &[FUNCTION_FIELD, FUNCTION_BODY_FIELD],
        "function payload",
    )?;
    let parameter = expect_string_field(entries, FUNCTION_FIELD, "function payload")?;
    if parameter != "state" {
        return Err(RuliaError::Evaluation(
            "function payload must bind '$fn' to 'state'".to_string(),
        ));
    }
    let body = map_get(entries, FUNCTION_BODY_FIELD)
        .ok_or_else(|| RuliaError::Evaluation("function payload must include body".to_string()))?;
    resolve_payload(body, state)
}

fn evaluate_expression_payload(entries: &[(Value, Value)], state: &Value) -> RuliaResult<Value> {
    let op = expect_string_field(entries, EXPR_FIELD, "expression payload")?;
    match op.as_str() {
        "state_get" => {
            ensure_allowed_keys(entries, &[EXPR_FIELD, "path"], "state_get expression")?;
            let path = expect_string_field(entries, "path", "state_get expression")?;
            lookup_path(state, path.as_str())
        }
        "if" => {
            ensure_allowed_keys(
                entries,
                &[EXPR_FIELD, "cond", "then", "else"],
                "if expression",
            )?;
            let cond = resolve_required_field(entries, "cond", state, "if expression")?;
            let is_true = expect_bool(&cond, "if expression cond must evaluate to bool")?;
            if is_true {
                resolve_required_field(entries, "then", state, "if expression")
            } else {
                resolve_required_field(entries, "else", state, "if expression")
            }
        }
        "not" => {
            ensure_allowed_keys(entries, &[EXPR_FIELD, "arg"], "not expression")?;
            let arg = resolve_required_field(entries, "arg", state, "not expression")?;
            Ok(Value::Bool(!expect_bool(
                &arg,
                "not expression arg must evaluate to bool",
            )?))
        }
        "and" => {
            ensure_allowed_keys(entries, &[EXPR_FIELD, "args"], "and expression")?;
            let args = expect_vector_field(entries, "args", "and expression")?;
            if args.is_empty() {
                return Err(RuliaError::Evaluation(
                    "and expression args must not be empty".to_string(),
                ));
            }
            for arg in args {
                let resolved = resolve_payload(arg, state)?;
                if !expect_bool(&resolved, "and expression args must evaluate to bool")? {
                    return Ok(Value::Bool(false));
                }
            }
            Ok(Value::Bool(true))
        }
        "or" => {
            ensure_allowed_keys(entries, &[EXPR_FIELD, "args"], "or expression")?;
            let args = expect_vector_field(entries, "args", "or expression")?;
            if args.is_empty() {
                return Err(RuliaError::Evaluation(
                    "or expression args must not be empty".to_string(),
                ));
            }
            for arg in args {
                let resolved = resolve_payload(arg, state)?;
                if expect_bool(&resolved, "or expression args must evaluate to bool")? {
                    return Ok(Value::Bool(true));
                }
            }
            Ok(Value::Bool(false))
        }
        "==" | "!=" | ">" | ">=" | "<" | "<=" => {
            ensure_allowed_keys(
                entries,
                &[EXPR_FIELD, "left", "right"],
                "comparison expression",
            )?;
            let left = resolve_required_field(entries, "left", state, "comparison expression")?;
            let right = resolve_required_field(entries, "right", state, "comparison expression")?;
            match op.as_str() {
                "==" => Ok(Value::Bool(left == right)),
                "!=" => Ok(Value::Bool(left != right)),
                ">" => Ok(Value::Bool(
                    compare_values(&left, &right)? == Ordering::Greater,
                )),
                ">=" => Ok(Value::Bool(
                    compare_values(&left, &right)? != Ordering::Less,
                )),
                "<" => Ok(Value::Bool(
                    compare_values(&left, &right)? == Ordering::Less,
                )),
                "<=" => Ok(Value::Bool(
                    compare_values(&left, &right)? != Ordering::Greater,
                )),
                _ => unreachable!("operator matched above"),
            }
        }
        _ => Err(RuliaError::Evaluation(format!(
            "unsupported expression op '{op}'"
        ))),
    }
}

fn resolve_required_field(
    entries: &[(Value, Value)],
    field: &str,
    state: &Value,
    context: &str,
) -> RuliaResult<Value> {
    let value = map_get(entries, field)
        .ok_or_else(|| RuliaError::Evaluation(format!("{context} must include '{field}'")))?;
    resolve_payload(value, state)
}

fn expect_vector_field<'a>(
    entries: &'a [(Value, Value)],
    field: &str,
    context: &str,
) -> RuliaResult<&'a [Value]> {
    let value = map_get(entries, field)
        .ok_or_else(|| RuliaError::Evaluation(format!("{context} must include '{field}'")))?;
    let Value::Vector(items) = value else {
        return Err(RuliaError::Evaluation(format!(
            "{context} '{field}' must be a vector"
        )));
    };
    Ok(items.as_slice())
}

fn expect_string_field(
    entries: &[(Value, Value)],
    field: &str,
    context: &str,
) -> RuliaResult<String> {
    let value = map_get(entries, field)
        .ok_or_else(|| RuliaError::Evaluation(format!("{context} must include '{field}'")))?;
    match value {
        Value::String(text) if !text.trim().is_empty() => Ok(text.clone()),
        _ => Err(RuliaError::Evaluation(format!(
            "{context} '{field}' must be a non-empty string"
        ))),
    }
}

fn ensure_allowed_keys(
    entries: &[(Value, Value)],
    allowed_keys: &[&str],
    context: &str,
) -> RuliaResult<()> {
    for (key, _) in entries {
        let Some(name) = map_key_to_owned_name(key) else {
            return Err(RuliaError::Evaluation(format!(
                "{context} map keys must be strings or keywords"
            )));
        };
        if !allowed_keys.iter().any(|allowed| *allowed == name) {
            return Err(RuliaError::Evaluation(format!(
                "{context} includes unsupported field '{name}'"
            )));
        }
    }
    Ok(())
}

fn map_get<'a>(entries: &'a [(Value, Value)], key_name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| map_key_matches(key, key_name).then_some(value))
}

fn map_key_matches(key: &Value, key_name: &str) -> bool {
    match key {
        Value::String(name) => name == key_name,
        Value::Keyword(keyword) => keyword.as_symbol().as_str() == key_name,
        _ => false,
    }
}

fn map_key_to_owned_name(key: &Value) -> Option<String> {
    match key {
        Value::String(name) => Some(name.clone()),
        Value::Keyword(keyword) => Some(keyword.as_symbol().as_str()),
        _ => None,
    }
}

fn lookup_path(state: &Value, path: &str) -> RuliaResult<Value> {
    if path.trim().is_empty() {
        return Err(RuliaError::Evaluation(
            "state_get expression path must be non-empty".to_string(),
        ));
    }

    let mut current = state;
    for segment in path.split('.') {
        if segment.is_empty() {
            return Err(RuliaError::Evaluation(format!(
                "state_get expression path '{path}' contains an empty segment"
            )));
        }
        current = match current {
            Value::Map(entries) => lookup_map_segment(entries, segment).ok_or_else(|| {
                RuliaError::Evaluation(format!(
                    "state_get expression path '{path}' missing segment '{segment}'"
                ))
            })?,
            Value::Vector(items) => {
                let index: usize = segment.parse().map_err(|_| {
                    RuliaError::Evaluation(format!(
                        "state_get expression path '{path}' has non-numeric vector segment '{segment}'"
                    ))
                })?;
                items.get(index).ok_or_else(|| {
                    RuliaError::Evaluation(format!(
                        "state_get expression path '{path}' index '{index}' is out of bounds"
                    ))
                })?
            }
            Value::Set(_) => {
                return Err(RuliaError::Evaluation(format!(
                    "state_get expression path '{path}' cannot traverse set segment '{segment}'"
                )));
            }
            _ => {
                return Err(RuliaError::Evaluation(format!(
                    "state_get expression path '{path}' cannot traverse non-container segment '{segment}'"
                )));
            }
        };
    }
    Ok(current.clone())
}

fn lookup_map_segment<'a>(entries: &'a [(Value, Value)], segment: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(key, value)| match key {
        Value::String(name) if name == segment => Some(value),
        Value::Keyword(keyword) if keyword.as_symbol().as_str() == segment => Some(value),
        _ => None,
    })
}

fn expect_bool(value: &Value, message: &str) -> RuliaResult<bool> {
    match value {
        Value::Bool(boolean) => Ok(*boolean),
        _ => Err(RuliaError::Evaluation(message.to_string())),
    }
}

fn compare_values(left: &Value, right: &Value) -> RuliaResult<Ordering> {
    if let (Some(left_num), Some(right_num)) = (value_to_f64(left), value_to_f64(right)) {
        return left_num.partial_cmp(&right_num).ok_or_else(|| {
            RuliaError::Evaluation("numeric comparison produced NaN ordering".to_string())
        });
    }
    match (left, right) {
        (Value::String(left), Value::String(right)) => Ok(left.cmp(right)),
        (Value::Bool(left), Value::Bool(right)) => Ok(left.cmp(right)),
        _ => Err(RuliaError::Evaluation(format!(
            "comparison type mismatch: '{}' vs '{}'",
            left.kind(),
            right.kind()
        ))),
    }
}

fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Int(number) => Some(*number as f64),
        Value::UInt(number) => Some(*number as f64),
        Value::Float32(number) => Some(f64::from(number.into_inner())),
        Value::Float64(number) => Some(number.into_inner()),
        Value::BigInt(number) => number.to_f64(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_kernel_expression_payload, payload_contains_kernel_expression};
    use crate::{Keyword, Value};

    fn object(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::String((*key).to_string()), value.clone()))
                .collect::<Vec<_>>(),
        )
    }

    fn keyword_object(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::Keyword(Keyword::simple(*key)), value.clone()))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn resolves_assign_like_if_expression() {
        let payload = object(&[
            ("$fn", Value::String("state".to_string())),
            (
                "body",
                object(&[
                    ("$expr", Value::String("if".to_string())),
                    (
                        "cond",
                        object(&[
                            ("$expr", Value::String(">=".to_string())),
                            (
                                "left",
                                object(&[
                                    ("$expr", Value::String("state_get".to_string())),
                                    ("path", Value::String("order.amount".to_string())),
                                ]),
                            ),
                            ("right", Value::UInt(1000)),
                        ]),
                    ),
                    ("then", Value::String("high_value".to_string())),
                    ("else", Value::String("standard".to_string())),
                ]),
            ),
        ]);
        let state = object(&[(
            "order",
            object(&[
                ("amount", Value::UInt(1250)),
                ("status", Value::String("new".to_string())),
            ]),
        )]);

        let resolved =
            evaluate_kernel_expression_payload(&payload, &state).expect("resolve payload");
        assert_eq!(resolved, Value::String("high_value".to_string()));
    }

    #[test]
    fn resolves_nested_request_args_payload() {
        let payload = object(&[
            (
                "amount",
                object(&[
                    ("$expr", Value::String("state_get".to_string())),
                    ("path", Value::String("order.amount".to_string())),
                ]),
            ),
            ("channel", Value::String("email".to_string())),
        ]);
        let state = object(&[(
            "order",
            object(&[
                ("amount", Value::UInt(1250)),
                ("status", Value::String("new".to_string())),
            ]),
        )]);

        let resolved =
            evaluate_kernel_expression_payload(&payload, &state).expect("resolve payload");
        assert_eq!(
            resolved,
            object(&[
                ("amount", Value::UInt(1250)),
                ("channel", Value::String("email".to_string())),
            ])
        );
    }

    #[test]
    fn rejects_missing_state_path() {
        let payload = object(&[
            ("$expr", Value::String("state_get".to_string())),
            ("path", Value::String("order.missing".to_string())),
        ]);
        let state = object(&[(
            "order",
            object(&[("status", Value::String("new".to_string()))]),
        )]);

        let error = evaluate_kernel_expression_payload(&payload, &state)
            .expect_err("missing path must fail deterministically");
        assert!(error.to_string().contains("missing segment 'missing'"));
    }

    #[test]
    fn detects_expression_markers_recursively() {
        let payload = object(&[
            ("event", Value::String("request_submitted".to_string())),
            (
                "payload",
                object(&[
                    (
                        "request_count",
                        object(&[
                            ("$expr", Value::String("state_get".to_string())),
                            ("path", Value::String("metrics.request_count".to_string())),
                        ]),
                    ),
                    ("status", Value::String("ok".to_string())),
                ]),
            ),
        ]);
        assert!(payload_contains_kernel_expression(&payload));
    }

    #[test]
    fn supports_keyword_field_names_for_authoring_maps() {
        let payload = keyword_object(&[
            ("$expr", Value::String("state_get".to_string())),
            ("path", Value::String("order.status".to_string())),
        ]);
        let state = object(&[(
            "order",
            object(&[("status", Value::String("open".to_string()))]),
        )]);
        let resolved =
            evaluate_kernel_expression_payload(&payload, &state).expect("resolve payload");
        assert_eq!(resolved, Value::String("open".to_string()));
    }
}
