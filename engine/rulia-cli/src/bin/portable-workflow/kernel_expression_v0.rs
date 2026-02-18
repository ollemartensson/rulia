use std::collections::BTreeMap;

use rulia::Value as RuliaValue;
use serde_json::{Map, Number, Value};

pub(crate) fn resolve_payload_against_state_json(
    payload: &Value,
    state: &Value,
) -> Result<Value, String> {
    let payload_value = json_to_rulia(payload)?;
    let state_value = json_to_rulia(state)?;
    let resolved = rulia::evaluate_kernel_expression_payload(&payload_value, &state_value)
        .map_err(|error| error.to_string())?;
    rulia_to_json(&resolved)
}

pub(crate) fn payload_contains_expression_json(payload: &Value) -> Result<bool, String> {
    let payload_value = json_to_rulia(payload)?;
    Ok(rulia::payload_contains_kernel_expression(&payload_value))
}

fn json_to_rulia(value: &Value) -> Result<RuliaValue, String> {
    match value {
        Value::Null => Ok(RuliaValue::Nil),
        Value::Bool(boolean) => Ok(RuliaValue::Bool(*boolean)),
        Value::Number(number) => json_number_to_rulia(number),
        Value::String(text) => Ok(RuliaValue::String(text.clone())),
        Value::Array(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(json_to_rulia(item)?);
            }
            Ok(RuliaValue::Vector(converted))
        }
        Value::Object(entries) => {
            let mut ordered = BTreeMap::new();
            for (key, candidate) in entries {
                if ordered.contains_key(key) {
                    return Err(format!(
                        "duplicate object key '{key}' is unsupported in kernel expression payload"
                    ));
                }
                ordered.insert(key.clone(), json_to_rulia(candidate)?);
            }
            let mut converted = Vec::with_capacity(ordered.len());
            for (key, candidate) in ordered {
                converted.push((RuliaValue::String(key), candidate));
            }
            Ok(RuliaValue::Map(converted))
        }
    }
}

fn json_number_to_rulia(number: &Number) -> Result<RuliaValue, String> {
    if let Some(value) = number.as_i64() {
        return Ok(RuliaValue::Int(value));
    }
    if let Some(value) = number.as_u64() {
        return Ok(RuliaValue::UInt(value));
    }
    let Some(value) = number.as_f64() else {
        return Err("unsupported JSON number in kernel expression payload".to_string());
    };
    if !value.is_finite() {
        return Err("non-finite float in kernel expression payload".to_string());
    }
    Ok(RuliaValue::Float64(value.into()))
}

fn rulia_to_json(value: &RuliaValue) -> Result<Value, String> {
    match value {
        RuliaValue::Nil => Ok(Value::Null),
        RuliaValue::Bool(boolean) => Ok(Value::Bool(*boolean)),
        RuliaValue::Int(number) => Ok(Value::Number(Number::from(*number))),
        RuliaValue::UInt(number) => Ok(Value::Number(Number::from(*number))),
        RuliaValue::Float32(number) => float_to_json(f64::from(number.into_inner())),
        RuliaValue::Float64(number) => float_to_json(number.into_inner()),
        RuliaValue::BigInt(_) => {
            Err("bigint is unsupported in kernel expression JSON bridge payloads".to_string())
        }
        RuliaValue::String(text) => Ok(Value::String(text.clone())),
        RuliaValue::Vector(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(rulia_to_json(item)?);
            }
            Ok(Value::Array(converted))
        }
        RuliaValue::Map(entries) => {
            let mut ordered = BTreeMap::new();
            for (key, candidate) in entries {
                let key_name = match key {
                    RuliaValue::String(name) => name.clone(),
                    RuliaValue::Keyword(keyword) => keyword.as_symbol().as_str(),
                    _ => {
                        return Err(
                            "kernel expression payload maps must use string/keyword keys"
                                .to_string(),
                        );
                    }
                };
                let converted = rulia_to_json(candidate)?;
                if ordered.insert(key_name.clone(), converted).is_some() {
                    return Err(format!(
                        "duplicate map key '{key_name}' in kernel expression payload"
                    ));
                }
            }
            let mut object = Map::new();
            for (key, candidate) in ordered {
                object.insert(key, candidate);
            }
            Ok(Value::Object(object))
        }
        other => Err(format!(
            "value kind '{}' is unsupported in kernel expression JSON bridge",
            other.kind()
        )),
    }
}

fn float_to_json(value: f64) -> Result<Value, String> {
    let Some(number) = Number::from_f64(value) else {
        return Err("non-finite float in kernel expression payload".to_string());
    };
    Ok(Value::Number(number))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{payload_contains_expression_json, resolve_payload_against_state_json};

    #[test]
    fn resolves_request_args_from_state() {
        let payload = json!({
            "amount": {"$expr": "state_get", "path": "order.amount"},
            "channel": "email",
        });
        let state = json!({
            "order": {"amount": 1250, "status": "new"}
        });
        let resolved =
            resolve_payload_against_state_json(&payload, &state).expect("resolve payload");
        assert_eq!(
            resolved,
            json!({
                "amount": 1250,
                "channel": "email",
            })
        );
    }

    #[test]
    fn detects_expression_markers() {
        let payload = json!({
            "amount": {"$expr": "state_get", "path": "order.amount"},
            "channel": "email",
        });
        assert!(payload_contains_expression_json(&payload).expect("detect markers"));
    }
}
