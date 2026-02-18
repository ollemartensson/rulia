use std::sync::OnceLock;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct VectorCase {
    stem: &'static str,
    value: Value,
    expected_bytes: Vec<u8>,
    expected_sha: String,
}

static BASE_CASES: OnceLock<Result<Vec<VectorCase>, String>> = OnceLock::new();
static BASE_VALUES: OnceLock<Result<Vec<Value>, String>> = OnceLock::new();
static STRESS_VALUES: OnceLock<Result<Vec<Value>, String>> = OnceLock::new();

#[no_mangle]
pub extern "C" fn bench_vectors(profile: u32) -> u32 {
    match profile_values(profile) {
        Ok(values) => values.len() as u32,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn bench_run(profile: u32, iterations: u32, warmup: u32) -> u64 {
    let values = match profile_values(profile) {
        Ok(values) => values,
        Err(_) => return 0,
    };

    let mut warmup_sink = 0u64;
    for _ in 0..warmup {
        warmup_sink = warmup_sink.wrapping_add(run_once(values));
    }

    let mut checksum = warmup_sink;
    for _ in 0..iterations {
        checksum = checksum.wrapping_add(run_once(values));
    }

    checksum
}

fn profile_values(profile: u32) -> Result<&'static Vec<Value>, String> {
    match profile {
        0 => base_values(),
        1 => stress_values(),
        _ => Err(format!("unsupported profile id: {profile} (expected 0=base, 1=stress)")),
    }
}

fn base_cases() -> Result<&'static Vec<VectorCase>, String> {
    match BASE_CASES.get_or_init(load_base_cases) {
        Ok(cases) => Ok(cases),
        Err(err) => Err(err.clone()),
    }
}

fn base_values() -> Result<&'static Vec<Value>, String> {
    match BASE_VALUES.get_or_init(build_base_values) {
        Ok(values) => Ok(values),
        Err(err) => Err(err.clone()),
    }
}

fn stress_values() -> Result<&'static Vec<Value>, String> {
    match STRESS_VALUES.get_or_init(build_stress_values) {
        Ok(values) => Ok(values),
        Err(err) => Err(err.clone()),
    }
}

fn load_base_cases() -> Result<Vec<VectorCase>, String> {
    let sources = [
        (
            "vec001",
            include_str!("../../../../../examples/contracts/canon_vectors/vec001.json"),
            include_str!("../../../../../examples/contracts/canon_vectors/vec001.canon.hex"),
            include_str!("../../../../../examples/contracts/canon_vectors/vec001.sha256"),
        ),
        (
            "vec002",
            include_str!("../../../../../examples/contracts/canon_vectors/vec002.json"),
            include_str!("../../../../../examples/contracts/canon_vectors/vec002.canon.hex"),
            include_str!("../../../../../examples/contracts/canon_vectors/vec002.sha256"),
        ),
        (
            "vec003",
            include_str!("../../../../../examples/contracts/canon_vectors/vec003.json"),
            include_str!("../../../../../examples/contracts/canon_vectors/vec003.canon.hex"),
            include_str!("../../../../../examples/contracts/canon_vectors/vec003.sha256"),
        ),
    ];

    let mut out = Vec::with_capacity(sources.len());
    for (stem, json_text, hex_text, sha_text) in sources {
        let value = serde_json::from_str::<Value>(json_text)
            .map_err(|err| format!("failed to parse {stem}.json: {err}"))?;
        let expected_bytes = hex_to_bytes(hex_text.trim())?;
        let expected_sha = sha_text.trim().to_ascii_lowercase();

        out.push(VectorCase {
            stem,
            value,
            expected_bytes,
            expected_sha,
        });
    }

    Ok(out)
}

fn build_base_values() -> Result<Vec<Value>, String> {
    let cases = base_cases()?;
    for case in cases {
        validate_case(case)?;
    }
    Ok(cases.iter().map(|case| case.value.clone()).collect())
}

fn build_stress_values() -> Result<Vec<Value>, String> {
    let base = base_values()?;
    let mut out = Vec::with_capacity(base.len() * 20);

    for round in 0..20u64 {
        for (index, value) in base.iter().enumerate() {
            let payload = value.clone();
            let mirror = payload.clone();
            out.push(json!({
                "case": round,
                "source_index": index,
                "kind": "stress",
                "payload": payload,
                "echo": [
                    mirror,
                    {
                        "flag": ((round + index as u64) % 2) == 0,
                        "seq": round * 10 + index as u64,
                        "text": "café😀"
                    }
                ],
                "metrics": {
                    "neg": -((round as i64) + index as i64),
                    "big": 1234567890123456789i64,
                    "small": round as i64
                }
            }));
        }
    }

    Ok(out)
}

fn validate_case(case: &VectorCase) -> Result<(), String> {
    let actual = canon_json_bytes(&case.value)?;
    if actual != case.expected_bytes {
        return Err(format!(
            "vector {} bytes mismatch (expected_len={}, actual_len={})",
            case.stem,
            case.expected_bytes.len(),
            actual.len()
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&actual);
    let digest = hasher.finalize();
    let sha = bytes_to_hex(&digest);
    if sha != case.expected_sha {
        return Err(format!(
            "vector {} sha mismatch (expected={}, actual={})",
            case.stem, case.expected_sha, sha
        ));
    }

    Ok(())
}

fn run_once(values: &[Value]) -> u64 {
    let mut sink = 0u64;
    for value in values {
        let bytes = canon_json_bytes(value).expect("canonicalization failed");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();

        let mut acc = [0u8; 8];
        acc.copy_from_slice(&digest[..8]);
        sink = sink.wrapping_add(u64::from_be_bytes(acc) ^ (bytes.len() as u64));
    }
    sink
}

fn canon_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(256);
    write_canon(value, &mut out)?;
    Ok(out)
}

fn write_canon(value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                out.extend_from_slice(int.to_string().as_bytes());
            } else if let Some(uint) = number.as_u64() {
                out.extend_from_slice(uint.to_string().as_bytes());
            } else if let Some(float) = number.as_f64() {
                if !float.is_finite() {
                    return Err("non-finite float not allowed in canonical scope".to_string());
                }
                if float == 0.0 {
                    out.push(b'0');
                } else {
                    let mut s = ryu::Buffer::new().format_finite(float).to_string();
                    if let Some(idx) = s.find('E') {
                        s.replace_range(idx..=idx, "e");
                    }
                    if let Some(idx) = s.find('e') {
                        let mantissa = &s[..idx];
                        let mut exp = s[idx + 1..].replace('+', "");
                        let negative = exp.starts_with('-');
                        if negative {
                            exp.remove(0);
                        }
                        let trimmed = exp.trim_start_matches('0');
                        let exp_final = if trimmed.is_empty() { "0" } else { trimmed };
                        s = if negative {
                            format!("{mantissa}e-{exp_final}")
                        } else {
                            format!("{mantissa}e{exp_final}")
                        };
                    }
                    out.extend_from_slice(s.as_bytes());
                }
            } else {
                return Err(format!("unsupported number value: {number}"));
            }
        }
        Value::String(string) => {
            let json = serde_json::to_string(string)
                .map_err(|err| format!("failed to encode json string: {err}"))?;
            out.extend_from_slice(json.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canon(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();

            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                let key_json = serde_json::to_string(key)
                    .map_err(|err| format!("failed to encode object key: {err}"))?;
                out.extend_from_slice(key_json.as_bytes());
                out.push(b':');
                write_canon(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }

    Ok(())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = from_hex_digit(bytes[i])?;
        let lo = from_hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn from_hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(10 + value - b'a'),
        b'A'..=b'F' => Ok(10 + value - b'A'),
        _ => Err(format!("invalid hex digit: {}", value as char)),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}
