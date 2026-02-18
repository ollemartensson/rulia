use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn CC_SHA256(data: *const core::ffi::c_void, len: u32, md: *mut u8) -> *mut u8;
}

fn main() -> Result<(), String> {
    let args = Args::parse(env::args().skip(1).collect())?;
    let vectors = load_vectors(&args.vectors_dir)?;
    if vectors.is_empty() {
        return Err(format!(
            "no .json vectors found in {}",
            args.vectors_dir.display()
        ));
    }

    for vector in &vectors {
        validate_vector(vector)?;
    }

    let values = KernelValues::new(build_profile_values(&args.profile, &vectors)?)?;
    let threads = args
        .threads
        .unwrap_or_else(|| auto_tune_threads(&values, &args.profile));
    let (warmup_sink, run_sink, elapsed) =
        run_benchmark(&values, args.warmup, args.iterations, threads);
    let checksum = warmup_sink.wrapping_add(run_sink);

    let ops = args.iterations * values.len() as u64;
    let elapsed_ns = elapsed.as_nanos() as u64;
    let ops_per_sec = if elapsed_ns == 0 {
        0.0
    } else {
        (ops as f64) * 1_000_000_000.0 / (elapsed_ns as f64)
    };

    println!(
        "{{\"language\":\"rust\",\"profile\":\"{}\",\"vectors\":{},\"iterations\":{},\"ops\":{},\"threads\":{},\"elapsed_ns\":{},\"ops_per_sec\":{:.3},\"checksum\":\"{:016x}\"}}",
        args.profile,
        values.len(),
        args.iterations,
        ops,
        threads,
        elapsed_ns,
        ops_per_sec,
        checksum
    );

    Ok(())
}

#[derive(Debug)]
struct Args {
    vectors_dir: PathBuf,
    profile: String,
    iterations: u64,
    warmup: u64,
    threads: Option<usize>,
}

impl Args {
    fn parse(raw: Vec<String>) -> Result<Self, String> {
        let mut vectors_dir = PathBuf::from("examples/contracts/canon_vectors");
        let mut profile = String::from("base");
        let mut iterations = 50_000u64;
        let mut warmup = 5_000u64;
        let mut threads = None;

        let mut i = 0usize;
        while i < raw.len() {
            match raw[i].as_str() {
                "--vectors-dir" => {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| "--vectors-dir requires a value".to_string())?;
                    vectors_dir = PathBuf::from(value);
                    i += 2;
                }
                "--profile" => {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| "--profile requires a value".to_string())?;
                    profile = value.to_string();
                    i += 2;
                }
                "--iterations" => {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| "--iterations requires a value".to_string())?;
                    iterations = value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --iterations value: {value}"))?;
                    i += 2;
                }
                "--warmup" => {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| "--warmup requires a value".to_string())?;
                    warmup = value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --warmup value: {value}"))?;
                    i += 2;
                }
                "--threads" => {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| "--threads requires a value".to_string())?;
                    let parsed = value
                        .parse::<usize>()
                        .map_err(|_| format!("invalid --threads value: {value}"))?;
                    if parsed == 0 {
                        return Err("--threads must be >= 1".to_string());
                    }
                    threads = Some(parsed);
                    i += 2;
                }
                "--help" | "-h" => {
                    println!(
                        "usage: cargo run -- --vectors-dir <path> --profile <base|stress> --iterations <n> --warmup <n> [--threads <n>]"
                    );
                    std::process::exit(0);
                }
                unknown => {
                    return Err(format!("unknown argument: {unknown}"));
                }
            }
        }

        Ok(Self {
            vectors_dir,
            profile,
            iterations,
            warmup,
            threads,
        })
    }
}

fn default_threads() -> usize {
    thread::available_parallelism().map_or(1, |count| {
        let total = count.get();
        total.saturating_sub(2).max(1)
    })
}

fn default_pilot_iterations(profile: &str) -> u64 {
    match profile {
        "base" => 40_000,
        "stress" => 4_000,
        _ => 2_000,
    }
}

fn auto_tune_threads(values: &KernelValues, profile: &str) -> usize {
    let max_threads = thread::available_parallelism().map_or(1, |count| count.get());
    if max_threads <= 1 || values.owners.is_empty() {
        return 1;
    }

    let pilot_iterations = default_pilot_iterations(profile);
    let mut candidates = Vec::with_capacity(7);
    for offset in 0..=4usize {
        let candidate = max_threads.saturating_sub(offset).max(1);
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    let half = (max_threads / 2).max(1);
    if !candidates.contains(&half) {
        candidates.push(half);
    }
    if !candidates.contains(&1) {
        candidates.push(1);
    }

    let mut best_threads = default_threads().min(max_threads);
    let mut best_ops_per_sec = 0.0f64;
    for candidate in candidates {
        let start = Instant::now();
        let _ = run_iterations(values, pilot_iterations, candidate);
        let elapsed_ns = start.elapsed().as_nanos() as f64;
        if elapsed_ns == 0.0 {
            return candidate;
        }
        let ops = (pilot_iterations as f64) * (values.len() as f64);
        let ops_per_sec = ops * 1_000_000_000.0 / elapsed_ns;
        if ops_per_sec > best_ops_per_sec {
            best_ops_per_sec = ops_per_sec;
            best_threads = candidate;
        }
    }

    best_threads
}

#[derive(Debug)]
struct VectorCase {
    stem: String,
    value: Value,
    expected_bytes: Vec<u8>,
    expected_sha: String,
}

struct KernelValues {
    owners: Vec<Vec<u8>>,
    lens_u32: Vec<u32>,
    lens_u64: Vec<u64>,
}

impl KernelValues {
    fn new(owners: Vec<Vec<u8>>) -> Result<Self, String> {
        let mut lens_u32 = Vec::with_capacity(owners.len());
        let mut lens_u64 = Vec::with_capacity(owners.len());
        for item in &owners {
            let len = item.len();
            lens_u32.push(
                u32::try_from(len)
                    .map_err(|_| format!("vector payload too large for CC_SHA256: {len} bytes"))?,
            );
            lens_u64.push(len as u64);
        }
        Ok(Self {
            owners,
            lens_u32,
            lens_u64,
        })
    }

    fn len(&self) -> usize {
        self.owners.len()
    }
}

fn load_vectors(dir: &Path) -> Result<Vec<VectorCase>, String> {
    let mut json_paths = Vec::new();
    for entry in fs::read_dir(dir)
        .map_err(|err| format!("failed to read vectors dir {}: {err}", dir.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read vectors entry: {err}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            json_paths.push(path);
        }
    }
    json_paths.sort();

    let mut out = Vec::with_capacity(json_paths.len());
    for path in json_paths {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("invalid vector file name: {}", path.display()))?
            .to_string();

        let raw = fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let value = serde_json::from_str::<Value>(&raw)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;

        let expected_hex_path = dir.join(format!("{stem}.canon.hex"));
        let expected_hex = fs::read_to_string(&expected_hex_path)
            .map_err(|err| format!("failed to read {}: {err}", expected_hex_path.display()))?;
        let expected_bytes = hex_to_bytes(expected_hex.trim())?;

        let expected_sha_path = dir.join(format!("{stem}.sha256"));
        let expected_sha = fs::read_to_string(&expected_sha_path)
            .map_err(|err| format!("failed to read {}: {err}", expected_sha_path.display()))?
            .trim()
            .to_ascii_lowercase();

        out.push(VectorCase {
            stem,
            value,
            expected_bytes,
            expected_sha,
        });
    }

    Ok(out)
}

fn validate_vector(vector: &VectorCase) -> Result<(), String> {
    let actual = canon_json_bytes(&vector.value)?;
    if actual != vector.expected_bytes {
        return Err(format!(
            "vector {} bytes mismatch (expected_len={}, actual_len={})",
            vector.stem,
            vector.expected_bytes.len(),
            actual.len()
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&actual);
    let digest = hasher.finalize();
    let sha = bytes_to_hex(&digest);
    if sha != vector.expected_sha {
        return Err(format!(
            "vector {} sha mismatch (expected={}, actual={})",
            vector.stem, vector.expected_sha, sha
        ));
    }

    Ok(())
}

fn build_profile_values(profile: &str, vectors: &[VectorCase]) -> Result<Vec<Vec<u8>>, String> {
    match profile {
        "base" => Ok(vectors
            .iter()
            .map(|vector| vector.expected_bytes.clone())
            .collect()),
        "stress" => {
            let mut out = Vec::with_capacity(vectors.len() * 20);
            for round in 0..20u64 {
                for (index, vector) in vectors.iter().enumerate() {
                    let payload = vector.value.clone();
                    let mirror = payload.clone();
                    let record = json!({
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
                    });
                    out.push(canon_json_bytes(&record)?);
                }
            }
            Ok(out)
        }
        other => Err(format!(
            "unsupported profile: {other} (expected base|stress)"
        )),
    }
}

fn run_iterations(values: &KernelValues, iterations: u64, threads: usize) -> u64 {
    if iterations == 0 || values.owners.is_empty() {
        return 0;
    }

    let workers = threads.max(1).min(iterations as usize);
    if workers == 1 {
        return run_iterations_single(values, iterations);
    }

    let chunk = iterations.div_ceil(workers as u64);
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = (worker as u64) * chunk;
            if start >= iterations {
                break;
            }
            let reps = (iterations - start).min(chunk);
            handles.push(scope.spawn(move || run_iterations_single(values, reps)));
        }

        let mut total = 0u64;
        for handle in handles {
            let partial = handle.join().expect("benchmark worker panicked");
            total = total.wrapping_add(partial);
        }
        total
    })
}

fn run_benchmark(
    values: &KernelValues,
    warmup: u64,
    iterations: u64,
    threads: usize,
) -> (u64, u64, Duration) {
    if values.owners.is_empty() {
        return (0, 0, Duration::ZERO);
    }

    if iterations == 0 {
        return (run_iterations(values, warmup, threads), 0, Duration::ZERO);
    }

    let workers = threads.max(1).min(iterations as usize);
    if workers == 1 {
        let warmup_sink = run_iterations_single(values, warmup);
        let start = Instant::now();
        let run_sink = run_iterations_single(values, iterations);
        return (warmup_sink, run_sink, start.elapsed());
    }

    let warmup_counts = split_counts(warmup, workers);
    let run_counts = split_counts(iterations, workers);
    let warmup_barrier = Arc::new(Barrier::new(workers + 1));
    let start_barrier = Arc::new(Barrier::new(workers + 1));

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let warm_reps = warmup_counts[worker];
            let run_reps = run_counts[worker];
            let warmup_barrier = Arc::clone(&warmup_barrier);
            let start_barrier = Arc::clone(&start_barrier);
            handles.push(scope.spawn(move || {
                let warmup_sink = run_iterations_single(values, warm_reps);
                warmup_barrier.wait();
                start_barrier.wait();
                let run_sink = run_iterations_single(values, run_reps);
                (warmup_sink, run_sink)
            }));
        }

        warmup_barrier.wait();
        let start = Instant::now();
        start_barrier.wait();

        let mut warmup_sink = 0u64;
        let mut run_sink = 0u64;
        for handle in handles {
            let (partial_warmup, partial_run) = handle.join().expect("benchmark worker panicked");
            warmup_sink = warmup_sink.wrapping_add(partial_warmup);
            run_sink = run_sink.wrapping_add(partial_run);
        }

        (warmup_sink, run_sink, start.elapsed())
    })
}

fn split_counts(total: u64, workers: usize) -> Vec<u64> {
    let workers_u64 = workers as u64;
    let base = total / workers_u64;
    let extra = total % workers_u64;
    (0..workers_u64)
        .map(|index| base + u64::from(index < extra))
        .collect()
}

#[cfg(target_os = "macos")]
fn run_iterations_single(values: &KernelValues, iterations: u64) -> u64 {
    let owners = &values.owners;
    let lens_u32 = &values.lens_u32;
    let lens = &values.lens_u64;
    let mut digest = [0u8; 32];
    let mut checksum = 0u64;
    for _ in 0..iterations {
        let mut sink = 0u64;
        for index in 0..owners.len() {
            let bytes = unsafe { owners.get_unchecked(index) };
            let len_u32 = unsafe { *lens_u32.get_unchecked(index) };
            let len_u64 = unsafe { *lens.get_unchecked(index) };
            unsafe {
                let _ = CC_SHA256(
                    bytes.as_ptr().cast::<core::ffi::c_void>(),
                    len_u32,
                    digest.as_mut_ptr(),
                );
            }
            let acc = unsafe { u64::from_be(std::ptr::read_unaligned(digest.as_ptr().cast())) };
            sink = sink.wrapping_add(acc ^ len_u64);
        }
        checksum = checksum.wrapping_add(sink);
    }
    checksum
}

#[cfg(not(target_os = "macos"))]
fn run_iterations_single(values: &KernelValues, iterations: u64) -> u64 {
    let owners = &values.owners;
    let lens = &values.lens_u64;
    let mut hasher = Sha256::new();
    let mut checksum = 0u64;
    for _ in 0..iterations {
        let mut sink = 0u64;
        for index in 0..owners.len() {
            let bytes = unsafe { owners.get_unchecked(index) };
            let len_u64 = unsafe { *lens.get_unchecked(index) };
            hasher.update(bytes);
            let digest = hasher.finalize_reset();
            let acc = unsafe { u64::from_be(std::ptr::read_unaligned(digest.as_ptr().cast())) };
            sink = sink.wrapping_add(acc ^ len_u64);
        }
        checksum = checksum.wrapping_add(sink);
    }
    checksum
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
                let mut buffer = itoa::Buffer::new();
                out.extend_from_slice(buffer.format(int).as_bytes());
            } else if let Some(uint) = number.as_u64() {
                let mut buffer = itoa::Buffer::new();
                out.extend_from_slice(buffer.format(uint).as_bytes());
            } else if let Some(float) = number.as_f64() {
                write_normalized_float(float, out)?;
            } else {
                return Err(format!("unsupported number value: {number}"));
            }
        }
        Value::String(string) => write_json_string(string, out),
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
            out.push(b'{');
            if map_keys_are_sorted(map) {
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_json_string(key, out);
                    out.push(b':');
                    write_canon(item, out)?;
                }
            } else {
                let mut entries: Vec<(&str, &Value)> =
                    map.iter().map(|(key, item)| (key.as_str(), item)).collect();
                entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
                for (index, (key, item)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_json_string(key, out);
                    out.push(b':');
                    write_canon(item, out)?;
                }
            }
            out.push(b'}');
        }
    }

    Ok(())
}

fn map_keys_are_sorted(map: &serde_json::Map<String, Value>) -> bool {
    let mut iter = map.keys();
    let Some(mut prev) = iter.next() else {
        return true;
    };
    for key in iter {
        if prev > key {
            return false;
        }
        prev = key;
    }
    true
}

fn write_normalized_float(float: f64, out: &mut Vec<u8>) -> Result<(), String> {
    if !float.is_finite() {
        return Err("non-finite float not allowed in canonical scope".to_string());
    }
    if float == 0.0 {
        out.push(b'0');
        return Ok(());
    }

    let mut buf = ryu::Buffer::new();
    let raw = buf.format_finite(float).as_bytes();
    if let Some(exp_idx) = raw.iter().position(|&b| b == b'e' || b == b'E') {
        out.extend_from_slice(&raw[..exp_idx]);
        out.push(b'e');

        let mut cursor = exp_idx + 1;
        let mut negative = false;
        if cursor < raw.len() {
            if raw[cursor] == b'+' {
                cursor += 1;
            } else if raw[cursor] == b'-' {
                negative = true;
                cursor += 1;
            }
        }
        while cursor < raw.len() && raw[cursor] == b'0' {
            cursor += 1;
        }
        if negative {
            out.push(b'-');
        }
        if cursor == raw.len() {
            out.push(b'0');
        } else {
            out.extend_from_slice(&raw[cursor..]);
        }
    } else {
        out.extend_from_slice(raw);
    }
    Ok(())
}

fn write_json_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    let bytes = value.as_bytes();
    let mut chunk_start = 0usize;
    for (idx, byte) in bytes.iter().copied().enumerate() {
        let escape = match byte {
            b'"' => Some(br#"\""#.as_slice()),
            b'\\' => Some(br#"\\"#.as_slice()),
            b'\x08' => Some(br#"\b"#.as_slice()),
            b'\x0c' => Some(br#"\f"#.as_slice()),
            b'\n' => Some(br#"\n"#.as_slice()),
            b'\r' => Some(br#"\r"#.as_slice()),
            b'\t' => Some(br#"\t"#.as_slice()),
            0x00..=0x1f => None,
            _ => continue,
        };

        if chunk_start < idx {
            out.extend_from_slice(&bytes[chunk_start..idx]);
        }

        if let Some(short_escape) = escape {
            out.extend_from_slice(short_escape);
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(br#"\u00"#);
            out.push(HEX[((byte >> 4) & 0x0f) as usize]);
            out.push(HEX[(byte & 0x0f) as usize]);
        }

        chunk_start = idx + 1;
    }
    if chunk_start < bytes.len() {
        out.extend_from_slice(&bytes[chunk_start..]);
    }
    out.push(b'"');
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
