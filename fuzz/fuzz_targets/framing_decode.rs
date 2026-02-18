#![no_main]

use std::fs;
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use rulia::decode_value;

const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut offset = 0usize;
        while offset < data.len() {
            if data.len() - offset < 4 {
                return;
            }
            let len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if len == 0 || len > MAX_FRAME_LEN || len > u32::MAX as usize {
                return;
            }
            if data.len() - offset < len {
                return;
            }

            let payload = &data[offset..offset + len];
            offset += len;
            let _ = decode_value(payload);
        }
    }));

    if result.is_err() {
        record_panic("framing_decode", data);
    }
});

fn record_panic(target: &str, data: &[u8]) {
    let hash = fnv1a64(data);
    let dir = Path::new("fuzz").join("artifacts").join(target);
    if let Err(err) = fs::create_dir_all(&dir) {
        eprintln!("fuzz panic capture failed: target={} err={}", target, err);
        return;
    }
    let path = dir.join(format!("panic_{:016x}.bin", hash));
    if let Err(err) = fs::write(&path, data) {
        eprintln!(
            "fuzz panic capture failed: target={} path={} err={}",
            target,
            path.display(),
            err
        );
        return;
    }
    let preview = hex_preview(data, 64);
    eprintln!(
        "fuzz panic captured: target={} path={} len={} seed_hex={}",
        target,
        path.display(),
        data.len(),
        preview
    );
}

fn fnv1a64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn hex_preview(data: &[u8], max_len: usize) -> String {
    let len = data.len().min(max_len);
    let mut out = String::with_capacity(len * 2);
    for byte in &data[..len] {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";
