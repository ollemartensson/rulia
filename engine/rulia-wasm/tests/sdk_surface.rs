#![cfg(target_arch = "wasm32")]

use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!();

#[wasm_bindgen_test]
fn format_and_canonical_roundtrip() {
    let canonical = rulia_wasm::format_text("(b = 2, a = 1)");
    assert!(rulia_wasm::format_check(&canonical));

    let encoded = rulia_wasm::encode_canonical("(b = 2, a = 1)");
    let decoded = rulia_wasm::decode_text(encoded.clone());
    assert_eq!(decoded, canonical);

    let recanonical = rulia_wasm::canonicalize_binary(encoded.clone());
    assert_eq!(recanonical.to_vec(), encoded.to_vec());

    let value_text = rulia_wasm::canonicalize_value_text("Tagged(\"complex_ns/tag\", \"data\")");
    assert!(value_text.contains("Tagged(\"complex_ns/tag\""));
}

#[wasm_bindgen_test]
fn digest_roundtrip() {
    let encoded = rulia_wasm::encode_with_digest("(a = 1, b = 2)", None);
    assert_eq!(encoded.algorithm(), rulia_wasm::digest_sha256_id());
    assert_eq!(encoded.digest().length(), 32);

    let verified = rulia_wasm::verify_digest(encoded.bytes());
    assert_eq!(verified, rulia_wasm::digest_sha256_id());
    assert!(rulia_wasm::has_valid_digest(encoded.bytes()));
}

#[wasm_bindgen_test]
fn frame_roundtrip() {
    let payload = Uint8Array::from(&[1u8, 2, 3, 4][..]);
    let frame = rulia_wasm::frame_encode(payload.clone());

    let mut decoder = rulia_wasm::FrameDecoder::new(Some(1024));
    let first = decoder.push(frame.clone());

    assert_eq!(first.frames().length(), 1);
    assert!(!first.need_more());
    assert_eq!(first.consumed(), frame.length() as usize);
    assert!(!first.eof());
}

#[wasm_bindgen_test]
fn typed_value_shape() {
    let typed = rulia_wasm::parse_typed("12345678901234567890N");
    assert_eq!(prop_str(&typed, "kind"), "bigint");
    assert_eq!(prop_str(&typed, "value"), "12345678901234567890");
}

fn prop_str(value: &JsValue, key: &str) -> String {
    Reflect::get(value, &JsValue::from_str(key))
        .expect("property should exist")
        .as_string()
        .expect("property should be string")
}
