#![cfg(target_arch = "wasm32")]

use js_sys::Uint8Array;
use rulia::{encode_canonical, Keyword, Symbol, TaggedValue, Value};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!();

#[wasm_bindgen_test]
fn js_view_v0_wrappers() {
    console_error_panic_hook::set_once();

    let value = Value::Map(vec![
        (
            Value::String("title".to_string()),
            Value::String("Rulia".to_string()),
        ),
        (
            Value::Keyword(Keyword::simple("data")),
            Value::Bytes(vec![0, 1, 2]),
        ),
        (
            Value::Keyword(Keyword::simple("when")),
            Value::Tagged(TaggedValue::new(
                Symbol::simple("instant"),
                Value::String("2026-02-04T12:34:56.123Z".to_string()),
            )),
        ),
    ]);

    let bytes = encode_canonical(&value).expect("encode");
    let reader = rulia_wasm::reader_new(Uint8Array::from(bytes.as_slice()));
    let root = rulia_wasm::reader_root(&reader);
    let json = rulia_wasm::to_json(&root);

    let expected = concat!(
        "{\"$map\":[",
        "[\"title\",\"Rulia\"],",
        "[{\"$kw\":\"data\"},{\"$bytes\":\"base64:AAEC\"}],",
        "[{\"$kw\":\"when\"},{\"$instant\":\"2026-02-04T12:34:56.123Z\"}]",
        "]}"
    );
    assert_eq!(json, expected);
}

mod console_error_panic_hook {
    use std::sync::Once;

    static SET_HOOK: Once = Once::new();

    pub fn set_once() {
        SET_HOOK.call_once(|| {
            std::panic::set_hook(Box::new(|info| {
                wasm_bindgen_test::console_error!("{info}");
            }));
        });
    }
}
