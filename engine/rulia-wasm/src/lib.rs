use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use js_sys::{Array, Object, Reflect, Uint8Array};
use rulia::binary::{MessageReader, TypeTag, ValueRef};
use rulia::{HashAlgorithm, Keyword, RuliaError, Symbol, Value};
use wasm_bindgen::prelude::*;

const DEFAULT_MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

const RULIA_DIGEST_SHA256: u8 = 1;
const RULIA_DIGEST_BLAKE3: u8 = 2;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(message: &str);
}

struct ReaderInner {
    #[allow(dead_code)]
    bytes: Arc<[u8]>,
    reader: MessageReader<'static>,
}

#[wasm_bindgen]
pub struct ReaderHandle {
    inner: Arc<ReaderInner>,
}

#[wasm_bindgen]
pub struct ValueHandle {
    #[allow(dead_code)]
    reader: Arc<ReaderInner>,
    value: ValueRef<'static>,
}

#[wasm_bindgen]
pub struct EncodedWithDigest {
    bytes: Vec<u8>,
    digest: Vec<u8>,
    algorithm: u8,
}

#[wasm_bindgen]
impl EncodedWithDigest {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(self.bytes.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn digest(&self) -> Uint8Array {
        Uint8Array::from(self.digest.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }
}

#[wasm_bindgen]
pub struct FrameDecodeResult {
    frames: Vec<Vec<u8>>,
    consumed: usize,
    need_more: bool,
    eof: bool,
}

#[wasm_bindgen]
impl FrameDecodeResult {
    #[wasm_bindgen(getter)]
    pub fn frames(&self) -> Array {
        let out = Array::new();
        for frame in &self.frames {
            out.push(&Uint8Array::from(frame.as_slice()));
        }
        out
    }

    #[wasm_bindgen(getter)]
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    #[wasm_bindgen(getter)]
    pub fn need_more(&self) -> bool {
        self.need_more
    }

    #[wasm_bindgen(getter)]
    pub fn eof(&self) -> bool {
        self.eof
    }
}

#[wasm_bindgen]
pub struct FrameDecoder {
    max_len: usize,
    header: [u8; 4],
    header_filled: usize,
    payload_len: Option<usize>,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl FrameDecoder {
    #[wasm_bindgen(constructor)]
    pub fn new(max_len: Option<u32>) -> FrameDecoder {
        let max_len = max_len
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_MAX_FRAME_LEN);
        FrameDecoder {
            max_len,
            header: [0u8; 4],
            header_filled: 0,
            payload_len: None,
            payload: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: Uint8Array) -> FrameDecodeResult {
        let bytes = uint8_array_to_vec(&chunk);
        let eof = bytes.is_empty();
        let mut offset = 0usize;
        let mut frames = Vec::new();

        while offset < bytes.len() {
            if self.payload_len.is_none() {
                while self.header_filled < 4 && offset < bytes.len() {
                    self.header[self.header_filled] = bytes[offset];
                    self.header_filled += 1;
                    offset += 1;
                }
                if self.header_filled < 4 {
                    break;
                }

                let frame_len = u32::from_le_bytes(self.header) as usize;
                if frame_len == 0 {
                    throw("RULIA_STATUS_FRAMING_INVALID_LENGTH");
                }
                if frame_len > self.max_len {
                    throw("RULIA_STATUS_FRAMING_TOO_LARGE");
                }

                self.payload_len = Some(frame_len);
                self.payload.clear();
                self.payload.reserve(frame_len);
            }

            let expected = match self.payload_len {
                Some(value) => value,
                None => throw("internal framing state error"),
            };
            let remaining = expected.saturating_sub(self.payload.len());
            if remaining == 0 {
                frames.push(std::mem::take(&mut self.payload));
                self.reset();
                continue;
            }

            let available = bytes.len() - offset;
            let take = remaining.min(available);
            if take > 0 {
                self.payload.extend_from_slice(&bytes[offset..offset + take]);
                offset += take;
            }

            if self.payload.len() == expected {
                frames.push(std::mem::take(&mut self.payload));
                self.reset();
            }
        }

        let need_more = self.header_filled > 0 || self.payload_len.is_some();
        if eof && need_more {
            if self.payload_len.is_none() {
                throw("RULIA_STATUS_FRAMING_TRUNCATED_HEADER");
            }
            throw("RULIA_STATUS_FRAMING_TRUNCATED_PAYLOAD");
        }

        FrameDecodeResult {
            frames,
            consumed: offset,
            need_more,
            eof,
        }
    }
}

impl FrameDecoder {
    fn reset(&mut self) {
        self.header = [0u8; 4];
        self.header_filled = 0;
        self.payload_len = None;
        self.payload.clear();
    }
}

type MapEntries<'a> = Vec<(ValueRef<'a>, ValueRef<'a>)>;

#[wasm_bindgen]
pub fn digest_sha256_id() -> u8 {
    RULIA_DIGEST_SHA256
}

#[wasm_bindgen]
pub fn digest_blake3_id() -> u8 {
    RULIA_DIGEST_BLAKE3
}

#[wasm_bindgen]
pub fn format_text(text: &str) -> String {
    let value = parse_value(text);
    let canonical_bytes =
        rulia::encode_canonical(&value).unwrap_or_else(|err| throw(err.to_string()));
    let canonical_value =
        rulia::decode_value(&canonical_bytes).unwrap_or_else(|err| throw(err.to_string()));
    rulia::text::to_string(&canonical_value)
}

#[wasm_bindgen]
pub fn format_check(text: &str) -> bool {
    let value = parse_value(text);
    let canonical = rulia::text::to_string(&value);
    canonical == text
}

#[wasm_bindgen]
pub fn encode(text: &str) -> Uint8Array {
    let value = parse_value(text);
    let bytes = rulia::encode_value(&value).unwrap_or_else(|err| throw(err.to_string()));
    Uint8Array::from(bytes.as_slice())
}

#[wasm_bindgen]
pub fn encode_canonical(text: &str) -> Uint8Array {
    let value = parse_value(text);
    let bytes = rulia::encode_canonical(&value).unwrap_or_else(|err| throw(err.to_string()));
    Uint8Array::from(bytes.as_slice())
}

#[wasm_bindgen]
pub fn decode_text(bytes: Uint8Array) -> String {
    let value = decode_value(bytes);
    rulia::text::to_string(&value)
}

#[wasm_bindgen]
pub fn canonicalize_binary(bytes: Uint8Array) -> Uint8Array {
    let value = decode_value(bytes);
    let canonical = rulia::encode_canonical(&value).unwrap_or_else(|err| throw(err.to_string()));
    Uint8Array::from(canonical.as_slice())
}

#[wasm_bindgen]
pub fn canonicalize_value_text(text: &str) -> String {
    let value = parse_value(text);
    rulia::text::to_string(&value)
}

#[wasm_bindgen]
pub fn parse_typed(text: &str) -> JsValue {
    let value = parse_value(text);
    typed_value_to_js(&value).unwrap_or_else(|err| throw(err))
}

#[wasm_bindgen]
pub fn decode_typed(bytes: Uint8Array) -> JsValue {
    let value = decode_value(bytes);
    typed_value_to_js(&value).unwrap_or_else(|err| throw(err))
}

#[wasm_bindgen]
pub fn encode_with_digest(text: &str, algorithm: Option<u8>) -> EncodedWithDigest {
    let value = parse_value(text);
    let algorithm_id = algorithm.unwrap_or(RULIA_DIGEST_SHA256);
    let hash_algorithm = hash_algorithm_from_id(algorithm_id);
    let encoded = rulia::encode_with_digest_using(&value, hash_algorithm)
        .unwrap_or_else(|err| throw(err.to_string()));
    EncodedWithDigest {
        bytes: encoded.bytes,
        digest: encoded.digest,
        algorithm: algorithm_id,
    }
}

#[wasm_bindgen]
pub fn verify_digest(bytes: Uint8Array) -> u8 {
    let input = uint8_array_to_vec(&bytes);
    match rulia::verify_digest(&input) {
        Ok((HashAlgorithm::Sha256, _)) => RULIA_DIGEST_SHA256,
        Ok((HashAlgorithm::Blake3, _)) => RULIA_DIGEST_BLAKE3,
        Err(_) => 0,
    }
}

#[wasm_bindgen]
pub fn has_valid_digest(bytes: Uint8Array) -> bool {
    verify_digest(bytes) != 0
}

#[wasm_bindgen]
pub fn frame_encode(payload: Uint8Array) -> Uint8Array {
    frame_encode_with_limit(payload, None)
}

#[wasm_bindgen]
pub fn frame_encode_with_limit(payload: Uint8Array, max_len: Option<u32>) -> Uint8Array {
    let payload = uint8_array_to_vec(&payload);
    let max_len = max_len
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_MAX_FRAME_LEN);
    if payload.is_empty() {
        throw("RULIA_STATUS_FRAMING_INVALID_LENGTH");
    }
    if payload.len() > max_len {
        throw("RULIA_STATUS_FRAMING_TOO_LARGE");
    }

    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Uint8Array::from(out.as_slice())
}

#[wasm_bindgen]
pub fn reader_new(bytes: Uint8Array) -> ReaderHandle {
    let buffer = uint8_array_to_vec(&bytes);
    let bytes_arc: Arc<[u8]> = Arc::from(buffer.into_boxed_slice());
    let reader =
        build_reader(Arc::clone(&bytes_arc)).unwrap_or_else(|err| wasm_bindgen::throw_str(&err));
    ReaderHandle {
        inner: Arc::new(ReaderInner {
            bytes: bytes_arc,
            reader,
        }),
    }
}

#[wasm_bindgen]
pub fn reader_root(reader: &ReaderHandle) -> ValueHandle {
    let root = reader
        .inner
        .reader
        .root()
        .unwrap_or_else(|err| wasm_bindgen::throw_str(&err.to_string()));
    let value = root.as_value();
    let value_static = unsafe { std::mem::transmute::<ValueRef<'_>, ValueRef<'static>>(value) };
    ValueHandle {
        reader: Arc::clone(&reader.inner),
        value: value_static,
    }
}

#[wasm_bindgen]
pub fn value_kind(value: &ValueHandle) -> u16 {
    value.value.kind() as u16
}

#[wasm_bindgen]
pub fn value_as_string(value: &ValueHandle) -> Option<String> {
    option_or_throw(value.value.as_string().map(str::to_string))
}

#[wasm_bindgen]
pub fn value_as_bytes(value: &ValueHandle) -> Option<Uint8Array> {
    let bytes = option_or_throw(value.value.as_bytes());
    bytes.map(Uint8Array::from)
}

#[wasm_bindgen]
pub fn to_js_view(value: &ValueHandle) -> JsValue {
    match to_js_view_inner(&value.value) {
        Ok(js) => js,
        Err(err) => wasm_bindgen::throw_str(&err),
    }
}

#[wasm_bindgen]
pub fn to_json(value: &ValueHandle) -> String {
    let js_value = to_js_view(value);
    match stringify_js(&js_value) {
        Ok(json) => json,
        Err(err) => wasm_bindgen::throw_str(&err),
    }
}

fn uint8_array_to_vec(bytes: &Uint8Array) -> Vec<u8> {
    let mut out = vec![0u8; bytes.length() as usize];
    bytes.copy_to(&mut out);
    out
}

fn parse_value(text: &str) -> Value {
    rulia::text::parse(text).unwrap_or_else(|err| throw(err.to_string()))
}

fn decode_value(bytes: Uint8Array) -> Value {
    let input = uint8_array_to_vec(&bytes);
    rulia::decode_value(&input).unwrap_or_else(|err| throw(err.to_string()))
}

fn hash_algorithm_from_id(id: u8) -> HashAlgorithm {
    match id {
        RULIA_DIGEST_SHA256 => HashAlgorithm::Sha256,
        RULIA_DIGEST_BLAKE3 => HashAlgorithm::Blake3,
        _ => throw(format!("unsupported digest algorithm id: {id}")),
    }
}

fn throw(message: impl AsRef<str>) -> ! {
    wasm_bindgen::throw_str(message.as_ref())
}

fn build_reader(bytes: Arc<[u8]>) -> Result<MessageReader<'static>, String> {
    let slice: &[u8] = &bytes;
    let reader = MessageReader::new(slice).map_err(|err| err.to_string())?;
    // SAFETY: the bytes are owned by ReaderInner and outlive the MessageReader.
    let reader_static =
        unsafe { std::mem::transmute::<MessageReader<'_>, MessageReader<'static>>(reader) };
    Ok(reader_static)
}

fn option_or_throw<T>(result: Result<T, RuliaError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(RuliaError::UnexpectedValueKind(_)) => None,
        Err(err) => wasm_bindgen::throw_str(&err.to_string()),
    }
}

fn typed_value_to_js(value: &Value) -> Result<JsValue, String> {
    let out = Object::new();
    match value {
        Value::Nil => {
            set_prop(&out, "kind", &JsValue::from_str("nil"))?;
            set_prop(&out, "value", &JsValue::NULL)?;
        }
        Value::Bool(flag) => {
            set_prop(&out, "kind", &JsValue::from_str("bool"))?;
            set_prop(&out, "value", &JsValue::from_bool(*flag))?;
        }
        Value::Int(number) => {
            set_prop(&out, "kind", &JsValue::from_str("int"))?;
            set_prop(&out, "value", &JsValue::from_str(&number.to_string()))?;
        }
        Value::UInt(number) => {
            set_prop(&out, "kind", &JsValue::from_str("uint"))?;
            set_prop(&out, "value", &JsValue::from_str(&number.to_string()))?;
        }
        Value::BigInt(number) => {
            set_prop(&out, "kind", &JsValue::from_str("bigint"))?;
            set_prop(&out, "value", &JsValue::from_str(&number.to_string()))?;
        }
        Value::Float32(number) => {
            set_prop(&out, "kind", &JsValue::from_str("f32"))?;
            set_prop(&out, "value", &JsValue::from_f64(number.0 as f64))?;
        }
        Value::Float64(number) => {
            set_prop(&out, "kind", &JsValue::from_str("f64"))?;
            set_prop(&out, "value", &JsValue::from_f64(number.0))?;
        }
        Value::String(text) => {
            set_prop(&out, "kind", &JsValue::from_str("string"))?;
            set_prop(&out, "value", &JsValue::from_str(text))?;
        }
        Value::Bytes(bytes) => {
            set_prop(&out, "kind", &JsValue::from_str("bytes"))?;
            set_prop(&out, "value", &Uint8Array::from(bytes.as_slice()))?;
        }
        Value::Keyword(keyword) => {
            set_prop(&out, "kind", &JsValue::from_str("keyword"))?;
            set_prop(&out, "name", &JsValue::from_str(keyword.name()))?;
            set_optional_string_prop(&out, "namespace", keyword.namespace())?;
            set_prop(
                &out,
                "canonical",
                &JsValue::from_str(&format!(":{}", keyword.as_symbol())),
            )?;
        }
        Value::Symbol(symbol) => {
            set_prop(&out, "kind", &JsValue::from_str("symbol"))?;
            set_prop(&out, "name", &JsValue::from_str(symbol.name()))?;
            set_optional_string_prop(&out, "namespace", symbol.namespace())?;
            set_prop(&out, "canonical", &JsValue::from_str(&symbol.as_str()))?;
        }
        Value::Vector(items) => {
            set_prop(&out, "kind", &JsValue::from_str("vector"))?;
            set_prop(&out, "value", &typed_array(items)?)?;
        }
        Value::Set(items) => {
            set_prop(&out, "kind", &JsValue::from_str("set"))?;
            set_prop(&out, "value", &typed_array(items)?)?;
        }
        Value::Map(entries) => {
            set_prop(&out, "kind", &JsValue::from_str("map"))?;
            let arr = Array::new();
            for (key, value) in entries {
                let entry = Object::new();
                set_prop(&entry, "key", &typed_value_to_js(key)?)?;
                set_prop(&entry, "value", &typed_value_to_js(value)?)?;
                arr.push(&entry);
            }
            set_prop(&out, "value", &arr.into())?;
        }
        Value::Tagged(tagged) => {
            set_prop(&out, "kind", &JsValue::from_str("tagged"))?;
            set_prop(&out, "tag", &symbol_to_js(&tagged.tag)?)?;
            set_prop(&out, "value", &typed_value_to_js(tagged.value.as_ref())?)?;
        }
        Value::Annotated(annotation) => {
            set_prop(&out, "kind", &JsValue::from_str("annotated"))?;
            let metadata = Array::new();
            for (key, value) in &annotation.metadata {
                let entry = Object::new();
                set_prop(&entry, "key", &typed_value_to_js(key)?)?;
                set_prop(&entry, "value", &typed_value_to_js(value)?)?;
                metadata.push(&entry);
            }
            set_prop(&out, "metadata", &metadata.into())?;
            set_prop(&out, "value", &typed_value_to_js(annotation.value.as_ref())?)?;
        }
    }
    Ok(out.into())
}

fn symbol_to_js(symbol: &Symbol) -> Result<JsValue, String> {
    let out = Object::new();
    set_prop(&out, "name", &JsValue::from_str(symbol.name()))?;
    set_optional_string_prop(&out, "namespace", symbol.namespace())?;
    set_prop(&out, "canonical", &JsValue::from_str(&symbol.as_str()))?;
    Ok(out.into())
}

fn typed_array(values: &[Value]) -> Result<JsValue, String> {
    let out = Array::new();
    for value in values {
        out.push(&typed_value_to_js(value)?);
    }
    Ok(out.into())
}

fn set_optional_string_prop(obj: &Object, key: &str, value: Option<&str>) -> Result<(), String> {
    match value {
        Some(value) => set_prop(obj, key, &JsValue::from_str(value)),
        None => set_prop(obj, key, &JsValue::NULL),
    }
}

fn to_js_view_inner(value: &ValueRef<'_>) -> Result<JsValue, String> {
    match value.kind() {
        TypeTag::Nil => Ok(JsValue::NULL),
        TypeTag::Bool => Ok(JsValue::from_bool(value.as_bool().map_err(err_string)?)),
        TypeTag::Int => wrap_string("$i64", value.as_int().map_err(err_string)?),
        TypeTag::UInt => wrap_string("$u64", value.as_uint().map_err(err_string)?),
        TypeTag::BigInt => bigint_wrapper(value),
        TypeTag::Float32 => float_value(value.as_float32().map_err(err_string)? as f64),
        TypeTag::Float64 => float_value(value.as_float64().map_err(err_string)?),
        TypeTag::String => Ok(JsValue::from_str(value.as_string().map_err(err_string)?)),
        TypeTag::Bytes => bytes_wrapper(value),
        TypeTag::Symbol => symbol_wrapper(value.as_symbol().map_err(err_string)?),
        TypeTag::Keyword => keyword_wrapper(value.as_keyword().map_err(err_string)?),
        TypeTag::Vector => vector_wrapper(value),
        TypeTag::Set => set_wrapper(value),
        TypeTag::Map => map_wrapper(value),
        TypeTag::Tagged => tagged_wrapper(value),
        TypeTag::Annotated => annotated_wrapper(value),
    }
}

fn err_string(err: RuliaError) -> String {
    err.to_string()
}

fn wrap_string(key: &str, value: impl ToString) -> Result<JsValue, String> {
    let obj = Object::new();
    let payload = JsValue::from_str(&value.to_string());
    set_prop(&obj, key, &payload)?;
    Ok(obj.into())
}

fn float_value(value: f64) -> Result<JsValue, String> {
    if value.is_finite() {
        Ok(JsValue::from_f64(value))
    } else {
        Err("JS View v0 rejects NaN and Infinity".to_string())
    }
}

fn bigint_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let bigint = match value.to_value().map_err(err_string)? {
        Value::BigInt(bigint) => bigint,
        _ => return Err("expected bigint value".to_string()),
    };
    wrap_string("$bigint", bigint.to_string())
}

fn bytes_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let bytes = value.as_bytes().map_err(err_string)?;
    let encoded = STANDARD.encode(bytes);
    let payload = format!("base64:{}", encoded);
    wrap_string("$bytes", payload)
}

fn symbol_wrapper(symbol: Symbol) -> Result<JsValue, String> {
    wrap_string("$sym", symbol.as_str())
}

fn keyword_wrapper(keyword: Keyword) -> Result<JsValue, String> {
    wrap_string("$kw", keyword.as_symbol().as_str())
}

fn vector_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let out = Array::new();
    for element in value.vector_iter().map_err(err_string)? {
        let element = element.map_err(err_string)?;
        out.push(&to_js_view_inner(&element)?);
    }
    Ok(out.into())
}

fn set_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let out = Array::new();
    for element in value.set_iter().map_err(err_string)? {
        let element = element.map_err(err_string)?;
        out.push(&to_js_view_inner(&element)?);
    }
    let obj = Object::new();
    set_prop(&obj, "$set", &out.into())?;
    Ok(obj.into())
}

fn map_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let entries = collect_map_entries(value)?;
    map_entries_to_js_view(&entries)
}

fn collect_map_entries<'a>(value: &ValueRef<'a>) -> Result<MapEntries<'a>, String> {
    let mut entries = Vec::new();
    for entry in value.map_iter().map_err(err_string)? {
        let (key, val) = entry.map_err(err_string)?;
        entries.push((key, val));
    }
    Ok(entries)
}

fn map_entries_to_js_view<'a>(entries: &MapEntries<'a>) -> Result<JsValue, String> {
    let mut string_keys = Vec::with_capacity(entries.len());
    let mut can_use_object = true;
    for (key, _) in entries {
        match key.as_string() {
            Ok(s) => {
                if s.starts_with('$') {
                    can_use_object = false;
                    break;
                }
                string_keys.push(s.to_string());
            }
            Err(RuliaError::UnexpectedValueKind(_)) => {
                can_use_object = false;
                break;
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    if can_use_object && string_keys.len() == entries.len() {
        let obj = Object::new();
        for ((_, value), key) in entries.iter().zip(string_keys.iter()) {
            let js_value = to_js_view_inner(value)?;
            set_prop(&obj, key, &js_value)?;
        }
        return Ok(obj.into());
    }

    let array = Array::new();
    for (key, value) in entries {
        let pair = Array::new();
        pair.push(&to_js_view_inner(key)?);
        pair.push(&to_js_view_inner(value)?);
        array.push(&pair.into());
    }
    let obj = Object::new();
    set_prop(&obj, "$map", &array.into())?;
    Ok(obj.into())
}

fn tagged_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let (tag, inner) = value.tagged().map_err(err_string)?;
    let tag_name = tag.as_str();
    match tag_name.as_str() {
        "decimal" => tag_string_wrapper("$decimal", &inner),
        "uuid" => tag_string_wrapper("$uuid", &inner),
        "ulid" => tag_string_wrapper("$ulid", &inner),
        "instant" => tag_string_wrapper("$instant", &inner),
        "ref" => ref_wrapper(&inner),
        _ => tagged_generic(&tag_name, &inner),
    }
}

fn tag_string_wrapper(key: &str, inner: &ValueRef<'_>) -> Result<JsValue, String> {
    let value = inner.as_string().map_err(err_string)?;
    wrap_string(key, value)
}

fn tagged_generic(tag: &str, inner: &ValueRef<'_>) -> Result<JsValue, String> {
    let obj = Object::new();
    set_prop(&obj, "$tag", &JsValue::from_str(tag))?;
    set_prop(&obj, "value", &to_js_view_inner(inner)?)?;
    Ok(obj.into())
}

fn ref_wrapper(inner: &ValueRef<'_>) -> Result<JsValue, String> {
    let payload = Object::new();
    if inner.kind() == TypeTag::Vector {
        let mut elements = Vec::new();
        for element in inner.vector_iter().map_err(err_string)? {
            elements.push(element.map_err(err_string)?);
        }
        if elements.len() != 2 {
            return Err("ref vector must have exactly 2 elements".to_string());
        }
        set_prop(&payload, "key", &to_js_view_inner(&elements[0])?)?;
        set_prop(&payload, "value", &to_js_view_inner(&elements[1])?)?;
    } else {
        set_prop(&payload, "id", &to_js_view_inner(inner)?)?;
    }
    let obj = Object::new();
    set_prop(&obj, "$ref", &payload.into())?;
    Ok(obj.into())
}

fn annotated_wrapper(value: &ValueRef<'_>) -> Result<JsValue, String> {
    let (metadata, inner) = value.annotated().map_err(err_string)?;
    if metadata.kind() != TypeTag::Map {
        return Err("annotation metadata must be a map".to_string());
    }
    let (doc, meta_entries) = extract_annotation_metadata(&metadata)?;
    let meta_js = map_entries_to_js_view(&meta_entries)?;
    let ann = Object::new();
    if let Some(doc) = doc {
        set_prop(&ann, "doc", &JsValue::from_str(&doc))?;
    }
    set_prop(&ann, "meta", &meta_js)?;

    let obj = Object::new();
    set_prop(&obj, "$ann", &ann.into())?;
    set_prop(&obj, "value", &to_js_view_inner(&inner)?)?;
    Ok(obj.into())
}

fn extract_annotation_metadata<'a>(
    metadata: &ValueRef<'a>,
) -> Result<(Option<String>, MapEntries<'a>), String> {
    let mut doc = None;
    let mut entries = Vec::new();
    for entry in metadata.map_iter().map_err(err_string)? {
        let (key, value) = entry.map_err(err_string)?;
        if is_doc_key(&key)? {
            if let Ok(doc_value) = value.as_string() {
                doc = Some(doc_value.to_string());
                continue;
            }
        }
        entries.push((key, value));
    }
    Ok((doc, entries))
}

fn is_doc_key(key: &ValueRef<'_>) -> Result<bool, String> {
    match key.as_keyword() {
        Ok(keyword) => Ok(keyword.namespace().is_none() && keyword.name() == "doc"),
        Err(RuliaError::UnexpectedValueKind(_)) => Ok(false),
        Err(err) => Err(err.to_string()),
    }
}

fn set_prop(obj: &Object, key: &str, value: &JsValue) -> Result<(), String> {
    Reflect::set(obj, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|err| {
            err.as_string()
                .unwrap_or_else(|| "JS set failed".to_string())
        })
}

fn stringify_js(value: &JsValue) -> Result<String, String> {
    let stringified = js_sys::JSON::stringify(value).map_err(|err| {
        let message = js_exception_string(&err);
        console_error(&format!("JSON.stringify threw: {message}"));
        message
    })?;
    stringified.as_string().ok_or_else(|| {
        let message = "JSON.stringify returned non-string".to_string();
        console_error(&message);
        message
    })
}

fn js_exception_string(err: &JsValue) -> String {
    if let Some(message) = err.as_string() {
        return message;
    }
    if let Ok(message) = Reflect::get(err, &JsValue::from_str("message")) {
        if let Some(message) = message.as_string() {
            return message;
        }
    }
    if let Ok(stack) = Reflect::get(err, &JsValue::from_str("stack")) {
        if let Some(stack) = stack.as_string() {
            return stack;
        }
    }
    "JS exception".to_string()
}
