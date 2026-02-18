# Rulia JS SDK (WASM-first)

JavaScript/TypeScript bindings for the canonical Rulia runtime using `rulia-wasm`.

## Build

```bash
cd sdk/javascript/rulia-js
npm install
npm run build
```

This runs:
- a temporary Rust workspace scaffold + `wasm-pack build` for `engine/rulia-wasm`
- TypeScript build for the JS wrapper

## Usage

```ts
import {
  DIGEST_SHA256,
  FrameDecoder,
  canonicalizeBinary,
  configureFormatter,
  canonicalizeValueText,
  decodeText,
  decodeTyped,
  encodeCanonical,
  encodeWithDigest,
  formatCheck,
  formatText,
  frameEncode,
  hasValidDigest,
  parseTyped,
  verifyDigest,
} from "@rulia/js";

const canonical = formatText("(b = 2, a = 1)");
const isCanonical = formatCheck(canonical);

const bytes = encodeCanonical("(b = 2, a = 1)");
const text = decodeText(bytes);
const recanonical = canonicalizeBinary(bytes);
const canonicalValueText = canonicalizeValueText("Tagged(\"complex_ns/tag\", \"data\")");

const digested = encodeWithDigest("(a = 1, b = 2)", DIGEST_SHA256);
const digestAlgo = verifyDigest(digested.bytes);
const digestOk = hasValidDigest(digested.bytes);

const typed = parseTyped("(user_first_name = \"Ada\", marker = Tagged(\"complex_ns/tag\", \"data\"))");
const decodedTyped = decodeTyped(bytes);

const payload = new Uint8Array([1, 2, 3]);
const frame = frameEncode(payload);
const decoder = new FrameDecoder();
const first = decoder.push(frame);

// Optional: formatter backend control (Node only)
configureFormatter({ backend: "auto" });   // default
// configureFormatter({ backend: "native", nativeBinaryPath: "/path/to/rulia-fmt" });
// configureFormatter({ backend: "wasm" });
// or set env var RULIA_FMT_BIN=/path/to/rulia-fmt
```

## API Surface

- Formatting: `formatText`, `formatCheck`, `configureFormatter`, `currentFormatterConfig`
- Binary + Canonicalization: `encode`, `encodeCanonical`, `decodeText`, `canonicalizeBinary`, `canonicalizeValueText`
- Typed traversal: `parseTyped`, `decodeTyped`
- Digest: `encodeWithDigest`, `verifyDigest`, `hasValidDigest`
- Framing: `frameEncode`, `FrameDecoder`
- JS View (zero-copy reader): `readerNew`, `readerRoot`, `valueKind`, `valueAsString`, `valueAsBytes`, `toJsView`, `toJson`

## Notes

- `int`, `uint`, and `bigint` typed values are exposed as decimal strings to preserve precision.
- Digest IDs match other SDKs:
  - `1` = SHA-256
  - `2` = BLAKE3
- Formatter backend behavior:
  - Browser: WASM formatter.
  - Node `backend: "auto"`: use native `rulia-fmt` when available, otherwise WASM.
  - Node `backend: "native"`: require `rulia-fmt` (tree-sitter formatter path).
  - Default native binary lookup: `RULIA_FMT_BIN` env var, then `rulia-fmt` on `PATH`.
