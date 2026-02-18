const fs = require("node:fs");
const path = require("node:path");

const sdkPath = path.resolve(__dirname, "../../../sdk/javascript/rulia-js/dist/index.js");
if (!fs.existsSync(sdkPath)) {
  throw new Error(
    `SDK bundle not found at ${sdkPath}. Run: cd sdk/javascript/rulia-js && npm run build`,
  );
}

const {
  DIGEST_SHA256,
  FrameDecoder,
  canonicalizeBinary,
  canonicalizeValueText,
  configureFormatter,
  currentFormatterConfig,
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
} = require(sdkPath);

function requireCondition(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((value, idx) => value === b[idx]);
}

configureFormatter({ backend: "wasm" });
const formatterConfig = currentFormatterConfig();
requireCondition(formatterConfig.backend === "wasm", "formatter backend should be wasm");

const formatted = formatText("(b = 2, a = 1)");
requireCondition(formatCheck(formatted), "formatted text should be canonical");

const canonicalBytes = encodeCanonical("(b = 2, a = 1)");
const decoded = decodeText(canonicalBytes);
requireCondition(formatCheck(decoded), "decoded canonical bytes should be canonical text");
requireCondition(
  formatCheck(canonicalizeValueText("(b = 2, a = 1)")),
  "canonicalizeValueText should return canonical text",
);
requireCondition(equalBytes(canonicalBytes, canonicalizeBinary(canonicalBytes)), "binary recanonicalization mismatch");

const typed = parseTyped('(user_first_name = "Ada", marker = Tagged("complex_ns/tag", "data"))');
requireCondition(typed.kind === "map", "typed parse should return map");
const firstNameEntry = typed.value.find(
  (entry) =>
    entry.key?.kind === "keyword" &&
    entry.key.namespace === "user" &&
    entry.key.name === "first_name",
);
requireCondition(firstNameEntry?.value?.kind === "string", "missing typed first_name");
requireCondition(firstNameEntry.value.value === "Ada", "typed first_name mismatch");

const decodedTyped = decodeTyped(canonicalBytes);
requireCondition(decodedTyped.kind === "map", "typed decode should return map");

const digested = encodeWithDigest("(a = 1, b = 2)", DIGEST_SHA256);
requireCondition(digested.digest.length === 32, "sha256 digest length mismatch");
requireCondition(verifyDigest(digested.bytes) === DIGEST_SHA256, "digest verification mismatch");
requireCondition(hasValidDigest(digested.bytes), "hasValidDigest expected true");

const payload = Uint8Array.from([1, 2, 3, 4]);
const frame = frameEncode(payload);
const decoder = new FrameDecoder(1024);

const first = decoder.push(frame.slice(0, 2));
requireCondition(first.frames.length === 0, "first chunk should not produce a frame");
requireCondition(first.needMore, "first chunk should require more data");

const second = decoder.push(frame.slice(2));
requireCondition(second.frames.length === 1, "second chunk should produce one frame");
requireCondition(equalBytes(second.frames[0], payload), "frame payload mismatch");

console.log("sdk javascript surface demo passed");
