declare const require: (name: string) => any;
declare const process:
  | {
      env?: { RULIA_FMT_BIN?: string };
      versions?: { node?: string };
    }
  | undefined;

const wasm: any = require("../pkg/rulia_wasm.js");

const DEFAULT_MAX_FRAME_LEN = 64 * 1024 * 1024;
const NON_CANONICAL_MARKER = "E_NONCANONICAL";

export const DIGEST_SHA256: number = wasm.digest_sha256_id();
export const DIGEST_BLAKE3: number = wasm.digest_blake3_id();

export type DigestAlgorithm = 1 | 2;
export type FormatterBackend = "auto" | "native" | "wasm";

export type ByteInput = Uint8Array | ArrayBuffer | number[];

export interface FormatterConfig {
  backend: FormatterBackend;
  nativeBinaryPath: string;
}

export interface TypedKeywordValue {
  kind: "keyword";
  namespace: string | null;
  name: string;
  canonical: string;
}

export interface TypedSymbolValue {
  kind: "symbol";
  namespace: string | null;
  name: string;
  canonical: string;
}

export interface TypedMapEntry {
  key: TypedValue;
  value: TypedValue;
}

export interface TypedTaggedValue {
  kind: "tagged";
  tag: {
    namespace: string | null;
    name: string;
    canonical: string;
  };
  value: TypedValue;
}

export interface TypedAnnotatedValue {
  kind: "annotated";
  metadata: TypedMapEntry[];
  value: TypedValue;
}

export type TypedValue =
  | { kind: "nil"; value: null }
  | { kind: "bool"; value: boolean }
  | { kind: "int"; value: string }
  | { kind: "uint"; value: string }
  | { kind: "bigint"; value: string }
  | { kind: "f32"; value: number }
  | { kind: "f64"; value: number }
  | { kind: "string"; value: string }
  | { kind: "bytes"; value: Uint8Array }
  | TypedKeywordValue
  | TypedSymbolValue
  | { kind: "vector"; value: TypedValue[] }
  | { kind: "set"; value: TypedValue[] }
  | { kind: "map"; value: TypedMapEntry[] }
  | TypedTaggedValue
  | TypedAnnotatedValue;

export interface EncodedWithDigest {
  bytes: Uint8Array;
  digest: Uint8Array;
  algorithm: DigestAlgorithm;
}

export interface FrameDecodeResult {
  frames: Uint8Array[];
  consumed: number;
  needMore: boolean;
  eof: boolean;
}

let formatterConfig: FormatterConfig = {
  backend: "auto",
  nativeBinaryPath:
    (typeof process !== "undefined" &&
      (process as { env?: { RULIA_FMT_BIN?: string } }).env?.RULIA_FMT_BIN) ||
    "rulia-fmt",
};
let cachedNativeAvailability: { binary: string; available: boolean } | null = null;

export function configureFormatter(config: Partial<FormatterConfig>): FormatterConfig {
  if (config.backend !== undefined) {
    formatterConfig.backend = config.backend;
  }
  if (config.nativeBinaryPath !== undefined && config.nativeBinaryPath.length > 0) {
    formatterConfig.nativeBinaryPath = config.nativeBinaryPath;
  }
  cachedNativeAvailability = null;
  return { ...formatterConfig };
}

export function currentFormatterConfig(): FormatterConfig {
  return { ...formatterConfig };
}

export function formatText(text: string): string {
  if (shouldUseNativeFormatter()) {
    return nativeFormatText(text);
  }
  return wasm.format_text(text);
}

export function formatCheck(text: string): boolean {
  if (shouldUseNativeFormatter()) {
    return nativeFormatCheck(text);
  }
  return wasm.format_check(text);
}

export function encode(text: string): Uint8Array {
  return wasm.encode(text);
}

export function encodeCanonical(text: string): Uint8Array {
  return wasm.encode_canonical(text);
}

export function decodeText(bytes: ByteInput): string {
  return wasm.decode_text(toUint8Array(bytes));
}

export function canonicalizeBinary(bytes: ByteInput): Uint8Array {
  return wasm.canonicalize_binary(toUint8Array(bytes));
}

export function canonicalizeValueText(text: string): string {
  return wasm.canonicalize_value_text(text);
}

export function parseTyped(text: string): TypedValue {
  return wasm.parse_typed(text) as TypedValue;
}

export function decodeTyped(bytes: ByteInput): TypedValue {
  return wasm.decode_typed(toUint8Array(bytes)) as TypedValue;
}

export function encodeWithDigest(
  text: string,
  algorithm: DigestAlgorithm = DIGEST_SHA256 as DigestAlgorithm,
): EncodedWithDigest {
  const encoded = wasm.encode_with_digest(text, algorithm);
  return {
    bytes: encoded.bytes as Uint8Array,
    digest: encoded.digest as Uint8Array,
    algorithm: encoded.algorithm as DigestAlgorithm,
  };
}

export function verifyDigest(bytes: ByteInput): DigestAlgorithm | null {
  const id: number = wasm.verify_digest(toUint8Array(bytes));
  if (id === DIGEST_SHA256 || id === DIGEST_BLAKE3) {
    return id as DigestAlgorithm;
  }
  return null;
}

export function hasValidDigest(bytes: ByteInput): boolean {
  return wasm.has_valid_digest(toUint8Array(bytes));
}

export function frameEncode(payload: ByteInput, maxLen?: number): Uint8Array {
  const bytes = toUint8Array(payload);
  if (maxLen === undefined) {
    return wasm.frame_encode(bytes);
  }
  return wasm.frame_encode_with_limit(bytes, maxLen);
}

export class FrameDecoder {
  private readonly inner: any;

  constructor(maxLen: number = DEFAULT_MAX_FRAME_LEN) {
    this.inner = new wasm.FrameDecoder(maxLen);
  }

  push(chunk: ByteInput): FrameDecodeResult {
    const out = this.inner.push(toUint8Array(chunk));
    return {
      frames: Array.from(out.frames as Uint8Array[]),
      consumed: out.consumed as number,
      needMore: out.need_more as boolean,
      eof: out.eof as boolean,
    };
  }
}

export function readerNew(bytes: ByteInput): any {
  return wasm.reader_new(toUint8Array(bytes));
}

export function readerRoot(reader: any): any {
  return wasm.reader_root(reader);
}

export function valueKind(value: any): number {
  return wasm.value_kind(value);
}

export function valueAsString(value: any): string | null {
  return wasm.value_as_string(value);
}

export function valueAsBytes(value: any): Uint8Array | null {
  return wasm.value_as_bytes(value);
}

export function toJsView(value: any): unknown {
  return wasm.to_js_view(value);
}

export function toJson(value: any): string {
  return wasm.to_json(value);
}

function toUint8Array(input: ByteInput): Uint8Array {
  if (input instanceof Uint8Array) {
    return input;
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  return Uint8Array.from(input);
}

function isNodeRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof (process as { versions?: { node?: string } }).versions?.node === "string"
  );
}

function shouldUseNativeFormatter(): boolean {
  if (!isNodeRuntime()) {
    return false;
  }
  if (formatterConfig.backend === "wasm") {
    return false;
  }
  if (formatterConfig.backend === "native") {
    return true;
  }
  return isNativeFormatterAvailable();
}

function isNativeFormatterAvailable(): boolean {
  if (
    cachedNativeAvailability !== null &&
    cachedNativeAvailability.binary === formatterConfig.nativeBinaryPath
  ) {
    return cachedNativeAvailability.available;
  }

  const childProcess = require("node:child_process") as {
    spawnSync: (
      cmd: string,
      args: string[],
      options: { encoding: "utf8" },
    ) => { error?: { message?: string } };
  };

  const probe = childProcess.spawnSync(formatterConfig.nativeBinaryPath, [], {
    encoding: "utf8",
  });
  const available = probe.error === undefined;
  cachedNativeAvailability = {
    binary: formatterConfig.nativeBinaryPath,
    available,
  };
  return available;
}

function nativeFormatText(text: string): string {
  const result = runNativeFormatter(text, false);
  if (result.status === 0) {
    return result.stdout;
  }
  throw new Error(nativeFormatterErrorMessage(result, "format"));
}

function nativeFormatCheck(text: string): boolean {
  const result = runNativeFormatter(text, true);
  if (result.status === 0) {
    return true;
  }
  if (result.stderr.includes(NON_CANONICAL_MARKER)) {
    return false;
  }
  throw new Error(nativeFormatterErrorMessage(result, "format-check"));
}

function runNativeFormatter(
  text: string,
  check: boolean,
): { status: number; stdout: string; stderr: string } {
  const fs = require("node:fs") as {
    mkdtempSync: (prefix: string) => string;
    writeFileSync: (path: string, data: string, opts: { encoding: "utf8" }) => void;
    rmSync: (path: string, opts: { recursive: true; force: true }) => void;
  };
  const os = require("node:os") as { tmpdir: () => string };
  const path = require("node:path") as { join: (...parts: string[]) => string };
  const childProcess = require("node:child_process") as {
    spawnSync: (
      cmd: string,
      args: string[],
      options: { encoding: "utf8" },
    ) => {
      status: number | null;
      stdout?: string;
      stderr?: string;
      error?: { message?: string };
    };
  };

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rulia-fmt-"));
  const filePath = path.join(tempDir, "input.rulia");
  fs.writeFileSync(filePath, text, { encoding: "utf8" });

  try {
    const args = check ? ["--check", filePath] : [filePath];
    const out = childProcess.spawnSync(formatterConfig.nativeBinaryPath, args, {
      encoding: "utf8",
    });
    if (out.error) {
      throw new Error(out.error.message || "failed to execute native formatter");
    }
    return {
      status: out.status === null ? 1 : out.status,
      stdout: out.stdout || "",
      stderr: out.stderr || "",
    };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function nativeFormatterErrorMessage(
  result: { status: number; stdout: string; stderr: string },
  operation: string,
): string {
  const stderr = result.stderr.trim();
  const stdout = result.stdout.trim();
  const details = stderr.length > 0 ? stderr : stdout;
  if (details.length > 0) {
    return `native formatter ${operation} failed: ${details}`;
  }
  return `native formatter ${operation} failed with exit code ${result.status}`;
}
