const http = require("node:http");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number.parseInt(process.env.PORT || "8080", 10);
const RULIA_JS_PATH = process.env.RULIA_JS_PATH || "/opt/rulia-js/dist/index.js";

let sdk = null;
let sdkLoadError = null;

try {
  sdk = require(RULIA_JS_PATH);
  sdk.configureFormatter({ backend: "wasm" });
} catch (error) {
  sdkLoadError = error;
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        if (raw.trim() === "") {
          resolve({});
          return;
        }
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function inspectWorkflow(text) {
  const isCanonical = sdk.formatCheck(text);
  const canonicalText = isCanonical ? text : sdk.formatText(text);
  const encoded = sdk.encodeWithDigest(canonicalText, sdk.DIGEST_SHA256);
  return {
    is_canonical: isCanonical,
    canonical_text: canonicalText,
    digest_hex: Buffer.from(encoded.digest).toString("hex"),
    encoded_size: encoded.bytes.length,
    digest_algorithm: "sha256",
  };
}

const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, `http://${req.headers.host || "localhost"}`).pathname;

  if (req.method === "GET" && path === "/sdk/health") {
    if (sdk === null) {
      sendJson(res, 503, {
        status: "degraded",
        sdk_ready: false,
        error: sdkLoadError ? String(sdkLoadError.message || sdkLoadError) : "sdk unavailable",
      });
      return;
    }
    sendJson(res, 200, { status: "ok", sdk_ready: true });
    return;
  }

  if (req.method === "POST" && path === "/sdk/workflow/inspect") {
    if (sdk === null) {
      sendJson(res, 503, { error: "sdk unavailable" });
      return;
    }
    try {
      const payload = await readJson(req);
      const text = typeof payload.text === "string" ? payload.text : "";
      if (text.trim() === "") {
        sendJson(res, 400, { error: "missing required field: text" });
        return;
      }
      sendJson(res, 200, inspectWorkflow(text));
    } catch (error) {
      sendJson(res, 400, { error: "invalid request body", detail: String(error.message || error) });
    }
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, HOST, () => {
  console.log(`sdk-gateway listening on ${HOST}:${PORT}`);
});
