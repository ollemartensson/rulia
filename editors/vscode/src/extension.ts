import * as vscode from "vscode";
import * as crypto from "crypto";
import * as fs from "fs";
import * as https from "https";
import * as os from "os";
import * as path from "path";
import { Transform, Writable } from "stream";
import { pipeline } from "stream/promises";
import * as tar from "tar";
import * as unzipper from "unzipper";
import { URL, fileURLToPath, pathToFileURL } from "url";
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
} from "vscode-languageclient/node";

const OUTPUT_CHANNEL_NAME = "Rulia";
const EXPECTED_BINS = ["rulia", "rulia-fmt", "rulia-lsp"];
const CHECKSUM_FILE = "artifact.sha256";

type ManifestArtifact = {
    target: string;
    file: string;
    sha256: string;
    url?: string;
    bins?: string[];
};

type ReleaseManifest = {
    version: string;
    artifacts: ManifestArtifact[];
};

type DownloadedFile = {
    filePath: string;
    sha256: string;
    cleanup: () => Promise<void>;
};

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel | undefined;

export function resolveTargetTriple(
    platform: NodeJS.Platform,
    arch: string,
): string | undefined {
    if (platform === "win32" && arch === "x64") {
        return "x86_64-pc-windows-msvc";
    }
    if (platform === "darwin" && arch === "arm64") {
        return "aarch64-apple-darwin";
    }
    if (platform === "darwin" && arch === "x64") {
        return "x86_64-apple-darwin";
    }
    if (platform === "linux" && arch === "x64") {
        return "x86_64-unknown-linux-gnu";
    }
    return undefined;
}

export function verifySha256(actualHex: string, expectedHex: string): boolean {
    const normalized = expectedHex.trim().toLowerCase();
    return actualHex.trim().toLowerCase() === normalized;
}

export function selectArtifact(
    manifest: ReleaseManifest,
    target: string,
): ManifestArtifact | undefined {
    return manifest.artifacts.find((artifact) => artifact.target === target);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}

function expectString(
    value: unknown,
    label: string,
    allowEmpty = false,
): string {
    if (typeof value !== "string") {
        throw new Error(`Manifest ${label} must be a string`);
    }
    const trimmed = value.trim();
    if (!allowEmpty && trimmed.length === 0) {
        throw new Error(`Manifest ${label} must be non-empty`);
    }
    return trimmed;
}

function parseManifest(bytes: Buffer): ReleaseManifest {
    let data: unknown;
    try {
        data = JSON.parse(bytes.toString("utf8"));
    } catch (err) {
        throw new Error(`Manifest JSON parse failed: ${String(err)}`);
    }

    if (!isRecord(data)) {
        throw new Error("Manifest JSON must be an object");
    }

    const version = expectString(data.version, "version");
    const artifactsRaw = data.artifacts;
    if (!Array.isArray(artifactsRaw)) {
        throw new Error("Manifest artifacts must be an array");
    }

    const artifacts: ManifestArtifact[] = artifactsRaw.map((entry, index) => {
        if (!isRecord(entry)) {
            throw new Error(`Manifest artifact[${index}] must be an object`);
        }
        let url: string | undefined;
        if (typeof entry.url === "string") {
            url = entry.url.trim();
            if (!url) {
                throw new Error(
                    `Manifest artifact[${index}].url must be non-empty when provided`,
                );
            }
        }
        return {
            target: expectString(entry.target, `artifact[${index}].target`),
            file: expectString(entry.file, `artifact[${index}].file`),
            sha256: expectString(entry.sha256, `artifact[${index}].sha256`),
            url,
            bins: Array.isArray(entry.bins)
                ? entry.bins.filter((bin) => typeof bin === "string")
                : undefined,
        };
    });

    if (artifacts.length === 0) {
        throw new Error("Manifest contains no artifacts");
    }

    return { version, artifacts };
}

function getExecutableName(base: string): string {
    return process.platform === "win32" ? `${base}.exe` : base;
}

function resolveArtifactUrlFromFile(manifestUrl: string, file: string): string {
    if (file.startsWith("https://") || file.startsWith("http://")) {
        return file;
    }
    const base = new URL(manifestUrl);
    const dir = new URL(".", base);
    return new URL(file, dir).toString();
}

function resolveArtifactUrl(
    manifestUrl: string,
    artifact: ManifestArtifact,
): string {
    if (artifact.url) {
        return artifact.url;
    }
    return resolveArtifactUrlFromFile(manifestUrl, artifact.file);
}

function createHashStream(hash: crypto.Hash): Transform {
    return new Transform({
        transform(chunk, _encoding, callback) {
            hash.update(chunk as Buffer);
            callback(null, chunk);
        },
    });
}

async function createTempFile(
    prefix: string,
    suffix: string,
): Promise<{ dir: string; filePath: string; cleanup: () => Promise<void> }> {
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
    const filePath = path.join(dir, `download${suffix}`);
    const cleanup = async () => {
        await fs.promises.rm(dir, { recursive: true, force: true });
    };
    return { dir, filePath, cleanup };
}

async function streamToFileWithSha256(
    source: NodeJS.ReadableStream,
    filePath: string,
): Promise<string> {
    const hash = crypto.createHash("sha256");
    const hashStream = createHashStream(hash);
    await pipeline(source, hashStream, fs.createWriteStream(filePath));
    return hash.digest("hex");
}

async function hashFileSha256(filePath: string): Promise<string> {
    const hash = crypto.createHash("sha256");
    const hashStream = createHashStream(hash);
    const sink = new Writable({
        write(_chunk, _encoding, callback) {
            callback();
        },
    });
    await pipeline(fs.createReadStream(filePath), hashStream, sink);
    return hash.digest("hex");
}

async function downloadToFile(
    url: string,
    maxRedirects = 5,
): Promise<DownloadedFile> {
    const parsed = new URL(url);
    if (parsed.protocol === "https:") {
        return new Promise<DownloadedFile>((resolve, reject) => {
            const request = https.get(url, (response) => {
                const status = response.statusCode ?? 0;
                if (
                    status >= 300 &&
                    status < 400 &&
                    response.headers.location
                ) {
                    if (maxRedirects <= 0) {
                        response.resume();
                        reject(new Error(`Too many redirects for ${url}`));
                        return;
                    }
                    const redirectUrl = new URL(
                        response.headers.location,
                        url,
                    ).toString();
                    response.resume();
                    resolve(downloadToFile(redirectUrl, maxRedirects - 1));
                    return;
                }
                if (status !== 200) {
                    response.resume();
                    reject(new Error(`HTTP ${status} for ${url}`));
                    return;
                }
                (async () => {
                    let temp:
                        | {
                              dir: string;
                              filePath: string;
                              cleanup: () => Promise<void>;
                          }
                        | undefined;
                    try {
                        temp = await createTempFile(
                            "rulia-download-",
                            path.extname(parsed.pathname),
                        );
                        const sha256 = await streamToFileWithSha256(
                            response,
                            temp.filePath,
                        );
                        resolve({
                            filePath: temp.filePath,
                            sha256,
                            cleanup: temp.cleanup,
                        });
                    } catch (err) {
                        if (temp) {
                            await temp.cleanup();
                        }
                        reject(err);
                    }
                })().catch((err) => {
                    response.resume();
                    reject(err);
                });
            });

            request.on("error", (err) => reject(err));
        });
    }

    if (parsed.protocol === "file:") {
        const sourcePath = fileURLToPath(parsed);
        const temp = await createTempFile(
            "rulia-download-",
            path.extname(sourcePath),
        );
        try {
            const sha256 = await streamToFileWithSha256(
                fs.createReadStream(sourcePath),
                temp.filePath,
            );
            return { filePath: temp.filePath, sha256, cleanup: temp.cleanup };
        } catch (err) {
            await temp.cleanup();
            throw err;
        }
    }

    throw new Error(`Unsupported download protocol for ${url}`);
}

function isSafeArchivePath(entryPath: string): boolean {
    const trimmed = entryPath.trim();
    if (!trimmed) {
        return false;
    }
    if (trimmed.includes("\0")) {
        return false;
    }
    const normalized = trimmed.replace(/\\/g, "/");
    if (path.posix.isAbsolute(normalized)) {
        return false;
    }
    if (path.win32.isAbsolute(trimmed)) {
        return false;
    }
    const cleaned = path.posix.normalize(normalized);
    if (cleaned === "." || cleaned.startsWith("../")) {
        return false;
    }
    if (cleaned.split("/").includes("..")) {
        return false;
    }
    if (process.platform === "win32" && cleaned.includes(":")) {
        return false;
    }
    return true;
}

function assertSafeArchivePath(entryPath: string, sourceLabel: string): void {
    if (!isSafeArchivePath(entryPath)) {
        throw new Error(
            `Unsafe ${sourceLabel} entry path detected: ${entryPath}`,
        );
    }
}

async function extractTarGz(archivePath: string, dest: string): Promise<void> {
    await tar.t({
        file: archivePath,
        gzip: true,
        onentry(entry) {
            assertSafeArchivePath(entry.path, "tar");
        },
    });
    await tar.x({
        cwd: dest,
        file: archivePath,
        gzip: true,
        preservePaths: false,
    });
}

async function extractZip(archivePath: string, dest: string): Promise<void> {
    const directory = await unzipper.Open.file(archivePath);
    for (const entry of directory.files) {
        assertSafeArchivePath(entry.path, "zip");
    }
    await directory.extract({ path: dest });
}

async function ensureExecutable(filePath: string): Promise<void> {
    if (process.platform === "win32") {
        return;
    }
    await fs.promises.chmod(filePath, 0o755);
}

async function fileExists(filePath: string): Promise<boolean> {
    try {
        await fs.promises.stat(filePath);
        return true;
    } catch {
        return false;
    }
}

async function validateInstalledTools(
    installDir: string,
    expectedSha: string,
): Promise<boolean> {
    const checksumPath = path.join(installDir, CHECKSUM_FILE);
    if (!(await fileExists(checksumPath))) {
        return false;
    }
    const existingSha = await fs.promises.readFile(checksumPath, "utf8");
    if (existingSha.trim().toLowerCase() !== expectedSha.trim().toLowerCase()) {
        return false;
    }

    const binDir = path.join(installDir, "bin");
    for (const bin of EXPECTED_BINS) {
        const binName = getExecutableName(bin);
        if (!(await fileExists(path.join(binDir, binName)))) {
            return false;
        }
    }

    return true;
}

async function installArtifact(
    archivePath: string,
    artifact: ManifestArtifact,
    installDir: string,
): Promise<void> {
    const tmpDir = `${installDir}.tmp`;
    await fs.promises.rm(tmpDir, { recursive: true, force: true });
    await fs.promises.mkdir(tmpDir, { recursive: true });

    if (artifact.file.endsWith(".tar.gz")) {
        await extractTarGz(archivePath, tmpDir);
    } else if (artifact.file.endsWith(".zip")) {
        await extractZip(archivePath, tmpDir);
    } else {
        throw new Error(`Unsupported artifact format: ${artifact.file}`);
    }

    const binDir = path.join(tmpDir, "bin");
    for (const bin of EXPECTED_BINS) {
        const binName = getExecutableName(bin);
        const binPath = path.join(binDir, binName);
        if (!(await fileExists(binPath))) {
            throw new Error(`Missing ${binName} after extraction`);
        }
        await ensureExecutable(binPath);
    }

    await fs.promises.writeFile(
        path.join(tmpDir, CHECKSUM_FILE),
        `${artifact.sha256}\n`,
    );

    await fs.promises.rm(installDir, { recursive: true, force: true });
    await fs.promises.rename(tmpDir, installDir);
}

function getExplicitServerPath(
    config: vscode.WorkspaceConfiguration,
): string | undefined {
    const inspected = config.inspect<string>("serverPath");
    const candidates = [
        inspected?.workspaceFolderValue,
        inspected?.workspaceValue,
        inspected?.globalValue,
        inspected?.workspaceFolderLanguageValue,
        inspected?.workspaceLanguageValue,
        inspected?.globalLanguageValue,
    ];
    for (const candidate of candidates) {
        if (typeof candidate === "string" && candidate.trim().length > 0) {
            return candidate.trim();
        }
    }
    return undefined;
}

function resolveCacheRoot(
    context: vscode.ExtensionContext,
    config: vscode.WorkspaceConfiguration,
): string {
    const cacheDir = (config.get<string>("tools.cacheDir", "") ?? "").trim();
    if (!cacheDir) {
        return context.globalStoragePath;
    }
    if (path.isAbsolute(cacheDir)) {
        return cacheDir;
    }
    return path.join(context.globalStoragePath, cacheDir);
}

async function resolveServerPath(
    context: vscode.ExtensionContext,
    output: vscode.OutputChannel,
): Promise<string | undefined> {
    const config = vscode.workspace.getConfiguration("rulia");
    const explicitServerPath = getExplicitServerPath(config);
    if (explicitServerPath) {
        output.appendLine(`Using configured serverPath: ${explicitServerPath}`);
        return explicitServerPath;
    }

    const autoDownload = config.get<boolean>("tools.autoDownload", true);
    if (!autoDownload) {
        const fallback = config.get<string>("serverPath", "rulia-lsp");
        output.appendLine(
            `Auto-download disabled; using serverPath: ${fallback}`,
        );
        return fallback;
    }

    const manifestUrl = (
        config.get<string>("tools.manifestUrl", "") ?? ""
    ).trim();
    if (!manifestUrl) {
        vscode.window.showWarningMessage(
            "Rulia tools auto-download is enabled but rulia.tools.manifestUrl is not set.",
        );
        return undefined;
    }

    const version = (
        config.get<string>("tools.version", "0.1.0") ?? "0.1.0"
    ).trim();
    const target = resolveTargetTriple(process.platform, process.arch);
    if (!target) {
        vscode.window.showErrorMessage(
            `Rulia tools auto-download does not support ${process.platform}/${process.arch}.`,
        );
        return undefined;
    }

    return vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: "Rulia tools",
            cancellable: false,
        },
        async (progress) => {
            try {
                progress.report({ message: "Downloading manifest" });
                const manifestDownload = await downloadToFile(manifestUrl);
                let manifest: ReleaseManifest;
                try {
                    const manifestBytes = await fs.promises.readFile(
                        manifestDownload.filePath,
                    );
                    manifest = parseManifest(manifestBytes);
                } finally {
                    await manifestDownload.cleanup();
                }
                if (version !== "latest" && manifest.version !== version) {
                    vscode.window.showErrorMessage(
                        `Manifest version ${manifest.version} does not match configured version ${version}.`,
                    );
                    return undefined;
                }

                const artifact = selectArtifact(manifest, target);
                if (!artifact) {
                    vscode.window.showErrorMessage(
                        `No artifact for target ${target} in manifest.`,
                    );
                    return undefined;
                }

                const resolvedVersion =
                    version === "latest" ? manifest.version : version;
                const cacheRoot = resolveCacheRoot(context, config);
                const installDir = path.join(
                    cacheRoot,
                    "tools",
                    resolvedVersion,
                    target,
                );
                const serverPath = path.join(
                    installDir,
                    "bin",
                    getExecutableName("rulia-lsp"),
                );

                await fs.promises.mkdir(cacheRoot, { recursive: true });

                if (await validateInstalledTools(installDir, artifact.sha256)) {
                    output.appendLine(
                        `Using cached tools at ${installDir} (${target}).`,
                    );
                    return serverPath;
                }

                progress.report({ message: "Downloading tools" });
                const artifactUrl = resolveArtifactUrl(manifestUrl, artifact);
                const artifactDownload = await downloadToFile(artifactUrl);
                try {
                    if (
                        !verifySha256(artifactDownload.sha256, artifact.sha256)
                    ) {
                        vscode.window.showErrorMessage(
                            "Rulia tools checksum mismatch. Downloaded artifact will not be executed.",
                        );
                        return undefined;
                    }

                    progress.report({ message: "Extracting tools" });
                    await installArtifact(
                        artifactDownload.filePath,
                        artifact,
                        installDir,
                    );
                } finally {
                    await artifactDownload.cleanup();
                }

                output.appendLine(
                    `Installed Rulia tools to ${installDir} (${target}).`,
                );

                return serverPath;
            } catch (err) {
                output.appendLine(
                    `Auto-download failed: ${err instanceof Error ? err.message : String(err)}`,
                );
                vscode.window.showWarningMessage(
                    "Rulia tools download failed. Configure rulia.serverPath to use a local installation.",
                );
                return undefined;
            }
        },
    );
}

export async function activate(context: vscode.ExtensionContext) {
    const output = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
    outputChannel = output;
    context.subscriptions.push(output);
    output.appendLine("Rulia extension activating");

    const resolvedServerPath = await resolveServerPath(context, output);

    if (resolvedServerPath) {
        const serverOptions: ServerOptions = {
            command: resolvedServerPath,
            args: [],
            transport: TransportKind.stdio,
        };

        const clientOptions: LanguageClientOptions = {
            documentSelector: [{ language: "rulia", scheme: "file" }],
            synchronize: {
                fileEvents:
                    vscode.workspace.createFileSystemWatcher("**/*.rjl"),
            },
        };

        client = new LanguageClient(
            "rulia",
            "Rulia Language Server",
            serverOptions,
            clientOptions,
        );

        client.start();
    } else {
        output.appendLine("Rulia language server not started.");
    }

    const selfTest = vscode.commands.registerCommand(
        "rulia.selfTest",
        async () => {
            const target = resolveTargetTriple(process.platform, process.arch);
            output.appendLine(`Self-test: platform=${process.platform}`);
            output.appendLine(`Self-test: arch=${process.arch}`);
            output.appendLine(`Self-test: target=${target ?? "unsupported"}`);

            try {
                const tempRoot = await fs.promises.mkdtemp(
                    path.join(os.tmpdir(), "rulia-selftest-"),
                );
                const payloadDir = path.join(tempRoot, "payload");
                const binDir = path.join(payloadDir, "bin");
                await fs.promises.mkdir(binDir, { recursive: true });
                for (const bin of EXPECTED_BINS) {
                    const binPath = path.join(binDir, getExecutableName(bin));
                    await fs.promises.writeFile(binPath, `self-test ${bin}\n`);
                }
                const archivePath = path.join(tempRoot, "artifact.tar.gz");
                await tar.c(
                    {
                        gzip: true,
                        cwd: payloadDir,
                        file: archivePath,
                    },
                    ["bin"],
                );
                const expectedSha256 = await hashFileSha256(archivePath);
                const fileUrl = pathToFileURL(archivePath).toString();
                const download = await downloadToFile(fileUrl);
                try {
                    if (!verifySha256(download.sha256, expectedSha256)) {
                        throw new Error(
                            "Self-test checksum mismatch for local artifact.",
                        );
                    }
                    const installDir = path.join(tempRoot, "install");
                    await installArtifact(
                        download.filePath,
                        {
                            target: "self-test",
                            file: "artifact.tar.gz",
                            sha256: expectedSha256,
                            bins: EXPECTED_BINS,
                        },
                        installDir,
                    );
                    if (
                        !(await validateInstalledTools(
                            installDir,
                            expectedSha256,
                        ))
                    ) {
                        throw new Error(
                            "Self-test validation failed after extraction.",
                        );
                    }
                    output.appendLine("Self-test: PASS");
                } finally {
                    await download.cleanup();
                    await fs.promises.rm(tempRoot, {
                        recursive: true,
                        force: true,
                    });
                }
                vscode.window.showInformationMessage(
                    "Rulia self-test complete. See the Rulia output channel for details.",
                );
            } catch (err) {
                output.appendLine(
                    `Self-test failed: ${err instanceof Error ? err.message : String(err)}`,
                );
                vscode.window.showWarningMessage(
                    "Rulia self-test failed. See the Rulia output channel.",
                );
            }
        },
    );

    context.subscriptions.push(selfTest);

    // Register hover provider for keywords
    const hoverProvider = vscode.languages.registerHoverProvider("rulia", {
        provideHover(document, position, token) {
            const range = document.getWordRangeAtPosition(position);
            const word = document.getText(range);

            // Provide hover information for keywords
            const keywords: Record<string, string> = {
                let: "Bind a value to a name.\n\nSyntax: `let name = value body`",
                fn: "Define an anonymous function.\n\nSyntax: `fn(params) => body`",
                import: 'Import a Rulia file.\n\nSyntax: `import "path" [hash:value]`',
                begin: "Start a namespace block.\n\nUsed with `@ns name begin ... end`",
                end: "End a namespace block.",
                true: "Boolean true value.",
                false: "Boolean false value.",
                nil: "Null/absent value.",
                Set: "Create a set from a vector.\n\nSyntax: `Set([items])`",
                Ref: "Create a graph reference.\n\nSyntax: `Ref(id)` or `Ref(:attr, value)`",
                UUID: 'Create a UUID tagged value.\n\nSyntax: `UUID("uuid-string")`',
                ULID: 'Create a ULID tagged value.\n\nSyntax: `ULID("ulid-string")`',
                Generator:
                    "Create a deferred value generator.\n\nSyntax: `Generator(:uuid)`, `Generator(:ulid)`, `Generator(:now)`",
                Query: "Create a Datalog query.\n\nSyntax: `Query(find = [...], where = [...])`",
                merge: "Merge multiple maps (later values win).\n\nSyntax: `merge(map1, map2, ...)`",
                concat: "Concatenate values as strings.\n\nSyntax: `concat(val1, val2, ...)`",
                get: "Get element by index or key.\n\nSyntax: `get(collection, index)`",
            };

            if (keywords[word]) {
                return new vscode.Hover(
                    new vscode.MarkdownString(keywords[word]),
                );
            }

            // Macros
            if (word === "meta" || word === "ns" || word === "new") {
                const macros: Record<string, string> = {
                    meta: "Attach metadata to a value.\n\nSyntax: `@meta(key = value) Value(...)`",
                    ns: "Apply namespace to map keys.\n\nSyntax: `@ns name begin (key = val) end`",
                    new: "Generate a value immediately.\n\nSyntax: `@new(:uuid)`, `@new(:ulid)`, `@new(:now)`",
                };
                return new vscode.Hover(
                    new vscode.MarkdownString(
                        `**@${word}**\n\n${macros[word]}`,
                    ),
                );
            }

            return null;
        },
    });

    context.subscriptions.push(hoverProvider);

    // Register document symbol provider for outline view
    const symbolProvider = vscode.languages.registerDocumentSymbolProvider(
        "rulia",
        {
            provideDocumentSymbols(document, token): vscode.DocumentSymbol[] {
                const symbols: vscode.DocumentSymbol[] = [];
                const text = document.getText();

                // Find let bindings at top level
                const letRegex = /let\s+(\w+)\s*=/g;
                let match;
                while ((match = letRegex.exec(text)) !== null) {
                    const name = match[1];
                    const startPos = document.positionAt(match.index);
                    const endPos = document.positionAt(
                        match.index + match[0].length,
                    );
                    const range = new vscode.Range(startPos, endPos);

                    const symbol = new vscode.DocumentSymbol(
                        name,
                        "binding",
                        vscode.SymbolKind.Variable,
                        range,
                        range,
                    );
                    symbols.push(symbol);
                }

                // Find PascalCase constructors
                const constructorRegex = /([A-Z][a-zA-Z0-9]*)\s*\(/g;
                while ((match = constructorRegex.exec(text)) !== null) {
                    const name = match[1];
                    // Skip builtin constructors for cleaner outline
                    if (["Set", "Keyword", "Symbol", "Tagged"].includes(name)) {
                        continue;
                    }
                    const startPos = document.positionAt(match.index);
                    const endPos = document.positionAt(
                        match.index + match[0].length - 1,
                    );
                    const range = new vscode.Range(startPos, endPos);

                    const symbol = new vscode.DocumentSymbol(
                        name,
                        "constructor",
                        vscode.SymbolKind.Class,
                        range,
                        range,
                    );
                    symbols.push(symbol);
                }

                return symbols;
            },
        },
    );

    context.subscriptions.push(symbolProvider);

    // Register completion provider
    const completionProvider = vscode.languages.registerCompletionItemProvider(
        "rulia",
        {
            provideCompletionItems(document, position, token, context) {
                const completions: vscode.CompletionItem[] = [];

                // Keywords
                const keywords = [
                    "let",
                    "fn",
                    "import",
                    "begin",
                    "end",
                    "true",
                    "false",
                    "nil",
                ];
                for (const kw of keywords) {
                    const item = new vscode.CompletionItem(
                        kw,
                        vscode.CompletionItemKind.Keyword,
                    );
                    completions.push(item);
                }

                // Builtins
                const builtins = [
                    "Set",
                    "Keyword",
                    "Symbol",
                    "Tagged",
                    "Ref",
                    "UUID",
                    "ULID",
                    "Instant",
                    "Generator",
                    "Query",
                    "merge",
                    "concat",
                    "get",
                ];
                for (const fn of builtins) {
                    const item = new vscode.CompletionItem(
                        fn,
                        vscode.CompletionItemKind.Function,
                    );
                    completions.push(item);
                }

                // Macros (after @)
                const linePrefix = document
                    .lineAt(position)
                    .text.substring(0, position.character);
                if (linePrefix.endsWith("@")) {
                    const macros = ["meta", "ns", "new"];
                    for (const macro of macros) {
                        const item = new vscode.CompletionItem(
                            macro,
                            vscode.CompletionItemKind.Method,
                        );
                        item.insertText = macro;
                        completions.push(item);
                    }
                }

                return completions;
            },
        },
        "@",
    );

    context.subscriptions.push(completionProvider);
}

export function deactivate() {
    outputChannel?.appendLine("Rulia extension is now deactivated");
    if (client) {
        return client.stop();
    }
    return undefined;
}
