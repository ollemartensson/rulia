# Rulia for Visual Studio Code

Language support for [Rulia](https://github.com/rulia/rulia), a dual-format data notation with content-addressable binary encoding.

## Features

### Syntax Highlighting

Full syntax highlighting support for all Rulia language features:

- **Primitives**: Numbers, strings, booleans, nil, bytes
- **Collections**: Maps, vectors, sets
- **Keywords**: Simple and namespaced (`:keyword`, `:ns_name`)
- **Symbols**: Regular and logic variables (`'symbol`, `@?var`)
- **Constructors**: PascalCase tagged values (`User(...)`, `UUID(...)`)
- **Macros**: `@meta`, `@ns`, `@new`
- **Functions**: Let bindings, lambdas, builtins
- **String interpolation**: `$var` and `$(expr)`
- **Comments**: Line comments with `#`

### Code Snippets

Over 40 snippets for common patterns:

| Prefix | Description |
|--------|-------------|
| `map` | Create a map |
| `vec` | Create a vector |
| `set` | Create a set |
| `let` | Let binding |
| `letb` | Let block |
| `letd` | Destructuring |
| `fn` | Anonymous function |
| `letfn` | Named function |
| `con` | Constructor |
| `uuid` | UUID literal |
| `uuidn` | Generate UUID |
| `ulid` | ULID literal |
| `ulidn` | Generate ULID |
| `ref` | Reference |
| `ns` | Namespace block |
| `meta` | Metadata decorator |
| `query` | Datalog query |
| `schema` | Schema template |

Type the prefix and press `Tab` to expand.

### Smart Editing

- **Auto-closing**: Brackets, parentheses, quotes
- **Bracket matching**: Colorized bracket pairs
- **Indentation**: Auto-indent for blocks
- **Folding**: Code folding for maps, vectors, blocks
- **Word wrap**: Automatic word wrapping

### Editor Defaults

Optimized settings for Rulia files:
- 2-space indentation
- Spaces instead of tabs
- Format on save
- Auto-closing brackets and quotes

### Language Server (rulia-lsp)

This extension starts `rulia-lsp` for `.rjl` files to provide diagnostics and formatting.

By default, the extension can auto-download the Rulia toolchain (lsp/fmt/cli) from a release manifest. The manifest provides the SHA256 checksums used to verify downloads.
Downloads are streamed to disk while hashing, archive paths are validated to prevent traversal, and extraction happens in a temporary directory before an atomic install.

### Toolchain installation options

A) Auto-download (default): configure `rulia.tools.autoDownload`, `rulia.tools.manifestUrl`, and `rulia.tools.version`.

B) Manual install via CLI: run `rulia tools install --manifest-url <...> --version <...>` and set `rulia.serverPath` to the installed `rulia-lsp` path.

Manifest URL example format: `https://storage.googleapis.com/<bucket>/rulia/<version>/manifest.json`.

Minimal setup (auto-download):

```json
{
  "rulia.tools.autoDownload": true,
  "rulia.tools.manifestUrl": "https://github.com/<org>/<repo>/releases/download/v0.1.0/manifest.json",
  "rulia.tools.version": "0.1.0"
}
```

Manual override:

```json
{
  "rulia.serverPath": "/absolute/path/to/rulia-lsp"
}
```

When `rulia.serverPath` is set, auto-download is skipped.

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "Rulia"
4. Click Install

### From VSIX

1. Download the `.vsix` file
2. Open VS Code
3. Go to Extensions
4. Click "..." menu → "Install from VSIX..."
5. Select the downloaded file

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/rulia/rulia.git
cd rulia/editors/vscode

# Install dependencies
npm install

# Package the extension
npx vsce package

# Install the generated .vsix file
code --install-extension rulia-*.vsix
```

## Toolchain Settings

The auto-downloaded toolchain is cached under the extension storage directory:

`<globalStorage>/tools/<version>/<target>/bin`

Settings overview:

- `rulia.tools.autoDownload` (boolean): Enable/disable toolchain download.
- `rulia.tools.manifestUrl` (string): HTTPS URL to `manifest.json` for a release.
- `rulia.tools.version` (string): Toolchain version or `latest`.
- `rulia.tools.cacheDir` (string): Optional absolute path or relative folder under the global storage path.
- `rulia.serverPath` (string): Explicit path to `rulia-lsp` (skips auto-download).

## Usage

1. Create a file with `.rjl` extension
2. Start typing Rulia code
3. Use snippets for common patterns (type prefix + Tab)
4. Run Format Document to apply canonical formatting

### Example

```rulia
# Configuration file
@meta(version = "1.0", author = "admin")
"Application configuration."
(
  app_name = "MyApp",
  app_version = "2.1.0",

  database = (
    host = "localhost",
    port = 5432,
    connection_pool = 10
  ),

  features = Set([:auth, :logging, :metrics]),

  users = [
    User(id = @new(:uuid), name = "Alice"),
    User(id = @new(:uuid), name = "Bob")
  ]
)
```

## Language Overview

Rulia is a data notation language that combines:

- **Human-readable syntax** inspired by Julia
- **Rich type system** with tagged values
- **Content-addressable binary format** with cryptographic digests
- **Schema support** for data validation
- **Datalog integration** for queries

See the [Rulia documentation](https://github.com/rulia/rulia) for complete language reference.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+/` | Toggle line comment |
| `Ctrl+Shift+[` | Fold region |
| `Ctrl+Shift+]` | Unfold region |
| `Tab` | Expand snippet |
| `Ctrl+Space` | Trigger suggestions |

## Troubleshooting

### Syntax highlighting not working

1. Ensure the file has `.rjl` extension
2. Check that the language mode is set to "Rulia" (bottom right corner)
3. Reload VS Code window (Ctrl+Shift+P → "Reload Window")

### Snippets not appearing

1. Ensure you're in a Rulia file
2. Start typing the snippet prefix
3. Press Ctrl+Space to trigger suggestions

### Toolchain download issues

1. Confirm `rulia.tools.manifestUrl` is set to a valid HTTPS manifest URL
2. Run the command `Rulia: Self Test Toolchain Download` to download a local test artifact, validate checksums + extraction, and log `PASS` on success
3. If you already have a local `rulia-lsp`, set `rulia.serverPath` to its absolute path

## Contributing

Contributions are welcome! Please see the [main repository](https://github.com/rulia/rulia) for contribution guidelines.

## License

MIT License - see [LICENSE](../../LICENSE-MIT) for details.

## Development

1. `npm install`
2. `npm run compile`
3. Press `F5` to launch the Extension Development Host
4. Open a `.rjl` file and confirm syntax highlighting, diagnostics, and Format Document
