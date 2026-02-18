# Rulia for IntelliJ (v0 config)

Config-only setup for IntelliJ-based IDEs. There is no IntelliJ plugin yet.

## What you get (v0)

- Basic file recognition via a custom file type for `.rjl`
- Diagnostics via `rulia-lsp` (syntax + gated semantic checks)
- Formatting via LSP (canonical, CST-based) or via `rulia-fmt`
- Optional External Tools entries for common CLI commands

## Requirements

- Rulia toolchain installed (includes `rulia-lsp`, `rulia-fmt`, and `rulia` CLI)

```bash
rulia tools install --manifest-url <...> --version <...>
```

## File type association (.rjl)

1. Open Settings/Preferences.
2. Go to `Editor` -> `File Types`.
3. Add a new file type named `Rulia` (or reuse an existing custom type).
4. Associate the pattern `*.rjl` with the `Rulia` file type.

This provides basic file recognition. Full syntax highlighting requires a real IntelliJ plugin (v1), but LSP still provides diagnostics and formatting.

## LSP setup

IntelliJ LSP support varies by IDE/version. Use one of the variants below.

### Variant 1: JetBrains LSP Support plugin (recommended)

1. Install the JetBrains LSP plugin (often named `LSP Support` or similar in the plugin marketplace).
2. Open Settings/Preferences and find the LSP configuration area (usually under `Tools` -> `LSP Support`).
3. Add a language server with these fields:

```
Name: Rulia
Command: rulia-lsp
File patterns: *.rjl
```

If needed, replace `rulia-lsp` with the installed binary path such as `<CACHE_DIR>/tools/<version>/<target>/bin/rulia-lsp`.
4. Ensure formatting is enabled for the server. Some IDEs expose a `Enable document formatting` or `Formatting` checkbox in the LSP settings. If your IDE supports `Format on Save`, enable it under `Editor` -> `General` -> `On Save`.

### Variant 2: External formatter only (fallback)

If LSP plugins are unavailable in your IDE edition/version, use `rulia-fmt` as an External Tool for formatting. Diagnostics will be limited to CLI usage in this fallback.

## Formatting options

Option A (preferred): LSP `Format Document`
- Uses the canonical, CST-based formatter provided by `rulia-lsp`.

Option B: External Tool `Format with rulia-fmt`
- Program: `rulia-fmt`
- Arguments: `$FilePath$`
- Optional check mode: `rulia-fmt --check $FilePath$`

## External tools (optional)

External Tools are configured at Settings/Preferences -> `Tools` -> `External Tools`. Create a tool for each command with:

- Program: `rulia` (or the installed binary path if your IDE does not inherit PATH)
- Arguments: as listed below
- Working directory: `$ProjectFileDir$`

Suggested entries:

| Tool name | Program | Arguments | Working directory |
| --- | --- | --- | --- |
| Rulia: fmt --check | `rulia` | `fmt --check $FilePath$` | `$ProjectFileDir$` |
| Rulia: encode | `rulia` | `encode $FilePath$` | `$ProjectFileDir$` |
| Rulia: decode | `rulia` | `decode $FilePath$` | `$ProjectFileDir$` |
| Rulia: verify | `rulia` | `verify $FilePath$` | `$ProjectFileDir$` |
| Rulia: frame decode | `rulia` | `frame decode $FilePath$ --out-dir $ProjectFileDir$/rulia-frames` | `$ProjectFileDir$` |

An illustrative config export is available at `editors/intellij/external-tools.json`. Adjust field names to match your IDE version if you import it.

## Troubleshooting

- Verify the LSP binary is runnable:

```bash
rulia-lsp --help
```

- If IntelliJ was launched from the GUI, it may not inherit your shell PATH. Use absolute paths in LSP and External Tools if needed.
- If diagnostics or formatting do not trigger, confirm the file is recognized as `Rulia` in the status bar and that the LSP server is attached to `*.rjl` files.
- Large files may have debounced diagnostics; allow a moment after edits for updates to appear.
