# Rulia for Zed (v0 config)

Config-only setup for Zed. There is no published Zed extension yet.

## What it enables

- Syntax highlighting via tree-sitter-rulia
- Diagnostics and formatting via rulia-lsp

## Requirements

- Zed installed
- Rulia toolchain installed (includes `rulia-lsp`)
- This repo available locally (tree-sitter grammar lives at `tools/tree-sitter-rulia`)

## Setup

### 1) Create a local language extension (grammar + queries)

Zed loads custom grammars through language extensions. Create a local extension folder and
install it as a dev extension.

Create the extension directory structure (example path shown):

```bash
mkdir -p ~/src/zed-extensions/rulia-local/languages/rulia
```

Add `extension.toml`:

```toml
id = "rulia-local"
name = "Rulia (Local)"
version = "0.0.1"
schema_version = 1

[grammars.rulia]
repository = "file://<RULIA_REPO>/tools/tree-sitter-rulia"
rev = "REPLACE_WITH_COMMIT_SHA"
```

Replace `<RULIA_REPO>` with the absolute path to your local clone.

Pin the grammar revision:

```bash
git -C <RULIA_REPO>/tools/tree-sitter-rulia rev-parse HEAD
```

Add `languages/rulia/config.toml`:

```toml
name = "Rulia"
grammar = "rulia"
path_suffixes = ["rjl"]
line_comments = ["#"]
```

`path_suffixes` associates `.rjl` files with the Rulia language.

Link the highlight queries from the grammar repo:

```bash
ln -s <RULIA_REPO>/tools/tree-sitter-rulia/queries/highlights.scm \
  ~/src/zed-extensions/rulia-local/languages/rulia/highlights.scm
```

Install the local extension in Zed:

- Open the Command Palette
- Run `zed: extensions`
- Choose `Install Dev Extension` and select `~/src/zed-extensions/rulia-local`

### 2) Configure language settings + LSP

Copy the sample config from `editors/zed/rulia.zed.json` into your Zed settings:

- Global: `~/.config/zed/settings.json`
- Workspace: `<repo>/.zed/settings.json`

The sample config also maps `.rjl` via `file_types` and registers `rulia-lsp` as the language
server for `Rulia`.

Install the toolchain:

```bash
rulia tools install --manifest-url <...> --version <...>
```

Then set `lsp.rulia-lsp.binary.path` to the installed binary. The install output prints the resolved cache directory and tool paths. Use a path like:

```
<CACHE_DIR>/tools/<version>/<target>/bin/rulia-lsp
```

If you already have `rulia-lsp` in PATH, you can set the path to the output of:

```bash
command -v rulia-lsp
```

### 3) Optional: format on save

The sample config enables formatting on save via the language server. If you prefer manual
formatting, set `format_on_save` to `off` or remove it.

## Troubleshooting

- Verify the LSP binary is runnable:

```bash
rulia-lsp --help
```

- If diagnostics or formatting do not trigger:
  - Confirm the file is recognized as "Rulia" (check the status bar).
  - Ensure `language_servers` includes `rulia-lsp` in settings.
  - Ensure `formatter` is set to `language_server` when using format-on-save.

- If Zed cannot find `rulia-lsp`:
  - Use an absolute `lsp.rulia-lsp.binary.path`.
  - Check PATH with `command -v rulia-lsp`.
