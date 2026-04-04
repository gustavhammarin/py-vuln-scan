# pypi-scanner

A CLI tool that resolves all transitive dependencies of a PyPI package and checks them for known vulnerabilities using the [OSV](https://osv.dev) database. Results are displayed in an interactive terminal UI.

## Installation

### Linux / macOS

```sh
curl -fsSL https://raw.githubusercontent.com/gustavhammarin/pypi-scanner/main/install.sh | sh
```

The script detects your OS and architecture, downloads the latest release binary to `~/.local/bin`, and adds it to your `PATH`. Reload your shell after:

```sh
source ~/.bashrc   # or ~/.zshrc
```

### Windows

Download the binary manually from the [releases page](../../releases) — see the table below.

### Manual download

Download a pre-built binary from the [releases page](../../releases) for your platform:

| Platform | Binary |
|---|---|
| Linux x86_64 | `pypi-scanner-x86_64-unknown-linux-gnu` |
| Linux arm64 | `pypi-scanner-aarch64-unknown-linux-gnu` |
| macOS x86_64 | `pypi-scanner-x86_64-apple-darwin` |
| macOS arm64 (Apple Silicon) | `pypi-scanner-aarch64-apple-darwin` |
| Windows x86_64 | `pypi-scanner-x86_64-pc-windows-msvc.exe` |

## Usage

```
pypi-scanner <PACKAGE> <VERSION>
```

### Arguments

| Argument | Description | Example |
|---|---|---|
| `PACKAGE` | The PyPI package name to scan | `requests` |
| `VERSION` | The exact version to scan | `2.28.0` |

### Example

```sh
pypi-scanner requests 2.28.0
```

Results are shown in an interactive TUI. Navigate with:

| Key | Action |
|---|---|
| `j` / `↓` | Next row |
| `k` / `↑` | Previous row |
| `q` / `Esc` | Quit |

The detail panel shows an advisory URL — Ctrl+click to open it in your browser.

## How it works

1. Resolves the full dependency graph of the given package using PubGrub version solving against the PyPI registry, recursively resolving all transitive dependencies.
2. Queries the OSV API for each resolved dependency to find known vulnerabilities.
3. Displays all findings in an interactive terminal table with severity, fixed version, and a direct advisory link.

## Build

Requires [Rust](https://www.rust-lang.org/tools/install).

```sh
cargo build --release
./target/release/pypi-scanner <PACKAGE> <VERSION>
```
