# GitPurge

> VSCode extension for real-time detection of secrets and sensitive information before they get committed to Git.

GitPurge helps developers detect accidentally committed API keys, tokens, connection strings, private keys, and high-entropy secrets in real-time across individual files or entire workspaces.

---

## ✨ Features

- **Multi-rule Secret Detection**
  - Detects exposed credentials, API keys, access tokens, connection strings, private keys, and other sensitive values.
  - Combines rule-based pattern matching with entropy analysis.

- **Shannon Entropy Analysis**
  - Calculates Shannon entropy to surface high-entropy values that may represent randomly generated secrets.
  - Uses sensitive context to reduce false positives from ordinary random data.

- **VS Code Extension Integration**
  - **Real-time Live Scanning**: Scans active documents as you type with debouncing.
  - **Workspace Scanner**: Full workspace scanning with progress reporting and configurable size/path limits.
  - **Git-Aware Filtering**: Respects `.gitignore` rules and reports repository tracking status.
  - **Problems Panel**: Surfaces findings directly in VS Code's standard Problems view.

- **Python Library & CLI**
  - Reusable Python package with clean models and a CLI for standalone scanning and integration into other tools.

---

## 🚀 VS Code Extension

### Getting Started

1. Open this repository in VS Code.
2. Install dependencies:
   ```sh
   npm install
   ```
3. Press `F5` (or run `Launch Extension`) to start the Extension Development Host.

### Commands

Accessible via `Ctrl+Shift+P` / `Cmd+Shift+P` (Command Palette):

| Command | Identifier | Description |
| :--- | :--- | :--- |
| **GitPurge: Scan Active File** | `gitpurge.scanFile` | Scans the currently open file in the editor |
| **GitPurge: Scan Workspace** | `gitpurge.scanWorkspace` | Scans all readable files in the workspace |
| **GitPurge: Show Findings** | `gitpurge.showFindings` | Opens a QuickPick listing all recent findings |
| **GitPurge: Show Scan Output** | `gitpurge.showOutput` | Reveals the GitPurge output channel |

### Configuration

Customize scanner behavior in your VS Code settings (`settings.json`):

```json
{
  "gitpurge.exclude": [
    "**/.git/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/dist/**",
    "**/build/**"
  ],
  "gitpurge.maxFileSize": 1048576
}
```

- **`gitpurge.exclude`** *(array)*: Glob patterns excluded from workspace scans.
- **`gitpurge.maxFileSize`** *(number)*: Maximum file size in bytes to scan (default: 1 MiB).

---

## 🐍 Python Package & CLI

### Installation

Requires Python `>= 3.14`:

```sh
# Using uv
uv sync

# Or using pip in a virtual environment
pip install -e .
```

### Python API Usage

```python
from gitpurge.scanner import scan

code_sample = """
API_KEY = "sk-live_1234567890abcdef1234567890abcdef"
"""

result = scan(code_sample)
for finding in result.findings:
    print(f"[{finding.severity.upper()}] {finding.rule_id} at line {finding.line + 1}: {finding.message}")
```

### CLI Entrypoint

```sh
# Execute the server / CLI runner
python3 -m gitpurge
```

---

## 🛠️ Development & Testing

### TypeScript & Extension Tests

```sh
# Run TypeScript compilation and Node test suite
npm test

# Watch / Compile TypeScript only
npm run compile
```

### Python Tests & Verification

```sh
python3 -c "import src.gitpurge as gp; gp.main()"
```

---

## 📁 Project Structure

```
GitPurge/
├── src/
│   ├── extension.ts       # VS Code extension entry point & TreeDataProvider
│   ├── gitignore.ts       # .gitignore matching utility
│   ├── scanner.ts         # TypeScript secret scanner & entropy engine
│   └── gitpurge/          # Python engine
│       ├── __init__.py    # Package root
│       ├── detectors.py   # Regex secret rules & patterns
│       ├── entropy.py     # Shannon entropy analysis
│       ├── models.py      # Dataclasses (Finding, ScanResult, GitStatus)
│       ├── scanner.py     # Python core scanner orchestration
│       └── server.py      # Request handler and CLI entry point
├── test/
│   ├── scanner.test.ts    # Test suite for scanner and .gitignore logic
│   ├── sample.json        # Test payload
│   └── output.json        # Expected scanner output
├── package.json           # Extension manifest & scripts
├── pyproject.toml         # Python project configuration
└── tsconfig.json          # TypeScript compiler configuration
```

---
