# Termigo Security Kit

Non-pentest security tools for Termigo: static analysis, dependency auditing, and malware scanning.

## Tools

| Tool | Description | Engines |
|------|-------------|---------|
| `sast_scan` | Static Application Security Testing | `semgrep`, `bandit`, `gosec`, `eslint-plugin-security` |
| `dependency_audit` | Dependency vulnerability audit | `osv-scanner`, `npm audit`, `pip audit`, `cargo audit`, `govulncheck` |
| `av_scan` | Antivirus / malware / adware scan | ClamAV, Windows Defender, YARA rules |

## Prerequisites

Install at least one engine per tool category:

### SAST
```bash
# Node.js projects
npm install -g semgrep eslint-plugin-security

# Python projects
pip install bandit

# Go projects
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

### Dependency Audit
```bash
# Multi-ecosystem (recommended)
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# npm
npm install -g npm-audit

# Python
pip install pip-audit

# Rust
cargo install cargo-audit

# Go
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### AV / Malware / Adware Scan
```bash
# Cross-platform (Windows, macOS, Linux)
brew install clamav        # macOS
sudo apt install clamav    # Linux
choco install clamav       # Windows

# YARA for adware rules (optional)
go install github.com/VirusTotal/yara@latest
# or: brew install yara | sudo apt install yara
```

## Installation

1. Download `termigo-security-kit.zip` from the [latest release](https://github.com/99apps-id/termigo-security-kit/releases)
2. Open Termigo → Extensions → Install from File
3. Select `termigo-security-kit.zip`
4. Verify integrity with `termigo-security-kit.zip.sha256`

```bash
# Verify checksum (PowerShell)
Get-FileHash termigo-security-kit.zip -Algorithm SHA256 | ForEach-Object { $_.Hash + "  termigo-security-kit.zip" } | Compare-Object (Get-Content termigo-security-kit.zip.sha256)
```

## How To

### Run SAST Scan

Scan a project directory for security vulnerabilities:

```json
{
  "tool": "sast_scan",
  "path": "./my-project",
  "engines": ["semgrep", "bandit"],
  "timeoutSecs": 300
}
```

**Parameters:**
- `path` (required) — Project root or file path to scan
- `engines` (optional) — Array of engines to run: `["semgrep"]`, `["bandit"]`, `["gosec"]`, `["eslint"]`
- `timeoutSecs` (optional) — Max execution time in seconds (default: 300)

**Output:**
- Markdown report saved to `security-reports/sast_scan-<target>-<timestamp>.md`
- Structured findings with severity, rule, file, and line number

### Run Dependency Audit

Audit project dependencies for known vulnerabilities:

```json
{
  "tool": "dependency_audit",
  "path": "./my-project",
  "ecosystem": "auto",
  "timeoutSecs": 180
}
```

**Parameters:**
- `path` (required) — Project root containing dependency manifests
- `ecosystem` (optional) — `"auto"`, `"npm"`, `"pip"`, `"cargo"`, `"go"`, or `"osv"`
- `timeoutSecs` (optional) — Max execution time in seconds (default: 180)

**Output:**
- Markdown report saved to `security-reports/dependency_audit-<target>-<timestamp>.md`
- Vulnerability list with severity, package name, and CVE/rule reference

### Run AV / Malware Scan

Scan files or directories for malware and adware:

```json
{
  "tool": "av_scan",
  "path": "./downloads",
  "engine": "auto"
}
```

**Parameters:**
- `path` (required) — File or directory to scan
- `engine` (optional) — `"auto"`, `"clamav"`, `"defender"`, or `"yara"`
- `timeoutSecs` (optional) — Max execution time in seconds (default: 300)

**Output:**
- Markdown report saved to `security-reports/av_scan-<target>-<timestamp>.md`
- Detection list with severity, file path, and malware name

### Run Adware-Only Scan with YARA

Scan specifically for adware, PUPs, and trackers:

```json
{
  "tool": "av_scan",
  "path": "./downloads",
  "adwareOnly": true,
  "yaraRules": "./rules/custom-adware.yar"
}
```

**Parameters:**
- `path` (required) — File or directory to scan
- `adwareOnly` (required) — Set to `true` for adware-only mode
- `yaraRules` (optional) — Path to custom YARA rules file (uses built-in rules if omitted)
- `timeoutSecs` (optional) — Max execution time in seconds (default: 300)

**Built-in Adware Rules:**
- `Adware_Generic_Bundle` — Detects generic adware bundles and PUPs
- `Adware_Browser_Hijacker` — Detects browser hijackers and toolbar installs
- `Adware_Tracker` — Detects analytics SDKs and ad trackers

## Settings

Access settings via Termigo → Extensions → Termigo Security Kit → Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `security.workingDir` | string | `security-reports` | Directory for storing scan reports |
| `security.shellTimeoutSecs` | number | `300` | Default timeout for shell commands (seconds) |

## Reports

All scan results are saved as Markdown files in the report directory:

```
security-reports/
├── sast_scan-my-project-2025-01-19T10-30-00.md
├── dependency_audit-my-project-2025-01-19T10-30-05.md
└── av_scan-downloads-2025-01-19T10-30-10.md
```

Each report contains:
- Tool metadata (name, target, command, timestamp)
- Structured findings (severity, summary, evidence)
- Raw output (truncated to 20KB)

## Troubleshooting

### "Engine not installed" error
Install the required engine:
```bash
# SAST
npm install -g semgrep

# Dependency audit
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# AV scan
brew install clamav   # macOS
sudo apt install clamav  # Linux
```

### "Command timed out"
Increase the timeout in settings or pass `timeoutSecs` parameter:
```json
{
  "tool": "sast_scan",
  "path": "./large-project",
  "timeoutSecs": 600
}
```

### "No findings detected"
This is normal if no issues were found. Check the report file for full output.

### YARA rules not loading
Ensure YARA is installed and the rules file path is absolute or relative to the project root:
```bash
# Verify YARA installation
yara --version

# Test rules file
yara ./rules/adware.yar ./test-file.exe
```

## Security

- All scans run **locally** — no data is sent to external servers
- ClamAV updates are managed by `freshclam` (run manually or via cron)
- YARA rules run in the local filesystem only
- Reports are stored in the configured `security.workingDir`

## License

MIT
