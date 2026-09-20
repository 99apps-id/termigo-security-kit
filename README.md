# Termigo Security Kit

Non-pentest security tools for Termigo: static analysis, dependency auditing, and malware scanning.

## Tools

- `sast_scan` — Static Application Security Testing (semgrep, bandit, gosec, eslint-plugin-security).
- `dependency_audit` — Dependency vulnerability audit (osv-scanner, npm audit, pip audit, cargo audit, govulncheck).
- `av_scan` — Antivirus / malware / adware scan (ClamAV, Windows Defender, YARA rules).

## Prerequisites

Install at least one engine per tool category:

- SAST: `semgrep`, `bandit`, `gosec`, or `eslint-plugin-security`
- Dependency audit: `osv-scanner`, `npm`, `pip`, `cargo`, or `govulncheck`
- AV scan: **ClamAV** (cross-platform: Windows, macOS, Linux) or **Windows Defender** (`MpCmdRun.exe`, Windows-only)
- Adware scan (optional): **YARA** (`go install github.com/VirusTotal/yara@latest` or `brew/apt install yara`)

## Adware Scanning with YARA

The `av_scan` tool supports adware-specific detection via YARA rules.

### `adwareOnly` mode
Set `adwareOnly: true` to scan only for adware/pup/tracker indicators using built-in YARA rules.

### Custom YARA rules
Provide a path to custom YARA rules via `yaraRules: "/path/to/rules.yar"`.

### Example usage
```json
{
  "tool": "av_scan",
  "path": "./downloads",
  "adwareOnly": true,
  "yaraRules": "./rules/adware.yar"
}
```

### Built-in adware rules
When `adwareOnly` is enabled without custom rules, the extension uses bundled rules that detect:
- Generic adware bundles
- Browser hijackers
- Adware trackers/analytics SDKs

## Install

1. Download `termigo-security-kit.zip`
2. Open Termigo → Extensions → Install from File
3. Verify checksum with `termigo-security-kit.zip.sha256`
