# Termigo Security Kit

Non-pentest security tools for Termigo: static analysis, dependency auditing, and malware scanning.

## Tools

- `sast_scan` — Static Application Security Testing (semgrep, bandit, gosec, eslint-plugin-security).
- `dependency_audit` — Dependency vulnerability audit (osv-scanner, npm audit, pip audit, cargo audit, govulncheck).
- `av_scan` — Antivirus / malware / adware scan (ClamAV, Windows Defender).

## Prerequisites

Install at least one engine per tool category:

- SAST: `semgrep`, `bandit`, `gosec`, or `eslint-plugin-security`
- Dependency audit: `osv-scanner`, `npm`, `pip`, `cargo`, or `govulncheck`
- AV scan: `clamav` or Windows Defender (`MpCmdRun.exe`)

## Install

1. Download `termigo-security-kit.zip`
2. Open Termigo → Extensions → Install from File
3. Verify checksum with `termigo-security-kit.zip.sha256`
