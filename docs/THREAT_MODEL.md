# SecScan Threat Model

This document summarizes SecScan's trust boundaries, assets, threats, and mitigations for v0.1.

## 1. System Overview

SecScan runs locally on a user's Windows or Linux machine under a standard (non-admin) or elevated user account. It reads OS configuration via native commands and files, evaluates YAML rules locally, and outputs terminal, JSON, or self-contained HTML reports.

## 2. Assets to Protect

1. **System integrity**: SecScan must never alter the host it inspects.
2. **Scan reports (JSON/HTML/terminal)**: Contain a blueprint of the machine's weaknesses (open ports, admin users, encryption state, password policy).
3. **Optional AI API key (`SECSCAN_AI_API_KEY`)** and **local PII** (usernames, hostnames, IP/MAC addresses, file paths).

## 3. Trust Boundaries

- **Trusted**: Local Python interpreter, OS-native binaries (`powershell`, `net`, `systemctl`, `ss`, `lsblk`), and shipped rule files in `secscan/rules/`.
- **Untrusted**:
  - CLI `--output` directory strings (resolved via `Path.resolve()`).
  - Parsed command/file output from the OS (handled defensively with `json.loads` / regex error handling and HTML escaping `_esc()` in HTML reports to prevent XSS).
  - Future LLM responses in `ai_explainer` (displayed as text only, never executed).

## 4. Threats & Mitigations

| Threat | Mitigation |
|---|---|
| **Accidental system modification** | Collectors only run read-only queries/file reads; no remediation code exists. |
| **Command injection** | All subprocesses use `safe_run([...])` with argument lists; `shell=True` is never used; no user input is passed into OS commands. |
| **Silent data exfiltration** | Core engine has zero network code. `--ai-explain` is off by default, interface-only in v0.1, requires `SECSCAN_AI_API_KEY` env var, redacts PII via `Redactor`, and requires `[y/N]` confirmation on the exact redacted payload. |
| **False sense of security** | Missing data, permission errors, or `None` facts always evaluate to `unknown`, never `pass`. |
| **XSS in HTML reports** | All dynamic strings (titles, details, fix steps, sources) pass through `_esc()` before insertion into the HTML template; no external scripts or CDNs are loaded. |
| **Information disclosure via reports** | Reports include a prominent warning banner advising users not to share them publicly; default `output/` directory is gitignored. |
