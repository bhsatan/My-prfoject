# Changelog

All notable changes to SecScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- SSH: first value wins and `Include` is followed, matching sshd; an unreadable config is `unknown`.
- Firewall: a disabled ufw no longer passes because its service is active.
- Password policy: reads `pwquality.conf` and `faillock.conf`, and ignores commented PAM lines.
- Network: detects `*` and interface-scoped wildcard listeners.
- Collector error messages now appear in findings.
- Linux fix steps no longer risk lockout; rules can cite a source per platform.

### Added
- Core rule engine with YAML rule loader, evaluator (8 operators), and dot-notation fact-path resolution.
- Scorer with 0-100 weighted posture score, letter grades (A–F), and ranked finding output.
- 13 security rules covering: firewall, disk encryption, antivirus, risky ports, guest account, admin count, password policy, SSH hardening, RDP/NLA, SMBv1, and automatic login.
- 9 collectors with Windows and Linux support: firewall, disk encryption, antivirus, network, accounts, password policy, SSH, remote access, and autologin.
- All collectors use `safe_run()` with argument lists (no `shell=True`) and graceful failure handling.
- Terminal report with ANSI colours, severity bar chart, and ranked findings.
- JSON report with machine-readable scan output.
- Self-contained HTML report with score gauge, severity chart, and fix steps (no CDN/network).
- CLI with `secscan scan`, `--dry-run`, `--format terminal|json|html`, `--output <dir>`.
- Plain-English permission notice before first scan with explicit confirmation.
- Repository scaffolding: Apache-2.0 license, README, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md.
- GitHub Actions CI: ruff lint + pytest on ubuntu/windows × Python 3.11/3.12.
- CodeQL analysis, Dependabot, CodeRabbit config, PR template with safety checklist.
- AI explainer interface stubs (disabled by default, no provider implemented).
- Comprehensive test suite (all tests use mocked facts, run on any OS).

## [0.1.0] - Unreleased

Initial prototype release.

### Security
- Read-only: never modifies system state.
- No network in core engine: no telemetry, no listeners, no outbound calls.
- Runs without admin/root; checks needing elevation report "unknown".
- No `shell=True`; all subprocess calls use argument lists.
- No secrets in repo; API keys read from environment variables only.
- Report files include warning banner about sensitive content.
