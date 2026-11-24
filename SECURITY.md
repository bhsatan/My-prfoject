# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecScan, **please do not open a public issue.**

Instead, please report it privately:

1. **Email**: Send a description to the maintainers via a private channel (see the repository's contact information).
2. **GitHub Security Advisories**: Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) feature on this repository.

Include in your report:
- A description of the vulnerability and its potential impact.
- Steps to reproduce.
- Any suggested fix.

We aim to acknowledge reports within **48 hours** and provide a fix or mitigation plan within **7 days** for critical issues.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (current) | ✅ |

## Threat Model Summary

SecScan is a **read-only, local-only** tool that inspects the machine it runs on. Here is what it does and does not do, and the risks to be aware of.

### What SecScan reads

- Operating system configuration (firewall, password policy, login settings)
- Listening network ports
- User accounts and group memberships
- Disk encryption status
- SSH server configuration (Linux)
- RDP and SMB configuration (Windows)
- Registry keys (Windows, read-only)
- System configuration files (Linux, read-only)

### What SecScan never does

- **Never modifies** system settings, files, or the registry.
- **Never installs or removes** software.
- **Never writes** outside its own output directory.
- **Never opens** network connections, listeners, or sends telemetry (core engine).
- **Never deletes** anything.
- **Never stores or transmits** credentials or secrets.

### Known risks

1. **Report files contain sensitive data.** Scan reports reveal your security posture — firewall state, user accounts, listening ports, encryption status, and password policy. Treat report files as confidential. SecScan writes them with restrictive file permissions where possible.

2. **AI Explainer sends data externally.** If explicitly enabled by the user, the optional AI explainer sends redacted finding summaries to an external LLM API. Even with redaction, this reveals some posture information. The user must confirm each payload before it is sent.

3. **Running without admin/root limits visibility.** Some checks (disk encryption, SMBv1 status) require administrator privileges. Without elevation, these report "unknown" rather than a potentially misleading "pass".

4. **The tool itself is a recon target.** An attacker who can read SecScan's output learns exactly which defences are missing. Protect the output directory.

5. **Supply chain.** SecScan depends on PyYAML (core) and pytest/ruff (dev). Pin dependency versions and monitor Dependabot alerts.

### Scope of trust

- SecScan trusts the Python runtime and the operating system's APIs/commands it calls.
- SecScan does **not** trust user-supplied file paths in CLI arguments — these are validated.
- Rule files in `secscan/rules/` are trusted data (shipped with the tool, not user-generated).
- The AI explainer does **not** trust LLM responses — they are displayed to the user, never executed.
