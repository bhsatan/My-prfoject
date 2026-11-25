# SecScan — Local Security Posture Scanner

> **Prototype v0.1** — Under active development. Not yet ready for production use.

SecScan is an open-source, local-first command-line tool that inspects your machine (read-only) and tells you what security gaps exist — with plain-language guidance a non-technical person can follow.

## Key Principles

- **Read-only**: SecScan never modifies your system. "Fixes" are text instructions only.
- **No network**: The core engine makes zero network calls — no telemetry, no listeners, no auto-update.
- **No admin required**: Runs without administrator/root. Checks that need elevation report "unknown" and move on.
- **Plain language**: Every finding is written so anyone can understand it without searching the web.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/bhsatan/secscan.git
cd secscan

# Create a virtual environment
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run a scan
secscan scan

# Dry run — see what would be inspected without collecting anything
secscan scan --dry-run

# Output as JSON or self-contained HTML
secscan scan --format json --output ./my-reports
secscan scan --format html --output ./my-reports
```

## What It Checks

SecScan evaluates your machine against checks in these areas:

| Area | Windows | Linux |
|---|---|---|
| Firewall enabled | ✅ | ✅ |
| Disk encryption (BitLocker / LUKS) | ✅ | ✅ |
| Antivirus real-time protection | ✅ | — |
| Risky listening ports | ✅ | ✅ |
| Guest account disabled | ✅ | — |
| Admin / sudo group size | ✅ | ✅ |
| Password policy (length, lockout) | ✅ | ✅ |
| SSH hardening (root login, password auth) | — | ✅ |
| RDP and SMBv1 exposure | ✅ | — |
| Automatic login disabled | ✅ | ✅ |

## Scoring

Each check has a severity weight (Critical = 10, High = 7, Medium = 4, Low = 2).

- **Pass** → full points
- **Unknown** (couldn't check) → half points
- **Fail** → 0 points

**Score = round(100 × earned / possible)**

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 50–74 | C |
| 25–49 | D |
| 0–24 | F |

Findings are ranked: failures first, highest severity first, easiest fix first.

## Project Structure

```
secscan/
  collectors/    # Read-only fact gatherers (one file per check area)
  rules/         # YAML data files — one check per file, no code
  engine/        # Loads rules, evaluates against facts
  scorer/        # 0-100 score + ranked fix list
  report/        # Terminal summary, JSON file, self-contained HTML
  ai_explainer/  # Optional LLM integration (off by default)
  cli.py         # Command-line entry point
tests/           # Unit tests with mocked facts (run on any OS)
docs/            # Additional documentation
```

## Optional AI Explainer

Disabled by default. If you have your own LLM API key, you can enable friendlier explanations:

```bash
export SECSCAN_AI_API_KEY="your-key-here"
secscan scan --ai-explain
```

Before sending anything to an external service, SecScan:
1. Redacts usernames, hostnames, IPs, MACs, and file paths.
2. Shows you the exact redacted payload.
3. Waits for your explicit confirmation.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for branching conventions, PR rules, and how to add a new check.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities and the tool's threat model.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
