# Contributing to SecScan

Thank you for considering contributing to SecScan! This document explains how to set up your development environment, follow our conventions, and submit changes.

## Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/secscan.git
cd secscan

# 2. Create a virtual environment (Python 3.11+)
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate

# 3. Install in development mode with dev dependencies
pip install -e ".[dev]"

# 4. Run the test suite (must pass on any OS)
pytest

# 5. Run the linter
ruff check .
```

## Branching and Commits

### Branching

- **Never commit directly to `main`.** All changes go through pull requests.
- Create a feature branch from `main` with a descriptive name:
  - `feat/collector-ssh` — new feature
  - `fix/firewall-parse-error` — bug fix
  - `docs/update-readme` — documentation
  - `test/scorer-edge-cases` — test improvements
  - `chore/update-ci` — maintenance

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SSH root login check for Linux
fix: handle missing sshd_config gracefully
test: add mocked facts for firewall collector
docs: document scoring formula in README
chore: pin ruff version in CI
```

Keep commits small and focused. One logical change per commit.

## Pull Request Guidelines

1. Keep PRs small — one feature, fix, or check per PR.
2. Fill out the pull request template checklist completely.
3. All CI checks (lint + tests) must pass.
4. At least one review approval is required before merging.
5. Use "Squash and merge" for single-purpose PRs; "Merge commit" for multi-commit work.

## How to Add a New Rule

Adding a security check involves two parts: a **collector** (if the data source is new) and a **rule** YAML file.

### 1. Rule file (required)

Create a new YAML file in `secscan/rules/` following this schema:

```yaml
id: "PREFIX-NNN"              # Unique ID, e.g. FW-001, SSH-002
title: "Short, clear title"
severity: "critical"           # critical | high | medium | low
applies_to:
  - "windows"                 # and/or "linux"
collector: "collector_name"    # Must match a Collector.name
fact_path: "collector.fact_key"  # Dot-notation path into facts dict
condition:
  operator: "equals"          # equals | not_equals | greater_than | less_than |
                              # is_true | is_false | contains | not_contains
  expected: true              # The value that means "pass"
why_it_matters: >
  1-2 plain sentences a non-technical person can understand.
  No jargon. No acronyms without explanation.
how_to_fix:
  windows:                    # Include only for applicable OS
    - "Step 1 in plain language."
    - "Step 2."
  linux:
    - "Step 1."
    - "Step 2."
difficulty: "easy"            # easy | medium | hard
source: "Verifiable URL or vendor doc reference"
```

**Requirements for rules:**
- `source` must be a real, publicly accessible reference. Do not invent sources.
- `why_it_matters` must be understandable by a non-technical person.
- Fix steps must be specific, numbered, and correct for the stated OS.
- Do not copy text from licensed benchmarks (CIS, DISA STIG); write original wording.

### 2. Collector (if needed)

If your rule needs data that no existing collector gathers:

1. Create a new file in `secscan/collectors/`, e.g. `my_check.py`.
2. Subclass `Collector` from `secscan.collectors.base`.
3. Implement `get_facts()` → returns a dict of simple, pre-computed values.
4. Implement `get_dry_run_info()` → returns what commands/files would be accessed.
5. **Hard rules for collectors:**
   - **Read-only**: never modify system state.
   - **No network**: never open connections.
   - **No `shell=True`**: use argument lists in `subprocess.run()`.
   - **Never crash**: catch all exceptions and return `{"error": "..."}`.
   - **No admin assumption**: if a check needs elevation, return an error fact gracefully.

### 3. Tests (required)

- Add a test file in `tests/test_collectors/` with **mocked command output**.
- Tests must run on **any OS** (don't depend on real system state).
- Test both the happy path and failure/permission-denied cases.

## Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_engine.py

# Run tests matching a pattern
pytest -k "firewall"
```

## Code Style

- **Type hints** on all function signatures.
- **Docstrings** on all public classes and functions.
- Run `ruff check .` before committing — CI enforces this.
- Clarity over cleverness. Comment the "why", not the "what".

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
