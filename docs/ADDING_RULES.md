# Adding a New Rule to SecScan

SecScan separates **what to check** (YAML rule files in `secscan/rules/`) from **how to gather data** (Python collectors in `secscan/collectors/`) and **how to evaluate it** (`secscan/engine/evaluator.py`).

## 1. Rule File Schema

Create a new `<ID>.yaml` file in `secscan/rules/`. Every top-level field below is required by `secscan/engine/loader.py`:

```yaml
id: "PREFIX-NNN"              # Unique uppercase ID (e.g. FW-001, SSH-003)
title: "Short human-readable title"
severity: "critical"          # critical | high | medium | low
applies_to:                   # At least one of: windows, linux
  - "windows"
  - "linux"
collector: "firewall"         # Must match a Collector.name
fact_path: "firewall.all_profiles_enabled"  # Dot-path into collector output
condition:
  operator: "equals"          # See supported operators below
  expected: true              # Required for all operators except is_true / is_false
why_it_matters: >
  1-2 plain sentences explaining the risk to a non-technical user.
  Avoid unexplained jargon.
how_to_fix:                   # Must include a non-empty list for every OS in applies_to
  windows:
    - "Step 1."
    - "Step 2."
  linux:
    - "Step 1."
    - "Step 2."
difficulty: "easy"            # easy | medium | hard
source: "Real, publicly verifiable vendor documentation or hardening URL"
```

### Supported Condition Operators

| Operator | Passes when… | `expected` required? |
|---|---|---|
| `equals` | `fact_value == expected` | Yes |
| `not_equals` | `fact_value != expected` | Yes |
| `greater_than` | `fact_value > expected` | Yes |
| `less_than` | `fact_value < expected` | Yes |
| `is_true` | `bool(fact_value) is True` | No |
| `is_false` | `bool(fact_value) is False` | No |
| `contains` | `expected in fact_value` | Yes |
| `not_contains` | `expected not in fact_value` | Yes |

If the `fact_path` is missing, resolves to `None`, or resolves to `{"error": "..."}`, the evaluator marks the finding **`unknown`**—never `pass`.

## 2. Adding or Updating a Collector (if needed)

If an existing collector does not gather the fact you need:

1. Subclass `Collector` in `secscan/collectors/`.
2. Implement `get_facts() -> dict[str, Any]` and `get_dry_run_info() -> list[dict[str, str]]`.
3. Register the collector in `get_all_collectors()` inside `secscan/collectors/__init__.py`.
4. Follow the hard constraints:
   - Strictly read-only; never modify system state.
   - No network calls.
   - Use `safe_run([...])` with argument lists—never `shell=True`.
   - Catch all exceptions and return `{"error": "..."}` so a single failure never crashes a scan.

## 3. Adding Tests

- Add mocked collector unit tests in `tests/test_collectors/`.
- Verify `load_rules()` loads your new YAML cleanly (`pytest tests/test_engine.py`).
- Make sure all tests run on both Windows and Linux without touching real system state.
- Run `ruff check .`, `ruff format --check .`, and `pytest -v`.
