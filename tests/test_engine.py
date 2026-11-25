"""Tests for the rule engine: loader, evaluator, and fact-path resolution.

All tests use mocked facts and temporary rule files — they never read the
real OS and run on any platform.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from secscan.engine.evaluator import (
    _MISSING,
    _evaluate_condition,
    _resolve_fact_path,
    evaluate,
)
from secscan.engine.loader import RuleValidationError, load_rules
from tests.conftest import make_rule

# ===================================================================
# Loader tests
# ===================================================================


class TestLoadRules:
    """Tests for load_rules() and rule validation."""

    def _write_rule(self, tmp_path: Path, filename: str, content: str) -> Path:
        """Helper: write a YAML rule file into a temp directory."""
        rule_file = tmp_path / filename
        rule_file.write_text(textwrap.dedent(content), encoding="utf-8")
        return rule_file

    def _minimal_rule_yaml(self, **overrides: object) -> str:
        """Return minimal valid rule YAML, with optional field overrides."""
        defaults = {
            "id": '"TEST-001"',
            "title": '"Test rule"',
            "severity": '"high"',
            "applies_to": '\n  - "windows"',
            "collector": '"test"',
            "fact_path": '"test.value"',
            "condition": '\n  operator: "equals"\n  expected: true',
            "why_it_matters": '"Important."',
            "how_to_fix": '\n  windows:\n    - "Step 1."',
            "difficulty": '"easy"',
            "source": '"https://example.com"',
        }
        defaults.update(overrides)
        lines = [f"{key}: {value}" for key, value in defaults.items()]
        return "\n".join(lines) + "\n"

    def test_loads_valid_rule(self, tmp_path: Path) -> None:
        """A valid YAML rule file is loaded successfully."""
        self._write_rule(tmp_path, "TEST-001.yaml", self._minimal_rule_yaml())
        rules = load_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].id == "TEST-001"
        assert rules[0].severity == "high"
        assert rules[0].applies_to == ["windows"]

    def test_loads_multiple_rules_sorted(self, tmp_path: Path) -> None:
        """Multiple rules are loaded in filename order."""
        self._write_rule(
            tmp_path,
            "B-001.yaml",
            self._minimal_rule_yaml(id='"B-001"', title='"Rule B"'),
        )
        self._write_rule(
            tmp_path,
            "A-001.yaml",
            self._minimal_rule_yaml(id='"A-001"', title='"Rule A"'),
        )
        rules = load_rules(tmp_path)
        assert len(rules) == 2
        assert rules[0].id == "A-001"
        assert rules[1].id == "B-001"

    def test_missing_field_raises(self, tmp_path: Path) -> None:
        """A rule missing a required field raises RuleValidationError."""
        # Remove the 'source' field
        content = self._minimal_rule_yaml()
        content = "\n".join(line for line in content.splitlines() if not line.startswith("source:"))
        self._write_rule(tmp_path, "BAD.yaml", content)
        with pytest.raises(RuleValidationError, match="Missing required fields.*source"):
            load_rules(tmp_path)

    def test_invalid_severity_raises(self, tmp_path: Path) -> None:
        """An unrecognised severity value raises RuleValidationError."""
        self._write_rule(
            tmp_path,
            "BAD.yaml",
            self._minimal_rule_yaml(severity='"super-critical"'),
        )
        with pytest.raises(RuleValidationError, match="severity"):
            load_rules(tmp_path)

    def test_invalid_platform_raises(self, tmp_path: Path) -> None:
        """An unrecognised platform raises RuleValidationError."""
        self._write_rule(
            tmp_path,
            "BAD.yaml",
            self._minimal_rule_yaml(applies_to='\n  - "macos"'),
        )
        with pytest.raises(RuleValidationError, match="applies_to"):
            load_rules(tmp_path)

    def test_duplicate_id_raises(self, tmp_path: Path) -> None:
        """Two rules with the same ID raise RuleValidationError."""
        self._write_rule(tmp_path, "A.yaml", self._minimal_rule_yaml(id='"DUP"'))
        self._write_rule(
            tmp_path,
            "B.yaml",
            self._minimal_rule_yaml(id='"DUP"', title='"Another rule"'),
        )
        with pytest.raises(RuleValidationError, match="Duplicate rule id"):
            load_rules(tmp_path)

    def test_invalid_operator_raises(self, tmp_path: Path) -> None:
        """An unrecognised condition operator raises RuleValidationError."""
        self._write_rule(
            tmp_path,
            "BAD.yaml",
            self._minimal_rule_yaml(
                condition='\n  operator: "magic"\n  expected: true',
            ),
        )
        with pytest.raises(RuleValidationError, match="condition.operator"):
            load_rules(tmp_path)

    def test_missing_expected_for_equals_raises(self, tmp_path: Path) -> None:
        """'equals' operator without 'expected' raises RuleValidationError."""
        self._write_rule(
            tmp_path,
            "BAD.yaml",
            self._minimal_rule_yaml(condition='\n  operator: "equals"'),
        )
        with pytest.raises(RuleValidationError, match="condition.expected"):
            load_rules(tmp_path)

    def test_is_true_without_expected_ok(self, tmp_path: Path) -> None:
        """'is_true' operator does not require 'expected'."""
        self._write_rule(
            tmp_path,
            "OK.yaml",
            self._minimal_rule_yaml(condition='\n  operator: "is_true"'),
        )
        rules = load_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].condition["operator"] == "is_true"

    def test_invalid_difficulty_raises(self, tmp_path: Path) -> None:
        """An unrecognised difficulty raises RuleValidationError."""
        self._write_rule(
            tmp_path,
            "BAD.yaml",
            self._minimal_rule_yaml(difficulty='"impossible"'),
        )
        with pytest.raises(RuleValidationError, match="difficulty"):
            load_rules(tmp_path)

    def test_how_to_fix_missing_platform_raises(self, tmp_path: Path) -> None:
        """how_to_fix must include steps for every platform in applies_to."""
        self._write_rule(
            tmp_path,
            "BAD.yaml",
            self._minimal_rule_yaml(
                applies_to='\n  - "windows"\n  - "linux"',
                how_to_fix='\n  windows:\n    - "Step 1."',
                # Missing linux fix steps
            ),
        )
        with pytest.raises(RuleValidationError, match="how_to_fix.*linux"):
            load_rules(tmp_path)

    def test_empty_rules_dir(self, tmp_path: Path) -> None:
        """An empty rules directory returns an empty list."""
        rules = load_rules(tmp_path)
        assert rules == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        """A nonexistent directory returns an empty list (with a warning)."""
        rules = load_rules(tmp_path / "does_not_exist")
        assert rules == []

    def test_loads_shipped_rules(self) -> None:
        """All 13 shipped rule files in secscan/rules/ load successfully."""
        rules_dir = Path(__file__).resolve().parent.parent / "secscan" / "rules"
        rules = load_rules(rules_dir)
        assert len(rules) == 13

        # Verify all expected IDs are present
        expected_ids = {
            "FW-001",
            "DISK-001",
            "AV-001",
            "NET-001",
            "ACCT-001",
            "ACCT-002",
            "PWD-001",
            "PWD-002",
            "SSH-001",
            "SSH-002",
            "RDP-001",
            "SMB-001",
            "AUTO-001",
        }
        loaded_ids = {r.id for r in rules}
        assert loaded_ids == expected_ids


# ===================================================================
# Fact-path resolution tests
# ===================================================================


class TestResolveFactPath:
    """Tests for the dot-notation fact path resolver."""

    def test_simple_path(self) -> None:
        facts = {"firewall": {"all_profiles_enabled": True}}
        assert _resolve_fact_path("firewall.all_profiles_enabled", facts) is True

    def test_nested_path(self) -> None:
        facts = {"a": {"b": {"c": 42}}}
        assert _resolve_fact_path("a.b.c", facts) == 42

    def test_missing_top_level(self) -> None:
        facts = {"firewall": {"enabled": True}}
        assert _resolve_fact_path("missing.key", facts) is _MISSING

    def test_missing_nested(self) -> None:
        facts = {"firewall": {"enabled": True}}
        assert _resolve_fact_path("firewall.nonexistent", facts) is _MISSING

    def test_non_dict_intermediate(self) -> None:
        facts = {"firewall": "not a dict"}
        assert _resolve_fact_path("firewall.enabled", facts) is _MISSING

    def test_single_segment(self) -> None:
        facts = {"firewall": {"enabled": True}}
        result = _resolve_fact_path("firewall", facts)
        assert result == {"enabled": True}

    def test_none_value_resolved(self) -> None:
        """A None value at the path is a valid resolved value (not MISSING)."""
        facts = {"check": {"value": None}}
        result = _resolve_fact_path("check.value", facts)
        assert result is None
        assert result is not _MISSING


# ===================================================================
# Condition evaluation tests
# ===================================================================


class TestEvaluateCondition:
    """Tests for every supported condition operator."""

    def test_equals_pass(self) -> None:
        assert _evaluate_condition(True, {"operator": "equals", "expected": True}) is True

    def test_equals_fail(self) -> None:
        assert _evaluate_condition(False, {"operator": "equals", "expected": True}) is False

    def test_equals_string(self) -> None:
        assert _evaluate_condition("no", {"operator": "equals", "expected": "no"}) is True

    def test_not_equals_pass(self) -> None:
        assert _evaluate_condition(5, {"operator": "not_equals", "expected": 3}) is True

    def test_not_equals_fail(self) -> None:
        assert _evaluate_condition(5, {"operator": "not_equals", "expected": 5}) is False

    def test_greater_than_pass(self) -> None:
        assert _evaluate_condition(10, {"operator": "greater_than", "expected": 7}) is True

    def test_greater_than_fail(self) -> None:
        assert _evaluate_condition(5, {"operator": "greater_than", "expected": 7}) is False

    def test_greater_than_equal_fails(self) -> None:
        """greater_than is strict: equal values do not pass."""
        assert _evaluate_condition(7, {"operator": "greater_than", "expected": 7}) is False

    def test_less_than_pass(self) -> None:
        assert _evaluate_condition(2, {"operator": "less_than", "expected": 3}) is True

    def test_less_than_fail(self) -> None:
        assert _evaluate_condition(5, {"operator": "less_than", "expected": 3}) is False

    def test_is_true_truthy(self) -> None:
        assert _evaluate_condition(1, {"operator": "is_true"}) is True

    def test_is_true_falsy(self) -> None:
        assert _evaluate_condition(0, {"operator": "is_true"}) is False

    def test_is_false_falsy(self) -> None:
        assert _evaluate_condition(0, {"operator": "is_false"}) is True

    def test_is_false_truthy(self) -> None:
        assert _evaluate_condition(1, {"operator": "is_false"}) is False

    def test_contains_string(self) -> None:
        assert (
            _evaluate_condition("hello world", {"operator": "contains", "expected": "world"})
            is True
        )

    def test_contains_list(self) -> None:
        assert _evaluate_condition([1, 2, 3], {"operator": "contains", "expected": 2}) is True

    def test_not_contains(self) -> None:
        assert _evaluate_condition("hello", {"operator": "not_contains", "expected": "xyz"}) is True

    def test_none_value_returns_none(self) -> None:
        """A None fact value produces an indeterminate (None) result."""
        assert _evaluate_condition(None, {"operator": "equals", "expected": True}) is None

    def test_unknown_operator_returns_none(self) -> None:
        """An unrecognised operator produces None (unknown)."""
        assert _evaluate_condition(True, {"operator": "banana", "expected": True}) is None


# ===================================================================
# End-to-end evaluator tests
# ===================================================================


class TestEvaluate:
    """Tests for the full evaluate() function with mocked facts."""

    def test_pass(self) -> None:
        """A rule whose condition is met produces a 'pass' finding."""
        rule = make_rule(
            fact_path="test.value",
            condition={"operator": "equals", "expected": True},
        )
        facts = {"test": {"value": True}}
        findings = evaluate([rule], facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "pass"

    def test_fail(self) -> None:
        """A rule whose condition is not met produces a 'fail' finding."""
        rule = make_rule(
            fact_path="test.value",
            condition={"operator": "equals", "expected": True},
        )
        facts = {"test": {"value": False}}
        findings = evaluate([rule], facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "fail"

    def test_unknown_missing_collector(self) -> None:
        """Missing collector data produces an 'unknown' finding."""
        rule = make_rule(fact_path="missing_collector.value")
        facts: dict[str, dict] = {}
        findings = evaluate([rule], facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "unknown"
        assert "not collected" in findings[0].detail.lower()

    def test_unknown_missing_fact(self) -> None:
        """Missing fact key within a collector produces 'unknown'."""
        rule = make_rule(fact_path="test.nonexistent")
        facts = {"test": {"other_key": True}}
        findings = evaluate([rule], facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "unknown"

    def test_unknown_error_dict(self) -> None:
        """A collector error dict produces 'unknown' with the error message."""
        rule = make_rule(fact_path="test.value")
        facts = {"test": {"value": {"error": "Permission denied"}}}
        findings = evaluate([rule], facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "unknown"
        assert "Permission denied" in findings[0].detail

    def test_unknown_none_fact_value(self) -> None:
        """A None fact value produces 'unknown' (indeterminate)."""
        rule = make_rule(
            fact_path="test.value",
            condition={"operator": "equals", "expected": True},
        )
        facts = {"test": {"value": None}}
        findings = evaluate([rule], facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "unknown"

    def test_platform_filtering(self) -> None:
        """Rules for another platform are skipped."""
        linux_only = make_rule(rule_id="L-001", applies_to=["linux"])
        windows_only = make_rule(rule_id="W-001", applies_to=["windows"])
        both = make_rule(rule_id="B-001", applies_to=["windows", "linux"])

        facts = {"test_collector": {"some_fact": True}}
        findings = evaluate([linux_only, windows_only, both], facts, "windows")

        finding_ids = {f.rule_id for f in findings}
        assert "L-001" not in finding_ids
        assert "W-001" in finding_ids
        assert "B-001" in finding_ids

    def test_fix_steps_match_platform(self) -> None:
        """The finding contains fix steps for the current platform only."""
        rule = make_rule(
            applies_to=["windows", "linux"],
            how_to_fix={
                "windows": ["Windows fix step."],
                "linux": ["Linux fix step."],
            },
        )
        facts = {"test_collector": {"some_fact": True}}

        findings = evaluate([rule], facts, "linux")
        assert findings[0].how_to_fix == ["Linux fix step."]

    def test_all_windows_rules_pass(self, all_pass_facts_windows: dict) -> None:
        """All shipped rules pass against the all-pass Windows facts."""
        rules_dir = Path(__file__).resolve().parent.parent / "secscan" / "rules"
        rules = load_rules(rules_dir)
        findings = evaluate(rules, all_pass_facts_windows, "windows")

        for f in findings:
            assert f.status == "pass", (
                f"Rule {f.rule_id} should pass but got '{f.status}': {f.detail}"
            )

    def test_all_linux_rules_pass(self, all_pass_facts_linux: dict) -> None:
        """All shipped rules pass against the all-pass Linux facts."""
        rules_dir = Path(__file__).resolve().parent.parent / "secscan" / "rules"
        rules = load_rules(rules_dir)
        findings = evaluate(rules, all_pass_facts_linux, "linux")

        for f in findings:
            assert f.status == "pass", (
                f"Rule {f.rule_id} should pass but got '{f.status}': {f.detail}"
            )

    def test_all_windows_rules_fail(self, all_fail_facts_windows: dict) -> None:
        """All shipped rules fail against the all-fail Windows facts."""
        rules_dir = Path(__file__).resolve().parent.parent / "secscan" / "rules"
        rules = load_rules(rules_dir)
        findings = evaluate(rules, all_fail_facts_windows, "windows")

        for f in findings:
            assert f.status == "fail", (
                f"Rule {f.rule_id} should fail but got '{f.status}': {f.detail}"
            )

    def test_evaluation_never_crashes(self) -> None:
        """Even with bizarre fact values, evaluate() returns findings, never raises."""
        rules = [
            make_rule(
                rule_id="R1",
                fact_path="a.b",
                condition={"operator": "greater_than", "expected": 5},
            ),
        ]
        # fact_value is a string, comparison with int will raise TypeError
        # The evaluator should catch it and return "unknown"
        facts = {"a": {"b": "not a number"}}
        findings = evaluate(rules, facts, "windows")
        assert len(findings) == 1
        assert findings[0].status == "unknown"
        assert "error" in findings[0].detail.lower()
