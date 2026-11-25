"""Rule loader — discovers, parses, and validates YAML rule files.

Each .yaml file in secscan/rules/ defines one security check.  This module
loads them all into a list of validated Rule objects for the evaluator.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from secscan.engine.models import (
    VALID_DIFFICULTIES,
    VALID_OPERATORS,
    VALID_PLATFORMS,
    VALID_SEVERITIES,
    Rule,
)

logger = logging.getLogger(__name__)

# Every rule file must contain these top-level keys.
_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "title",
        "severity",
        "applies_to",
        "collector",
        "fact_path",
        "condition",
        "why_it_matters",
        "how_to_fix",
        "difficulty",
        "source",
    }
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class RuleValidationError(Exception):
    """Raised when a rule file fails schema validation."""

    def __init__(self, rule_path: str, message: str) -> None:
        self.rule_path = rule_path
        super().__init__(f"{rule_path}: {message}")


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """Load and validate all YAML rule files from the rules directory.

    Args:
        rules_dir: Path to the directory containing ``*.yaml`` rule files.
            Defaults to ``secscan/rules/`` relative to this package.

    Returns:
        A list of validated :class:`Rule` objects, sorted by filename.

    Raises:
        RuleValidationError: If any rule file fails validation.
    """
    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parent.parent / "rules"

    if not rules_dir.is_dir():
        logger.warning("Rules directory not found: %s", rules_dir)
        return []

    rules: list[Rule] = []
    seen_ids: set[str] = set()

    for rule_path in sorted(rules_dir.glob("*.yaml")):
        rule = _load_single_rule(rule_path, seen_ids)
        rules.append(rule)
        seen_ids.add(rule.id)

    logger.info("Loaded %d rule(s) from %s", len(rules), rules_dir)
    return rules


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_single_rule(rule_path: Path, seen_ids: set[str]) -> Rule:
    """Load and validate a single YAML rule file."""
    path_str = str(rule_path)

    # --- Parse YAML ---
    try:
        with open(rule_path, encoding="utf-8") as fh:
            data: dict[str, Any] = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise RuleValidationError(path_str, f"Invalid YAML syntax: {exc}") from exc

    if not isinstance(data, dict):
        raise RuleValidationError(path_str, "Rule file must contain a YAML mapping")

    # --- Check required fields ---
    missing = _REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise RuleValidationError(
            path_str,
            f"Missing required fields: {', '.join(sorted(missing))}",
        )

    # --- Validate individual fields ---
    _validate_id(path_str, data["id"], seen_ids)
    _validate_severity(path_str, data["severity"])
    _validate_applies_to(path_str, data["applies_to"])
    _validate_condition(path_str, data["condition"])
    _validate_how_to_fix(path_str, data["how_to_fix"], data["applies_to"])
    _validate_difficulty(path_str, data["difficulty"])

    return Rule(
        id=str(data["id"]),
        title=str(data["title"]),
        severity=data["severity"],
        applies_to=list(data["applies_to"]),
        collector=str(data["collector"]),
        fact_path=str(data["fact_path"]),
        condition=dict(data["condition"]),
        why_it_matters=str(data["why_it_matters"]).strip(),
        how_to_fix={os_name: list(steps) for os_name, steps in data["how_to_fix"].items()},
        difficulty=data["difficulty"],
        source=str(data["source"]).strip(),
    )


def _validate_id(path_str: str, rule_id: object, seen_ids: set[str]) -> None:
    """Rule ID must be a unique, non-empty string."""
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleValidationError(path_str, "id must be a non-empty string")
    if rule_id in seen_ids:
        raise RuleValidationError(path_str, f"Duplicate rule id: {rule_id}")


def _validate_severity(path_str: str, severity: object) -> None:
    if severity not in VALID_SEVERITIES:
        raise RuleValidationError(
            path_str,
            f"severity must be one of {sorted(VALID_SEVERITIES)}, got '{severity}'",
        )


def _validate_applies_to(path_str: str, applies_to: object) -> None:
    if not isinstance(applies_to, list) or not applies_to:
        raise RuleValidationError(path_str, "applies_to must be a non-empty list")
    for platform in applies_to:
        if platform not in VALID_PLATFORMS:
            raise RuleValidationError(
                path_str,
                f"applies_to values must be in {sorted(VALID_PLATFORMS)}, got '{platform}'",
            )


def _validate_condition(path_str: str, condition: object) -> None:
    if not isinstance(condition, dict):
        raise RuleValidationError(path_str, "condition must be a mapping")
    if "operator" not in condition:
        raise RuleValidationError(path_str, "condition must have an 'operator' field")
    if condition["operator"] not in VALID_OPERATORS:
        raise RuleValidationError(
            path_str,
            f"condition.operator must be one of {sorted(VALID_OPERATORS)}, "
            f"got '{condition['operator']}'",
        )
    # Operators that compare against a value require 'expected'
    _needs_expected = {
        "equals",
        "not_equals",
        "greater_than",
        "less_than",
        "contains",
        "not_contains",
    }
    if condition["operator"] in _needs_expected and "expected" not in condition:
        raise RuleValidationError(
            path_str,
            f"condition.expected is required for operator '{condition['operator']}'",
        )


def _validate_how_to_fix(
    path_str: str,
    how_to_fix: object,
    applies_to: list[str],
) -> None:
    if not isinstance(how_to_fix, dict):
        raise RuleValidationError(path_str, "how_to_fix must be a mapping")
    for platform in applies_to:
        if platform not in how_to_fix:
            raise RuleValidationError(
                path_str,
                f"how_to_fix must include steps for '{platform}' (listed in applies_to)",
            )
        steps = how_to_fix[platform]
        if not isinstance(steps, list) or not steps:
            raise RuleValidationError(
                path_str,
                f"how_to_fix.{platform} must be a non-empty list of steps",
            )


def _validate_difficulty(path_str: str, difficulty: object) -> None:
    if difficulty not in VALID_DIFFICULTIES:
        raise RuleValidationError(
            path_str,
            f"difficulty must be one of {sorted(VALID_DIFFICULTIES)}, got '{difficulty}'",
        )
