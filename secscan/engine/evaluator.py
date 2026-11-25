"""Rule evaluator — matches rules against collected facts.

For each rule applicable to the current platform, the evaluator:
1. Resolves the ``fact_path`` to a value in the facts dictionary.
2. Applies the rule's ``condition`` to that value.
3. Produces a :class:`Finding` with status pass / fail / unknown.

A failure in one rule never prevents evaluation of subsequent rules.
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.engine.models import Finding, Rule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate(
    rules: list[Rule],
    facts: dict[str, dict[str, Any]],
    platform: str,
) -> list[Finding]:
    """Evaluate rules against collected facts for the given platform.

    Args:
        rules: All loaded rules (may include rules for other platforms).
        facts: Collected facts keyed by collector name, e.g.
            ``{"firewall": {"all_profiles_enabled": True, ...}, ...}``.
        platform: Current platform (``"windows"`` or ``"linux"``).

    Returns:
        A list of :class:`Finding` objects, one per applicable rule.
        Never raises — individual evaluation errors produce ``"unknown"``
        findings.
    """
    findings: list[Finding] = []

    for rule in rules:
        # Skip rules that do not apply to this platform
        if platform not in rule.applies_to:
            continue

        finding = _evaluate_single_rule(rule, facts, platform)
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Sentinel for missing values
# ---------------------------------------------------------------------------


class _MissingSentinel:
    """Sentinel indicating a fact path could not be resolved."""

    def __repr__(self) -> str:
        return "<MISSING>"


_MISSING = _MissingSentinel()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _evaluate_single_rule(
    rule: Rule,
    facts: dict[str, Any],
    platform: str,
) -> Finding:
    """Evaluate one rule and return a Finding.  Never raises."""
    # Resolve the fact value from the dot-notation path
    fact_value = _resolve_fact_path(rule.fact_path, facts)

    # Collector reported an error dict
    if isinstance(fact_value, dict) and "error" in fact_value:
        return _make_finding(
            rule,
            platform,
            "unknown",
            detail=f"Could not check: {fact_value['error']}",
        )

    # Fact path could not be resolved at all
    if fact_value is _MISSING:
        return _make_finding(
            rule,
            platform,
            "unknown",
            detail="Required data was not collected.",
        )

    # Evaluate the condition
    try:
        passed = _evaluate_condition(fact_value, rule.condition)
    except Exception as exc:  # noqa: BLE001 — intentionally broad
        logger.warning("Error evaluating condition for rule %s: %s", rule.id, exc)
        return _make_finding(
            rule,
            platform,
            "unknown",
            detail=f"Error during evaluation: {exc}",
        )

    if passed is None:
        return _make_finding(
            rule,
            platform,
            "unknown",
            detail="Check could not determine a result.",
        )

    if passed:
        return _make_finding(
            rule,
            platform,
            "pass",
            detail=f"Check passed (value: {fact_value}).",
        )

    return _make_finding(
        rule,
        platform,
        "fail",
        detail=f"Check failed (value: {fact_value}).",
    )


def _resolve_fact_path(fact_path: str, facts: dict[str, Any]) -> Any:
    """Resolve a dot-notation path like ``firewall.all_profiles_enabled``.

    Returns the value at the path, or :data:`_MISSING` if any segment is
    absent or the intermediate value is not a dict.
    """
    segments = fact_path.split(".")
    current: Any = facts

    for segment in segments:
        if not isinstance(current, dict) or segment not in current:
            return _MISSING
        current = current[segment]

    return current


def _evaluate_condition(value: Any, condition: dict[str, Any]) -> bool | None:
    """Apply a condition to a fact value.

    Returns:
        ``True`` if the condition passes, ``False`` if it fails,
        ``None`` if the result is indeterminate (e.g. ``value`` is ``None``).
    """
    operator = condition["operator"]
    expected = condition.get("expected")

    # A None fact value means the collector ran but couldn't determine a value
    if value is None:
        return None

    if operator == "equals":
        return value == expected
    if operator == "not_equals":
        return value != expected
    if operator == "greater_than":
        return value > expected
    if operator == "less_than":
        return value < expected
    if operator == "is_true":
        return bool(value)
    if operator == "is_false":
        return not bool(value)
    if operator == "contains":
        return expected in value
    if operator == "not_contains":
        return expected not in value

    logger.warning("Unknown condition operator: %s", operator)
    return None


def _make_finding(
    rule: Rule,
    platform: str,
    status: str,
    *,
    detail: str,
) -> Finding:
    """Create a Finding from a Rule, selecting OS-appropriate fix steps."""
    fix_steps = rule.how_to_fix.get(platform, [])
    # Fallback: if no platform-specific fix, use whatever is available
    if not fix_steps:
        for steps in rule.how_to_fix.values():
            fix_steps = steps
            break

    return Finding(
        rule_id=rule.id,
        title=rule.title,
        status=status,
        severity=rule.severity,
        why_it_matters=rule.why_it_matters,
        how_to_fix=fix_steps,
        difficulty=rule.difficulty,
        source=rule.source,
        detail=detail,
    )
