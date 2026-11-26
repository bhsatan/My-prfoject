"""Data models for the rule engine.

Defines the core data structures used throughout SecScan:
- Rule: a security check definition loaded from a YAML file
- Finding: the result of evaluating a single rule against collected facts
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Valid values for constrained fields
# ---------------------------------------------------------------------------

VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
VALID_PLATFORMS: frozenset[str] = frozenset({"windows", "linux"})
VALID_DIFFICULTIES: frozenset[str] = frozenset({"easy", "medium", "hard"})
VALID_OPERATORS: frozenset[str] = frozenset(
    {
        "equals",
        "not_equals",
        "greater_than",
        "less_than",
        "is_true",
        "is_false",
        "contains",
        "not_contains",
    }
)
VALID_STATUSES: frozenset[str] = frozenset({"pass", "fail", "unknown"})


# ---------------------------------------------------------------------------
# Rule — loaded from YAML, evaluated by the engine
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """A single security check definition loaded from a YAML rule file.

    Rules are data-only — they describe *what* to check and what "pass" means.
    The engine evaluates them against facts collected from the system.
    Treat Rule instances as immutable after loading.
    """

    id: str
    title: str
    severity: str  # "critical" | "high" | "medium" | "low"
    applies_to: list[str]  # ["windows"], ["linux"], or both
    collector: str  # name of the collector providing facts
    fact_path: str  # dot-notation path into the facts dict
    condition: dict[str, object]  # {"operator": "...", "expected": ...}
    why_it_matters: str
    how_to_fix: dict[str, list[str]]  # {"windows": [...], "linux": [...]}
    difficulty: str  # "easy" | "medium" | "hard"
    source: str | dict[str, str]  # one for all, or per platform


# ---------------------------------------------------------------------------
# Finding — produced by the evaluator, consumed by scorer and reports
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """The result of evaluating a single rule against collected facts.

    Produced by the engine, consumed by the scorer and report generators.
    """

    rule_id: str
    title: str
    status: str  # "pass" | "fail" | "unknown"
    severity: str  # "critical" | "high" | "medium" | "low"
    why_it_matters: str
    how_to_fix: list[str]  # OS-appropriate fix steps only
    difficulty: str  # "easy" | "medium" | "hard"
    source: str
    detail: str  # human-readable context about the check result
