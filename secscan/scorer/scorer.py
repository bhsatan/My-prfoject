"""Scorer — computes the 0-100 posture score and ranks findings.

Scoring formula (documented in README):
    Each severity has a weight:
        critical = 10,  high = 7,  medium = 4,  low = 2

    For each applicable rule:
        pass    → earns full weight
        unknown → earns half weight (integer division)
        fail    → earns 0

    score = round(100 × earned / possible)

Findings are ranked for display:
    1. Status:   fail → unknown → pass
    2. Severity: highest weight first
    3. Difficulty: easy → medium → hard (quick wins first)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secscan.engine.models import Finding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
}

_DIFFICULTY_ORDER: dict[str, int] = {
    "easy": 0,
    "medium": 1,
    "hard": 2,
}

_STATUS_ORDER: dict[str, int] = {
    "fail": 0,
    "unknown": 1,
    "pass": 2,
}

_GRADE_BANDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (50, "C"),
    (25, "D"),
    (0, "F"),
]


# ---------------------------------------------------------------------------
# ScoreResult
# ---------------------------------------------------------------------------


@dataclass
class ScoreResult:
    """The final scored and ranked output of a scan."""

    score: int  # 0–100
    grade: str  # A / B / C / D / F
    total_checks: int
    passed: int
    failed: int
    unknown: int
    findings: list[Finding]  # ranked: fail → unknown → pass
    summary_by_severity: dict[str, dict[str, int]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_score(findings: list[Finding]) -> ScoreResult:
    """Compute the posture score and rank findings.

    Args:
        findings: Unranked findings from the evaluator.

    Returns:
        A :class:`ScoreResult` with the score, grade, counts, ranked
        findings, and a severity-by-status summary table.
    """
    if not findings:
        return ScoreResult(
            score=100,
            grade="A",
            total_checks=0,
            passed=0,
            failed=0,
            unknown=0,
            findings=[],
            summary_by_severity={},
        )

    total_possible = 0
    total_earned = 0
    passed = 0
    failed = 0
    unknown = 0

    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
        total_possible += weight

        if finding.status == "pass":
            total_earned += weight
            passed += 1
        elif finding.status == "unknown":
            total_earned += weight // 2
            unknown += 1
        else:  # "fail"
            failed += 1

    # Compute score (guard against zero division)
    score = 100 if total_possible == 0 else round(100 * total_earned / total_possible)

    score = max(0, min(100, score))
    grade = _compute_grade(score)
    ranked = _rank_findings(findings)
    summary = _build_severity_summary(findings)

    return ScoreResult(
        score=score,
        grade=grade,
        total_checks=len(findings),
        passed=passed,
        failed=failed,
        unknown=unknown,
        findings=ranked,
        summary_by_severity=summary,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _compute_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    for threshold, grade in _GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def _rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings: failures first, highest severity first, easiest fix first."""
    return sorted(
        findings,
        key=lambda f: (
            _STATUS_ORDER.get(f.status, 99),
            -SEVERITY_WEIGHTS.get(f.severity, 0),
            _DIFFICULTY_ORDER.get(f.difficulty, 99),
        ),
    )


def _build_severity_summary(
    findings: list[Finding],
) -> dict[str, dict[str, int]]:
    """Build a table of counts by severity × status.

    Returns:
        ``{"critical": {"pass": 1, "fail": 0, "unknown": 0}, ...}``
    """
    summary: dict[str, dict[str, int]] = {}
    for severity in SEVERITY_WEIGHTS:
        summary[severity] = {"pass": 0, "fail": 0, "unknown": 0}

    for finding in findings:
        sev = finding.severity
        status = finding.status
        if sev in summary and status in summary[sev]:
            summary[sev][status] += 1

    return summary
