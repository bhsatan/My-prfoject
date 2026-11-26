"""Deterministic plain-language insights, summaries, and text sanitization."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from secscan_ui.schema import FindingRecord, ScanReport
from secscan_ui.store import TrendSummary

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_DIFFICULTY_RANK = {"easy": 0, "medium": 1, "hard": 2}

_GRADE_EXPLANATIONS: dict[str, str] = {
    "A": "Strong baseline: almost all checks passed with minimal gaps.",
    "B": "Good baseline: most checks passed, with a few important gaps to fix.",
    "C": "Fair baseline: several security gaps leave your machine exposed.",
    "D": "Weak baseline: major protections are missing or turned off.",
    "F": "High risk: critical protections are missing; address the top fixes right away.",
}


def clean_text(value: Any) -> str:
    """Strip ANSI escape codes and ASCII control characters from untrusted text."""
    text = str(value) if value is not None else ""
    text = _ANSI_ESCAPE_RE.sub("", text)
    return _CONTROL_CHAR_RE.sub("", text)


def grade_explanation(grade: str) -> str:
    """Return a plain-English explanation for a letter grade."""
    return _GRADE_EXPLANATIONS.get(grade, "Security posture summary.")


def top_fixes(findings: list[FindingRecord], limit: int = 5) -> list[FindingRecord]:
    """Return the top *limit* failed findings ordered by severity then ease."""
    failed = [f for f in findings if f.status == "fail"]
    failed.sort(
        key=lambda f: (
            _SEVERITY_RANK.get(f.severity, 99),
            _DIFFICULTY_RANK.get(f.difficulty, 99),
            f.rule_id,
        )
    )
    return failed[:limit]


def category_breakdown(findings: list[FindingRecord]) -> list[dict[str, Any]]:
    """Aggregate pass/fail/unknown counts by finding category."""
    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "unknown": 0, "total": 0}
    )
    for f in findings:
        buckets[f.category][f.status] += 1
        buckets[f.category]["total"] += 1

    rows = []
    for cat in sorted(buckets):
        c = buckets[cat]
        rows.append(
            {
                "category": cat.replace("_", " ").title(),
                "raw_category": cat,
                "pass": c["pass"],
                "fail": c["fail"],
                "unknown": c["unknown"],
                "total": c["total"],
            }
        )
    return rows


def generate_insights(report: ScanReport, trends: TrendSummary | None = None) -> list[str]:
    """Generate short plain-language takeaways deterministically from scan data."""
    insights: list[str] = []

    crit_fail = sum(1 for f in report.findings if f.status == "fail" and f.severity == "critical")
    high_fail = sum(1 for f in report.findings if f.status == "fail" and f.severity == "high")
    easy_fail = sum(1 for f in report.findings if f.status == "fail" and f.difficulty == "easy")

    if report.summary["failed"] == 0 and report.summary["unknown"] == 0:
        insights.append(
            "Every check passed on this scan. Keep your system updated and re-scan periodically."
        )
    else:
        if crit_fail > 0:
            insights.append(
                f"{crit_fail} critical gap(s) need immediate attention "
                "because they expose core defences."
            )
        if high_fail > 0:
            insights.append(
                f"{high_fail} high-severity gap(s) should be fixed after critical items."
            )
        if easy_fail > 0:
            insights.append(
                f"{easy_fail} failing check(s) are marked easy to fix — "
                "start with those for quick wins."
            )

    if report.summary["unknown"] > 0:
        insights.append(
            f"{report.summary['unknown']} check(s) could not be verified "
            "(shown as 'Unknown', never as passing)."
        )

    if trends is not None and trends.score_delta is not None:
        if trends.score_delta > 0:
            insights.append(
                f"Your score rose by {trends.score_delta} point(s) since the previous scan"
                + (f"; {len(trends.resolved)} gap(s) were fixed." if trends.resolved else ".")
            )
        elif trends.score_delta < 0:
            insights.append(
                f"Your score dropped by {abs(trends.score_delta)} point(s) since the previous scan"
                + (
                    f"; {len(trends.newly_failed)} new gap(s) appeared."
                    if trends.newly_failed
                    else "."
                )
            )
        else:
            insights.append("Your score is unchanged compared to the previous scan.")

    return insights


def trend_text_summary(trends: TrendSummary) -> str:
    """Return a single plain-English sentence summarizing the score trend."""
    if not trends.points:
        return "No scans are available yet."
    if len(trends.points) == 1:
        p = trends.points[0]
        return f"Only 1 scan recorded so far (score {p['score']}/100, Grade {p['grade']})."
    prev = trends.points[-2]
    curr = trends.points[-1]
    if trends.score_delta is not None and trends.score_delta > 0:
        direction = f"rose from {prev['score']} to {curr['score']}"
    elif trends.score_delta is not None and trends.score_delta < 0:
        direction = f"fell from {prev['score']} to {curr['score']}"
    else:
        direction = f"stayed at {curr['score']}"

    parts = [f"Your score {direction} since the previous scan"]
    if trends.resolved:
        parts.append(f"{len(trends.resolved)} gap(s) were fixed")
    if trends.newly_failed:
        parts.append(f"{len(trends.newly_failed)} new gap(s) appeared")
    return "; ".join(parts) + "."
