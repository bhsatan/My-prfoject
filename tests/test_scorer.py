"""Tests for the scorer: score computation, grading, and finding ranking.

All tests use fabricated Finding objects — no real OS data.
"""

from __future__ import annotations

import pytest

from secscan.scorer.scorer import (
    _compute_grade,
    _rank_findings,
    compute_score,
)
from tests.conftest import make_finding

# ===================================================================
# Score computation tests
# ===================================================================


class TestComputeScore:
    """Tests for the scoring formula."""

    def test_all_pass(self) -> None:
        """When every check passes, the score is 100."""
        findings = [
            make_finding(status="pass", severity="critical"),
            make_finding(rule_id="R2", status="pass", severity="high"),
            make_finding(rule_id="R3", status="pass", severity="medium"),
        ]
        result = compute_score(findings)
        assert result.score == 100
        assert result.grade == "A"
        assert result.passed == 3
        assert result.failed == 0
        assert result.unknown == 0

    def test_all_fail(self) -> None:
        """When every check fails, the score is 0."""
        findings = [
            make_finding(status="fail", severity="critical"),
            make_finding(rule_id="R2", status="fail", severity="high"),
        ]
        result = compute_score(findings)
        assert result.score == 0
        assert result.grade == "F"
        assert result.failed == 2

    def test_all_unknown(self) -> None:
        """When every check is unknown, the score is 50 (half credit)."""
        findings = [
            make_finding(status="unknown", severity="critical"),  # 10 -> earns 5
            make_finding(rule_id="R2", status="unknown", severity="critical"),  # 10 -> earns 5
        ]
        result = compute_score(findings)
        # possible = 20, earned = 10, score = 50
        assert result.score == 50
        assert result.grade == "C"

    def test_mixed_results(self) -> None:
        """Test the worked example from the plan."""
        findings = [
            make_finding(rule_id="FW", status="pass", severity="critical"),  # 10/10
            make_finding(rule_id="DISK", status="unknown", severity="high"),  # 3/7
            make_finding(rule_id="AV", status="pass", severity="critical"),  # 10/10
            make_finding(rule_id="NET", status="fail", severity="high"),  # 0/7
            make_finding(rule_id="ACCT1", status="pass", severity="high"),  # 7/7
            make_finding(rule_id="ACCT2", status="fail", severity="medium"),  # 0/4
            make_finding(rule_id="PWD1", status="pass", severity="high"),  # 7/7
            make_finding(rule_id="PWD2", status="pass", severity="medium"),  # 4/4
            make_finding(rule_id="RDP", status="pass", severity="high"),  # 7/7
            make_finding(rule_id="SMB", status="unknown", severity="high"),  # 3/7
            make_finding(rule_id="AUTO", status="pass", severity="high"),  # 7/7
        ]
        result = compute_score(findings)
        # possible = 10+7+10+7+7+4+7+4+7+7+7 = 77
        # earned = 10+3+10+0+7+0+7+4+7+3+7 = 58
        # score = round(100 * 58 / 77) = 75
        assert result.score == 75
        assert result.grade == "B"
        assert result.passed == 7
        assert result.failed == 2
        assert result.unknown == 2

    def test_empty_findings(self) -> None:
        """No findings at all yields score 100 (nothing to check)."""
        result = compute_score([])
        assert result.score == 100
        assert result.grade == "A"
        assert result.total_checks == 0

    def test_single_critical_fail(self) -> None:
        """A single critical failure scores 0."""
        findings = [make_finding(status="fail", severity="critical")]
        result = compute_score(findings)
        assert result.score == 0

    def test_unknown_half_credit_integer_division(self) -> None:
        """Unknown credit uses integer division: high(7) -> 3, low(2) -> 1."""
        findings = [
            make_finding(rule_id="H", status="unknown", severity="high"),  # earns 3/7
            make_finding(rule_id="L", status="unknown", severity="low"),  # earns 1/2
        ]
        result = compute_score(findings)
        # possible = 9, earned = 4, score = round(100*4/9) = 44
        assert result.score == 44
        assert result.grade == "D"


# ===================================================================
# Grade band tests
# ===================================================================


class TestGradeBands:
    """Test grade boundaries."""

    @pytest.mark.parametrize(
        ("score", "expected_grade"),
        [
            (100, "A"),
            (95, "A"),
            (90, "A"),
            (89, "B"),
            (75, "B"),
            (74, "C"),
            (50, "C"),
            (49, "D"),
            (25, "D"),
            (24, "F"),
            (0, "F"),
        ],
    )
    def test_grade_boundaries(self, score: int, expected_grade: str) -> None:
        assert _compute_grade(score) == expected_grade


# ===================================================================
# Finding ranking tests
# ===================================================================


class TestRankFindings:
    """Test that findings are sorted correctly for display."""

    def test_fail_before_unknown_before_pass(self) -> None:
        """Status order: fail → unknown → pass."""
        findings = [
            make_finding(rule_id="P", status="pass", severity="critical"),
            make_finding(rule_id="U", status="unknown", severity="critical"),
            make_finding(rule_id="F", status="fail", severity="critical"),
        ]
        ranked = _rank_findings(findings)
        assert [f.rule_id for f in ranked] == ["F", "U", "P"]

    def test_severity_within_same_status(self) -> None:
        """Within the same status, higher severity comes first."""
        findings = [
            make_finding(rule_id="L", status="fail", severity="low"),
            make_finding(rule_id="C", status="fail", severity="critical"),
            make_finding(rule_id="H", status="fail", severity="high"),
            make_finding(rule_id="M", status="fail", severity="medium"),
        ]
        ranked = _rank_findings(findings)
        assert [f.rule_id for f in ranked] == ["C", "H", "M", "L"]

    def test_difficulty_within_same_status_and_severity(self) -> None:
        """Among same-status same-severity findings, easier fixes come first."""
        findings = [
            make_finding(rule_id="H", status="fail", severity="high", difficulty="hard"),
            make_finding(rule_id="E", status="fail", severity="high", difficulty="easy"),
            make_finding(rule_id="M", status="fail", severity="high", difficulty="medium"),
        ]
        ranked = _rank_findings(findings)
        assert [f.rule_id for f in ranked] == ["E", "M", "H"]

    def test_full_ranking_integration(self) -> None:
        """Full ranking: status > severity > difficulty."""
        findings = [
            make_finding(rule_id="pass-low", status="pass", severity="low"),
            make_finding(
                rule_id="fail-high-hard", status="fail", severity="high", difficulty="hard"
            ),
            make_finding(
                rule_id="fail-high-easy", status="fail", severity="high", difficulty="easy"
            ),
            make_finding(rule_id="fail-crit", status="fail", severity="critical"),
            make_finding(rule_id="unknown-med", status="unknown", severity="medium"),
        ]
        ranked = _rank_findings(findings)
        expected = [
            "fail-crit",  # fail, critical (highest)
            "fail-high-easy",  # fail, high, easy
            "fail-high-hard",  # fail, high, hard
            "unknown-med",  # unknown, medium
            "pass-low",  # pass, low
        ]
        assert [f.rule_id for f in ranked] == expected

    def test_ranked_findings_in_score_result(self) -> None:
        """compute_score() returns findings in ranked order."""
        findings = [
            make_finding(rule_id="pass", status="pass", severity="high"),
            make_finding(rule_id="fail", status="fail", severity="critical"),
        ]
        result = compute_score(findings)
        assert result.findings[0].rule_id == "fail"
        assert result.findings[1].rule_id == "pass"


# ===================================================================
# Severity summary tests
# ===================================================================


class TestSeveritySummary:
    """Test the severity-by-status summary table."""

    def test_summary_structure(self) -> None:
        findings = [
            make_finding(rule_id="F1", status="fail", severity="critical"),
            make_finding(rule_id="F2", status="pass", severity="high"),
            make_finding(rule_id="F3", status="unknown", severity="high"),
        ]
        result = compute_score(findings)
        summary = result.summary_by_severity

        assert summary["critical"] == {"pass": 0, "fail": 1, "unknown": 0}
        assert summary["high"] == {"pass": 1, "fail": 0, "unknown": 1}
        assert summary["medium"] == {"pass": 0, "fail": 0, "unknown": 0}
        assert summary["low"] == {"pass": 0, "fail": 0, "unknown": 0}

    def test_empty_summary(self) -> None:
        result = compute_score([])
        assert result.summary_by_severity == {}
