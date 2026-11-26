"""Tests for terminal, JSON, and HTML report generators.

All tests use fabricated ScoreResult objects — no real OS data or network.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from secscan.report.html_report import render_html
from secscan.report.json_report import render_json
from secscan.report.terminal import render_terminal
from secscan.scorer.scorer import compute_score
from tests.conftest import make_finding


def _sample_result():
    """Return a realistic ScoreResult with pass, fail, and unknown findings."""
    findings = [
        make_finding(
            rule_id="FW-001",
            title="Firewall enabled",
            status="fail",
            severity="critical",
            why_it_matters="Blocks unwanted incoming connections.",
            how_to_fix=["Turn on firewall."],
            difficulty="easy",
            source="https://example.com/fw",
            detail="Firewall is OFF.",
        ),
        make_finding(
            rule_id="DISK-001",
            title="Disk encryption",
            status="unknown",
            severity="high",
            why_it_matters="Protects data if stolen.",
            how_to_fix=["Enable BitLocker."],
            difficulty="hard",
            source="https://example.com/disk",
            detail="Needs administrator.",
        ),
        make_finding(
            rule_id="AUTO-001",
            title="Autologin disabled",
            status="pass",
            severity="high",
            why_it_matters="Prevents unauthenticated access.",
            how_to_fix=["Disable autologin."],
            difficulty="easy",
            source="https://example.com/auto",
            detail="Check passed.",
        ),
    ]
    return compute_score(findings)


# ===================================================================
# Terminal report tests
# ===================================================================


class TestTerminalReport:
    def test_contains_score_and_grade(self) -> None:
        result = _sample_result()
        output = render_terminal(result)
        assert f"{result.score}/100" in output
        assert f"Grade: {result.grade}" in output

    def test_contains_issues_and_passed(self) -> None:
        result = _sample_result()
        output = render_terminal(result)
        assert "Firewall enabled" in output
        assert "Turn on firewall." in output
        assert "Disk encryption" in output
        assert "Autologin disabled" in output

    def test_contains_sensitive_warning(self) -> None:
        result = _sample_result()
        output = render_terminal(result)
        assert "sensitive" in output.lower()

    def test_writes_to_stream(self) -> None:
        result = _sample_result()
        buf = io.StringIO()
        returned = render_terminal(result, stream=buf)
        assert buf.getvalue() == returned


# ===================================================================
# JSON report tests
# ===================================================================


class TestJsonReport:
    def test_valid_json_structure(self) -> None:
        result = _sample_result()
        raw = render_json(result)
        data = json.loads(raw)

        assert data["secscan_version"] == "0.1.0"
        assert data["score"] == result.score
        assert data["grade"] == result.grade
        assert data["summary"]["total_checks"] == 3
        assert data["summary"]["passed"] == 1
        assert data["summary"]["failed"] == 1
        assert data["summary"]["unknown"] == 1
        assert len(data["findings"]) == 3
        assert data["findings"][0]["rule_id"] == "FW-001"

    def test_writes_to_file(self, tmp_path: Path) -> None:
        result = _sample_result()
        out_file = tmp_path / "sub" / "report.json"
        render_json(result, output_path=out_file)
        assert out_file.is_file()
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        assert parsed["score"] == result.score


# ===================================================================
# HTML report tests
# ===================================================================


class TestHtmlReport:
    def test_self_contained_no_external_urls(self) -> None:
        """HTML report must not load scripts, styles, or fonts from CDNs."""
        result = _sample_result()
        html = render_html(result)
        assert "<!DOCTYPE html>" in html
        assert "http://" not in html.split("Source:")[0]
        assert "<script src=" not in html
        assert '<link rel="stylesheet"' not in html

    def test_contains_score_and_warning_banner(self) -> None:
        result = _sample_result()
        html = render_html(result)
        assert f"Score {result.score}/100" in html
        assert f"Grade {result.grade}" in html
        assert "sensitive information" in html.lower()

    def test_escapes_html_in_findings(self) -> None:
        """User/system strings in findings must be HTML-escaped to prevent XSS."""
        findings = [
            make_finding(
                rule_id="XSS-001",
                title='<script>alert("xss")</script>',
                status="fail",
                severity="high",
                detail="Value: <img src=x onerror=alert(1)>",
            ),
        ]
        result = compute_score(findings)
        html = render_html(result)
        assert "<script>alert" not in html
        assert "&lt;script&gt;alert" in html
        assert "<img src=x" not in html

    def test_writes_to_file(self, tmp_path: Path) -> None:
        result = _sample_result()
        out_file = tmp_path / "reports" / "report.html"
        render_html(result, output_path=out_file)
        assert out_file.is_file()
        assert "SecScan Security Posture Report" in out_file.read_text(encoding="utf-8")
