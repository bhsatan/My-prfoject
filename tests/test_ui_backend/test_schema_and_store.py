"""Hostile-input and contract tests for secscan_ui.schema and secscan_ui.store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan_ui.schema import (
    MAX_JSON_DEPTH,
    MAX_REPORT_BYTES,
    LegacyReportError,
    ReportValidationError,
    load_report_file,
    validate_report_dict,
)
from secscan_ui.store import (
    DashboardStore,
    DashboardValidationError,
    ReportStore,
    validate_dashboard_dict,
)


def _valid_v1_report(
    *,
    scan_id: str = "20261126T120000Z_deadbeef",
    scan_time: str = "2026-11-26T12:00:00+00:00",
    score: int = 75,
    fw_status: str = "fail",
) -> dict:
    return {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "scan_time": scan_time,
        "os": "linux",
        "tool_version": "0.2.0",
        "score": score,
        "grade": "B",
        "summary": {"total_checks": 2, "passed": 1, "failed": 1, "unknown": 0},
        "severity_summary": {
            "critical": {"pass": 0, "fail": 1, "unknown": 0},
            "high": {"pass": 1, "fail": 0, "unknown": 0},
        },
        "findings": [
            {
                "rule_id": "FW-001",
                "category": "firewall",
                "title": "Firewall enabled",
                "status": fw_status,
                "severity": "critical",
                "detail": "Firewall is off.",
                "why_it_matters": "Blocks unwanted connections.",
                "how_to_fix": ["Enable ufw."],
                "difficulty": "easy",
                "source": "https://example.com/fw",
            },
            {
                "rule_id": "AUTO-001",
                "category": "autologin",
                "title": "Autologin disabled",
                "status": "pass",
                "severity": "high",
                "detail": "Off.",
                "why_it_matters": "Prevents physical bypass.",
                "how_to_fix": ["Disable autologin."],
                "difficulty": "easy",
                "source": "https://example.com/auto",
            },
        ],
        "not_checked": [],
    }


class TestReportSchemaValidation:
    def test_valid_v1_report_loads(self, tmp_path: Path) -> None:
        p = tmp_path / "r1.json"
        p.write_text(json.dumps(_valid_v1_report()), encoding="utf-8")
        report = load_report_file(p, tmp_path)
        assert report.scan_id == "20261126T120000Z_deadbeef"
        assert report.score == 75
        assert len(report.findings) == 2

    def test_legacy_v01_report_rejected_gracefully(self, tmp_path: Path) -> None:
        legacy = {
            "secscan_version": "0.1.0",
            "scan_time": "2026-11-26T10:00:00+00:00",
            "score": 80,
            "grade": "B",
            "summary": {"total_checks": 1, "passed": 1, "failed": 0, "unknown": 0},
            "severity_summary": {},
            "findings": [],
        }
        p = tmp_path / "legacy.json"
        p.write_text(json.dumps(legacy), encoding="utf-8")
        with pytest.raises(LegacyReportError, match="Legacy v0.1 report format"):
            load_report_file(p, tmp_path)

    def test_malformed_json_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ReportValidationError, match="Malformed JSON"):
            load_report_file(p, tmp_path)

    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "huge.json"
        # Create a sparse/large file > MAX_REPORT_BYTES
        p.write_bytes(b"{" + b" " * (MAX_REPORT_BYTES + 10) + b"}")
        with pytest.raises(ReportValidationError, match="maximum allowed size"):
            load_report_file(p, tmp_path)

    def test_deeply_nested_json_rejected(self, tmp_path: Path) -> None:
        # Build nesting deeper than MAX_JSON_DEPTH
        nested: dict | str = "leaf"
        for _ in range(MAX_JSON_DEPTH + 3):
            nested = {"a": nested}
        p = tmp_path / "deep.json"
        p.write_text(json.dumps(nested), encoding="utf-8")
        with pytest.raises(ReportValidationError, match="maximum depth"):
            load_report_file(p, tmp_path)

    def test_hostile_strings_accepted_in_data_model(self) -> None:
        """Process/host strings with HTML/JS/ANSI/control chars must not crash loader."""
        data = _valid_v1_report()
        data["findings"][0]["detail"] = "<script>alert(1)</script>\x1b[31mRED\x1b[0m\x07"
        report = validate_report_dict(data)
        assert "<script>alert(1)</script>" in report.findings[0].detail

    def test_unknown_top_level_key_rejected_in_1_0(self) -> None:
        data = _valid_v1_report()
        data["unexpected"] = "nope"
        with pytest.raises(ReportValidationError, match="Unknown field"):
            validate_report_dict(data)

    def test_minor_version_1_1_ignores_unknown_top_key(self) -> None:
        data = _valid_v1_report()
        data["schema_version"] = "1.1"
        data["future_field"] = {"extra": True}
        report = validate_report_dict(data)
        assert report.schema_version == "1.1"

    def test_symlink_outside_reports_dir_rejected(self, tmp_path: Path) -> None:
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        outside = tmp_path / "secret.json"
        outside.write_text(json.dumps(_valid_v1_report()), encoding="utf-8")
        link = reports_dir / "escape.json"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("Symlink creation requires elevated privileges on this Windows host")
        with pytest.raises(ReportValidationError, match="outside the reports directory"):
            load_report_file(link, reports_dir)


class TestReportStoreAndTrends:
    @pytest.mark.parametrize(
        "bad_id",
        ["../etc/passwd", r"..\secret", "a/b", "short", "<script>"],
    )
    def test_path_traversal_scan_id_rejected(self, tmp_path: Path, bad_id: str) -> None:
        store = ReportStore(tmp_path)
        with pytest.raises(ReportValidationError, match="Invalid scan_id"):
            store.load_scan(bad_id)

    def test_list_scans_skips_invalid_and_computes_trends(self, tmp_path: Path) -> None:
        (tmp_path / "scan1.json").write_text(
            json.dumps(
                _valid_v1_report(
                    scan_id="20261125T100000Z_11111111",
                    scan_time="2026-11-25T10:00:00+00:00",
                    score=60,
                    fw_status="fail",
                )
            ),
            encoding="utf-8",
        )
        (tmp_path / "scan2.json").write_text(
            json.dumps(
                _valid_v1_report(
                    scan_id="20261126T100000Z_22222222",
                    scan_time="2026-11-26T10:00:00+00:00",
                    score=85,
                    fw_status="pass",
                )
            ),
            encoding="utf-8",
        )
        (tmp_path / "broken.json").write_text("{broken", encoding="utf-8")

        store = ReportStore(tmp_path)
        valid, skipped = store.list_scans()
        assert len(valid) == 2
        assert valid[0].scan_id == "20261126T100000Z_22222222"
        assert len(skipped) == 1
        assert skipped[0].filename == "broken.json"

        trends = store.compute_trends()
        assert trends.score_delta == 25
        assert trends.resolved == ["FW-001"]
        assert trends.newly_failed == []


class TestDashboardStore:
    def test_valid_custom_dashboard_saved(self, tmp_path: Path) -> None:
        store = DashboardStore(tmp_path)
        payload = json.dumps(
            {
                "schema_version": "1.0",
                "id": "custom-1",
                "name": "My Workstation",
                "widgets": [
                    {"type": "score_gauge", "title": "Score", "filters": {"status": ["fail"]}},
                ],
            }
        )
        saved = store.save_dashboard(payload)
        assert saved["id"] == "custom-1"
        assert len(store.list_dashboards()) == 4  # 3 prebuilt + 1 custom

    def test_rejects_html_or_urls_in_dashboard(self) -> None:
        with pytest.raises(DashboardValidationError, match="HTML or URLs"):
            validate_dashboard_dict(
                {
                    "schema_version": "1.0",
                    "id": "bad-html",
                    "name": "<script>alert(1)</script>",
                    "widgets": [{"type": "score_gauge", "title": "Ok", "filters": {}}],
                }
            )

        with pytest.raises(DashboardValidationError, match="HTML or URLs"):
            validate_dashboard_dict(
                {
                    "schema_version": "1.0",
                    "id": "bad-url",
                    "name": "My Dash",
                    "widgets": [
                        {"type": "score_gauge", "title": "https://evil.example/x", "filters": {}},
                    ],
                }
            )

    def test_rejects_too_many_widgets(self) -> None:
        with pytest.raises(DashboardValidationError, match="1..12"):
            validate_dashboard_dict(
                {
                    "schema_version": "1.0",
                    "id": "too-many",
                    "name": "Too Many",
                    "widgets": [
                        {"type": "score_gauge", "title": f"W{i}", "filters": {}} for i in range(13)
                    ],
                }
            )

    def test_save_dashboard_blocks_path_escape(self, tmp_path: Path, monkeypatch) -> None:
        store = DashboardStore(tmp_path / "data")
        payload = json.dumps(
            {
                "schema_version": "1.0",
                "id": "escape-test",
                "name": "Escape",
                "widgets": [{"type": "score_gauge", "title": "Score", "filters": {}}],
            }
        )
        monkeypatch.setattr(
            "secscan_ui.store.validate_dashboard_dict",
            lambda _d: {
                "schema_version": "1.0",
                "id": "../outside",
                "name": "Escape",
                "widgets": [{"type": "score_gauge", "title": "Score", "filters": {}}],
            },
        )
        with pytest.raises(DashboardValidationError, match="outside"):
            store.save_dashboard(payload)

    def test_rejects_naive_scan_time_and_non_string_finding_enum(self) -> None:
        data = _valid_v1_report(scan_time="2026-11-26T12:00:00")
        with pytest.raises(ReportValidationError, match="timezone"):
            validate_report_dict(data)

        bad_enum = _valid_v1_report()
        bad_enum["findings"][0]["status"] = ["fail"]
        with pytest.raises(ReportValidationError, match="status is invalid"):
            validate_report_dict(bad_enum)

    def test_rejects_ftp_protocol_relative_and_unhashable_filter(self) -> None:
        for bad_title in ("ftp://files.example/a", "//evil.example/x"):
            with pytest.raises(DashboardValidationError, match="HTML or URLs"):
                validate_dashboard_dict(
                    {
                        "schema_version": "1.0",
                        "id": "bad-link",
                        "name": "Ok",
                        "widgets": [{"type": "score_gauge", "title": bad_title, "filters": {}}],
                    }
                )

        with pytest.raises(DashboardValidationError, match="filters.severity"):
            validate_dashboard_dict(
                {
                    "schema_version": "1.0",
                    "id": "bad-filter",
                    "name": "Ok",
                    "widgets": [
                        {"type": "score_gauge", "title": "Ok", "filters": {"severity": [{"a": 1}]}},
                    ],
                }
            )

    def test_recursion_error_in_json_loads_converted(self, tmp_path: Path, monkeypatch) -> None:
        p = tmp_path / "rec.json"
        p.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(
            "secscan_ui.schema.json.loads", lambda _s: (_ for _ in ()).throw(RecursionError())
        )
        with pytest.raises(ReportValidationError, match="maximum depth"):
            load_report_file(p, tmp_path)
