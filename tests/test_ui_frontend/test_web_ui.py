"""Hostile-input, security-header, CSRF, Host-header, and route tests for secscan_ui."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from secscan_ui.app import create_app


def _write_sample_report(reports_dir: Path, scan_id: str = "20261126T120000Z_deadbeef") -> None:
    report = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "scan_time": "2026-11-26T12:00:00+00:00",
        "os": "linux",
        "tool_version": "0.2.0",
        "score": 65,
        "grade": "C",
        "summary": {"total_checks": 2, "passed": 1, "failed": 1, "unknown": 0},
        "severity_summary": {
            "critical": {"pass": 0, "fail": 1, "unknown": 0},
            "high": {"pass": 1, "fail": 0, "unknown": 0},
        },
        "findings": [
            {
                "rule_id": "NET-001",
                "category": "network",
                "title": "Risky port <script>alert(1)</script>",
                "status": "fail",
                "severity": "critical",
                "detail": "Process <img src=x onerror=alert(1)> on \x1b[31mhost-01\x1b[0m\x07",
                "why_it_matters": "Exposes services.",
                "how_to_fix": ["Stop the service."],
                "difficulty": "easy",
                "source": "https://example.com/net",
            },
            {
                "rule_id": "AUTO-001",
                "category": "autologin",
                "title": "Autologin disabled",
                "status": "pass",
                "severity": "high",
                "detail": "Disabled.",
                "why_it_matters": "Prevents physical bypass.",
                "how_to_fix": ["Disable autologin."],
                "difficulty": "easy",
                "source": "https://example.com/auto",
            },
        ],
        "not_checked": [],
    }
    (reports_dir / f"secscan_{scan_id}.json").write_text(json.dumps(report), encoding="utf-8")


def _extract_csrf(html: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert match is not None, "Expected CSRF token in form"
    return match.group(1)


@pytest.fixture()
def ui_client(tmp_path: Path):
    reports_dir = tmp_path / "reports"
    data_dir = tmp_path / "data"
    reports_dir.mkdir()
    data_dir.mkdir()
    _write_sample_report(reports_dir)
    app = create_app(reports_dir=reports_dir, data_dir=data_dir)
    return app.test_client()


class TestWebSecurityControls:
    def test_security_headers_present(self, ui_client) -> None:
        resp = ui_client.get("/")
        assert resp.status_code == 200
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("Referrer-Policy") == "no-referrer"
        assert resp.headers.get("Cache-Control") == "no-store"
        assert "Access-Control-Allow-Origin" not in resp.headers

    def test_escapes_xss_and_strips_ansi_control_chars(self, ui_client) -> None:
        resp = ui_client.get("/scans/20261126T120000Z_deadbeef")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
        assert "<img src=x" not in body
        assert "\x1b" not in body
        assert "\x07" not in body

    def test_bad_host_header_rejected(self, ui_client) -> None:
        resp = ui_client.get("/", headers={"Host": "evil.attacker.com"})
        assert resp.status_code == 403

    def test_missing_csrf_token_rejected(self, ui_client) -> None:
        resp = ui_client.post("/dashboards/import", data={"dashboard_json": "{}"})
        assert resp.status_code == 403

    def test_malicious_dashboard_json_rejected(self, ui_client) -> None:
        page = ui_client.get("/dashboards/new")
        csrf = _extract_csrf(page.get_data(as_text=True))
        bad_dash = json.dumps(
            {
                "schema_version": "1.0",
                "id": "evil",
                "name": "<script>alert(1)</script>",
                "widgets": [{"type": "score_gauge", "title": "Score", "filters": {}}],
            }
        )
        resp = ui_client.post(
            "/dashboards/import",
            data={"csrf_token": csrf, "dashboard_json": bad_dash},
        )
        assert resp.status_code == 400

    def test_oversized_post_rejected(self, ui_client) -> None:
        page = ui_client.get("/dashboards/new")
        csrf = _extract_csrf(page.get_data(as_text=True))
        resp = ui_client.post(
            "/dashboards/import",
            data={"csrf_token": csrf, "dashboard_json": "x" * (70 * 1024)},
        )
        assert resp.status_code == 413

    def test_rate_limit_returns_429(self, tmp_path: Path) -> None:
        app = create_app(
            reports_dir=tmp_path,
            data_dir=tmp_path,
            rate_limit_per_minute=2,
        )
        client = app.test_client()
        assert client.get("/health").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/health").status_code == 429

    def test_non_localhost_bind_fails_closed(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("SECSCAN_UI_BIND_HOST", "0.0.0.0")  # noqa: S104
        monkeypatch.delenv("SECSCAN_UI_ALLOW_REMOTE", raising=False)
        with pytest.raises(RuntimeError, match="Refusing to bind"):
            create_app(reports_dir=tmp_path, data_dir=tmp_path)


class TestWebRoutesAndDashboards:
    def test_core_pages_render(self, ui_client) -> None:
        assert ui_client.get("/health").get_json() == {"status": "ok"}
        assert "Latest Security Score" in ui_client.get("/").get_data(as_text=True)
        assert "Score Over Time" in ui_client.get("/scans").get_data(as_text=True)
        assert "Beginner overview" in ui_client.get("/dashboards").get_data(as_text=True)

    def test_create_and_export_custom_dashboard(self, ui_client) -> None:
        page = ui_client.get("/dashboards/new")
        csrf = _extract_csrf(page.get_data(as_text=True))
        resp = ui_client.post(
            "/dashboards/new",
            data={
                "csrf_token": csrf,
                "dash_id": "my-custom",
                "name": "My Custom View",
                "widget_type": ["score_gauge", "top_fixes"],
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert "My Custom View" in resp.get_data(as_text=True)

        exported = ui_client.get("/dashboards/my-custom/export")
        assert exported.status_code == 200
        assert json.loads(exported.get_data(as_text=True))["id"] == "my-custom"

    def test_ai_panel_disabled_by_default(self, monkeypatch, ui_client) -> None:
        monkeypatch.delenv("SECSCAN_AI_API_KEY", raising=False)
        resp = ui_client.get("/ai")
        assert resp.status_code == 200
        assert "Disabled by default" in resp.get_data(as_text=True)
