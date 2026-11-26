"""Tests for the SecScan CLI (scan, --dry-run, permission notice, formats).

All tests mock collectors and platform detection so they never touch the
real OS and run on any platform.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from secscan.cli import main


def _mock_collector(name: str = "firewall", facts: dict | None = None) -> MagicMock:
    """Create a mock Collector returning deterministic facts and dry-run info."""
    collector = MagicMock()
    collector.name = name
    collector.is_supported.return_value = True
    collector.get_facts.return_value = facts or {
        "firewall": {"all_profiles_enabled": True, "detail": "All enabled."},
    }
    collector.get_dry_run_info.return_value = [
        {"type": "command", "detail": "mock-command --check"},
    ]
    return collector


class TestCliDryRun:
    @patch("secscan.cli.get_platform", return_value="linux")
    @patch("secscan.cli.get_all_collectors")
    def test_dry_run_does_not_collect(self, mock_get_collectors, mock_plat, capsys) -> None:
        collector = _mock_collector()
        mock_get_collectors.return_value = [collector]

        rc = main(["scan", "--dry-run"])
        assert rc == 0
        collector.get_facts.assert_not_called()
        collector.get_dry_run_info.assert_called_once()

        captured = capsys.readouterr()
        assert "dry-run" in captured.out.lower()
        assert "mock-command --check" in captured.out


class TestCliPermissionNotice:
    @patch("secscan.cli.get_platform", return_value="windows")
    @patch("secscan.cli.get_all_collectors")
    def test_scan_aborts_when_user_declines(self, mock_get_collectors, mock_plat, capsys) -> None:
        collector = _mock_collector()
        mock_get_collectors.return_value = [collector]

        with patch("builtins.input", return_value="n"):
            rc = main(["scan"])

        assert rc == 0
        collector.get_facts.assert_not_called()
        captured = capsys.readouterr()
        assert "Permission Notice" in captured.out
        assert "Scan cancelled" in captured.out

    @patch("secscan.cli.get_platform", return_value="windows")
    @patch("secscan.cli.get_all_collectors")
    def test_scan_proceeds_when_user_confirms(self, mock_get_collectors, mock_plat, capsys) -> None:
        collector = _mock_collector()
        mock_get_collectors.return_value = [collector]

        with patch("builtins.input", return_value="y"):
            rc = main(["scan"])

        assert rc == 0
        collector.get_facts.assert_called_once()
        captured = capsys.readouterr()
        assert "SecScan — Security Posture Report" in captured.out


class TestCliFormats:
    @patch("secscan.cli.get_platform", return_value="windows")
    @patch("secscan.cli.get_all_collectors")
    def test_json_output_to_file(self, mock_get_collectors, mock_plat, tmp_path: Path) -> None:
        mock_get_collectors.return_value = [_mock_collector()]
        out_dir = tmp_path / "out"

        rc = main(["scan", "--yes", "--format", "json", "--output", str(out_dir)])
        assert rc == 0

        files = list(out_dir.glob("secscan_report_*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text(encoding="utf-8"))
        assert "score" in data
        assert "findings" in data

    @patch("secscan.cli.get_platform", return_value="windows")
    @patch("secscan.cli.get_all_collectors")
    def test_html_output_to_file(self, mock_get_collectors, mock_plat, tmp_path: Path) -> None:
        mock_get_collectors.return_value = [_mock_collector()]
        out_dir = tmp_path / "out"

        rc = main(["scan", "--yes", "--format", "html", "--output", str(out_dir)])
        assert rc == 0

        files = list(out_dir.glob("secscan_report_*.html"))
        assert len(files) == 1
        content = files[0].read_text(encoding="utf-8")
        assert "SecScan Security Posture Report" in content

    @patch("secscan.cli.get_platform", return_value="windows")
    @patch("secscan.cli.get_all_collectors")
    def test_collector_exception_does_not_crash_scan(
        self, mock_get_collectors, mock_plat, capsys
    ) -> None:
        broken = _mock_collector(name="firewall")
        broken.get_facts.side_effect = RuntimeError("unexpected boom")
        mock_get_collectors.return_value = [broken]

        rc = main(["scan", "--yes"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Score:" in captured.out

    @patch("secscan.cli.get_platform", side_effect=RuntimeError("Unsupported platform: darwin"))
    def test_unsupported_platform_returns_nonzero(self, mock_plat, capsys) -> None:
        rc = main(["scan", "--yes"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "Unsupported platform" in captured.err


class TestCliUi:
    def test_ui_refuses_non_loopback_without_allow_remote(self, tmp_path: Path, capsys) -> None:
        rc = main(["ui", "--host", "0.0.0.0", "--reports-dir", str(tmp_path)])  # noqa: S104
        assert rc == 1
        err = capsys.readouterr().err
        assert "--allow-remote" in err

    def test_ui_refuses_privileged_without_allow_privileged(self, tmp_path: Path, capsys) -> None:
        with patch("secscan_ui.__main__._is_privileged", return_value=True):
            rc = main(["ui", "--reports-dir", str(tmp_path)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "--allow-privileged" in err

    def test_ui_missing_extra_prints_plain_message(self, tmp_path: Path, capsys) -> None:
        with patch("secscan.cli._import_ui_runner", side_effect=ImportError("No module flask")):
            rc = main(["ui", "--reports-dir", str(tmp_path)])
        assert rc == 1
        err = capsys.readouterr().err
        assert ".[ui]" in err

    def test_ui_warns_on_world_readable_reports(self, tmp_path: Path, capsys) -> None:
        report_file = tmp_path / "secscan_20261126T120000Z_deadbeef.json"
        report_file.write_text("{}", encoding="utf-8")
        with (
            patch("secscan_ui.__main__._is_privileged", return_value=False),
            patch("secscan_ui.__main__._is_world_readable", return_value=True),
            patch("secscan_ui.__main__._serve") as mock_serve,
        ):
            rc = main(["ui", "--reports-dir", str(tmp_path), "--port", "8081"])
        assert rc == 0
        mock_serve.assert_called_once()
        err = capsys.readouterr().err
        assert "world-readable" in err.lower()

    def test_ui_ipv6_and_allowed_hosts_env_merged(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("SECSCAN_UI_ALLOWED_HOSTS", "custom.local:8080")
        captured: dict[str, object] = {}

        def fake_create_app(**kwargs):
            captured.update(kwargs)
            return object()

        with (
            patch("secscan_ui.__main__._is_privileged", return_value=False),
            patch("secscan_ui.__main__._serve"),
            patch("secscan_ui.app.create_app", side_effect=fake_create_app),
        ):
            rc = main(["ui", "--host", "::1", "--port", "9090", "--reports-dir", str(tmp_path)])
        assert rc == 0
        hosts = captured["allowed_hosts"]
        assert isinstance(hosts, set)
        assert "[::1]:9090" in hosts
        assert "custom.local:8080" in hosts
