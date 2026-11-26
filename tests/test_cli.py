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
