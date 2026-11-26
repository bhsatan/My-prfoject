"""Windows Defender / antivirus status collector.

Uses ``Get-MpComputerStatus`` PowerShell cmdlet.  Windows only.
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.collectors.base import Collector, safe_run

logger = logging.getLogger(__name__)


class AntivirusCollector(Collector):
    name = "antivirus"
    supported_platforms = ["windows"]

    def get_facts(self) -> dict[str, Any]:
        try:
            return self._collect_windows()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Antivirus collector error: %s", exc)
            return {"antivirus": {"error": str(exc)}}

    def get_dry_run_info(self) -> list[dict[str, str]]:
        return [
            {
                "type": "command",
                "detail": (
                    "powershell -NoProfile -Command "
                    '"Get-MpComputerStatus | Select-Object AMServiceEnabled, '
                    "AntivirusEnabled, RealTimeProtectionEnabled, "
                    'AntivirusSignatureLastUpdated | ConvertTo-Json"'
                ),
            },
        ]

    def _collect_windows(self) -> dict[str, Any]:
        import json

        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-MpComputerStatus | Select-Object AMServiceEnabled, "
                    "AntivirusEnabled, RealTimeProtectionEnabled, "
                    "AntispywareEnabled, AntivirusSignatureLastUpdated "
                    "| ConvertTo-Json"
                ),
            ]
        )
        if rc != 0:
            return {
                "antivirus": {
                    "error": f"Get-MpComputerStatus failed: {stderr.strip()}",
                },
            }

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"antivirus": {"error": "Failed to parse antivirus output."}}

        real_time = bool(data.get("RealTimeProtectionEnabled", False))
        engine = bool(data.get("AMServiceEnabled", False))
        sig_date = data.get("AntivirusSignatureLastUpdated", "Unknown")

        parts = []
        parts.append(f"Real-time: {'ON' if real_time else 'OFF'}")
        parts.append(f"Engine: {'running' if engine else 'stopped'}")
        parts.append(f"Signatures: {sig_date}")

        return {
            "antivirus": {
                "real_time_enabled": real_time,
                "engine_running": engine,
                "detail": "Windows Defender — " + ", ".join(parts),
            },
        }
