"""Firewall status collector.

Windows: uses ``Get-NetFirewallProfile`` to check Domain/Private/Public profiles.
Linux:   checks for ``ufw`` or ``firewalld`` service status.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from secscan.collectors.base import Collector, get_platform, safe_run

logger = logging.getLogger(__name__)


class FirewallCollector(Collector):
    name = "firewall"
    supported_platforms = ["windows", "linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            current = get_platform()
            if current == "windows":
                return self._collect_windows()
            return self._collect_linux()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Firewall collector error: %s", exc)
            return {"firewall": {"error": str(exc)}}

    def get_dry_run_info(self) -> list[dict[str, str]]:
        try:
            current = get_platform()
        except RuntimeError:
            return []
        if current == "windows":
            return [
                {
                    "type": "command",
                    "detail": (
                        "powershell -NoProfile -Command "
                        '"Get-NetFirewallProfile | Select-Object Name, Enabled '
                        '| ConvertTo-Json"'
                    ),
                },
            ]
        return [
            {"type": "command", "detail": "systemctl is-active firewalld"},
            {"type": "file_read", "detail": "/etc/ufw/ufw.conf"},
        ]

    # ----- Windows -----

    def _collect_windows(self) -> dict[str, Any]:
        import json

        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json",
            ]
        )
        if rc != 0:
            return {"firewall": {"error": f"PowerShell failed: {stderr.strip()}"}}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return {"firewall": {"error": f"Failed to parse firewall output: {exc}"}}

        # PowerShell returns a single object if only one profile, list otherwise
        if isinstance(data, dict):
            data = [data]

        profiles = []
        all_enabled = True
        for profile in data:
            enabled = bool(profile.get("Enabled", False))
            profiles.append({"name": profile.get("Name", "Unknown"), "enabled": enabled})
            if not enabled:
                all_enabled = False

        disabled_names = [p["name"] for p in profiles if not p["enabled"]]
        detail = "All firewall profiles are enabled."
        if disabled_names:
            detail = f"Firewall disabled on: {', '.join(disabled_names)}"

        return {
            "firewall": {
                "all_profiles_enabled": all_enabled,
                "profiles": profiles,
                "detail": detail,
            },
        }

    # ----- Linux -----

    def _collect_linux(self) -> dict[str, Any]:
        # ufw.service reports "active" even after "ufw disable", so only the
        # ENABLED flag in ufw.conf says whether ufw is filtering.
        try:
            with open("/etc/ufw/ufw.conf", encoding="utf-8") as fh:
                for line in fh:
                    # Strip trailing comments only when preceded by whitespace
                    cleaned = re.sub(r"\s+#.*$", "", line).strip().lower().replace('"', "")
                    if cleaned == "enabled=yes":
                        return {
                            "firewall": {
                                "all_profiles_enabled": True,
                                "backend": "ufw",
                                "detail": "ufw is enabled (from ufw.conf).",
                            },
                        }
        except OSError:
            pass  # File doesn't exist or unreadable — try firewalld

        # Try firewalld
        stdout, _, rc = safe_run(["systemctl", "is-active", "firewalld"])
        if rc == 0 and "active" in stdout.strip().lower():
            return {
                "firewall": {
                    "all_profiles_enabled": True,
                    "backend": "firewalld",
                    "detail": "firewalld is active.",
                },
            }

        return {
            "firewall": {
                "all_profiles_enabled": False,
                "backend": None,
                "detail": "No active firewall detected (checked ufw and firewalld).",
            },
        }
