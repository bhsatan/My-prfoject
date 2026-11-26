"""Automatic login collector.

Windows: reads the ``Winlogon`` registry key for ``AutoAdminLogon``.
Linux:   checks GDM, LightDM, and SDDM configuration files.
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.collectors.base import Collector, get_platform, safe_run

logger = logging.getLogger(__name__)


class AutologinCollector(Collector):
    name = "autologin"
    supported_platforms = ["windows", "linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            current = get_platform()
            if current == "windows":
                return self._collect_windows()
            return self._collect_linux()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Autologin collector error: %s", exc)
            return {"autologin": {"error": str(exc)}}

    def get_dry_run_info(self) -> list[dict[str, str]]:
        try:
            current = get_platform()
        except RuntimeError:
            return []
        if current == "windows":
            return [
                {
                    "type": "registry_read",
                    "detail": (
                        r"HKLM:\SOFTWARE\Microsoft\Windows NT"
                        r"\CurrentVersion\Winlogon -> AutoAdminLogon"
                    ),
                },
            ]
        return [
            {"type": "file_read", "detail": "/etc/gdm3/custom.conf"},
            {"type": "file_read", "detail": "/etc/gdm/custom.conf"},
            {"type": "file_read", "detail": "/etc/lightdm/lightdm.conf"},
            {"type": "file_read", "detail": "/etc/sddm.conf"},
        ]

    def _collect_windows(self) -> dict[str, Any]:
        import json

        stdout, _, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-ItemProperty "
                    "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
                    "-Name AutoAdminLogon -ErrorAction SilentlyContinue "
                    "| Select-Object AutoAdminLogon | ConvertTo-Json"
                ),
            ]
        )
        if rc != 0 or not stdout.strip():
            # Key doesn't exist — autologin is off
            return {
                "autologin": {
                    "enabled": False,
                    "detail": "AutoAdminLogon registry key not found (autologin is off).",
                },
            }

        try:
            data = json.loads(stdout)
            value = str(data.get("AutoAdminLogon", "0"))
            enabled = value == "1"
        except json.JSONDecodeError:
            enabled = False

        return {
            "autologin": {
                "enabled": enabled,
                "detail": f"AutoAdminLogon = {value}" if not enabled else "Automatic login is ON.",
            },
        }

    def _collect_linux(self) -> dict[str, Any]:
        # Check GDM
        for gdm_path in ("/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"):
            if self._check_gdm(gdm_path):
                return {
                    "autologin": {
                        "enabled": True,
                        "detail": f"Automatic login enabled in {gdm_path}.",
                    },
                }

        # Check LightDM
        if self._check_lightdm("/etc/lightdm/lightdm.conf"):
            return {
                "autologin": {
                    "enabled": True,
                    "detail": "Automatic login enabled in /etc/lightdm/lightdm.conf.",
                },
            }

        # Check SDDM
        if self._check_sddm("/etc/sddm.conf"):
            return {
                "autologin": {
                    "enabled": True,
                    "detail": "Automatic login enabled in /etc/sddm.conf.",
                },
            }

        return {
            "autologin": {
                "enabled": False,
                "detail": "No automatic login detected (checked GDM, LightDM, SDDM).",
            },
        }

    @staticmethod
    def _check_gdm(path: str) -> bool:
        """Check GDM config for AutomaticLoginEnable=true."""
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip().lower()
                    if stripped.startswith("automaticloginenable") and "true" in stripped:
                        return True
        except OSError:
            pass
        return False

    @staticmethod
    def _check_lightdm(path: str) -> bool:
        """Check LightDM config for autologin-user setting."""
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if stripped.lower().startswith("autologin-user") and "=" in stripped:
                        # autologin-user=username means autologin is on
                        _, _, value = stripped.partition("=")
                        if value.strip():
                            return True
        except OSError:
            pass
        return False

    @staticmethod
    def _check_sddm(path: str) -> bool:
        """Check SDDM config for [Autologin] section with User= set."""
        try:
            with open(path, encoding="utf-8") as fh:
                in_autologin_section = False
                for line in fh:
                    stripped = line.strip()
                    if stripped.lower() == "[autologin]":
                        in_autologin_section = True
                        continue
                    if stripped.startswith("[") and in_autologin_section:
                        break  # Entered another section
                    if in_autologin_section and stripped.lower().startswith("user"):
                        _, _, value = stripped.partition("=")
                        if value.strip():
                            return True
        except OSError:
            pass
        return False
