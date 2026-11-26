"""RDP and SMBv1 exposure collector.  Windows only.

RDP:  reads registry ``fDenyTSConnections`` and ``UserAuthentication``.
SMBv1: uses ``Get-SmbServerConfiguration`` (requires admin).
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.collectors.base import Collector, safe_run

logger = logging.getLogger(__name__)


class RemoteAccessCollector(Collector):
    name = "remote_access"
    supported_platforms = ["windows"]

    def get_facts(self) -> dict[str, Any]:
        try:
            return self._collect()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Remote access collector error: %s", exc)
            return {"remote_access": {"error": str(exc)}}

    def get_dry_run_info(self) -> list[dict[str, str]]:
        return [
            {
                "type": "registry_read",
                "detail": (
                    r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
                    r" -> fDenyTSConnections"
                ),
            },
            {
                "type": "registry_read",
                "detail": (
                    r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
                    r"\WinStations\RDP-Tcp -> UserAuthentication"
                ),
            },
            {
                "type": "command",
                "detail": (
                    "powershell -NoProfile -Command "
                    '"Get-SmbServerConfiguration '
                    '| Select-Object EnableSMB1Protocol | ConvertTo-Json"'
                ),
            },
        ]

    def _collect(self) -> dict[str, Any]:
        import json

        facts: dict[str, Any] = {}

        # --- RDP: fDenyTSConnections ---
        stdout, _, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-ItemProperty "
                    "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                    "-Name fDenyTSConnections -ErrorAction SilentlyContinue "
                    "| Select-Object fDenyTSConnections | ConvertTo-Json"
                ),
            ]
        )
        rdp_enabled = None
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                # fDenyTSConnections: 1 = RDP disabled, 0 = RDP enabled
                rdp_enabled = data.get("fDenyTSConnections", 1) == 0
            except json.JSONDecodeError:
                pass
        facts["rdp_enabled"] = rdp_enabled

        # --- RDP: NLA (UserAuthentication) ---
        nla_required = None
        if rdp_enabled is False:
            # RDP is disabled — NLA is irrelevant, treat as safe
            nla_required = True
        else:
            stdout, _, rc = safe_run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-ItemProperty "
                        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
                        "\\WinStations\\RDP-Tcp' "
                        "-Name UserAuthentication -ErrorAction SilentlyContinue "
                        "| Select-Object UserAuthentication | ConvertTo-Json"
                    ),
                ]
            )
            if rc == 0 and stdout.strip():
                try:
                    data = json.loads(stdout)
                    # UserAuthentication: 1 = NLA required, 0 = not required
                    nla_required = data.get("UserAuthentication", 0) == 1
                except json.JSONDecodeError:
                    pass
        facts["rdp_nla_required"] = nla_required

        # --- SMBv1 ---
        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                ("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json"),
            ]
        )
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                facts["smb1_enabled"] = bool(data.get("EnableSMB1Protocol", False))
            except json.JSONDecodeError:
                facts["smb1_enabled"] = None
                facts["smb1_error"] = "Failed to parse SMB configuration."
        else:
            facts["smb1_enabled"] = None
            facts["smb1_error"] = "Needs administrator to check SMB configuration."

        # Build detail string
        parts = []
        if rdp_enabled is not None:
            rdp_status = "enabled" if rdp_enabled else "disabled"
            nla_status = "required" if nla_required else "not required"
            parts.append(f"RDP: {rdp_status}" + (f" (NLA {nla_status})" if rdp_enabled else ""))
        if facts.get("smb1_enabled") is not None:
            parts.append(f"SMBv1: {'enabled' if facts['smb1_enabled'] else 'disabled'}")
        elif facts.get("smb1_error"):
            parts.append(f"SMBv1: unknown ({facts['smb1_error']})")
        facts["detail"] = "; ".join(parts) if parts else "Partial data collected."

        return {"remote_access": facts}
