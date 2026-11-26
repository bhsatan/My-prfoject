"""User accounts and admin membership collector.

Windows: uses ``Get-LocalUser`` and ``Get-LocalGroupMember``.
Linux:   reads ``/etc/passwd`` and ``/etc/group``.
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.collectors.base import Collector, get_platform, safe_run

logger = logging.getLogger(__name__)


class AccountsCollector(Collector):
    name = "accounts"
    supported_platforms = ["windows", "linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            current = get_platform()
            if current == "windows":
                return self._collect_windows()
            return self._collect_linux()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Accounts collector error: %s", exc)
            return {"accounts": {"error": str(exc)}}

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
                        '"Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json"'
                    ),
                },
                {
                    "type": "command",
                    "detail": (
                        "powershell -NoProfile -Command "
                        "\"Get-LocalGroupMember -Group 'Administrators' "
                        '| Select-Object Name, ObjectClass | ConvertTo-Json"'
                    ),
                },
            ]
        return [
            {"type": "file_read", "detail": "/etc/passwd"},
            {"type": "file_read", "detail": "/etc/group"},
        ]

    def _collect_windows(self) -> dict[str, Any]:
        import json

        facts: dict[str, Any] = {}

        # --- Guest account ---
        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-LocalUser -Name Guest | Select-Object Name, Enabled | ConvertTo-Json",
            ]
        )
        if rc == 0:
            try:
                guest = json.loads(stdout)
                facts["guest_enabled"] = bool(guest.get("Enabled", False))
            except json.JSONDecodeError:
                facts["guest_enabled"] = None
        else:
            facts["guest_enabled"] = None

        # --- Admin group ---
        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-LocalGroupMember -Group 'Administrators' "
                    "| Select-Object Name, ObjectClass | ConvertTo-Json"
                ),
            ]
        )
        if rc == 0:
            try:
                data = json.loads(stdout)
                if isinstance(data, dict):
                    data = [data]
                admin_names = [str(m.get("Name", "")) for m in data]
                facts["admin_count"] = len(admin_names)
                facts["admin_users"] = admin_names
            except json.JSONDecodeError:
                facts["admin_count"] = None
                facts["admin_users"] = []
        else:
            facts["admin_count"] = None
            facts["admin_users"] = []

        parts = []
        if facts.get("guest_enabled") is not None:
            parts.append(f"Guest: {'enabled' if facts['guest_enabled'] else 'disabled'}")
        if facts.get("admin_count") is not None:
            parts.append(f"Admin accounts: {facts['admin_count']}")
        facts["detail"] = "; ".join(parts) if parts else "Partial data collected."

        return {"accounts": facts}

    def _collect_linux(self) -> dict[str, Any]:
        facts: dict[str, Any] = {}

        # --- Guest account (rare on Linux) ---
        try:
            with open("/etc/passwd", encoding="utf-8") as fh:
                passwd_lines = fh.readlines()
        except OSError:
            return {"accounts": {"error": "Cannot read /etc/passwd."}}

        # Count real users (UID >= 1000 or 0) and check for guest
        users = []
        guest_found = False
        for line in passwd_lines:
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            username = parts[0]
            try:
                uid = int(parts[2])
            except ValueError:
                continue
            shell = parts[6]
            # Skip system accounts with nologin/false shells, except root
            if uid == 0 or (uid >= 1000 and "/nologin" not in shell and "/false" not in shell):
                users.append(username)
            if username.lower() == "guest":
                guest_found = True

        facts["guest_enabled"] = guest_found
        facts["total_users"] = len(users)

        # --- Admin (sudo/wheel) group ---
        try:
            with open("/etc/group", encoding="utf-8") as fh:
                group_lines = fh.readlines()
        except OSError:
            facts["admin_count"] = None
            facts["admin_users"] = []
            facts["detail"] = "Cannot read /etc/group."
            return {"accounts": facts}

        admin_users: list[str] = []
        for line in group_lines:
            parts = line.strip().split(":")
            if len(parts) < 4:
                continue
            group_name = parts[0]
            if group_name in ("sudo", "wheel", "admin"):
                members = [m for m in parts[3].split(",") if m.strip()]
                admin_users.extend(members)

        # Deduplicate
        admin_users = sorted(set(admin_users))
        facts["admin_count"] = len(admin_users)
        facts["admin_users"] = admin_users
        facts["detail"] = (
            f"Guest: {'found' if guest_found else 'not found'}; "
            f"sudo/wheel members: {len(admin_users)}"
        )

        return {"accounts": facts}
