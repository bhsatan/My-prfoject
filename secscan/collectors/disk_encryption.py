"""Disk encryption collector.

Windows: uses ``Get-BitLockerVolume`` (requires admin).
Linux:   uses ``lsblk`` and checks ``/etc/crypttab``.
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.collectors.base import Collector, get_platform, safe_run

logger = logging.getLogger(__name__)


class DiskEncryptionCollector(Collector):
    name = "disk_encryption"
    supported_platforms = ["windows", "linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            current = get_platform()
            if current == "windows":
                return self._collect_windows()
            return self._collect_linux()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Disk encryption collector error: %s", exc)
            return {"disk_encryption": {"error": str(exc)}}

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
                        '"Get-BitLockerVolume | Select-Object MountPoint, '
                        'VolumeStatus, ProtectionStatus | ConvertTo-Json"'
                    ),
                },
            ]
        return [
            {"type": "command", "detail": "lsblk -o NAME,TYPE,FSTYPE --json"},
            {"type": "file_read", "detail": "/etc/crypttab"},
        ]

    def _collect_windows(self) -> dict[str, Any]:
        import json

        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, "
                    "ProtectionStatus | ConvertTo-Json"
                ),
            ]
        )
        if rc != 0:
            # Most likely: not admin, or BitLocker not available
            return {
                "disk_encryption": {
                    "os_drive_encrypted": None,
                    "error": "Needs administrator to check BitLocker status.",
                },
            }

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {
                "disk_encryption": {
                    "os_drive_encrypted": None,
                    "error": "Failed to parse BitLocker output.",
                },
            }

        if isinstance(data, dict):
            data = [data]

        # Look for the C: drive (OS drive)
        for vol in data:
            mount = str(vol.get("MountPoint", ""))
            if mount.upper().startswith("C"):
                # ProtectionStatus: 1 = On, 0 = Off
                protected = vol.get("ProtectionStatus", 0) == 1
                status_text = vol.get("VolumeStatus", "Unknown")
                return {
                    "disk_encryption": {
                        "os_drive_encrypted": protected,
                        "detail": f"BitLocker on C: — status: {status_text}, "
                        f"protection: {'On' if protected else 'Off'}",
                    },
                }

        return {
            "disk_encryption": {
                "os_drive_encrypted": None,
                "error": "Could not find C: drive in BitLocker output.",
            },
        }

    def _collect_linux(self) -> dict[str, Any]:
        import json

        # Check lsblk for crypto_LUKS
        stdout, _, rc = safe_run(["lsblk", "-o", "NAME,TYPE,FSTYPE", "--json"])
        if rc == 0:
            try:
                data = json.loads(stdout)
                if self._has_luks(data.get("blockdevices", [])):
                    return {
                        "disk_encryption": {
                            "os_drive_encrypted": True,
                            "detail": "LUKS encryption detected via lsblk.",
                        },
                    }
            except json.JSONDecodeError:
                pass

        # Fallback: check /etc/crypttab
        try:
            with open("/etc/crypttab", encoding="utf-8") as fh:
                content = fh.read().strip()
                # Non-empty crypttab with non-comment lines indicates encryption
                active_lines = [
                    line
                    for line in content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                if active_lines:
                    return {
                        "disk_encryption": {
                            "os_drive_encrypted": True,
                            "detail": "Encryption entries found in /etc/crypttab.",
                        },
                    }
        except OSError:
            pass

        return {
            "disk_encryption": {
                "os_drive_encrypted": False,
                "detail": "No disk encryption detected (checked lsblk and /etc/crypttab).",
            },
        }

    def _has_luks(self, devices: list[dict]) -> bool:
        """Recursively check lsblk output for crypto_LUKS filesystem type."""
        for dev in devices:
            if str(dev.get("fstype", "")).lower() == "crypto_luks":
                return True
            children = dev.get("children", [])
            if children and self._has_luks(children):
                return True
        return False
