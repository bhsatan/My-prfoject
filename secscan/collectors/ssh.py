"""SSH server configuration collector.  Linux only.

Reads ``/etc/ssh/sshd_config`` (and drop-in overrides in
``/etc/ssh/sshd_config.d/``) to check ``PermitRootLogin`` and
``PasswordAuthentication``.
"""

from __future__ import annotations

import glob
import logging
import os
import re
from pathlib import Path
from typing import Any

from secscan.collectors.base import Collector, safe_run

logger = logging.getLogger(__name__)

# OpenSSH defaults (used when a directive is absent)
_DEFAULTS: dict[str, str] = {
    "PermitRootLogin": "prohibit-password",
    "PasswordAuthentication": "yes",
}


class SSHCollector(Collector):
    name = "ssh"
    supported_platforms = ["linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            return self._collect()
        except Exception as exc:  # noqa: BLE001
            logger.warning("SSH collector error: %s", exc)
            return {"ssh": {"error": str(exc)}}

    def get_dry_run_info(self) -> list[dict[str, str]]:
        return [
            {"type": "file_read", "detail": "/etc/ssh/sshd_config"},
            {"type": "file_read", "detail": "/etc/ssh/sshd_config.d/*.conf"},
            {"type": "command", "detail": "systemctl is-active sshd"},
            {"type": "command", "detail": "systemctl is-active ssh"},
        ]

    def _collect(self) -> dict[str, Any]:
        # Check if sshd is running
        service_running = False
        for svc in ("sshd", "ssh"):
            stdout, _, rc = safe_run(["systemctl", "is-active", svc])
            if rc == 0 and "active" in stdout.strip().lower():
                service_running = True
                break

        # Parse config. Without a readable main config we know nothing.
        config = self._parse_sshd_config()
        if config is None:
            return {"ssh": {"error": "Cannot read /etc/ssh/sshd_config (is sshd installed?)."}}

        permit_root = config.get(
            "permitrootlogin",
            _DEFAULTS["PermitRootLogin"],
        ).lower()
        password_auth_str = config.get(
            "passwordauthentication",
            _DEFAULTS["PasswordAuthentication"],
        ).lower()
        password_auth_enabled = password_auth_str != "no"  # noqa: S105

        parts = []
        parts.append(f"sshd: {'active' if service_running else 'inactive'}")
        parts.append(f"PermitRootLogin: {permit_root}")
        parts.append(f"PasswordAuthentication: {password_auth_str}")

        return {
            "ssh": {
                "service_running": service_running,
                "permit_root_login": permit_root,
                "password_auth_enabled": password_auth_enabled,
                "detail": "; ".join(parts),
            },
        }

    def _parse_sshd_config(self) -> dict[str, str] | None:
        """Parse the global section of sshd_config, following ``Include``.

        Like sshd, the first value seen for a directive wins and included
        files are read at the point of the ``Include`` line.  ``Match`` blocks
        are ignored.  Returns ``None`` if the main config cannot be read.
        """
        result: dict[str, str] = {}
        if not self._parse_file(Path("/etc/ssh/sshd_config"), result):
            return None
        return result

    @classmethod
    def _parse_file(cls, path: Path, result: dict[str, str], depth: int = 0) -> bool:
        """Parse one config file into *result*.  Returns False if unreadable."""
        try:
            with open(path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.debug("Cannot read %s: %s", path, exc)
            return False

        for line in lines:
            # Directives are "Key value" or "Key=value"
            parts = re.split(r"[ \t=]+", line.strip(), maxsplit=1)
            if len(parts) != 2 or parts[0].startswith("#"):
                continue
            directive, value = parts[0].lower(), parts[1].strip().strip('"')
            if directive == "match":
                break
            if directive == "include" and depth < 8:
                for pattern in value.split():
                    # Relative patterns are relative to /etc/ssh
                    full = os.path.join("/etc/ssh", pattern.strip('"'))
                    for included in sorted(glob.glob(full)):
                        cls._parse_file(Path(included), result, depth + 1)
                continue
            result.setdefault(directive, value)
        return True
