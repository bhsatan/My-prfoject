"""SSH server configuration collector.  Linux only.

Reads ``/etc/ssh/sshd_config`` (and drop-in overrides in
``/etc/ssh/sshd_config.d/``) to check ``PermitRootLogin`` and
``PasswordAuthentication``.
"""

from __future__ import annotations

import logging
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

        # Parse config
        config = self._parse_sshd_config()

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

    def _parse_sshd_config(self) -> dict[str, str]:
        """Parse sshd_config and drop-in overrides.

        Returns a dict of ``{directive_lowercase: last_value}``.
        Later files and later lines override earlier ones (matching sshd
        behaviour for most directives — ``Match`` blocks are ignored for
        simplicity in v0.1).
        """
        result: dict[str, str] = {}

        # Main config
        self._parse_file(Path("/etc/ssh/sshd_config"), result)

        # Drop-in overrides
        drop_in_dir = Path("/etc/ssh/sshd_config.d")
        if drop_in_dir.is_dir():
            for conf in sorted(drop_in_dir.glob("*.conf")):
                self._parse_file(conf, result)

        return result

    @staticmethod
    def _parse_file(path: Path, result: dict[str, str]) -> None:
        """Parse a single sshd config file into *result*."""
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    # Lines are "Directive value" (space or tab separated)
                    parts = stripped.split(None, 1)
                    if len(parts) == 2:
                        directive, value = parts
                        result[directive.lower()] = value
        except OSError as exc:
            logger.debug("Cannot read %s: %s", path, exc)
