"""SSH server configuration collector.  Linux only.

Reads ``/etc/ssh/sshd_config`` (and ``Include`` files) to check
``PermitRootLogin`` and ``PasswordAuthentication``.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shlex
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

        # Parse config. Without a readable main config or included file we know nothing.
        config = self._parse_sshd_config()
        if config is None:
            return {"ssh": {"error": "Cannot read /etc/ssh/sshd_config or included file."}}

        # If a Match block may override a directive, report None (unknown) rather than
        # giving a false pass/fail.
        raw_permit_root = config.get("permitrootlogin", _DEFAULTS["PermitRootLogin"])
        permit_root: str | None = None if raw_permit_root is None else str(raw_permit_root).lower()

        raw_pw_auth = config.get("passwordauthentication", _DEFAULTS["PasswordAuthentication"])
        if raw_pw_auth is None:
            password_auth_str = "unknown"  # noqa: S105
            password_auth_enabled: bool | None = None
        else:
            password_auth_str = str(raw_pw_auth).lower()
            password_auth_enabled = password_auth_str != "no"  # noqa: S105

        parts = [
            f"sshd: {'active' if service_running else 'inactive'}",
            f"PermitRootLogin: {permit_root or 'unknown (conditional Match)'}",
            f"PasswordAuthentication: {password_auth_str}",
        ]

        return {
            "ssh": {
                "service_running": service_running,
                "permit_root_login": permit_root,
                "password_auth_enabled": password_auth_enabled,
                "detail": "; ".join(parts),
            },
        }

    def _parse_sshd_config(self) -> dict[str, str | None] | None:
        """Parse sshd_config, following ``Include`` and tracking ``Match`` overrides.

        Like sshd, the first value seen for a global directive wins and
        included files are read at the point of the ``Include`` line.
        If a ``Match`` block may override ``PermitRootLogin`` or
        ``PasswordAuthentication``, that directive is marked ``None`` (unknown)
        unless the ``Match`` condition clearly cannot apply (e.g.
        ``Match User <non-root>`` for ``PermitRootLogin``).
        Returns ``None`` if the main config or any matched include cannot be read.
        """
        result: dict[str, str | None] = {}
        state: dict[str, Any] = {"match_spec": None}
        if not self._parse_file(Path("/etc/ssh/sshd_config"), result, state=state):
            return None
        return result

    @staticmethod
    def _match_can_apply_to_root(match_spec: str) -> bool:
        """Return False only when a Match condition clearly excludes root."""
        tokens = match_spec.strip().split()
        # Handle simple "User <pattern>" criteria
        if len(tokens) >= 2 and tokens[0].lower() == "user":
            user_list = tokens[1].split(",")
            # If none of the patterns is root or a wildcard/negation, root is excluded
            if not any(
                u in ("root", "*") or "*" in u or "?" in u or u.startswith("!") for u in user_list
            ):
                return False
        return True

    @classmethod
    def _parse_file(
        cls,
        path: Path,
        result: dict[str, str | None],
        depth: int = 0,
        state: dict[str, Any] | None = None,
    ) -> bool:
        """Parse one config file into *result*.  Returns False if unreadable."""
        if state is None:
            state = {"match_spec": None}

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
            directive = parts[0].lower()
            raw_value = parts[1].strip()

            if directive == "match":
                state["match_spec"] = raw_value
                continue

            if directive == "include" and depth < 8:
                try:
                    patterns = shlex.split(raw_value)
                except ValueError:
                    patterns = raw_value.split()
                for pattern in patterns:
                    # Relative patterns are relative to /etc/ssh
                    full = os.path.join("/etc/ssh", pattern)
                    for included in sorted(glob.glob(full)):
                        if not cls._parse_file(Path(included), result, depth + 1, state=state):
                            return False
                continue

            value = raw_value.strip('"')
            if state["match_spec"] is not None:
                if directive == "permitrootlogin" and cls._match_can_apply_to_root(
                    state["match_spec"]
                ):
                    result["permitrootlogin"] = None
                elif directive == "passwordauthentication":
                    result["passwordauthentication"] = None
                continue

            result.setdefault(directive, value)
        return True
