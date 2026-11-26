"""Password and lockout policy collector.

Windows: uses ``net accounts``.
Linux:   reads PAM config files, pwquality.conf and faillock.conf.
"""

from __future__ import annotations

import glob
import logging
import re
from typing import Any

from secscan.collectors.base import Collector, get_platform, safe_run

logger = logging.getLogger(__name__)


class PasswordPolicyCollector(Collector):
    name = "password_policy"
    supported_platforms = ["windows", "linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            current = get_platform()
            if current == "windows":
                return self._collect_windows()
            return self._collect_linux()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Password policy collector error: %s", exc)
            return {"password_policy": {"error": str(exc)}}

    def get_dry_run_info(self) -> list[dict[str, str]]:
        try:
            current = get_platform()
        except RuntimeError:
            return []
        if current == "windows":
            return [{"type": "command", "detail": "net accounts"}]
        return [
            {"type": "file_read", "detail": "/etc/pam.d/common-password"},
            {"type": "file_read", "detail": "/etc/pam.d/system-auth"},
            {"type": "file_read", "detail": "/etc/pam.d/common-auth"},
            {"type": "file_read", "detail": "/etc/security/pwquality.conf"},
            {"type": "file_read", "detail": "/etc/security/pwquality.conf.d/*.conf"},
            {"type": "file_read", "detail": "/etc/security/faillock.conf"},
        ]

    def _collect_windows(self) -> dict[str, Any]:
        stdout, stderr, rc = safe_run(["net", "accounts"])
        if rc != 0:
            return {"password_policy": {"error": f"net accounts failed: {stderr.strip()}"}}

        facts: dict[str, Any] = {}

        # Parse "Minimum password length" line
        for line in stdout.splitlines():
            lower = line.lower().strip()
            if "minimum password length" in lower:
                match = re.search(r"(\d+)", line)
                if match:
                    facts["min_length"] = int(match.group(1))
            elif "lockout threshold" in lower:
                match = re.search(r"(\d+|never)", line, re.IGNORECASE)
                if match:
                    val = match.group(1)
                    facts["lockout_threshold"] = 0 if val.lower() == "never" else int(val)

        parts = []
        if "min_length" in facts:
            parts.append(f"Min length: {facts['min_length']}")
        if "lockout_threshold" in facts:
            val = facts["lockout_threshold"]
            parts.append(f"Lockout: {'off' if val == 0 else f'after {val} attempts'}")
        facts["detail"] = "; ".join(parts) if parts else "Could not parse net accounts output."

        return {"password_policy": facts}

    def _collect_linux(self) -> dict[str, Any]:
        password = self._pam_lines(
            ("/etc/pam.d/common-password", "/etc/pam.d/system-auth"), "password"
        )
        auth = self._pam_lines(("/etc/pam.d/common-auth", "/etc/pam.d/system-auth"), "auth")

        # None means "could not determine" and is reported as unknown
        min_length = None if password is None else self._min_length(password)
        threshold = None if auth is None else self._lockout_threshold(auth)

        lockout = {None: "unknown", 0: "not configured"}.get(
            threshold, f"after {threshold} attempts"
        )
        length = "unknown" if min_length is None else min_length

        return {
            "password_policy": {
                "min_length": min_length,
                "lockout_threshold": threshold,
                "detail": f"Min length: {length}; Lockout: {lockout}",
            },
        }

    @staticmethod
    def _pam_lines(paths: tuple[str, ...], kind: str) -> list[str] | None:
        """Active (uncommented) PAM lines of one type, or None if unreadable."""
        lines: list[str] = []
        readable = False
        for path in paths:
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        text = line.split("#", 1)[0].strip()
                        if text.lstrip("-").startswith(kind):
                            lines.append(text)
                readable = True
            except OSError:
                continue
        return lines if readable else None

    def _min_length(self, lines: list[str]) -> int:
        # Module name -> its built-in default minimum length
        for module, default in (("pam_pwquality", 8), ("pam_cracklib", 9), ("pam_unix", 6)):
            matching = [line for line in lines if module in line]
            if not matching:
                continue
            # A module argument overrides the config file
            for line in matching:
                if match := re.search(r"\bminlen=(\d+)", line):
                    return int(match.group(1))
            if module == "pam_pwquality":
                configured = self._read_setting(
                    ["/etc/security/pwquality.conf"]
                    + sorted(glob.glob("/etc/security/pwquality.conf.d/*.conf")),
                    "minlen",
                )
                return default if configured is None else configured
            return default
        return 0

    def _lockout_threshold(self, lines: list[str]) -> int:
        # pam_faillock only counts failures if an "authfail" line is present
        faillock = [line for line in lines if "pam_faillock" in line]
        if any("authfail" in line for line in faillock):
            for line in faillock:
                if match := re.search(r"\bdeny=(\d+)", line):
                    return int(match.group(1))
            configured = self._read_setting(["/etc/security/faillock.conf"], "deny")
            return 3 if configured is None else configured

        for line in lines:
            if "pam_tally2" in line and (match := re.search(r"\bdeny=(\d+)", line)):
                return int(match.group(1))
        return 0

    @staticmethod
    def _read_setting(paths: list[str], key: str) -> int | None:
        """Last integer value of ``key = N`` across the given config files."""
        value = None
        for path in paths:
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        if match := re.match(rf"\s*{key}\s*=\s*(\d+)", line):
                            value = int(match.group(1))
            except OSError:
                continue
        return value
