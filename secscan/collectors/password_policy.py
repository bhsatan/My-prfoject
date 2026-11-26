"""Password and lockout policy collector.

Windows: uses ``net accounts``.
Linux:   reads ``/etc/login.defs`` and PAM config files.
"""

from __future__ import annotations

import contextlib
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
            {"type": "file_read", "detail": "/etc/login.defs"},
            {"type": "file_read", "detail": "/etc/pam.d/common-password"},
            {"type": "file_read", "detail": "/etc/pam.d/system-auth"},
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
        facts: dict[str, Any] = {}

        # --- /etc/login.defs ---
        try:
            with open("/etc/login.defs", encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    parts = stripped.split()
                    if len(parts) >= 2 and parts[0] == "PASS_MIN_LEN":
                        with contextlib.suppress(ValueError):
                            facts["min_length"] = int(parts[1])
        except OSError:
            pass

        # --- PAM config (pam_pwquality / pam_cracklib for minlen) ---
        pam_paths = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]
        for pam_path in pam_paths:
            try:
                with open(pam_path, encoding="utf-8") as fh:
                    for line in fh:
                        if "pam_pwquality" in line or "pam_cracklib" in line:
                            match = re.search(r"minlen=(\d+)", line)
                            if match:
                                facts["min_length"] = int(match.group(1))
            except OSError:
                continue

        # --- PAM faillock for lockout ---
        pam_auth_paths = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]
        for pam_path in pam_auth_paths:
            try:
                with open(pam_path, encoding="utf-8") as fh:
                    for line in fh:
                        if "pam_faillock" in line or "pam_tally2" in line:
                            match = re.search(r"deny=(\d+)", line)
                            if match:
                                facts["lockout_threshold"] = int(match.group(1))
            except OSError:
                continue

        # Default lockout_threshold to 0 if not found
        facts.setdefault("lockout_threshold", 0)
        # Default min_length if not found anywhere
        facts.setdefault("min_length", 5)  # login.defs default on many distros

        parts = []
        parts.append(f"Min length: {facts['min_length']}")
        val = facts["lockout_threshold"]
        parts.append(f"Lockout: {'not configured' if val == 0 else f'after {val} attempts'}")
        facts["detail"] = "; ".join(parts)

        return {"password_policy": facts}
