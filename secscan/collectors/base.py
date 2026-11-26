"""Collector base class and shared utilities.

Every collector inherits from :class:`Collector` and implements:
- ``get_facts()``      → dict of collected facts (never raises)
- ``get_dry_run_info()`` → list of commands/files that would be accessed

Shared helpers:
- ``get_platform()``    → ``"windows"`` or ``"linux"``
- ``safe_run()``        → run a subprocess safely with argument lists
"""

from __future__ import annotations

import logging
import platform
import subprocess
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def get_platform() -> str:
    """Return the current platform as ``'windows'`` or ``'linux'``.

    Raises:
        RuntimeError: If the platform is not Windows or Linux.
    """
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    msg = f"Unsupported platform: {system}"
    raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# Safe subprocess execution
# ---------------------------------------------------------------------------


def safe_run(
    args: list[str],
    *,
    timeout: int = 30,
) -> tuple[str, str, int]:
    """Run a command safely using an argument list (never ``shell=True``).

    Args:
        args: Command and arguments as a list (e.g. ``["net", "accounts"]``).
        timeout: Seconds before the subprocess is killed.

    Returns:
        ``(stdout, stderr, returncode)`` — always returns, never raises.
        On error (command not found, timeout, etc.) returns
        ``("", "<error message>", -1)``.
    """
    try:
        result = subprocess.run(  # noqa: S603
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"Command not found: {args[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s: {' '.join(args)}", -1
    except OSError as exc:
        return "", f"OS error running {args[0]}: {exc}", -1


# ---------------------------------------------------------------------------
# Collector ABC
# ---------------------------------------------------------------------------


class Collector(ABC):
    """Base class for all read-only fact-gathering collectors.

    Subclasses must set ``name`` and ``supported_platforms``, and implement
    ``get_facts()`` and ``get_dry_run_info()``.

    **Hard rules for every collector:**

    - **Read-only**: never modify system state.
    - **No network**: never open connections.
    - **No shell=True**: use argument lists via :func:`safe_run`.
    - **Never crash**: catch all exceptions and return ``{"error": "..."}``
      for failed sub-checks.
    - **No admin assumption**: if a check needs elevation, return an error
      fact gracefully.
    """

    name: str
    """Collector name — must match the ``collector`` field in rule YAML files."""

    supported_platforms: list[str]
    """Platforms this collector supports: ``["windows"]``, ``["linux"]``, or both."""

    @abstractmethod
    def get_facts(self) -> dict[str, Any]:
        """Collect and return facts as a dictionary.

        **Must never raise.** Catch all exceptions internally and return
        ``{"error": "<description>"}`` for failed sub-checks.
        """
        ...

    @abstractmethod
    def get_dry_run_info(self) -> list[dict[str, str]]:
        """Return a list of items describing what would be accessed.

        Each item is a dict like::

            {"type": "command", "detail": "Get-NetFirewallProfile ..."}
            {"type": "file_read", "detail": "/etc/ssh/sshd_config"}
            {"type": "registry_read", "detail": "HKLM:\\\\...\\\\fDenyTSConnections"}
        """
        ...

    def is_supported(self, current_platform: str) -> bool:
        """Check whether this collector runs on the given platform."""
        return current_platform in self.supported_platforms
