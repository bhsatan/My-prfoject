"""Listening ports collector.

Windows: uses ``Get-NetTCPConnection -State Listen``.
Linux:   uses ``ss -tlnp``.

Flags well-known risky ports bound to all interfaces (0.0.0.0 / ::).
"""

from __future__ import annotations

import logging
from typing import Any

from secscan.collectors.base import Collector, get_platform, safe_run

logger = logging.getLogger(__name__)

# Ports that are common attack targets when exposed on all interfaces
_RISKY_PORTS: frozenset[int] = frozenset(
    {
        21,  # FTP
        23,  # Telnet
        445,  # SMB
        3389,  # RDP
        5900,  # VNC
        5901,
        5902,
        5903,
        5904,
        5905,
    }
)

_ALL_INTERFACES = frozenset({"0.0.0.0", "::", "[::]"})  # noqa: S104


class NetworkCollector(Collector):
    name = "network"
    supported_platforms = ["windows", "linux"]

    def get_facts(self) -> dict[str, Any]:
        try:
            current = get_platform()
            if current == "windows":
                return self._collect_windows()
            return self._collect_linux()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Network collector error: %s", exc)
            return {"network": {"error": str(exc)}}

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
                        '"Get-NetTCPConnection -State Listen '
                        "| Select-Object LocalAddress, LocalPort, OwningProcess "
                        '| ConvertTo-Json"'
                    ),
                },
            ]
        return [{"type": "command", "detail": "ss -tlnp"}]

    def _collect_windows(self) -> dict[str, Any]:
        import json

        stdout, stderr, rc = safe_run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-NetTCPConnection -State Listen "
                    "| Select-Object LocalAddress, LocalPort, OwningProcess "
                    "| ConvertTo-Json"
                ),
            ]
        )
        if rc != 0:
            return {"network": {"error": f"PowerShell failed: {stderr.strip()}"}}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"network": {"error": "Failed to parse network output."}}

        if isinstance(data, dict):
            data = [data]

        return self._build_facts(data, addr_key="LocalAddress", port_key="LocalPort")

    def _collect_linux(self) -> dict[str, Any]:
        stdout, _, rc = safe_run(["ss", "-tlnp"])
        if rc != 0:
            return {"network": {"error": "ss command failed."}}

        entries: list[dict[str, Any]] = []
        for line in stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[3]
            # Format: address:port or [::]:port
            addr, _, port_str = local.rpartition(":")
            try:
                port = int(port_str)
            except ValueError:
                continue
            # Clean up addr
            addr = addr.strip("[]")
            entries.append({"LocalAddress": addr, "LocalPort": port})

        return self._build_facts(entries, addr_key="LocalAddress", port_key="LocalPort")

    def _build_facts(
        self,
        entries: list[dict[str, Any]],
        *,
        addr_key: str,
        port_key: str,
    ) -> dict[str, Any]:
        """Common fact-building logic for both platforms."""
        listening: list[dict[str, Any]] = []
        risky_exposed: list[int] = []

        for entry in entries:
            addr = str(entry.get(addr_key, ""))
            port = int(entry.get(port_key, 0))
            listening.append({"address": addr, "port": port})

            if addr in _ALL_INTERFACES and port in _RISKY_PORTS and port not in risky_exposed:
                risky_exposed.append(port)

        has_risky = len(risky_exposed) > 0
        if risky_exposed:
            detail = f"Risky ports on all interfaces: {', '.join(map(str, sorted(risky_exposed)))}"
        else:
            detail = f"{len(listening)} port(s) listening; none are risky on all interfaces."

        return {
            "network": {
                "listening_ports": listening,
                "risky_ports_exposed": sorted(risky_exposed),
                "has_risky_ports": has_risky,
                "detail": detail,
            },
        }
