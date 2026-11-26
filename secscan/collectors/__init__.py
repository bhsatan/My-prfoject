"""Read-only fact-gathering collectors.

Each collector module exposes a single class inheriting from
:class:`~secscan.collectors.base.Collector`.  Use :func:`get_all_collectors`
to get an instance of every registered collector.
"""

from __future__ import annotations

from secscan.collectors.accounts import AccountsCollector
from secscan.collectors.antivirus import AntivirusCollector
from secscan.collectors.autologin import AutologinCollector
from secscan.collectors.base import Collector
from secscan.collectors.disk_encryption import DiskEncryptionCollector
from secscan.collectors.firewall import FirewallCollector
from secscan.collectors.network import NetworkCollector
from secscan.collectors.password_policy import PasswordPolicyCollector
from secscan.collectors.remote_access import RemoteAccessCollector
from secscan.collectors.ssh import SSHCollector


def get_all_collectors() -> list[Collector]:
    """Return one instance of every registered collector."""
    return [
        FirewallCollector(),
        DiskEncryptionCollector(),
        AntivirusCollector(),
        NetworkCollector(),
        AccountsCollector(),
        PasswordPolicyCollector(),
        SSHCollector(),
        RemoteAccessCollector(),
        AutologinCollector(),
    ]


__all__ = [
    "AccountsCollector",
    "AntivirusCollector",
    "AutologinCollector",
    "Collector",
    "DiskEncryptionCollector",
    "FirewallCollector",
    "NetworkCollector",
    "PasswordPolicyCollector",
    "RemoteAccessCollector",
    "SSHCollector",
    "get_all_collectors",
]
