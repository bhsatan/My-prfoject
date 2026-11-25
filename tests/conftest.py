"""Shared test fixtures and mock fact factories.

All tests use mocked facts — they never touch the real operating system.
Fixtures here provide reusable building blocks for engine and scorer tests.
"""

from __future__ import annotations

import pytest

from secscan.engine.models import Finding, Rule

# ---------------------------------------------------------------------------
# Mock fact dictionaries
# ---------------------------------------------------------------------------


@pytest.fixture()
def all_pass_facts_windows() -> dict[str, dict]:
    """Facts where every Windows rule should pass."""
    return {
        "firewall": {
            "all_profiles_enabled": True,
            "profiles": [
                {"name": "Domain", "enabled": True},
                {"name": "Private", "enabled": True},
                {"name": "Public", "enabled": True},
            ],
        },
        "disk_encryption": {
            "os_drive_encrypted": True,
            "detail": "BitLocker: FullyEncrypted on C:",
        },
        "antivirus": {
            "real_time_enabled": True,
            "engine_running": True,
            "signature_age_days": 1,
        },
        "network": {
            "listening_ports": [
                {"address": "127.0.0.1", "port": 5432, "pid": 1234},
            ],
            "risky_ports_exposed": [],
            "has_risky_ports": False,
        },
        "accounts": {
            "guest_enabled": False,
            "admin_count": 1,
            "admin_users": ["admin"],
            "total_users": 3,
        },
        "password_policy": {
            "min_length": 12,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 30,
            "max_age_days": 90,
        },
        "remote_access": {
            "rdp_enabled": False,
            "rdp_nla_required": True,
            "smb1_enabled": False,
        },
        "autologin": {
            "enabled": False,
        },
    }


@pytest.fixture()
def all_pass_facts_linux() -> dict[str, dict]:
    """Facts where every Linux rule should pass."""
    return {
        "firewall": {
            "all_profiles_enabled": True,
            "backend": "ufw",
        },
        "disk_encryption": {
            "os_drive_encrypted": True,
            "detail": "LUKS encryption detected",
        },
        "network": {
            "listening_ports": [
                {"address": "127.0.0.1", "port": 5432, "pid": 1234},
            ],
            "risky_ports_exposed": [],
            "has_risky_ports": False,
        },
        "accounts": {
            "admin_count": 1,
            "admin_users": ["admin"],
            "total_users": 3,
        },
        "password_policy": {
            "min_length": 12,
            "lockout_threshold": 5,
        },
        "ssh": {
            "service_running": True,
            "permit_root_login": "no",
            "password_auth_enabled": False,
        },
        "autologin": {
            "enabled": False,
        },
    }


@pytest.fixture()
def all_fail_facts_windows() -> dict[str, dict]:
    """Facts where every Windows rule should fail."""
    return {
        "firewall": {
            "all_profiles_enabled": False,
        },
        "disk_encryption": {
            "os_drive_encrypted": False,
        },
        "antivirus": {
            "real_time_enabled": False,
        },
        "network": {
            "listening_ports": [
                {"address": "0.0.0.0", "port": 445, "pid": 4},  # noqa: S104
            ],
            "risky_ports_exposed": [445],
            "has_risky_ports": True,
        },
        "accounts": {
            "guest_enabled": True,
            "admin_count": 5,
            "admin_users": ["a", "b", "c", "d", "e"],
        },
        "password_policy": {
            "min_length": 4,
            "lockout_threshold": 0,
        },
        "remote_access": {
            "rdp_enabled": True,
            "rdp_nla_required": False,
            "smb1_enabled": True,
        },
        "autologin": {
            "enabled": True,
        },
    }


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def make_rule(
    *,
    rule_id: str = "TEST-001",
    title: str = "Test rule",
    severity: str = "high",
    applies_to: list[str] | None = None,
    collector: str = "test_collector",
    fact_path: str = "test_collector.some_fact",
    condition: dict | None = None,
    why_it_matters: str = "This is a test rule.",
    how_to_fix: dict[str, list[str]] | None = None,
    difficulty: str = "easy",
    source: str = "https://example.com/test",
) -> Rule:
    """Create a Rule with sensible defaults for testing."""
    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        applies_to=applies_to or ["windows", "linux"],
        collector=collector,
        fact_path=fact_path,
        condition=condition or {"operator": "equals", "expected": True},
        why_it_matters=why_it_matters,
        how_to_fix=how_to_fix
        or {
            "windows": ["Fix step 1 for Windows."],
            "linux": ["Fix step 1 for Linux."],
        },
        difficulty=difficulty,
        source=source,
    )


def make_finding(
    *,
    rule_id: str = "TEST-001",
    title: str = "Test finding",
    status: str = "pass",
    severity: str = "high",
    why_it_matters: str = "This is a test finding.",
    how_to_fix: list[str] | None = None,
    difficulty: str = "easy",
    source: str = "https://example.com/test",
    detail: str = "Check passed.",
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        rule_id=rule_id,
        title=title,
        status=status,
        severity=severity,
        why_it_matters=why_it_matters,
        how_to_fix=how_to_fix or ["Fix step 1."],
        difficulty=difficulty,
        source=source,
        detail=detail,
    )
