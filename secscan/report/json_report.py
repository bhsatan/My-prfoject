"""JSON report — machine-readable scan output (Schema v1.0)."""

from __future__ import annotations

import contextlib
import json
import os
import platform as _platform
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscan import __version__
from secscan.scorer.scorer import ScoreResult

SCHEMA_VERSION = "1.0"

_RULE_PREFIX_TO_CATEGORY: dict[str, str] = {
    "FW": "firewall",
    "DISK": "disk_encryption",
    "AV": "antivirus",
    "NET": "network",
    "ACCT": "accounts",
    "PWD": "password_policy",
    "SSH": "ssh",
    "RDP": "remote_access",
    "SMB": "remote_access",
    "AUTO": "autologin",
}


def _category_for_rule(rule_id: str) -> str:
    prefix = rule_id.split("-", 1)[0].upper()
    return _RULE_PREFIX_TO_CATEGORY.get(prefix, "other")


def _detect_os_name() -> str:
    system = _platform.system().lower()
    if system in ("windows", "linux"):
        return system
    return "linux"


def render_json(
    result: ScoreResult,
    *,
    output_path: Path | None = None,
    platform_name: str | None = None,
    scan_id: str | None = None,
) -> str:
    """Render the scan results to a Schema v1.0 JSON string.

    Args:
        result: The scored scan result.
        output_path: If provided, write the JSON to this file path with
            owner-only permissions (``0o600`` on POSIX).
        platform_name: ``"windows"`` or ``"linux"`` (auto-detected if omitted).
        scan_id: Optional explicit scan ID (generated if omitted).

    Returns:
        The JSON string.
    """
    now = datetime.now(tz=UTC)
    resolved_os = platform_name if platform_name in ("windows", "linux") else _detect_os_name()
    resolved_id = scan_id or f"{now.strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"

    not_checked = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "reason": f.detail,
        }
        for f in result.findings
        if f.status == "unknown"
    ]

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": resolved_id,
        "scan_time": now.isoformat(),
        "os": resolved_os,
        "tool_version": __version__,
        "score": result.score,
        "grade": result.grade,
        "summary": {
            "total_checks": result.total_checks,
            "passed": result.passed,
            "failed": result.failed,
            "unknown": result.unknown,
        },
        "severity_summary": result.summary_by_severity,
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": _category_for_rule(f.rule_id),
                "title": f.title,
                "status": f.status,
                "severity": f.severity,
                "detail": f.detail,
                "why_it_matters": f.why_it_matters,
                "how_to_fix": f.how_to_fix,
                "difficulty": f.difficulty,
                "source": f.source,
            }
            for f in result.findings
        ],
        "not_checked": not_checked,
    }

    json_str = json.dumps(report, indent=2, ensure_ascii=False)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(output_path, 0o600)

    return json_str
