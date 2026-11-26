"""Report JSON Schema v1 validation and safe file loading.

Handles untrusted/hostile report files defensively:
- Rejects files larger than MAX_REPORT_BYTES (5 MiB) before parsing.
- Rejects JSON nested deeper than MAX_JSON_DEPTH (16).
- Rejects symlinks or paths resolving outside ``reports_dir``.
- Rejects legacy unversioned v0.1 reports with a plain-English message.
- Validates all required fields, types, and enums strictly.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 5 * 1024 * 1024  # 5 MiB
MAX_JSON_DEPTH = 16

SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
SCHEMA_VERSION_RE = re.compile(r"^1\.(\d+)$")

VALID_OS = frozenset({"windows", "linux"})
VALID_GRADES = frozenset({"A", "B", "C", "D", "F"})
VALID_STATUSES = frozenset({"pass", "fail", "unknown"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_DIFFICULTIES = frozenset({"easy", "medium", "hard"})

_REQUIRED_TOP_KEYS = frozenset(
    {
        "schema_version",
        "scan_id",
        "scan_time",
        "os",
        "tool_version",
        "score",
        "grade",
        "summary",
        "severity_summary",
        "findings",
        "not_checked",
    }
)

_REQUIRED_FINDING_KEYS = frozenset(
    {
        "rule_id",
        "category",
        "title",
        "status",
        "severity",
        "detail",
        "why_it_matters",
        "how_to_fix",
        "difficulty",
        "source",
    }
)


class ReportValidationError(Exception):
    """Raised when a report file fails validation."""


class LegacyReportError(ReportValidationError):
    """Raised when a v0.1 unversioned report is encountered."""


@dataclass(frozen=True)
class FindingRecord:
    """Validated finding entry from a v1 report."""

    rule_id: str
    category: str
    title: str
    status: str
    severity: str
    detail: str
    why_it_matters: str
    how_to_fix: list[str]
    difficulty: str
    source: str


@dataclass(frozen=True)
class NotCheckedRecord:
    """Validated not-checked entry from a v1 report."""

    rule_id: str
    title: str
    reason: str


@dataclass(frozen=True)
class ScanReport:
    """Validated v1 scan report."""

    schema_version: str
    scan_id: str
    scan_time: datetime
    scan_time_iso: str
    os: str
    tool_version: str
    score: int
    grade: str
    summary: dict[str, int]
    severity_summary: dict[str, dict[str, int]]
    findings: list[FindingRecord]
    not_checked: list[NotCheckedRecord]
    filename: str


def _check_json_depth(obj: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Iteratively verify JSON nesting depth does not exceed *max_depth*."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ReportValidationError(f"JSON nesting exceeds maximum depth ({max_depth}).")
        if isinstance(current, dict):
            for val in current.values():
                if isinstance(val, (dict, list)):
                    stack.append((val, depth + 1))
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))


def _ensure_contained(path: Path, root: Path) -> Path:
    """Ensure *path* is not a symlink escaping *root* and resolves inside *root*."""
    root_real = Path(os.path.realpath(root))
    if path.is_symlink():
        target_real = Path(os.path.realpath(path))
        try:
            target_real.relative_to(root_real)
        except ValueError as exc:
            raise ReportValidationError("Symlink points outside the reports directory.") from exc
    resolved = Path(os.path.realpath(path))
    try:
        resolved.relative_to(root_real)
    except ValueError as exc:
        raise ReportValidationError("Path resolves outside the reports directory.") from exc
    if not resolved.is_file():
        raise ReportValidationError("Report path is not a regular file.")
    return resolved


def _read_bounded_utf8(path: Path, max_bytes: int = MAX_REPORT_BYTES) -> str:
    """Read at most *max_bytes* + 1 bytes and reject oversized files."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ReportValidationError(f"Cannot inspect report file: {type(exc).__name__}.") from exc

    if size > max_bytes:
        raise ReportValidationError(
            f"Report file exceeds maximum allowed size ({max_bytes // (1024 * 1024)} MiB)."
        )

    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError as exc:
        raise ReportValidationError(f"Cannot read report file: {type(exc).__name__}.") from exc

    if len(raw) > max_bytes:
        raise ReportValidationError(
            f"Report file exceeds maximum allowed size ({max_bytes // (1024 * 1024)} MiB)."
        )

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportValidationError("Report file is not valid UTF-8.") from exc


def validate_report_dict(data: Any, *, filename: str = "<memory>") -> ScanReport:
    """Validate a parsed JSON object against Report Schema v1."""
    if not isinstance(data, dict):
        raise ReportValidationError("Report root must be a JSON object.")

    # Detect legacy v0.1 reports before checking required v1 fields
    if "schema_version" not in data:
        if "secscan_version" in data and "findings" in data:
            raise LegacyReportError(
                "Legacy v0.1 report format is not supported by the v0.2 UI; "
                "re-run 'secscan scan --format json' to generate a v1 report."
            )
        raise ReportValidationError("Missing required field: schema_version.")

    schema_version = data["schema_version"]
    if not isinstance(schema_version, str):
        raise ReportValidationError("schema_version must be a string.")
    sv_match = SCHEMA_VERSION_RE.match(schema_version)
    if not sv_match:
        raise ReportValidationError(
            f"Unsupported schema_version '{schema_version}' (expected '1.x')."
        )
    minor_version = int(sv_match.group(1))

    missing = _REQUIRED_TOP_KEYS - set(data.keys())
    if missing:
        raise ReportValidationError(f"Missing required field(s): {', '.join(sorted(missing))}.")

    # For 1.0, reject unknown top-level keys; for 1.x (x > 0), ignore additive keys
    if minor_version == 0:
        extra = set(data.keys()) - _REQUIRED_TOP_KEYS
        if extra:
            raise ReportValidationError(
                f"Unknown field(s) in schema 1.0: {', '.join(sorted(extra))}."
            )

    scan_id = data["scan_id"]
    if not isinstance(scan_id, str) or not SCAN_ID_RE.match(scan_id):
        raise ReportValidationError("Invalid scan_id format.")

    scan_time_raw = data["scan_time"]
    if not isinstance(scan_time_raw, str):
        raise ReportValidationError("scan_time must be an ISO-8601 string.")
    try:
        scan_time = datetime.fromisoformat(scan_time_raw)
    except ValueError as exc:
        raise ReportValidationError("scan_time is not a valid ISO-8601 timestamp.") from exc

    os_name = data["os"]
    if not isinstance(os_name, str) or os_name not in VALID_OS:
        raise ReportValidationError("Invalid os value (expected 'windows' or 'linux').")

    tool_version = data["tool_version"]
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ReportValidationError("tool_version must be a non-empty string.")

    score = data["score"]
    if isinstance(score, bool) or not isinstance(score, int) or not (0 <= score <= 100):
        raise ReportValidationError("score must be an integer between 0 and 100.")

    grade = data["grade"]
    if not isinstance(grade, str) or grade not in VALID_GRADES:
        raise ReportValidationError("Invalid grade value.")

    summary = _validate_summary(data["summary"])
    severity_summary = _validate_severity_summary(data["severity_summary"])
    findings = _validate_findings(data["findings"])
    not_checked = _validate_not_checked(data["not_checked"])

    return ScanReport(
        schema_version=schema_version,
        scan_id=scan_id,
        scan_time=scan_time,
        scan_time_iso=scan_time_raw,
        os=os_name,
        tool_version=tool_version,
        score=score,
        grade=grade,
        summary=summary,
        severity_summary=severity_summary,
        findings=findings,
        not_checked=not_checked,
        filename=filename,
    )


def _validate_summary(summary: Any) -> dict[str, int]:
    if not isinstance(summary, dict):
        raise ReportValidationError("summary must be an object.")
    out: dict[str, int] = {}
    for key in ("total_checks", "passed", "failed", "unknown"):
        val = summary.get(key)
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise ReportValidationError(f"summary.{key} must be a non-negative integer.")
        out[key] = val
    return out


def _validate_severity_summary(sev_summary: Any) -> dict[str, dict[str, int]]:
    if not isinstance(sev_summary, dict):
        raise ReportValidationError("severity_summary must be an object.")
    out: dict[str, dict[str, int]] = {}
    for sev, counts in sev_summary.items():
        if sev not in VALID_SEVERITIES or not isinstance(counts, dict):
            raise ReportValidationError("Invalid severity_summary entry.")
        clean_counts: dict[str, int] = {}
        for status in VALID_STATUSES:
            val = counts.get(status, 0)
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise ReportValidationError(f"severity_summary.{sev}.{status} must be >= 0.")
            clean_counts[status] = val
        out[sev] = clean_counts
    return out


def _validate_findings(findings: Any) -> list[FindingRecord]:
    if not isinstance(findings, list):
        raise ReportValidationError("findings must be a list.")
    records: list[FindingRecord] = []
    for idx, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ReportValidationError(f"findings[{idx}] must be an object.")
        missing = _REQUIRED_FINDING_KEYS - set(item.keys())
        if missing:
            raise ReportValidationError(
                f"findings[{idx}] missing field(s): {', '.join(sorted(missing))}."
            )
        for str_key in (
            "rule_id",
            "category",
            "title",
            "detail",
            "why_it_matters",
            "source",
        ):
            if not isinstance(item[str_key], str):
                raise ReportValidationError(f"findings[{idx}].{str_key} must be a string.")
        if item["status"] not in VALID_STATUSES:
            raise ReportValidationError(f"findings[{idx}].status is invalid.")
        if item["severity"] not in VALID_SEVERITIES:
            raise ReportValidationError(f"findings[{idx}].severity is invalid.")
        if item["difficulty"] not in VALID_DIFFICULTIES:
            raise ReportValidationError(f"findings[{idx}].difficulty is invalid.")
        steps = item["how_to_fix"]
        if not isinstance(steps, list) or not all(isinstance(s, str) for s in steps):
            raise ReportValidationError(f"findings[{idx}].how_to_fix must be a list of strings.")

        records.append(
            FindingRecord(
                rule_id=item["rule_id"],
                category=item["category"],
                title=item["title"],
                status=item["status"],
                severity=item["severity"],
                detail=item["detail"],
                why_it_matters=item["why_it_matters"],
                how_to_fix=list(steps),
                difficulty=item["difficulty"],
                source=item["source"],
            )
        )
    return records


def _validate_not_checked(not_checked: Any) -> list[NotCheckedRecord]:
    if not isinstance(not_checked, list):
        raise ReportValidationError("not_checked must be a list.")
    records: list[NotCheckedRecord] = []
    for idx, item in enumerate(not_checked):
        if not isinstance(item, dict):
            raise ReportValidationError(f"not_checked[{idx}] must be an object.")
        for key in ("rule_id", "title", "reason"):
            if not isinstance(item.get(key), str):
                raise ReportValidationError(f"not_checked[{idx}].{key} must be a string.")
        records.append(
            NotCheckedRecord(
                rule_id=item["rule_id"],
                title=item["title"],
                reason=item["reason"],
            )
        )
    return records


def load_report_file(path: Path, reports_dir: Path) -> ScanReport:
    """Safely load and validate a v1 JSON report inside *reports_dir*."""
    safe_path = _ensure_contained(path, reports_dir)
    raw_text = _read_bounded_utf8(safe_path)
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"Malformed JSON: {exc.msg}.") from exc
    _check_json_depth(parsed)
    return validate_report_dict(parsed, filename=safe_path.name)
