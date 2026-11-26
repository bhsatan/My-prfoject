"""Read-only report store, trend computation, and declarative dashboard store."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secscan_ui.schema import (
    SCAN_ID_RE,
    VALID_SEVERITIES,
    VALID_STATUSES,
    ReportValidationError,
    ScanReport,
    _check_json_depth,
    load_report_file,
)

logger = logging.getLogger(__name__)

MAX_DASHBOARD_BYTES = 64 * 1024  # 64 KiB
MAX_WIDGETS = 12

VALID_WIDGET_TYPES = frozenset(
    {
        "score_gauge",
        "severity_chart",
        "trend_line",
        "top_fixes",
        "findings_table",
        "insight_cards",
    }
)

DASHBOARD_ID_RE = re.compile(r"^[a-z0-9_-]{2,48}$")
_URL_SCHEME_RE = re.compile(
    r"(?:://|javascript:|data:|vbscript:|(?:^|\s)//)",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(r"[<>]")


@dataclass(frozen=True)
class SkippedFile:
    """A report file that failed validation and was skipped safely."""

    filename: str
    reason: str


@dataclass(frozen=True)
class TrendSummary:
    """Score and finding changes across scans (oldest -> newest)."""

    points: list[dict[str, Any]]
    score_delta: int | None
    newly_failed: list[str]
    resolved: list[str]


class ReportStore:
    """Strictly read-only store over a directory of v1 JSON reports."""

    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir

    def list_scans(self) -> tuple[list[ScanReport], list[SkippedFile]]:
        """Return ``(valid_scans_newest_first, skipped_files)``."""
        if not self.reports_dir.is_dir():
            return [], []

        valid: list[ScanReport] = []
        skipped: list[SkippedFile] = []

        for entry in sorted(self.reports_dir.glob("*.json")):
            try:
                report = load_report_file(entry, self.reports_dir)
                valid.append(report)
            except ReportValidationError as exc:
                skipped.append(SkippedFile(filename=entry.name, reason=str(exc)))

        valid.sort(key=lambda r: r.scan_time, reverse=True)
        return valid, skipped

    def load_scan(self, scan_id: str) -> ScanReport | None:
        """Load a single scan by validated ``scan_id``."""
        if not SCAN_ID_RE.match(scan_id):
            raise ReportValidationError("Invalid scan_id.")

        valid, _ = self.list_scans()
        for report in valid:
            if report.scan_id == scan_id:
                return report
        return None

    def compute_trends(self, valid: list[ScanReport] | None = None) -> TrendSummary:
        """Compute score trend and finding diffs across valid scans."""
        if valid is None:
            valid, _ = self.list_scans()
        if not valid:
            return TrendSummary(points=[], score_delta=None, newly_failed=[], resolved=[])

        oldest_first = list(reversed(valid))
        points = [
            {
                "scan_id": r.scan_id,
                "scan_time": r.scan_time_iso,
                "score": r.score,
                "grade": r.grade,
                "failed": r.summary["failed"],
            }
            for r in oldest_first
        ]

        if len(oldest_first) < 2:
            return TrendSummary(points=points, score_delta=None, newly_failed=[], resolved=[])

        prev = oldest_first[-2]
        curr = oldest_first[-1]
        score_delta = curr.score - prev.score

        prev_failed = {f.rule_id for f in prev.findings if f.status == "fail"}
        curr_failed = {f.rule_id for f in curr.findings if f.status == "fail"}
        curr_passed = {f.rule_id for f in curr.findings if f.status == "pass"}

        newly_failed = sorted(curr_failed - prev_failed)
        resolved = sorted(prev_failed & curr_passed)

        return TrendSummary(
            points=points,
            score_delta=score_delta,
            newly_failed=newly_failed,
            resolved=resolved,
        )


# ---------------------------------------------------------------------------
# Declarative dashboards (pre-built + custom validated JSON)
# ---------------------------------------------------------------------------


class DashboardValidationError(Exception):
    """Raised when a custom dashboard JSON fails validation."""


PREBUILT_DASHBOARDS: dict[str, dict[str, Any]] = {
    "beginner": {
        "schema_version": "1.0",
        "id": "beginner",
        "name": "Beginner overview",
        "widgets": [
            {"type": "score_gauge", "title": "Your Security Score", "filters": {}},
            {"type": "insight_cards", "title": "Plain-Language Takeaways", "filters": {}},
            {
                "type": "top_fixes",
                "title": "Fix These First",
                "filters": {"status": ["fail"]},
            },
        ],
    },
    "home": {
        "schema_version": "1.0",
        "id": "home",
        "name": "Home user",
        "widgets": [
            {"type": "score_gauge", "title": "Home Machine Score", "filters": {}},
            {"type": "severity_chart", "title": "Issues by Severity", "filters": {}},
            {
                "type": "findings_table",
                "title": "Action Items",
                "filters": {"status": ["fail", "unknown"]},
            },
        ],
    },
    "small-business": {
        "schema_version": "1.0",
        "id": "small-business",
        "name": "Small business",
        "widgets": [
            {"type": "score_gauge", "title": "Posture Score", "filters": {}},
            {"type": "trend_line", "title": "Score Over Time", "filters": {}},
            {"type": "severity_chart", "title": "Severity Breakdown", "filters": {}},
            {"type": "findings_table", "title": "All Findings", "filters": {}},
        ],
    },
}


def _check_safe_text(value: Any, field: str, max_len: int = 80) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DashboardValidationError(f"{field} must be a non-empty string.")
    if len(value) > max_len:
        raise DashboardValidationError(f"{field} exceeds {max_len} characters.")
    if _HTML_TAG_RE.search(value) or _URL_SCHEME_RE.search(value):
        raise DashboardValidationError(f"{field} cannot contain HTML or URLs.")
    if any(ord(ch) < 32 for ch in value):
        raise DashboardValidationError(f"{field} cannot contain control characters.")
    return value.strip()


def validate_dashboard_dict(data: Any) -> dict[str, Any]:
    """Strictly validate a declarative custom dashboard JSON document."""
    if not isinstance(data, dict):
        raise DashboardValidationError("Dashboard must be a JSON object.")

    allowed_top = {"schema_version", "id", "name", "widgets"}
    if set(data.keys()) != allowed_top:
        raise DashboardValidationError(
            f"Dashboard must contain exactly: {', '.join(sorted(allowed_top))}."
        )

    if data["schema_version"] != "1.0":
        raise DashboardValidationError("Dashboard schema_version must be '1.0'.")

    dash_id = data["id"]
    if not isinstance(dash_id, str) or not DASHBOARD_ID_RE.match(dash_id):
        raise DashboardValidationError("Dashboard id must match ^[a-z0-9_-]{2,48}$.")
    if dash_id in PREBUILT_DASHBOARDS:
        raise DashboardValidationError("Cannot overwrite a built-in dashboard id.")

    name = _check_safe_text(data["name"], "name", max_len=60)

    widgets = data["widgets"]
    if not isinstance(widgets, list) or not (1 <= len(widgets) <= MAX_WIDGETS):
        raise DashboardValidationError(f"widgets must be a list of 1..{MAX_WIDGETS} items.")

    clean_widgets: list[dict[str, Any]] = []
    for idx, w in enumerate(widgets):
        if not isinstance(w, dict):
            raise DashboardValidationError(f"widgets[{idx}] must be an object.")
        if set(w.keys()) - {"type", "title", "filters"} or "type" not in w or "title" not in w:
            raise DashboardValidationError(f"widgets[{idx}] has invalid keys.")
        w_type = w["type"]
        if not isinstance(w_type, str) or w_type not in VALID_WIDGET_TYPES:
            raise DashboardValidationError(f"widgets[{idx}].type '{w_type}' is not allowed.")
        w_title = _check_safe_text(w["title"], f"widgets[{idx}].title", max_len=60)
        filters = _validate_widget_filters(w.get("filters", {}), idx)
        clean_widgets.append({"type": w_type, "title": w_title, "filters": filters})

    return {
        "schema_version": "1.0",
        "id": dash_id,
        "name": name,
        "widgets": clean_widgets,
    }


def _validate_widget_filters(filters: Any, idx: int) -> dict[str, list[str]]:
    if not isinstance(filters, dict):
        raise DashboardValidationError(f"widgets[{idx}].filters must be an object.")
    allowed_filter_keys = {"severity", "status"}
    if set(filters.keys()) - allowed_filter_keys:
        raise DashboardValidationError(f"widgets[{idx}].filters has unsupported keys.")

    clean: dict[str, list[str]] = {}
    if "severity" in filters:
        sevs = filters["severity"]
        if not isinstance(sevs, list) or not all(
            isinstance(s, str) and s in VALID_SEVERITIES for s in sevs
        ):
            raise DashboardValidationError(f"widgets[{idx}].filters.severity is invalid.")
        clean["severity"] = list(sevs)
    if "status" in filters:
        statuses = filters["status"]
        if not isinstance(statuses, list) or not all(
            isinstance(s, str) and s in VALID_STATUSES for s in statuses
        ):
            raise DashboardValidationError(f"widgets[{idx}].filters.status is invalid.")
        clean["status"] = list(statuses)
    return clean


class DashboardStore:
    """Reads/writes validated declarative custom dashboards in ``data_dir``."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir

    def list_dashboards(self) -> list[dict[str, Any]]:
        dashboards = list(PREBUILT_DASHBOARDS.values())
        if not self.data_dir.is_dir():
            return dashboards
        for path in sorted(self.data_dir.glob("*.json")):
            try:
                raw = path.read_bytes()
                if len(raw) > MAX_DASHBOARD_BYTES:
                    continue
                parsed = json.loads(raw.decode("utf-8"))
                _check_json_depth(parsed)
                dashboards.append(validate_dashboard_dict(parsed))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, Exception) as exc:
                logger.debug("Skipping invalid dashboard %s: %s", path.name, type(exc).__name__)
                continue
        return dashboards

    def save_dashboard(self, raw_json: str) -> dict[str, Any]:
        if len(raw_json.encode("utf-8")) > MAX_DASHBOARD_BYTES:
            raise DashboardValidationError("Dashboard JSON exceeds 64 KiB limit.")
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise DashboardValidationError(f"Invalid JSON: {exc.msg}.") from exc
        except RecursionError as exc:
            raise DashboardValidationError("Dashboard JSON nesting exceeds maximum depth.") from exc
        try:
            _check_json_depth(parsed)
        except ReportValidationError as exc:
            raise DashboardValidationError(str(exc)) from exc

        validated = validate_dashboard_dict(parsed)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        base_dir = os.path.realpath(self.data_dir)
        fullpath = os.path.realpath(os.path.join(base_dir, f"{validated['id']}.json"))
        if not fullpath.startswith(base_dir + os.sep):
            raise DashboardValidationError("Dashboard path resolves outside data directory.")
        Path(fullpath).write_text(json.dumps(validated, indent=2), encoding="utf-8")
        return validated
