"""JSON report — machine-readable scan output."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscan.scorer.scorer import ScoreResult


def render_json(result: ScoreResult, *, output_path: Path | None = None) -> str:
    """Render the scan results to a JSON string.

    Args:
        result: The scored scan result.
        output_path: If provided, write the JSON to this file path.

    Returns:
        The JSON string.
    """
    report: dict[str, Any] = {
        "secscan_version": "0.1.0",
        "scan_time": datetime.now(tz=UTC).isoformat(),
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
    }

    json_str = json.dumps(report, indent=2, ensure_ascii=False)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
