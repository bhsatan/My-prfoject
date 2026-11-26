"""Self-contained HTML report — no CDN, no network dependencies.

Generates a single HTML file with:
- Score gauge (SVG)
- Severity bar chart
- Ranked findings with fix steps
- Warning banner about sensitive data
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from secscan import __version__
from secscan.report._html_template import HTML_TEMPLATE
from secscan.scorer.scorer import ScoreResult


def render_html(result: ScoreResult, *, output_path: Path | None = None) -> str:
    """Render the scan results to a self-contained HTML string.

    Args:
        result: The scored scan result.
        output_path: If provided, write the HTML to this file path.

    Returns:
        The HTML string.
    """
    scan_time = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    findings_html = _build_findings_html(result)
    severity_chart = _build_severity_chart(result)
    score_colour = _score_colour(result.score)

    html = HTML_TEMPLATE.replace("{{SCORE}}", str(result.score))
    html = html.replace("{{GRADE}}", result.grade)
    html = html.replace("{{SCORE_COLOUR}}", score_colour)
    html = html.replace("{{SCAN_TIME}}", scan_time)
    html = html.replace("{{TOTAL}}", str(result.total_checks))
    html = html.replace("{{PASSED}}", str(result.passed))
    html = html.replace("{{FAILED}}", str(result.failed))
    html = html.replace("{{UNKNOWN}}", str(result.unknown))
    html = html.replace("{{SEVERITY_CHART}}", severity_chart)
    html = html.replace("{{FINDINGS}}", findings_html)
    html = html.replace("{{VERSION}}", __version__)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    return html


def _score_colour(score: int) -> str:
    if score >= 90:
        return "#22c55e"
    if score >= 75:
        return "#84cc16"
    if score >= 50:
        return "#eab308"
    if score >= 25:
        return "#f97316"
    return "#ef4444"


def _build_severity_chart(result: ScoreResult) -> str:
    if not result.summary_by_severity:
        return ""

    rows: list[str] = []
    for sev in ("critical", "high", "medium", "low"):
        counts = result.summary_by_severity.get(sev, {})
        p = counts.get("pass", 0)
        f = counts.get("fail", 0)
        u = counts.get("unknown", 0)
        total = p + f + u
        if total == 0:
            continue
        max_bar = 20
        f_w = round(f / total * max_bar) if total else 0
        u_w = round(u / total * max_bar) if total else 0
        p_w = max_bar - f_w - u_w

        bar = (
            f'<span class="bar-fail" style="width:{f_w}em"></span>'
            f'<span class="bar-unknown" style="width:{u_w}em"></span>'
            f'<span class="bar-pass" style="width:{p_w}em"></span>'
        )
        rows.append(
            f'<tr><td class="sev-label sev-{sev}">{sev.upper()}</td>'
            f'<td class="bar-cell">{bar}</td>'
            f"<td>{p}✓ {f}✗ {u}?</td></tr>"
        )

    if not rows:
        return ""
    return f'<table class="sev-table">{"".join(rows)}</table>'


def _build_findings_html(result: ScoreResult) -> str:
    sections: list[str] = []

    fail_unknown = [f for f in result.findings if f.status in ("fail", "unknown")]
    passed = [f for f in result.findings if f.status == "pass"]

    if fail_unknown:
        sections.append('<h2 class="section-title issues">Issues to Address</h2>')
        for finding in fail_unknown:
            status_cls = "fail" if finding.status == "fail" else "unknown"
            steps_html = ""
            if finding.how_to_fix:
                steps_li = "".join(f"<li>{_esc(s)}</li>" for s in finding.how_to_fix)
                steps_html = (
                    f'<div class="fix"><strong>How to fix:</strong><ol>{steps_li}</ol></div>'
                )

            sections.append(f"""
<div class="finding {status_cls}">
  <div class="finding-header">
    <span class="badge sev-{finding.severity}">{finding.severity.upper()}</span>
    <span class="finding-title">{_esc(finding.title)}</span>
    <span class="badge status-{finding.status}">{finding.status.upper()}</span>
  </div>
  <p class="detail">{_esc(finding.detail)}</p>
  <p class="why"><strong>Why it matters:</strong> {_esc(finding.why_it_matters)}</p>
  {steps_html}
  <p class="meta">Difficulty: {finding.difficulty} · Source: {_esc(finding.source)}</p>
</div>""")

    if passed:
        sections.append('<h2 class="section-title passed-title">Checks Passed</h2>')
        sections.append('<ul class="passed-list">')
        for finding in passed:
            sections.append(f"<li>✓ {_esc(finding.title)}</li>")
        sections.append("</ul>")

    return "\n".join(sections)


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
