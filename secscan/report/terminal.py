"""Terminal report — coloured, human-readable scan output."""

from __future__ import annotations

import sys
from typing import TextIO

from secscan.scorer.scorer import ScoreResult

# ---------------------------------------------------------------------------
# ANSI helpers (disabled when stdout is not a TTY)
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_COLOURS: dict[str, str] = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "white": "\033[97m",
}

_SEVERITY_COLOUR: dict[str, str] = {
    "critical": "red",
    "high": "yellow",
    "medium": "cyan",
    "low": "white",
}

_STATUS_SYMBOL: dict[str, str] = {
    "fail": "✗",
    "unknown": "?",
    "pass": "✓",
}

_GRADE_COLOUR: dict[str, str] = {
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "red",
}


def _c(text: str, colour: str, *, bold: bool = False) -> str:
    """Wrap text in ANSI colour codes if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    prefix = _COLOURS.get(colour, "")
    if bold:
        prefix = _BOLD + prefix
    return f"{prefix}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_terminal(result: ScoreResult, *, stream: TextIO | None = None) -> str:
    """Render the scan results to a human-readable terminal string.

    Args:
        result: The scored scan result.
        stream: If provided, also write the output to this stream.

    Returns:
        The full rendered report as a string.
    """
    lines: list[str] = []

    # --- Header ---
    lines.append("")
    lines.append(_c("═" * 60, "cyan"))
    lines.append(_c("  SecScan — Security Posture Report", "cyan", bold=True))
    lines.append(_c("═" * 60, "cyan"))
    lines.append("")

    # --- Score ---
    grade_col = _GRADE_COLOUR.get(result.grade, "white")
    lines.append(
        f"  Score: {_c(str(result.score), grade_col, bold=True)}/100  "
        f"Grade: {_c(result.grade, grade_col, bold=True)}"
    )
    lines.append("")
    lines.append(
        f"  {_c(str(result.passed), 'green')} passed  "
        f"{_c(str(result.failed), 'red')} failed  "
        f"{_c(str(result.unknown), 'yellow')} unknown  "
        f"({result.total_checks} total)"
    )
    lines.append("")

    # --- Severity summary bar ---
    if result.summary_by_severity:
        lines.append(_c("  Severity Summary", "white", bold=True))
        for sev in ("critical", "high", "medium", "low"):
            counts = result.summary_by_severity.get(sev, {})
            p = counts.get("pass", 0)
            f_count = counts.get("fail", 0)
            u = counts.get("unknown", 0)
            total = p + f_count + u
            if total == 0:
                continue
            col = _SEVERITY_COLOUR.get(sev, "white")
            bar = _c("█" * f_count, "red") + _c("░" * u, "yellow") + _c("▓" * p, "green")
            lines.append(f"  {_c(f'{sev.upper():>8s}', col)}  {bar}  ({p}✓ {f_count}✗ {u}?)")
        lines.append("")

    # --- Findings ---
    lines.append(_c("─" * 60, "cyan"))

    fail_unknown = [f for f in result.findings if f.status in ("fail", "unknown")]
    passed = [f for f in result.findings if f.status == "pass"]

    if fail_unknown:
        lines.append(_c("  Issues to Address", "red", bold=True))
        lines.append("")
        for finding in fail_unknown:
            sev_col = _SEVERITY_COLOUR.get(finding.severity, "white")
            status_sym = _STATUS_SYMBOL.get(finding.status, "?")
            status_col = "red" if finding.status == "fail" else "yellow"

            lines.append(
                f"  {_c(status_sym, status_col)} "
                f"{_c(f'[{finding.severity.upper()}]', sev_col)} "
                f"{_c(finding.title, 'white', bold=True)}"
            )
            lines.append(f"    {_c(finding.detail, 'white')}")
            lines.append(f"    {_c('Why:', 'cyan')} {finding.why_it_matters}")
            if finding.how_to_fix:
                lines.append(f"    {_c('How to fix:', 'green')}")
                for step in finding.how_to_fix:
                    lines.append(f"      • {step}")
            lines.append(
                f"    {_c('Difficulty:', 'cyan')} {finding.difficulty}  "
                f"{_c('Source:', 'cyan')} {finding.source}"
            )
            lines.append("")

    if passed:
        lines.append(_c("  Checks Passed", "green", bold=True))
        lines.append("")
        for finding in passed:
            lines.append(f"  {_c('✓', 'green')} {finding.title}")
        lines.append("")

    # --- Footer ---
    lines.append(_c("─" * 60, "cyan"))
    lines.append(
        _c(
            "  ⚠ This report contains sensitive system information. Do not share publicly.",
            "yellow",
        )
    )
    lines.append(_c("═" * 60, "cyan"))
    lines.append("")

    output = "\n".join(lines)
    if stream is not None:
        stream.write(output)
    return output
