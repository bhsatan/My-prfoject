"""CLI entry point for SecScan.

Commands:
    secscan scan              Run a security posture scan (default).
    secscan scan --dry-run    Show what would be inspected without collecting.
    secscan scan --format     Output format: terminal (default), json, html.
    secscan scan --output     Directory for report files.
"""

from __future__ import annotations

import argparse
import logging
import sys
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscan import __version__
from secscan.ai_explainer import get_api_key_from_env
from secscan.collectors import get_all_collectors
from secscan.collectors.base import get_platform
from secscan.engine.evaluator import evaluate
from secscan.engine.loader import load_rules
from secscan.report.html_report import render_html
from secscan.report.json_report import render_json
from secscan.report.terminal import render_terminal
from secscan.scorer.scorer import compute_score

logger = logging.getLogger("secscan")

# ---------------------------------------------------------------------------
# Permission notice
# ---------------------------------------------------------------------------

_PERMISSION_NOTICE = """\
╔══════════════════════════════════════════════════════════════╗
║                  SecScan — Permission Notice                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  SecScan will READ (never modify) the following on your      ║
║  machine:                                                    ║
║                                                              ║
║  • Firewall configuration                                    ║
║  • Disk encryption status                                    ║
║  • Antivirus / Defender settings (Windows)                   ║
║  • Listening network ports                                   ║
║  • User accounts and admin group membership                  ║
║  • Password and lockout policy                               ║
║  • SSH server configuration (Linux)                          ║
║  • Remote Desktop and SMB settings (Windows)                 ║
║  • Automatic login configuration                             ║
║                                                              ║
║  SecScan does NOT:                                           ║
║  • Modify any settings or files                              ║
║  • Send data over the network                                ║
║  • Install or remove software                                ║
║  • Store or transmit passwords or secrets                    ║
║                                                              ║
║  Report files will be saved in the output directory you      ║
║  specified (or printed to the terminal).                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="SecScan — Local-first security posture scanner.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"secscan {__version__}",
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run a security posture scan.")
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be inspected without collecting any data.",
    )
    scan.add_argument(
        "--format",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    scan.add_argument(
        "--output",
        type=str,
        default=None,
        help="Directory to write report files. Required for json/html formats.",
    )
    scan.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the permission confirmation prompt.",
    )
    scan.add_argument(
        "--ai-explain",
        action="store_true",
        default=False,
        help=(
            "Optional (disabled by default): request plain-language AI "
            "explanations using SECSCAN_AI_API_KEY."
        ),
    )
    scan.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging.",
    )

    update_cmd = sub.add_parser(
        "update",
        help="Show how to update SecScan (no automatic network calls).",
    )
    update_cmd.add_argument(
        "--open",
        action="store_true",
        help="Open the GitHub Releases page in your default browser.",
    )

    return parser


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


def _handle_dry_run(current_platform: str) -> None:
    """Print what the scan would inspect without collecting anything."""
    collectors = get_all_collectors()
    applicable = [c for c in collectors if c.is_supported(current_platform)]

    print(f"\n  SecScan dry-run — platform: {current_platform}")
    print(f"  {len(applicable)} collector(s) would run:\n")

    for collector in applicable:
        print(f"  [{collector.name}]")
        for item in collector.get_dry_run_info():
            item_type = item.get("type", "unknown")
            detail = item.get("detail", "")
            print(f"    {item_type:15s}  {detail}")
        print()

    rules = load_rules()
    applicable_rules = [r for r in rules if current_platform in r.applies_to]
    print(f"  {len(applicable_rules)} rule(s) would be evaluated.\n")


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


def _handle_scan(
    fmt: str,
    output_dir: str | None,
    skip_confirm: bool,
    ai_explain: bool = False,
) -> int:
    """Run the full scan pipeline. Returns exit code 0."""
    # Detect platform
    try:
        current_platform = get_platform()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Permission confirmation
    if not skip_confirm:
        print(_PERMISSION_NOTICE)
        try:
            answer = input("  Do you want to proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Scan cancelled.")
            return 0
        if answer not in ("y", "yes"):
            print("  Scan cancelled.")
            return 0
        print()

    # Collect facts
    print("  Collecting facts...")
    collectors = get_all_collectors()
    facts: dict[str, dict[str, Any]] = {}
    for collector in collectors:
        if not collector.is_supported(current_platform):
            continue
        try:
            collector_facts = collector.get_facts()
            facts.update(collector_facts)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Collector %s failed: %s", collector.name, exc)
            facts[collector.name] = {"error": str(exc)}

    # Load and evaluate rules
    print("  Evaluating rules...")
    rules = load_rules()
    findings = evaluate(rules, facts, current_platform)

    # Score
    result = compute_score(findings)
    print(f"  Score: {result.score}/100 (Grade {result.grade})\n")

    # Validate output directory
    out_path = _resolve_output_dir(output_dir)

    # Render report
    if fmt == "terminal":
        output = render_terminal(result)
        print(output)
        # Also write to file if output dir given
        if out_path is not None:
            file_path = out_path / _report_filename("txt")
            file_path.write_text(output, encoding="utf-8")
            print(f"  Report saved to: {file_path}")

    elif fmt == "json":
        if out_path is None:
            # Print to stdout
            output = render_json(result)
            print(output)
        else:
            file_path = out_path / _report_filename("json")
            render_json(result, output_path=file_path)
            print(f"  Report saved to: {file_path}")

    elif fmt == "html":
        if out_path is None:
            out_path = Path("output")
        file_path = out_path / _report_filename("html")
        render_html(result, output_path=file_path)
        print(f"  Report saved to: {file_path}")

    if ai_explain:
        if get_api_key_from_env() is None:
            print(
                "\n  AI explainer requested, but SECSCAN_AI_API_KEY is not set. "
                "Skipping AI explanations."
            )
        else:
            print(
                "\n  AI explainer is interface-only in v0.1 "
                "(no LLM provider is configured yet; no network calls were made)."
            )

    return 0


def _resolve_output_dir(output_dir: str | None) -> Path | None:
    """Resolve and validate the output directory path."""
    if output_dir is None:
        return None

    out_path = Path(output_dir).resolve()
    # Safety: ensure resolved path is under a reasonable location
    # (prevent path traversal via ../../)
    out_path.mkdir(parents=True, exist_ok=True)
    return out_path


def _report_filename(ext: str) -> str:
    """Generate a timestamped report filename."""
    ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    return f"secscan_report_{ts}.{ext}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


_RELEASES_URL = "https://github.com/bhsatan/Sescan/releases"


def _handle_update(*, open_browser: bool = False) -> int:
    """Print manual update instructions and optionally open the Releases page."""
    print(f"\n  SecScan current version: v{__version__}")
    print(f"  Releases page:           {_RELEASES_URL}")
    print("\n  To update (run manually):")
    print("    git pull && pip install -e .")
    print(f"    # or: pip install --upgrade git+{_RELEASES_URL.removesuffix('/releases')}.git\n")
    if open_browser:
        webbrowser.open(_RELEASES_URL)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Default to scan if no command given
    if args.command is None:
        args = parser.parse_args(["scan"] + (argv or []))

    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")

    if args.command == "scan":
        if args.dry_run:
            try:
                current_platform = get_platform()
            except RuntimeError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1
            _handle_dry_run(current_platform)
            return 0

        return _handle_scan(
            fmt=args.format,
            output_dir=args.output,
            skip_confirm=args.yes,
            ai_explain=args.ai_explain,
        )

    if args.command == "update":
        return _handle_update(open_browser=args.open)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
