"""Native entry point for the SecScan Web UI (``python -m secscan_ui``)."""

from __future__ import annotations

import argparse
import ctypes
import os
import stat
import sys
from pathlib import Path
from typing import Any

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_privileged() -> bool:
    """Return True if running as root (POSIX) or Administrator (Windows)."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _is_world_readable(path: Path) -> bool:
    """Return True on POSIX if *path* has the world-readable bit (o+r) set."""
    if os.name == "nt":
        return False
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    return bool(mode & stat.S_IROTH)


def _warn_if_world_readable(reports_dir: Path) -> None:
    """Warn the user if the reports directory or any JSON report is world-readable."""
    if not reports_dir.exists():
        return
    if _is_world_readable(reports_dir):
        print(
            f"Warning: Reports directory '{reports_dir}' is world-readable. "
            "Consider restricting permissions (e.g. chmod 700).",
            file=sys.stderr,
        )
    if reports_dir.is_dir():
        for entry in sorted(reports_dir.glob("*.json")):
            if _is_world_readable(entry):
                print(
                    f"Warning: Report file '{entry.name}' is world-readable. "
                    "Consider restricting permissions (e.g. chmod 600).",
                    file=sys.stderr,
                )


def _serve(app: Any, *, host: str, port: int) -> None:
    """Serve the Flask app using Waitress."""
    from waitress import serve

    serve(app, host=host, port=port, threads=4)


def run_ui(
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    reports_dir: Path | None = None,
    data_dir: Path | None = None,
    allow_remote: bool = False,
    allow_privileged: bool = False,
) -> int:
    """Validate safety guards and start the native Web UI server."""
    if not (1 <= port <= 65535):
        print(f"Error: Invalid port {port} (must be 1..65535).", file=sys.stderr)
        return 1

    if host not in _LOOPBACK_HOSTS:
        if not allow_remote:
            print(
                f"Error: Refusing to bind to non-loopback address '{host}'. "
                "Use 127.0.0.1 (default), or pass --allow-remote if you understand the risk.",
                file=sys.stderr,
            )
            return 1
        print(
            "WARNING: Binding Web UI to a non-loopback address exposes sensitive "
            "security reports and has NO authentication.",
            file=sys.stderr,
        )

    if _is_privileged() and not allow_privileged:
        print(
            "Error: Refusing to run the Web UI as root/Administrator. "
            "The UI only reads reports and never needs elevated privileges "
            "(pass --allow-privileged to override).",
            file=sys.stderr,
        )
        return 1

    resolved_reports = reports_dir or Path("output")
    resolved_data = data_dir or (Path.home() / ".secscan" / "ui_data")
    _warn_if_world_readable(resolved_reports)

    from secscan_ui.app import create_app

    allowed_hosts = {
        "127.0.0.1",
        "localhost",
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        "testclient",
    }
    if allow_remote:
        allowed_hosts.update({host.lower(), f"{host.lower()}:{port}"})

    app = create_app(
        reports_dir=resolved_reports,
        data_dir=resolved_data,
        allowed_hosts=allowed_hosts,
        allow_remote=allow_remote,
    )
    print(f"SecScan Web UI listening on http://{host}:{port} (reports: {resolved_reports})")
    _serve(app, host=host, port=port)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``python -m secscan_ui``."""
    parser = argparse.ArgumentParser(
        prog="secscan-ui",
        description="SecScan local-only Web UI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080).")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=None,
        help="Directory containing v1 JSON reports (default: ./output).",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Directory for custom dashboards (default: ~/.secscan/ui_data).",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow binding to a non-loopback address (exposes unauthenticated UI).",
    )
    parser.add_argument(
        "--allow-privileged",
        action="store_true",
        help="Allow running as root/Administrator.",
    )
    args = parser.parse_args(argv)
    return run_ui(
        host=args.host,
        port=args.port,
        reports_dir=args.reports_dir,
        data_dir=args.data_dir,
        allow_remote=args.allow_remote,
        allow_privileged=args.allow_privileged,
    )


if __name__ == "__main__":
    sys.exit(main())
