"""Static import-graph test ensuring SecScan has no network imports."""

from __future__ import annotations

import ast
from pathlib import Path

_SECSCAN_ROOT = Path(__file__).resolve().parent.parent / "secscan"

_FORBIDDEN_NETWORK_MODULES: frozenset[str] = frozenset(
    {
        "aiohttp",
        "http",
        "httpx",
        "requests",
        "urllib",
        "urllib3",
        "webbrowser",
    }
)


def _imported_top_modules(py_file: Path) -> set[str]:
    """Return all top-level module names imported in *py_file*."""
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def test_no_network_or_updater_imports_in_secscan() -> None:
    """No module in secscan/ may import HTTP, browser, or updater modules."""
    for py_file in sorted(_SECSCAN_ROOT.rglob("*.py")):
        rel = py_file.relative_to(_SECSCAN_ROOT).as_posix()
        imported = _imported_top_modules(py_file)

        forbidden = imported & _FORBIDDEN_NETWORK_MODULES
        assert not forbidden, f"{rel} imports forbidden network/browser module(s): {forbidden}"

        # socket is allowed only in ai_explainer/redactor.py (for local gethostname())
        if "socket" in imported:
            assert rel == "ai_explainer/redactor.py", (
                f"{rel} imports socket, which is only allowed in ai_explainer/redactor.py"
            )
