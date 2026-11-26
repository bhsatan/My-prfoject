"""SecScan Web UI — Flask application factory with strict security controls."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from secscan import __version__
from secscan.ai_explainer import Redactor, get_api_key_from_env
from secscan_ui.insights import (
    category_breakdown,
    clean_text,
    generate_insights,
    grade_explanation,
    top_fixes,
    trend_text_summary,
)
from secscan_ui.schema import FindingRecord, ReportValidationError, ScanReport
from secscan_ui.store import (
    PREBUILT_DASHBOARDS,
    VALID_WIDGET_TYPES,
    DashboardStore,
    DashboardValidationError,
    ReportStore,
)

_DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "127.0.0.1",
        "127.0.0.1:8080",
        "localhost",
        "localhost:8080",
        "testclient",
    }
)

_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'none'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def create_app(
    *,
    reports_dir: Path | None = None,
    data_dir: Path | None = None,
    allowed_hosts: set[str] | None = None,
    rate_limit_per_minute: int = 120,
    allow_remote: bool = False,
) -> Flask:
    """Create and configure the hardened SecScan Web UI Flask app."""
    # Fail closed if someone configures a non-localhost bind without explicit opt-in
    bind_host = os.environ.get("SECSCAN_UI_BIND_HOST", "127.0.0.1").strip()
    if (
        bind_host not in ("127.0.0.1", "::1", "localhost")
        and not allow_remote
        and os.environ.get("SECSCAN_UI_ALLOW_REMOTE") != "1"
    ):
        raise RuntimeError(
            f"Refusing to bind to non-localhost '{bind_host}' without explicit "
            "SECSCAN_UI_ALLOW_REMOTE=1 opt-in and authentication."
        )

    resolved_reports = reports_dir or Path(os.environ.get("SECSCAN_REPORTS_DIR", "output"))
    resolved_data = data_dir or Path(
        os.environ.get("SECSCAN_DATA_DIR", str(Path.home() / ".secscan" / "ui_data"))
    )

    env_hosts = os.environ.get("SECSCAN_UI_ALLOWED_HOSTS", "")
    extra_hosts = {h.strip().lower() for h in env_hosts.split(",") if h.strip()}
    effective_hosts = (
        {h.lower() for h in allowed_hosts}
        if allowed_hosts is not None
        else set(_DEFAULT_ALLOWED_HOSTS) | extra_hosts
    )

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config.update(
        DEBUG=False,
        SECRET_KEY=os.urandom(32),
        MAX_CONTENT_LENGTH=64 * 1024,  # 64 KiB
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    app.jinja_env.autoescape = True
    app.jinja_env.filters["clean"] = clean_text

    report_store = ReportStore(resolved_reports)
    dashboard_store = DashboardStore(resolved_data)
    rate_buckets: dict[str, deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    # Security middleware: Host allowlist, Rate limit, CSRF, Headers
    # ------------------------------------------------------------------

    @app.before_request
    def _security_checks() -> None:
        # 1. Host header allowlist (DNS-rebinding defence)
        host = (request.host or "").lower()
        if host not in effective_hosts:
            abort(403, description="Invalid Host header.")

        # 2. Basic sliding-window rate limit per client IP
        if rate_limit_per_minute > 0:
            client_ip = request.remote_addr or "unknown"
            now = time.monotonic()
            bucket = rate_buckets[client_ip]
            while bucket and now - bucket[0] > 60.0:
                bucket.popleft()
            if len(bucket) >= rate_limit_per_minute:
                abort(429, description="Rate limit exceeded. Please wait a moment.")
            bucket.append(now)

        # 3. Synchronizer CSRF check on all state-changing requests
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected = session.get("csrf_token", "")
            provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not expected or not provided or not hmac.compare_digest(expected, provided):
                abort(403, description="Invalid or missing CSRF token.")

    @app.context_processor
    def _inject_globals() -> dict[str, Any]:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {
            "csrf_token": session["csrf_token"],
            "tool_version": __version__,
        }

    @app.after_request
    def _security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = _CSP_HEADER
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers.pop("Access-Control-Allow-Origin", None)
        return response

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.get("/health")
    def health() -> Response:
        return jsonify({"status": "ok"})

    @app.get("/")
    def home() -> str:
        valid, skipped = report_store.list_scans()
        latest = valid[0] if valid else None
        trends = report_store.compute_trends(valid) if valid else None
        return render_template(
            "home.html",
            latest=latest,
            skipped=skipped,
            grade_text=grade_explanation(latest.grade) if latest else "",
            fixes=top_fixes(latest.findings) if latest else [],
            insights=generate_insights(latest, trends) if latest else [],
            categories=category_breakdown(latest.findings) if latest else [],
        )

    @app.get("/scans")
    def scans_list() -> str:
        valid, skipped = report_store.list_scans()
        trends = report_store.compute_trends(valid)
        return render_template(
            "scans.html",
            scans=valid,
            skipped=skipped,
            trends=trends,
            trend_summary=trend_text_summary(trends),
        )

    @app.get("/scans/<scan_id>")
    def scan_detail(scan_id: str) -> str:
        try:
            report = report_store.load_scan(scan_id)
        except ReportValidationError:
            abort(400, description="Invalid scan ID.")
        if report is None:
            abort(404, description="Scan not found.")

        sev_filter = request.args.get("severity", "").strip().lower()
        status_filter = request.args.get("status", "").strip().lower()
        diff_filter = request.args.get("difficulty", "").strip().lower()
        cat_filter = request.args.get("category", "").strip().lower()
        sort_by = request.args.get("sort", "status").strip().lower()

        filtered = _filter_and_sort_findings(
            report.findings,
            severity=sev_filter,
            status=status_filter,
            difficulty=diff_filter,
            category=cat_filter,
            sort_by=sort_by,
        )
        categories = sorted({f.category for f in report.findings})
        return render_template(
            "scan_detail.html",
            report=report,
            findings=filtered,
            categories=categories,
            filters={
                "severity": sev_filter,
                "status": status_filter,
                "difficulty": diff_filter,
                "category": cat_filter,
                "sort": sort_by,
            },
        )

    @app.get("/dashboards")
    def dashboards_view() -> str:
        dashboards = dashboard_store.list_dashboards()
        selected_id = request.args.get("id", "beginner").strip()
        active = next((d for d in dashboards if d["id"] == selected_id), dashboards[0])
        valid, _ = report_store.list_scans()
        latest = valid[0] if valid else None
        trends = report_store.compute_trends(valid) if valid else None

        rendered_widgets = []
        for w in active["widgets"]:
            rendered_widgets.append(_build_widget_context(w, latest, trends))

        return render_template(
            "dashboards.html",
            dashboards=dashboards,
            active=active,
            widgets=rendered_widgets,
            latest=latest,
            is_custom=active["id"] not in PREBUILT_DASHBOARDS,
        )

    @app.route("/dashboards/new", methods=["GET", "POST"])
    def dashboard_new() -> str | Response:
        error = None
        if request.method == "POST":
            dash_id = request.form.get("dash_id", "").strip()
            name = request.form.get("name", "").strip()
            widget_types = request.form.getlist("widget_type")
            sev_filter = [s for s in request.form.getlist("filter_severity") if s]
            status_filter = [s for s in request.form.getlist("filter_status") if s]

            filters: dict[str, list[str]] = {}
            if sev_filter:
                filters["severity"] = sev_filter
            if status_filter:
                filters["status"] = status_filter

            widgets = [
                {"type": wt, "title": wt.replace("_", " ").title(), "filters": filters}
                for wt in widget_types
                if wt in VALID_WIDGET_TYPES
            ]
            payload = json.dumps(
                {
                    "schema_version": "1.0",
                    "id": dash_id,
                    "name": name,
                    "widgets": widgets,
                }
            )
            try:
                saved = dashboard_store.save_dashboard(payload)
                return redirect(url_for("dashboards_view", id=saved["id"]))
            except DashboardValidationError as exc:
                error = str(exc)

        return render_template(
            "dashboard_form.html",
            mode="new",
            widget_types=sorted(VALID_WIDGET_TYPES),
            error=error,
            form_data=request.form,
        )

    @app.post("/dashboards/import")
    def dashboard_import() -> Response | tuple[str, int]:
        raw_json = request.form.get("dashboard_json", "")
        try:
            saved = dashboard_store.save_dashboard(raw_json)
            return redirect(url_for("dashboards_view", id=saved["id"]))
        except DashboardValidationError as exc:
            return render_template(
                "dashboard_form.html",
                mode="import",
                widget_types=sorted(VALID_WIDGET_TYPES),
                error=str(exc),
                form_data=request.form,
            ), 400

    @app.get("/dashboards/<dash_id>/export")
    def dashboard_export(dash_id: str) -> Response:
        dashboards = dashboard_store.list_dashboards()
        found = next((d for d in dashboards if d["id"] == dash_id), None)
        if found is None:
            abort(404, description="Dashboard not found.")
        return Response(
            json.dumps(found, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{dash_id}.json"',
            },
        )

    @app.route("/ai", methods=["GET", "POST"])
    def ai_assistant() -> str:
        api_key_set = get_api_key_from_env() is not None
        valid, _ = report_store.list_scans()
        latest = valid[0] if valid else None

        preview_payload: str | None = None
        selected_rule_id = ""
        ai_message: str | None = None

        if request.method == "POST" and latest is not None:
            selected_rule_id = request.form.get("rule_id", "").strip()
            confirm = request.form.get("confirm_send", "") == "yes"
            target = next((f for f in latest.findings if f.rule_id == selected_rule_id), None)
            if target is not None:
                raw_text = (
                    f"Rule: {target.rule_id} — {target.title}\n"
                    f"Status: {target.status} (Severity: {target.severity})\n"
                    f"Detail: {target.detail}\n"
                    f"Why it matters: {target.why_it_matters}"
                )
                redacted, _ = Redactor(include_system_identity=False).redact(raw_text)
                preview_payload = redacted
                if confirm:
                    ai_message = (
                        "AI explainer is interface-only in v0.2 (no LLM provider is configured; "
                        "no outbound network request was made)."
                    )

        return render_template(
            "ai.html",
            api_key_set=api_key_set,
            latest=latest,
            selected_rule_id=selected_rule_id,
            preview_payload=preview_payload,
            ai_message=ai_message,
        )

    return app


def _filter_and_sort_findings(
    findings: list[FindingRecord],
    *,
    severity: str,
    status: str,
    difficulty: str,
    category: str,
    sort_by: str,
) -> list[FindingRecord]:
    out = list(findings)
    if severity:
        out = [f for f in out if f.severity == severity]
    if status:
        out = [f for f in out if f.status == status]
    if difficulty:
        out = [f for f in out if f.difficulty == difficulty]
    if category:
        out = [f for f in out if f.category == category]

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    diff_rank = {"easy": 0, "medium": 1, "hard": 2}
    stat_rank = {"fail": 0, "unknown": 1, "pass": 2}

    if sort_by == "severity":
        out.sort(key=lambda f: (sev_rank.get(f.severity, 9), stat_rank.get(f.status, 9)))
    elif sort_by == "difficulty":
        out.sort(key=lambda f: (diff_rank.get(f.difficulty, 9), sev_rank.get(f.severity, 9)))
    else:
        out.sort(
            key=lambda f: (
                stat_rank.get(f.status, 9),
                sev_rank.get(f.severity, 9),
                diff_rank.get(f.difficulty, 9),
            )
        )
    return out


def _build_widget_context(
    widget: dict[str, Any],
    latest: ScanReport | None,
    trends: Any,
) -> dict[str, Any]:
    ctx: dict[str, Any] = {"widget": widget}
    if latest is None:
        return ctx

    filters = widget.get("filters", {})
    sev_set = set(filters.get("severity", []))
    stat_set = set(filters.get("status", []))

    filtered = [
        f
        for f in latest.findings
        if (not sev_set or f.severity in sev_set) and (not stat_set or f.status in stat_set)
    ]

    ctx["findings"] = filtered
    ctx["top_fixes"] = top_fixes(filtered)
    ctx["insights"] = generate_insights(latest, trends)
    ctx["categories"] = category_breakdown(filtered)
    ctx["trends"] = trends
    ctx["trend_summary"] = trend_text_summary(trends) if trends else ""
    return ctx
