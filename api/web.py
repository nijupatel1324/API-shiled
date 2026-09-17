"""
Web UI routes for API-SHIELD.

Serves the SOC-style dashboard templates and manages session-based
authentication. Routes are registered directly on the Flask app so the
endpoint names (``dashboard``, ``new_scan``, ``scan_detail`` ...) match the
``url_for()`` calls used throughout the provided frontend templates.

CSRF protection:
  - Every HTML form includes the session CSRF token (``_csrf_token`` field).
  - Validated for any state-changing request that carries an existing session
    token; brand-new visitors (first request, no prior token) are allowed
    through so the REST API remains usable without a browser session.
"""

import json
import os
import secrets
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, g, current_app, render_template, request, redirect, url_for, session,
    send_file, abort, Response,
)

from database.models import db, Project, Endpoint
from scanner.orchestrator import (
    load_allowed_hosts, is_local_target, start_async_scan,
)

_REPORT_DIR = os.path.join("reports", "output")

# Maps a persisted category string to the OWASP API Security risk name.
_OWASP_MAP = {
    "API1:2023 - Broken Object Level Authorization": "Broken Object Level Authorization",
    "API2:2023 - Broken Authentication": "Broken Authentication",
    "API3:2023 - Broken Object Property Level Authorization": "Broken Object Property Level Authorization",
    "API4:2023 - Unrestricted Resource Consumption": "Unrestricted Resource Consumption",
    "API5:2023 - Broken Function Level Authorization": "Broken Function Level Authorization",
    "API6:2023 - Unrestricted Access to Sensitive Business Flows": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023 - Server-Side Request Forgery": "Server-Side Request Forgery",
    "API8:2023 - Security Misconfiguration": "Security Misconfiguration",
    "API9:2023 - Improper Inventory Management": "Improper Inventory Management",
    "API10:2023 - Unsafe Consumption of APIs": "Unsafe Consumption of APIs",
}


def _owasp_short_name(category: str) -> str:
    if not category:
        return "Uncategorised"
    if category in _OWASP_MAP:
        return _OWASP_MAP[category]
    if " - " in category:
        return category.split(" - ", 1)[1]
    return category


def _scan_datetime(ts) -> str:
    """Formats an epoch-float scan timestamp as a UTC date/time label."""
    from datetime import datetime, timezone
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError, TypeError):
        return ""


def build_score_trend() -> list:
    """Groups completed scans by target into chronological score-trend series."""
    from models import Scan

    scans = (
        Scan.query
        .filter(Scan.status == "completed", Scan.score.isnot(None))
        .order_by(Scan.started_at.asc())
        .all()
    )
    groups = {}
    for s in scans:
        key = s.target.base_url if s.target else f"target-{s.target_id}"
        counts = {}
        try:
            counts = json.loads(s.severity_counts or "{}")
        except (ValueError, TypeError):
            counts = {}
        group = groups.setdefault(key, {
            "target": s.target.name if s.target else key,
            "base_url": key,
            "points": [],
        })
        group["points"].append({
            "scan_id": s.id,
            "label": _scan_datetime(s.started_at) or f"scan #{s.id}",
            "score": s.score or 0,
            "status": s.status,
            "endpoints": s.endpoints_count or 0,
            "findings": s.tests_completed or 0,
            "counts": counts,
        })
    return [groups[key] for key in sorted(groups)]


def _current_user():
    from models import User
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.full_path))
        return view(*args, **kwargs)
    return wrapper


def _validate_target_url(url: str):
    """Returns an error string if the URL is not allowed, else None."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return "Target URL must start with http:// or https://."
    host = (parsed.hostname or "").lower()
    if host not in load_allowed_hosts():
        return (
            f"Host '{host}' is not in the scanning allowlist. "
            f"Allowed: {', '.join(load_allowed_hosts())}."
        )
    return None


_LOGIN_CANDIDATES = ["/api/login", "/auth/login", "/api/auth/login", "/login", "/token"]
_SPEC_CANDIDATES = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger"]


def _obtain_token(base_url: str, username: str, password: str):
    """Obtains a bearer token for a local lab API using provided test credentials."""
    from scanner.request_engine import SafeRequestEngine

    engine = SafeRequestEngine(allowed_hosts=load_allowed_hosts())
    payload = {"username": username, "password": password}
    for path in _LOGIN_CANDIDATES:
        resp = engine.send_request(
            "POST", base_url.rstrip("/") + path,
            headers={"Content-Type": "application/json"},
            json_data=payload,
        )
        if resp.get("error") or resp.get("status_code", 0) >= 400:
            continue
        text = resp.get("text", "") or ""
        try:
            data = json.loads(text) if text.lstrip().startswith(("{", "[")) else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        for key in ("access_token", "token", "jwt"):
            tok = data.get(key)
            if isinstance(tok, str) and tok:
                return tok
    return None


def _discover_spec_text(base_url: str):
    """Introspects common OpenAPI locations to auto-import endpoints (Option A)."""
    from scanner.request_engine import SafeRequestEngine

    engine = SafeRequestEngine(allowed_hosts=load_allowed_hosts())
    for path in _SPEC_CANDIDATES:
        resp = engine.send_request("GET", base_url.rstrip("/") + path)
        if resp.get("error") or resp.get("status_code", 0) != 200:
            continue
        text = resp.get("text", "") or ""
        if not text:
            continue
        try:
            data = json.loads(text) if text.lstrip().startswith(("{", "[")) else None
            if data is None:
                import yaml
                data = yaml.safe_load(text)
        except Exception:
            continue
        if isinstance(data, dict) and ("swagger" in data or "openapi" in data):
            return text
    return None


def _bola_config(form, spec_string=None) -> dict:
    """Obtains two BOLA test tokens from the supplied lab credentials (local target only)."""
    admin_u = (form.get("admin_username") or "").strip()
    admin_p = form.get("admin_password") or ""
    user_u = (form.get("user_username") or "").strip()
    user_p = form.get("user_password") or ""
    target_url = (form.get("target_url") or "").strip()

    if not (admin_u and admin_p and user_u and user_p):
        return None
    if not is_local_target(target_url):
        return None

    admin_token = _obtain_token(target_url, admin_u, admin_p)
    user_token = _obtain_token(target_url, user_u, user_p)
    if not (admin_token and user_token):
        return None
    return {
        "user_a_token": admin_token,
        "user_b_token": user_token,
        "resource_id_a": _resolve_resource_id(form, spec_string),
    }


def _save_spec_to_project(project: Project, spec_string: str):
    """Parses an OpenAPI spec and (re)populates the project's endpoints."""
    from scanner.openapi_parser import OpenAPIParser

    parser = OpenAPIParser(spec_string)
    parsed = parser.parse()
    project.api_specification = spec_string
    Endpoint.query.filter_by(project_id=project.id).delete()
    for ep_data in parsed["endpoints"]:
        db.session.add(Endpoint(
            project_id=project.id,
            path=ep_data["path"],
            method=ep_data["method"],
            auth_required=ep_data["auth_required"],
            parameters_count=ep_data["parameters"],
            has_body=ep_data["has_body"],
        ))
    db.session.commit()
    return parsed


def _spec_base_url(spec_string: str, form_url: str) -> str:
    """Resolves the scan base URL from form input or the spec's servers[0]."""
    form_url = (form_url or "").strip()
    if form_url:
        return form_url
    data = None
    try:
        data = json.loads(spec_string)
    except ValueError:
        import yaml
        try:
            data = yaml.safe_load(spec_string)
        except yaml.YAMLError:
            data = None
    if isinstance(data, dict):
        servers = data.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            return servers[0].get("url", "")
    return ""


def _param_example(p: dict):
    """Reads example/default values from an OpenAPI parameter object."""
    if not isinstance(p, dict):
        return None
    value = p.get("example")
    schema = p.get("schema")
    if value is None and isinstance(schema, dict):
        value = schema.get("default")
        if value is None:
            value = schema.get("example")
    if isinstance(value, bool):
        value = str(value).lower()
    elif isinstance(value, (int, float)):
        value = str(value)
    return value if isinstance(value, str) and value else None


def _extract_resource_id(spec_string: str):
    """Extracts the first path-parameter example id from an OpenAPI spec.

    Checks operation-level parameters first, then path-level parameters across
    all operations. Only 'in: path' parameters with an example/default are used
    so BOLA tests resolve parameterized endpoints with a realistic value.
    """
    if not spec_string:
        return None
    data = None
    try:
        data = json.loads(spec_string)
    except ValueError:
        import yaml
        try:
            data = yaml.safe_load(spec_string)
        except yaml.YAMLError:
            data = None
    if not isinstance(data, dict):
        return None

    paths = data.get("paths") or {}
    for item in paths.values():
        if not isinstance(item, dict):
            continue
        param_lists = []
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            operation = item.get(method)
            if isinstance(operation, dict) and operation.get("parameters"):
                param_lists.append(operation["parameters"])
        if item.get("parameters"):
            param_lists.append(item["parameters"])
        for params in param_lists:
            for p in params:
                if isinstance(p, dict) and p.get("in") == "path":
                    value = _param_example(p)
                    if value is not None:
                        return value
    return None


def _resolve_resource_id(form, spec_string=None) -> str:
    """Form-specified BOLA resource id, else spec example, else default '1'."""
    resource_id = (form.get("resource_id") or "").strip()
    if resource_id:
        return resource_id
    return _extract_resource_id(spec_string) or "1"


def register_web_routes(app: Flask):
    """Attach all page/form routes to the app (endpoints used by templates)."""

    @app.before_request
    def _ensure_csrf_token():
        g.csrf_new = "csrf_token" not in session
        if g.csrf_new:
            session["csrf_token"] = secrets.token_hex(16)

    @app.before_request
    def _validate_csrf():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        if request.path.startswith("/api/"):
            return  # REST API is protected by session cookie + SameSite=Lax
        if getattr(g, "csrf_new", True):
            return  # fresh visitor, no prior token to protect
        token = session.get("csrf_token")
        supplied = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("_csrf_token")
            or request.form.get("csrf_token")
        )
        if not token or not supplied or supplied != token:
            return render_template("error.html", code=400,
                                   message="CSRF validation failed. Refresh the page and try again."), 400

    @app.context_processor
    def _inject_globals():
        return {
            "csrf_token": session.get("csrf_token", ""),
            "current_user": _current_user(),
        }

    # ── Auth ──────────────────────────────────────────────────────────
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            from models import User
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                session["user_id"] = user.id
                session.permanent = True
                nxt = (request.form.get("next") or "").strip() or url_for("dashboard")
                if not nxt.startswith("/"):
                    nxt = url_for("dashboard")
                return redirect(nxt)
            return render_template(
                "login.html",
                error="Invalid username or password.",
                next=request.form.get("next", ""),
            ), 401
        return render_template("login.html", next=request.args.get("next", ""))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ── Pages ──────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        from models import Scan
        recent = Scan.query.order_by(Scan.started_at.desc()).limit(6).all()
        return render_template("dashboard.html", recent=recent)

    @app.route("/trends")
    @login_required
    def trends():
        return render_template("trends.html", trends=build_score_trend())

    @app.route("/trends/export")
    @login_required
    def trends_export():
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "target", "base_url", "scan_id", "scan_date_utc", "score",
            "status", "endpoints", "findings",
            "critical", "high", "medium", "low", "info",
        ])
        for group in build_score_trend():
            for p in group["points"]:
                writer.writerow([
                    group["target"], group["base_url"], p["scan_id"], p["label"],
                    p["score"], p["status"], p["endpoints"], p["findings"],
                    p["counts"].get("CRITICAL", 0), p["counts"].get("HIGH", 0),
                    p["counts"].get("MEDIUM", 0), p["counts"].get("LOW", 0),
                    p["counts"].get("INFO", 0),
                ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=score_trend.csv"},
        )

    @app.route("/scan/new")
    @login_required
    def new_scan():
        return render_template("new_scan.html")

    @app.route("/scan/start", methods=["POST"])
    @login_required
    def start_scan_form():
        name = (request.form.get("target_name") or "").strip() or "Imported target"
        base_url = (request.form.get("target_url") or "").strip()
        err = _validate_target_url(base_url)
        if err:
            return render_template("new_scan.html", error=err), 400
        try:
            project = Project(name=name, base_url=base_url)
            db.session.add(project)
            db.session.commit()

            # Auto-import endpoints from the target's OpenAPI doc if available.
            spec_text = _discover_spec_text(base_url)
            if spec_text:
                _save_spec_to_project(project, spec_text)
            elif Endpoint.query.filter_by(project_id=project.id).count() == 0:
                db.session.delete(project)
                db.session.commit()
                return render_template(
                    "new_scan.html",
                    error="No endpoints were discovered at this base URL. "
                          "Use Option B to upload an OpenAPI/Swagger file.",
                ), 400

            scan_id = start_async_scan(current_app._get_current_object(),
                                       project.id, bola=_bola_config(request.form, spec_text))
        except Exception as exc:
            db.session.rollback()
            return render_template("new_scan.html",
                                   error=f"Scan could not be started: {exc}"), 500
        return redirect(url_for("scan_detail", scan_id=scan_id))

    @app.route("/scan/upload", methods=["POST"])
    @login_required
    def start_scan_upload():
        upload = request.files.get("spec_file")
        if not upload:
            return render_template("new_scan.html", error="No spec file provided."), 400
        if upload.filename and not upload.filename.lower().endswith((".json", ".yaml", ".yml")):
            return render_template("new_scan.html",
                                   error="Spec file must be JSON or YAML (.json/.yaml/.yml)."), 400
        if request.content_length and request.content_length > 2 * 1024 * 1024:
            return render_template("new_scan.html", error="Spec file exceeds the 2 MB limit."), 413

        spec_string = upload.read().decode("utf-8", errors="replace")
        base_url = _spec_base_url(spec_string, request.form.get("target_url", ""))
        err = _validate_target_url(base_url)
        if err:
            return render_template("new_scan.html", error=err), 400

        name = (request.form.get("target_name") or "").strip() \
            or os.path.splitext(upload.filename or "spec")[0] or "Imported target"
        try:
            project = Project(name=name, base_url=base_url)
            db.session.add(project)
            db.session.commit()
            _save_spec_to_project(project, spec_string)
            scan_id = start_async_scan(current_app._get_current_object(),
                                       project.id, bola=_bola_config(request.form, spec_string))
        except Exception as exc:
            db.session.rollback()
            return render_template("new_scan.html",
                                   error=f"Scan could not be started: {exc}"), 500
        return redirect(url_for("scan_detail", scan_id=scan_id))

    @app.route("/scans")
    @login_required
    def scans():
        from models import Scan
        scans = Scan.query.order_by(Scan.started_at.desc()).all()
        return render_template("scans.html", scans=scans)

    @app.route("/scans/<int:scan_id>")
    @login_required
    def scan_detail(scan_id):
        from models import Scan, Finding
        scan = Scan.query.get(scan_id)
        if not scan:
            abort(404)
        findings = (Finding.query.filter_by(scan_id=scan.id)
                    .order_by(Finding.severity_order).all())
        return render_template("scan_results.html", scan=scan, findings=findings)

    @app.route("/scans/<int:scan_id>/rescan", methods=["POST"])
    @login_required
    def rescan_scan(scan_id):
        from models import Scan
        scan = Scan.query.get(scan_id)
        if not scan or not scan.target:
            abort(404)
        project = Project.query.filter_by(base_url=scan.target.base_url).first()
        if not project:
            abort(404)
        new_scan_id = start_async_scan(current_app._get_current_object(),
                                       project.id)
        return redirect(url_for("scan_detail", scan_id=new_scan_id))

    def _render_schedules(error=None, **overrides):
        from models import ScanSchedule, Target
        rendered = []
        for s in ScanSchedule.query.order_by(ScanSchedule.id.desc()).all():
            rendered.append({
                "id": s.id,
                "target": s.target,
                "interval_hours": s.interval_hours,
                "enabled": s.enabled,
                "next_label": _scan_datetime(s.next_run_at) or "as soon as possible",
                "last_label": _scan_datetime(s.last_run_at) or "—",
            })
        ctx = {
            "schedules": rendered,
            "targets": Target.query.order_by(Target.base_url).all(),
            "error": error,
        }
        ctx.update(overrides)
        return render_template("schedules.html", **ctx)

    @app.route("/schedules")
    @login_required
    def schedules():
        return _render_schedules()

    @app.route("/schedules/new", methods=["POST"])
    @login_required
    def schedule_new():
        import time as _time

        from models import ScanSchedule, Target

        target_id = request.form.get("target_id")
        interval = request.form.get("interval_hours") or "24"
        try:
            target_id = int(target_id)
            interval = max(1, int(interval))
        except (TypeError, ValueError):
            return _render_schedules(error="Invalid target or interval."), 400
        if not Target.query.get(target_id):
            return _render_schedules(error="Selected target does not exist."), 404
        sched = ScanSchedule(
            target_id=target_id,
            interval_hours=interval,
            enabled=True,
            next_run_at=_time.time(),
        )
        db.session.add(sched)
        db.session.commit()
        return redirect(url_for("schedules"))

    @app.route("/schedules/<int:sched_id>/toggle", methods=["POST"])
    @login_required
    def schedule_toggle(sched_id):
        from models import ScanSchedule
        sched = ScanSchedule.query.get(sched_id)
        if not sched:
            abort(404)
        sched.enabled = not sched.enabled
        db.session.commit()
        return redirect(url_for("schedules"))

    @app.route("/schedules/<int:sched_id>/delete", methods=["POST"])
    @login_required
    def schedule_delete(sched_id):
        from models import ScanSchedule
        sched = ScanSchedule.query.get(sched_id)
        if not sched:
            abort(404)
        db.session.delete(sched)
        db.session.commit()
        return redirect(url_for("schedules"))

    @app.route("/findings/<int:fid>")
    @login_required
    def finding_detail(fid):
        from models import Finding
        finding = Finding.query.get(fid)
        if not finding:
            abort(404)
        return render_template("finding.html", f=finding, owasp=_OWASP_MAP)

    @app.route("/reports")
    @login_required
    def reports():
        from models import Report
        rows = Report.query.order_by(Report.id.desc()).all()
        return render_template("reports.html", reports=rows)

    @app.route("/reports/download")
    @login_required
    def download_report_file():
        fname = request.args.get("filepath") or ""
        safe = os.path.basename(fname)
        if not safe:
            abort(404)
        full = os.path.join(_REPORT_DIR, safe)
        if not os.path.exists(full):
            abort(404)
        return send_file(full, as_attachment=True, download_name=safe)