"""
Scanner Orchestrator

Runs every analyzer in sequence against a project's endpoints, aggregates the
findings, computes the risk posture, syncs endpoint risk levels to the database,
and persists scans/findings to the scan-history tables.

Supports both synchronous scans (REST API) and asynchronous background scans
(web dashboard) with progress tracking.

SAFETY:
  - Uses SafeRequestEngine (allowlist, timeouts, rate limiting, size caps).
  - Does not perform destructive requests, brute force, or DoS.
"""

import json
import logging
import re
import threading
import yaml
from datetime import datetime, timezone

from database.models import db, Project, Endpoint

logger = logging.getLogger("api-shield.orchestrator")

# In-memory scan progress (fraction 0..1) keyed by scan id.
_PROGRESS = {}
_PROGRESS_LOCK = threading.Lock()

# Sensitive key prefixes that must be masked before storage / display.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|authorization|private[_-]?key"
    r"|access[_-]?token|refresh[_-]?token|SECRET_KEY)\s*[=:]\s*([^\s,}'\"]+)"
)

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def mask_sensitive_value(text: str, keep: int = 6) -> str:
    """Redact credential-looking values keeping only a short prefix."""
    if not text:
        return text
    def _mask(match):
        key = match.group(1)
        value = match.group(2)
        if len(value) <= keep + 3:
            return f"{key}=******"
        return f"{key}={value[:keep]}***"
    return _SENSITIVE_KEY_RE.sub(_mask, text)


def get_progress(scan_id) -> float:
    with _PROGRESS_LOCK:
        return _PROGRESS.get(scan_id, 0.0)


def _set_progress(scan_id, value):
    with _PROGRESS_LOCK:
        _PROGRESS[scan_id] = max(0.0, min(1.0, value))


def load_allowed_hosts():
    """Load scanning allowlist from config/config.yaml."""
    try:
        with open("config/config.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return config.get("security", {}).get(
            "allowed_hosts", ["127.0.0.1", "localhost"]
        )
    except Exception:
        return ["127.0.0.1", "localhost"]


def is_local_target(url: str) -> bool:
    """Checks whether the target host is on the local/private allowlist."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _endpoint_urls(endpoints, base_url):
    """Yield (endpoint, full_url) skipping nothing; path-param endpoints are unresolved."""
    out = []
    for ep in endpoints:
        url = base_url.rstrip("/") + ep.path
        out.append((ep, url))
    return out


def run_full_scan(project_id: int, persist: bool = True) -> dict:
    """
    Executes the full security scan for a project (synchronously).

    :param project_id: Database id of the Project.
    :param persist:    If True, writes a Scan row and Finding rows.
    :return: Consolidated scan result.
    :raises ValueError: If the project or its endpoints do not exist.
    """
    project = Project.query.get(project_id)
    if not project:
        raise ValueError("Project not found")

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        raise ValueError("No endpoints found. Upload an OpenAPI spec first.")

    result = _execute_scan(project, endpoints, progress_scan_id=None)

    if persist:
        scan = persist_scan(project=project, result=result, endpoints=endpoints,
                            all_findings=result["_findings"])
        result["scan_id"] = scan.id
    del result["_findings"]
    return result


def _execute_scan(project, endpoints, progress_scan_id=None) -> dict:
    """Runs all analyzers and returns the report dict (includes '_findings')."""
    from scanner.request_engine import SafeRequestEngine
    from scanner.risk_engine import RiskEngine
    from tests_engine.headers import SecurityHeaderAnalyzer
    from tests_engine.tls import TLSAnalyzer
    from tests_engine.cors import CORSAnalyzer, TEST_ORIGIN
    from tests_engine.cookies import CookieAnalyzer
    from tests_engine.authentication import AuthenticationAnalyzer
    from tests_engine.error_analysis import ErrorAnalyzer
    from tests_engine.validation import InputValidationAnalyzer
    from tests_engine.rate_limit import RateLimitAnalyzer

    report = {
        "headers": [],
        "tls": [],
        "cors": [],
        "cookies": [],
        "authentication": [],
        "error_handling": [],
        "input_validation": [],
        "rate_limiting": [],
    }
    validation_test_log = []

    engine = SafeRequestEngine(allowed_hosts=load_allowed_hosts())
    total_steps = 3 + len([e for e in endpoints if "{" not in e.path])
    step = 0

    def bump():
        nonlocal step
        step += 1
        if progress_scan_id:
            _set_progress(progress_scan_id, step / total_steps)

    # 1. Project-level checks: TLS/SSL
    ta = TLSAnalyzer(base_url=project.base_url)
    report["tls"].extend(ta.analyze())
    bump()

    scanned = {"ok": 0, "skipped": 0, "error": 0}

    for ep in endpoints:
        url = project.base_url.rstrip("/") + ep.path
        has_path_param = "{" in ep.path

        if has_path_param:
            scanned["skipped"] += 1
            bump()
            continue

        response = engine.send_request(ep.method, url)
        if response.get("error"):
            scanned["error"] += 1
            bump()
            continue
        scanned["ok"] += 1

        resp_headers = response.get("headers", {})

        ha = SecurityHeaderAnalyzer(response_headers=resp_headers, endpoint_url=url, method=ep.method)
        report["headers"].extend(ha.analyze())

        cors_probe = engine.send_request(ep.method, url, headers={"Origin": TEST_ORIGIN})
        cors_headers = cors_probe.get("headers", {}) if not cors_probe.get("error") else resp_headers
        report["cors"].extend(CORSAnalyzer(response_headers=cors_headers, endpoint_url=url, method=ep.method).analyze())

        report["cookies"].extend(CookieAnalyzer(response_headers=resp_headers, endpoint_url=url, method=ep.method).analyze())

        report["authentication"].extend(AuthenticationAnalyzer(
            endpoint_url=url, method=ep.method, response_no_auth=response,
            endpoint_spec_requires_auth=ep.auth_required,
        ).analyze())

        report["error_handling"].extend(ErrorAnalyzer(
            base_url=project.base_url, endpoint_url=url, method=ep.method, request_engine=engine,
        ).analyze())

        if ep.method in {"POST", "PUT", "PATCH"}:
            va = InputValidationAnalyzer(endpoint_url=url, method=ep.method, request_engine=engine)
            va_result = va.analyze()
            report["input_validation"].extend(va_result["findings"])
            validation_test_log.extend(va_result["test_results"])

        bump()

    # Project-level checks: rate limiting + request payload size limits (API4)
    rla = RateLimitAnalyzer(
        base_url=project.base_url,
        endpoints=endpoints,
        request_engine=engine,
    )
    report["rate_limiting"] = rla.analyze()
    bump()

    all_findings = []
    for module_findings in report.values():
        all_findings.extend(module_findings)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = str(f.get("severity", "INFO")).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    risk_engine = RiskEngine()
    risk_report = risk_engine.evaluate_project(endpoints=endpoints, all_findings=all_findings)
    risk_engine.sync_endpoint_risks_to_db(project_id=project.id, all_findings=all_findings)

    project.last_scan = datetime.now(timezone.utc)
    db.session.commit()

    return {
        "scan_type": "Full Security Scan",
        "project": project.name,
        "project_id": project.id,
        "base_url": project.base_url,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints_scanned": scanned["ok"],
        "severity_summary": severity_counts,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "risk_assessment": {
            "security_score": risk_report["security_score"],
            "grade": risk_report["grade"],
            "total_risk_points": risk_report["total_risk_points"],
            "endpoint_breakdown": risk_report["endpoint_breakdown_by_risk"],
            "top_remediation_priorities": risk_report["top_priorities"],
        },
        "results_by_module": {
            "security_headers": {"count": len(report["headers"]), "findings": report["headers"]},
            "tls_ssl": {"count": len(report["tls"]), "findings": report["tls"]},
            "cors": {"count": len(report["cors"]), "findings": report["cors"]},
            "cookies": {"count": len(report["cookies"]), "findings": report["cookies"]},
            "authentication": {"count": len(report["authentication"]), "findings": report["authentication"]},
            "error_handling": {"count": len(report["error_handling"]), "findings": report["error_handling"]},
            "input_validation": {
                "count": len(report["input_validation"]),
                "findings": report["input_validation"],
                "test_log": validation_test_log,
            },
            "rate_limiting": {
                "count": len(report["rate_limiting"]),
                "findings": report["rate_limiting"],
            },
        },
        "_findings": all_findings,
        "note": "BOLA scan requires separate credentials.",
    }


# ── BOLA (extracted so both REST and web flows can reuse it) ──────────
def run_bola_analyzer(project_id: int, user_a_token: str, user_b_token: str,
                      resource_id_a="1") -> list:
    """Runs safe BOLA tests against parameterized endpoints of a project."""
    import re as _re
    from scanner.request_engine import SafeRequestEngine
    from tests_engine.authorization import AuthorizationAnalyzer

    project = Project.query.get(project_id)
    if not project:
        raise ValueError("Project not found")

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    parameterized = [ep for ep in endpoints if "{" in ep.path]
    if not parameterized:
        return []

    engine = SafeRequestEngine(allowed_hosts=load_allowed_hosts())
    all_findings = []
    for ep in parameterized:
        resolved_path = _re.sub(r"\{[^}]+\}", str(resource_id_a), ep.path)
        url = project.base_url.rstrip("/") + resolved_path
        analyzer = AuthorizationAnalyzer(
            endpoint_url=url,
            method=ep.method,
            path_template=ep.path,
            user_a_token=user_a_token,
            user_b_token=user_b_token,
            resource_id_a=resource_id_a,
            request_engine=engine,
        )
        all_findings.extend(analyzer.analyze())
    return all_findings


# ── Persistence ───────────────────────────────────────────────────────
def attach_findings(scan_id: int, findings: list):
    """Appends Finding rows to an existing scan (deduplicated by title+endpoint)."""
    from models import Scan, Finding

    scan = Scan.query.get(scan_id)
    if not scan:
        return
    existing = set()
    for f in Finding.query.filter_by(scan_id=scan_id).all():
        existing.add(f"{f.title}|{f.endpoint}|{f.method}")

    added = 0
    for f in findings:
        if "severity" not in f:
            continue
        severity = str(f.get("severity", "INFO")).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"
        key = f"{f.get('title', '')}|{f.get('endpoint', '')}|{f.get('method', '')}"
        if key in existing:
            continue
        finding = Finding(
            scan_id=scan_id,
            title=str(f.get("title", "Finding"))[:200],
            severity=severity,
            severity_order=Finding.severity_rank(severity),
            endpoint=str(f.get("endpoint", ""))[:500],
            method=str(f.get("method", ""))[:10],
            category=str(f.get("owasp", "") or f.get("category", ""))[:100],
            description=str(f.get("description", "") or ""),
            evidence=mask_sensitive_value(str(f.get("evidence", "") or "")),
            recommendation=str(f.get("recommendation", "") or ""),
            status="open",
        )
        db.session.add(finding)
        existing.add(key)
        added += 1
    db.session.commit()
    if added:
        logger.info("Scan #%s: attached %s new findings", scan_id, added)


def recompute_scan_summary(scan):
    """Recalculates severity counts + score from the scan's findings."""
    from models import Finding
    findings = Finding.query.filter_by(scan_id=scan.id).all()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    points = 0
    for f in findings:
        sev = str(f.severity).upper()
        if sev in counts:
            counts[sev] += 1
            points += SEVERITY_WEIGHTS.get(sev, 0)
    scan.severity_counts = json.dumps(counts)
    scan.tests_completed = len(findings)
    scan.score = max(0, 100 - points)
    db.session.commit()
    return scan


def persist_scan(project, result: dict, endpoints, all_findings: list):
    """Creates a Scan row with its findings (used by the synchronous flow)."""
    from models import Scan, Target

    target = Target.query.filter_by(base_url=project.base_url).first()
    if not target:
        target = Target(name=project.name, base_url=project.base_url, scan_type="full")
        db.session.add(target)
        db.session.flush()

    now_ts = datetime.now(timezone.utc).timestamp()
    scan = Scan(
        target_id=target.id,
        status="completed",
        started_at=now_ts,
        completed_at=now_ts,
        score=result["risk_assessment"]["security_score"],
        endpoints_count=result["endpoints_scanned"],
        tests_completed=result["total_findings"],
        severity_counts=json.dumps(result["severity_summary"]),
    )
    db.session.add(scan)
    db.session.flush()
    db.session.commit()

    attach_findings(scan.id, all_findings)
    logger.info("Persisted scan #%s for project '%s' (%s findings)",
                scan.id, project.name, len(all_findings))
    return scan


# ── Asynchronous scan lifecycle (web dashboard) ───────────────────────
def start_async_scan(app, project_id: int, bola: dict = None) -> int:
    """
    Creates a 'running' Scan row and launches a background worker thread.
    :return: scan id.
    """
    from models import Scan, Target

    project = Project.query.get(project_id)
    if not project:
        raise ValueError("Project not found")

    target = Target.query.filter_by(base_url=project.base_url).first()
    if not target:
        target = Target(name=project.name, base_url=project.base_url, scan_type="full")
        db.session.add(target)
        db.session.flush()

    now_ts = datetime.now(timezone.utc).timestamp()
    scan = Scan(target_id=target.id, status="running", started_at=now_ts)
    db.session.add(scan)
    db.session.commit()

    worker = threading.Thread(
        target=_async_worker,
        args=(app, project_id, scan.id, bola),
        daemon=True,
    )
    worker.start()
    return scan.id


def _async_worker(app, project_id, scan_id, bola) -> None:
    """Background job: run scan, persist results, optionally run BOLA."""
    from models import Scan

    with app.app_context():
        scan = Scan.query.get(scan_id)
        try:
            project = Project.query.get(project_id)
            if not project:
                raise ValueError("Project not found")
            endpoints = Endpoint.query.filter_by(project_id=project_id).all()
            if not endpoints:
                raise ValueError("No endpoints found. Upload an OpenAPI spec first.")

            _set_progress(scan_id, 0.02)
            result = _execute_scan(project, endpoints, progress_scan_id=scan_id)
            all_findings = result["_findings"]
            del result["_findings"]

            attach_findings(scan_id, all_findings)

            # Optional BOLA checks (authorized local lab only)
            if bola and bola.get("user_a_token") and bola.get("user_b_token"):
                if is_local_target(project.base_url):
                    bola_findings = run_bola_analyzer(
                        project_id=project_id,
                        user_a_token=bola["user_a_token"],
                        user_b_token=bola["user_b_token"],
                        resource_id_a=bola.get("resource_id_a", "1"),
                    )
                    attach_findings(scan_id, bola_findings)
                else:
                    logger.warning("BOLA skipped: target not in local lab allowlist (%s)",
                                   project.base_url)

            scan = Scan.query.get(scan_id)
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc).timestamp()
            scan.endpoints_count = result["endpoints_scanned"]
            recompute_scan_summary(scan)
            _set_progress(scan_id, 1.0)
            logger.info("Async scan #%s for project '%s' completed.", scan_id, project.name)
        except Exception as exc:
            logger.exception("Async scan #%s failed: %s", scan_id, exc)
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc).timestamp()
                db.session.commit()
            _set_progress(scan_id, 0.0)


def build_scan_report(scan_id: int) -> dict:
    """Reconstructs a ReportGenerator-ready payload from a persisted Scan."""
    from models import Scan, Target, Finding
    from scanner.risk_engine import RiskEngine
    from scanner.remediation_engine import RemediationEngine
    from scanner.report_generator import ReportGenerator

    scan = Scan.query.get(scan_id)
    if not scan:
        raise ValueError("Scan not found")
    target = Target.query.get(scan.target_id)
    if not target:
        raise ValueError("Scan target not found")

    findings = Finding.query.filter_by(scan_id=scan.id).all()
    finding_payloads = [f.to_dict() for f in findings]

    # Endpoints for risk evaluation come from the linked Project (matched by base_url).
    project = Project.query.filter_by(base_url=target.base_url).first()
    endpoints = Endpoint.query.filter_by(project_id=project.id).all() if project else []

    risk_engine = RiskEngine()
    risk_report = risk_engine.evaluate_project(endpoints=endpoints, all_findings=finding_payloads)

    remediation_engine = RemediationEngine()
    advisories = remediation_engine.generate_advisories_for_findings(finding_payloads)

    project_data = {
        "id": target.id,
        "name": target.name,
        "base_url": target.base_url,
        "description": target.notes or "",
        "owner": "admin",
        "created_date": None,
        "last_scan": None,
    }

    generator = ReportGenerator(
        project_data=project_data,
        risk_data=risk_report,
        advisories=advisories,
        findings=finding_payloads,
    )
    return {
        "generator": generator,
        "risk_report": risk_report,
        "project_data": project_data,
        "findings": finding_payloads,
    }