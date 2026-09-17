"""End-to-end scan flow tests (live local lab) — orchestrator, persistence, BOLA, reports."""

import json

import requests

from database.models import db, Project, Endpoint
from scanner.openapi_parser import OpenAPIParser
from scanner.orchestrator import (
    load_allowed_hosts, run_bola_analyzer, run_full_scan, build_scan_report,
)
from scanner.request_engine import SafeRequestEngine


def _seed_lab_project(app):
    """Creates a Project with all endpoints from the lab's own swagger.json."""
    spec = requests.get("http://127.0.0.1:5001/swagger.json", timeout=10).text
    parsed = OpenAPIParser(spec).parse()
    project = Project(name="Lab End-to-End", base_url="http://127.0.0.1:5001")
    db.session.add(project)
    db.session.flush()
    for ep in parsed["endpoints"]:
        db.session.add(Endpoint(
            project_id=project.id,
            path=ep["path"], method=ep["method"],
            auth_required=ep["auth_required"],
            parameters_count=ep["parameters"], has_body=ep["has_body"],
        ))
    db.session.commit()
    return project


def _lab_tokens():
    engine = SafeRequestEngine(allowed_hosts=load_allowed_hosts())
    tokens = {}
    for user, pwd in (("admin", "admin123"), ("user", "user123")):
        resp = engine.send_request(
            "POST", "http://127.0.0.1:5001/api/login",
            headers={"Content-Type": "application/json"},
            json_data={"username": user, "password": pwd},
        )
        body = json.loads(resp["text"])
        tokens[user] = body.get("access_token")
    return tokens


def test_full_scan_persists_findings(app, lab_server):
    with app.app_context():
        project = _seed_lab_project(app)
        result = run_full_scan(project.id, persist=True)

        assert result["endpoints_scanned"] >= 5
        assert result["total_findings"] > 0
        assert result["severity_summary"]["CRITICAL"] >= 1
        assert result["risk_assessment"]["security_score"] <= 60

        from models import Scan, Finding
        scan = Scan.query.get(result["scan_id"])
        assert scan is not None
        assert scan.status == "completed"
        assert scan.score is not None
        assert len(scan.findings) > 0
        assert Finding.query.filter_by(scan_id=scan.id).count() == len(scan.findings)


def test_bola_analysis_detects_idor(app, lab_server):
    with app.app_context():
        project = _seed_lab_project(app)
        tokens = _lab_tokens()
        assert tokens["admin"] and tokens["user"]

        findings = run_bola_analyzer(
            project.id, tokens["admin"], tokens["user"], resource_id_a="1",
        )
        assert findings, "laboratory IDOR endpoint must yield BOLA findings"
        severities = {f.get("severity") for f in findings}
        assert "CRITICAL" in severities or "HIGH" in severities


def test_report_generation_from_persisted_scan(app, lab_server, tmp_path):
    with app.app_context():
        project = _seed_lab_project(app)
        result = run_full_scan(project.id, persist=True)
        scan_id = result["scan_id"]

        payload = build_scan_report(scan_id)
        generator = payload["generator"]

        html = generator.generate_html_report()
        md = generator.generate_markdown_report()
        js = generator.generate_json_report()
        assert "API-SHIELD" in html
        assert isinstance(js, dict)
        summary = js.get("executive_summary", {})
        assert summary.get("total_findings") == len(payload["findings"])
        assert summary.get("total_endpoints") > 0
        assert "all_findings" in js and len(js["all_findings"]) > 0


def test_scan_persistence_roundtrip_through_api(app, lab_server):
    with app.app_context():
        project = _seed_lab_project(app)
        result = run_full_scan(project.id, persist=True)
        scan_id = result["scan_id"]

        from models import Scan
        scan = Scan.query.get(scan_id)
        assert scan.target is not None
        assert scan.target.base_url == "http://127.0.0.1:5001"
        assert scan.severity_counts
        counts = json.loads(scan.severity_counts)
        assert isinstance(counts, dict)