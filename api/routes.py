from flask import Blueprint, request, jsonify
from database.models import db, Project, Endpoint
from scanner.openapi_parser import OpenAPIParser

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/projects', methods=['POST'])
def create_project():
    data = request.get_json()
    if not data or not data.get('name') or not data.get('base_url'):
        return jsonify({"error": "Missing required fields: 'name' and 'base_url'"}), 400

    new_project = Project(
        name=data['name'],
        base_url=data['base_url'],
        description=data.get('description', '')
    )
    
    db.session.add(new_project)
    db.session.commit()

    return jsonify({"message": "Project created successfully", "project": new_project.to_dict()}), 201

@api_bp.route('/projects', methods=['GET'])
def list_projects():
    projects = Project.query.all()
    return jsonify([p.to_dict() for p in projects]), 200

@api_bp.route('/projects/<int:project_id>/spec', methods=['POST'])
def upload_spec(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    spec_string = request.get_data(as_text=True)
    if not spec_string:
        return jsonify({"error": "No specification provided"}), 400

    try:
        parser = OpenAPIParser(spec_string)
        parsed_data = parser.parse()
        
        # Save raw spec to project
        project.api_specification = spec_string
        
        # Delete existing endpoints for this project before re-importing
        Endpoint.query.filter_by(project_id=project.id).delete()

        # Save endpoints to database
        saved_endpoints = []
        for ep_data in parsed_data['endpoints']:
            new_endpoint = Endpoint(
                project_id=project.id,
                path=ep_data['path'],
                method=ep_data['method'],
                auth_required=ep_data['auth_required'],
                parameters_count=ep_data['parameters'],
                has_body=ep_data['has_body']
            )
            db.session.add(new_endpoint)
            saved_endpoints.append(new_endpoint)
            
        db.session.commit()

        return jsonify({
            "message": "Specification parsed and endpoints saved successfully",
            "metadata": {
                "title": parsed_data["title"],
                "version": parsed_data["version"],
                "endpoints_found": len(saved_endpoints)
            }
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to parse specification: {str(e)}"}), 500

@api_bp.route('/projects/<int:project_id>/endpoints', methods=['GET'])
def get_project_endpoints(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404
        
    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    return jsonify([ep.to_dict() for ep in endpoints]), 200


from scanner.request_engine import SafeRequestEngine
from tests_engine.headers import SecurityHeaderAnalyzer
import yaml

def _load_app_config():
    """Load allowed_hosts from config.yaml."""
    try:
        with open('config/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        return config.get('security', {}).get('allowed_hosts', ['127.0.0.1', 'localhost'])
    except Exception:
        return ['127.0.0.1', 'localhost']

@api_bp.route('/projects/<int:project_id>/scan/headers', methods=['POST'])
def scan_headers(project_id):
    """
    Runs the Security Header Analyzer against all endpoints of a project.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found. Upload a spec first."}), 400

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []
    for ep in endpoints:
        url = project.base_url.rstrip('/') + ep.path
        response = engine.send_request(ep.method, url)

        if response.get("error"):
            # Log the error but continue scanning other endpoints
            all_findings.append({
                "endpoint": url,
                "method": ep.method,
                "error": response["error"]
            })
            continue

        analyzer = SecurityHeaderAnalyzer(
            response_headers=response.get("headers", {}),
            endpoint_url=url,
            method=ep.method
        )
        findings = analyzer.analyze()
        all_findings.extend(findings)

    return jsonify({
        "scan_type": "Security Header Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings
    }), 200


from tests_engine.tls import TLSAnalyzer

@api_bp.route('/projects/<int:project_id>/scan/tls', methods=['POST'])
def scan_tls(project_id):
    """
    Runs the TLS/HTTPS Analyzer against the project's base URL.
    TLS analysis is performed at the project level (not per-endpoint),
    since TLS configuration applies to the entire server.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    analyzer = TLSAnalyzer(base_url=project.base_url)
    findings = analyzer.analyze()

    return jsonify({
        "scan_type": "TLS/HTTPS Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "total_findings": len(findings),
        "findings": findings
    }), 200


from tests_engine.cors import CORSAnalyzer, TEST_ORIGIN

@api_bp.route('/projects/<int:project_id>/scan/cors', methods=['POST'])
def scan_cors(project_id):
    """
    Runs CORS analysis against all endpoints of a project.
    Sends a preflight-style request with a custom test Origin header
    to evaluate what the server reflects back.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found. Upload a spec first."}), 400

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []
    for ep in endpoints:
        url = project.base_url.rstrip('/') + ep.path

        # Send request with a fake cross-origin Origin header to probe the CORS policy
        cors_headers = {"Origin": TEST_ORIGIN}
        response = engine.send_request(ep.method, url, headers=cors_headers)

        if response.get("error"):
            all_findings.append({
                "endpoint": url,
                "method": ep.method,
                "error": response["error"]
            })
            continue

        analyzer = CORSAnalyzer(
            response_headers=response.get("headers", {}),
            endpoint_url=url,
            method=ep.method
        )
        findings = analyzer.analyze()
        all_findings.extend(findings)

    return jsonify({
        "scan_type": "CORS Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "test_origin_used": TEST_ORIGIN,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings
    }), 200


from tests_engine.cookies import CookieAnalyzer

@api_bp.route('/projects/<int:project_id>/scan/cookies', methods=['POST'])
def scan_cookies(project_id):
    """
    Runs Cookie Security Analysis against all endpoints of a project.
    Checks for missing Secure, HttpOnly, SameSite flags and broad domain scope.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found. Upload a spec first."}), 400

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []
    cookies_found = 0

    for ep in endpoints:
        url = project.base_url.rstrip('/') + ep.path
        response = engine.send_request(ep.method, url)

        if response.get("error"):
            all_findings.append({
                "endpoint": url,
                "method": ep.method,
                "error": response["error"]
            })
            continue

        resp_headers = response.get("headers", {})

        # Count how many Set-Cookie headers we found across all endpoints
        for key in resp_headers:
            if key.lower() == "set-cookie":
                cookies_found += 1

        analyzer = CookieAnalyzer(
            response_headers=resp_headers,
            endpoint_url=url,
            method=ep.method
        )
        findings = analyzer.analyze()
        all_findings.extend(findings)

    return jsonify({
        "scan_type": "Cookie Security Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "cookies_found": cookies_found,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings
    }), 200


from tests_engine.authentication import AuthenticationAnalyzer

@api_bp.route('/projects/<int:project_id>/scan/auth', methods=['POST'])
def scan_authentication(project_id):
    """
    Runs Authentication Security Analysis against all project endpoints.

    For each endpoint, sends ONE unauthenticated request and checks:
      1. Does an auth-required endpoint return 2xx without credentials? (Missing Auth)
      2. Is the authentication scheme weak (e.g., HTTP Basic)?
      3. Do error responses leak verbose information?

    SAFETY: Does NOT brute-force. ONE request per endpoint, no credentials used.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found. Upload a spec first."}), 400

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []
    summary = {"protected": 0, "public": 0, "missing_auth": 0}

    for ep in endpoints:
        url = project.base_url.rstrip('/') + ep.path

        # Send a single request with NO authentication headers
        response = engine.send_request(ep.method, url)

        if response.get("error"):
            all_findings.append({
                "endpoint": url,
                "method": ep.method,
                "error": response["error"]
            })
            continue

        status = response.get("status_code", 0)

        # Update summary counters
        if status in {401, 403}:
            summary["protected"] += 1
        elif status in {200, 201, 202, 204} and ep.auth_required:
            summary["missing_auth"] += 1
        else:
            summary["public"] += 1

        analyzer = AuthenticationAnalyzer(
            endpoint_url=url,
            method=ep.method,
            response_no_auth=response,
            endpoint_spec_requires_auth=ep.auth_required
        )
        findings = analyzer.analyze()
        all_findings.extend(findings)

    return jsonify({
        "scan_type": "Authentication Security Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "summary": summary,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings
    }), 200


from tests_engine.authorization import AuthorizationAnalyzer
import base64

@api_bp.route('/projects/<int:project_id>/scan/bola', methods=['POST'])
def scan_bola(project_id):
    """
    Runs BOLA (Broken Object Level Authorization) tests against parameterized
    endpoints in the project using two pre-configured lab test accounts.

    Request body (JSON) — required:
    {
        "user_a": {
            "username": "admin",
            "token": "<base64_encoded_username>"
        },
        "user_b": {
            "username": "john",
            "token": "<base64_encoded_username>"
        },
        "resource_id_a": "1"
    }

    SAFETY: Only works against this project's authorized base_url.
    All tokens and users must be pre-created in the local lab environment.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required with user_a, user_b, and resource_id_a"}), 400

    user_a = data.get("user_a", {})
    user_b = data.get("user_b", {})
    resource_id_a = data.get("resource_id_a", "1")

    if not user_a.get("token") or not user_b.get("token"):
        return jsonify({"error": "Both user_a.token and user_b.token are required"}), 400

    # Find all parameterized endpoints (those with {id} or path parameters)
    all_endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    parameterized = [ep for ep in all_endpoints if '{' in ep.path]

    if not parameterized:
        return jsonify({
            "scan_type": "BOLA Analysis",
            "message": "No parameterized endpoints (e.g., /api/users/{id}) found in inventory.",
            "findings": []
        }), 200

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []

    for ep in parameterized:
        # Substitute the path parameter with User A's resource ID
        # Handles {id}, {user_id}, {userId} etc.
        import re
        resolved_path = re.sub(r'\{[^}]+\}', str(resource_id_a), ep.path)
        url = project.base_url.rstrip('/') + resolved_path

        analyzer = AuthorizationAnalyzer(
            endpoint_url=url,
            method=ep.method,
            path_template=ep.path,
            user_a_token=user_a["token"],
            user_b_token=user_b["token"],
            resource_id_a=resource_id_a,
            request_engine=engine
        )
        findings = analyzer.analyze()
        all_findings.extend(findings)

    return jsonify({
        "scan_type": "BOLA Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "parameterized_endpoints_tested": len(parameterized),
        "user_a": user_a.get("username"),
        "user_b": user_b.get("username"),
        "resource_id_tested": resource_id_a,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings
    }), 200


from tests_engine.validation import InputValidationAnalyzer

@api_bp.route('/projects/<int:project_id>/scan/validation', methods=['POST'])
def scan_validation(project_id):
    """
    Runs safe Input Validation tests against all POST/PUT/PATCH endpoints.

    Sends 8 safe, non-destructive test payloads per qualifying endpoint:
      - Empty body
      - Missing required fields
      - Type mismatches
      - Boundary values (very long strings, negatives)
      - Invalid formats
      - Mass assignment probe (extra fields like 'role: admin')

    Detects:
      - Missing input validation (API accepts bad input with 2xx)
      - Server crashes on bad input (500 errors)
      - Potential mass assignment vulnerabilities
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found. Upload a spec first."}), 400

    # Only test endpoints that accept a body
    body_endpoints = [ep for ep in endpoints if ep.method in {"POST", "PUT", "PATCH"}]

    if not body_endpoints:
        return jsonify({
            "scan_type": "Input Validation Analysis",
            "message": "No POST/PUT/PATCH endpoints found in inventory.",
            "findings": []
        }), 200

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []
    all_test_results = []
    endpoints_tested = 0

    for ep in body_endpoints:
        url = project.base_url.rstrip('/') + ep.path
        # Skip URLs with unresolved path parameters for body tests
        if '{' in url:
            continue

        analyzer = InputValidationAnalyzer(
            endpoint_url=url,
            method=ep.method,
            request_engine=engine
        )
        result = analyzer.analyze()
        all_findings.extend(result["findings"])
        all_test_results.extend(result["test_results"])
        endpoints_tested += 1

    return jsonify({
        "scan_type": "Input Validation Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "endpoints_tested": endpoints_tested,
        "test_cases_run": len(all_test_results),
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings,
        "test_log": all_test_results
    }), 200


from tests_engine.error_analysis import ErrorAnalyzer

@api_bp.route('/projects/<int:project_id>/scan/errors', methods=['POST'])
def scan_errors(project_id):
    """
    Runs Error Handling / Information Disclosure analysis.

    Sends safe error-triggering requests (non-existent paths, malformed JSON,
    invalid auth) and scans error responses for:
      - Stack traces
      - File system paths
      - Database error messages
      - Framework version disclosure
      - Internal IP addresses
      - Debug mode indicators
      - Secret/credential leaks
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found. Upload a spec first."}), 400

    allowed_hosts = _load_app_config()
    engine = SafeRequestEngine(allowed_hosts=allowed_hosts)

    all_findings = []

    for ep in endpoints:
        url = project.base_url.rstrip('/') + ep.path
        if '{' in url:
            continue

        analyzer = ErrorAnalyzer(
            base_url=project.base_url,
            endpoint_url=url,
            method=ep.method,
            request_engine=engine
        )
        findings = analyzer.analyze()
        all_findings.extend(findings)

    return jsonify({
        "scan_type": "Error Handling / Information Disclosure Analysis",
        "project": project.name,
        "base_url": project.base_url,
        "total_findings": len([f for f in all_findings if "severity" in f]),
        "findings": all_findings
    }), 200


# ═══════════════════════════════════════════════════════════════
# Phase 15 — Full Scan Aggregator
# Runs ALL security analyzers in one call and returns a
# consolidated report with severity breakdown.
# ═══════════════════════════════════════════════════════════════
from scanner.orchestrator import run_full_scan

@api_bp.route('/projects/<int:project_id>/scan/full', methods=['POST'])
def scan_full(project_id):
    """
    Runs a full security scan covering all available analyzers:
      1. Security Headers
      2. TLS/SSL
      3. CORS
      4. Cookies
      5. Authentication
      6. Error Handling / Info Disclosure
      7. Input Validation (POST/PUT/PATCH only)

    BOLA is excluded from the full scan because it requires explicit
    test-account credentials. Use POST /scan/bola separately.

    Returns a consolidated report grouped by scan module with
    an overall severity summary.
    """
    try:
        result = run_full_scan(project_id)
    except ValueError as e:
        msg = str(e)
        return jsonify({"error": msg}), 404 if "not found" in msg.lower() else 400
    except Exception as e:
        logger = __import__("logging").getLogger("api-shield.routes")
        logger.exception("Full scan failed for project #%s", project_id)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500
    return jsonify(result), 200


# ═══════════════════════════════════════════════════════════════
# Phase 19 — Scan History API
# Persists scans, lists history, and regenerates reports.
# ═══════════════════════════════════════════════════════════════
from models import Scan, Target, Finding, Report as Reporting
from flask import jsonify, Response as FlaskResponse, send_file

@api_bp.route('/scan', methods=['POST'])
def start_scan():
    """
    Starts (and synchronously completes) a full security scan for a project.

    Request body:
    {
      "project_id": 1,
      "persist": true
    }

    Returns the consolidated scan result including a scan_id once complete.
    """
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "Field 'project_id' is required."}), 400

    persist = bool(data.get("persist", True))

    try:
        result = run_full_scan(int(project_id), persist=persist)
    except ValueError as e:
        msg = str(e)
        return jsonify({"error": msg}), 404 if "not found" in msg.lower() else 400
    except Exception as e:
        logger = __import__("logging").getLogger("api-shield.routes")
        logger.exception("API scan failed for project #%s", project_id)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    return jsonify(result), 200


@api_bp.route('/scans', methods=['GET'])
def list_scans():
    """Lists all persisted scans, newest first, with target info and score."""
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    items = []
    for sc in scans:
        target = Target.query.get(sc.target_id)
        items.append({
            "id": sc.id,
            "status": sc.status,
            "target": target.name if target else None,
            "base_url": target.base_url if target else None,
            "score": sc.score,
            "endpoints_count": sc.endpoints_count,
            "tests_completed": sc.tests_completed,
            "started_at": _ts_to_iso(sc.started_at),
            "completed_at": _ts_to_iso(sc.completed_at),
            "severity_counts": _safe_json(sc.severity_counts),
        })
    return jsonify({"total": len(items), "scans": items}), 200


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Returns a single persisted scan with its findings (wrapped as data.scan)."""
    from scanner.orchestrator import get_progress

    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    target = Target.query.get(scan.target_id)
    findings = Finding.query.filter_by(scan_id=scan.id).order_by(Finding.severity_order).all()
    counts = _safe_json(scan.severity_counts)
    if scan.status == "running":
        progress = get_progress(scan_id)
    elif scan.status == "completed":
        progress = 1.0
    else:
        progress = 0.0

    payload = {
        "id": scan.id,
        "status": scan.status,
        "target": target.name if target else None,
        "base_url": target.base_url if target else None,
        "score": scan.score,
        "grade": _score_to_grade(scan.score),
        "progress": progress,
        "endpoints_count": scan.endpoints_count,
        "tests_completed": scan.tests_completed,
        "started_at": _ts_to_iso(scan.started_at),
        "completed_at": _ts_to_iso(scan.completed_at),
        "severity_counts": counts,
        "counts": counts,
        "findings": [f.to_dict() for f in findings],
        "total_findings": len(findings),
    }
    return jsonify({"scan": payload}), 200


@api_bp.route('/score/<int:scan_id>', methods=['GET'])
def get_scan_score(scan_id):
    """Severity counts, OWASP category counts, score and grade for chart widgets."""
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = Finding.query.filter_by(scan_id=scan.id).all()
    counts = _safe_json(scan.severity_counts)
    if not counts:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = str(f.severity).upper()
            if sev in counts:
                counts[sev] += 1

    owasp = {}
    for f in findings:
        name = (f.category or "Uncategorised").split(" - ", 1)[-1]
        owasp[name] = owasp.get(name, 0) + 1

    return jsonify({
        "counts": counts,
        "owasp": owasp,
        "score": scan.score or 0,
        "grade": _score_to_grade(scan.score),
        "endpoints_count": scan.endpoints_count,
    }), 200


@api_bp.route('/findings/<int:finding_id>', methods=['GET'])
def get_finding(finding_id):
    """Returns a single finding by id."""
    finding = Finding.query.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify(finding.to_dict()), 200


@api_bp.route('/report/<int:scan_id>', methods=['POST'])
def generate_report(scan_id):
    """
    Generates report files (HTML, JSON, PDF) for a persisted scan.
    Returns the generated file paths and their report rows.
    """
    from scanner.orchestrator import build_scan_report
    from scanner.report_generator import ReportGenerator
    from scanner.pdf_report import generate_pdf_report

    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    try:
        payload = build_scan_report(scan_id)
        generator = payload["generator"]

        out_dir = _os.path.join("reports", "output")
        _os.makedirs(out_dir, exist_ok=True)

        from datetime import datetime as _dt
        stamp = _dt.now().strftime("%Y%m%d_%H%M%S")
        base = _os.path.join(out_dir, f"scan_{scan_id}_{stamp}")

        html_path = base + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(generator.generate_html_report())

        json_path = base + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            _json.dump(generator.generate_json_report(), f, indent=2)

        pdf_path = base + ".pdf"
        generate_pdf_report(generator.generate_json_report(), pdf_path)

        # Record report rows
        generated = []
        for rtype, path in (("html", html_path), ("json", json_path), ("pdf", pdf_path)):
            report_row = Reporting(
                scan_id=scan_id, report_type=rtype,
                file_path=path,
                generated_at=_dt.now().timestamp(),
            )
            db.session.add(report_row)
            generated.append({"type": rtype, "file_path": path, "id": report_row.id})
        db.session.commit()

        return jsonify({"message": "Reports generated successfully", "reports": generated}), 200
    except Exception as e:
        logger = __import__("logging").getLogger("api-shield.routes")
        logger.exception("Report generation failed for scan #%s", scan_id)
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500


@api_bp.route('/report/<int:scan_id>/html', methods=['GET'])
def view_scan_html_report(scan_id):
    """Renders the regenerated HTML report for a persisted scan in the browser."""
    from scanner.orchestrator import build_scan_report
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    try:
        generator = build_scan_report(scan_id)["generator"]
        return FlaskResponse(generator.generate_html_report(), mimetype="text/html")
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500


@api_bp.route('/report/<int:scan_id>/download', methods=['GET'])
def download_scan_report(scan_id):
    """Downloads the most recent generated report (query ?type= or ?format= pdf|html|json)."""
    report_type = (request.args.get("type") or request.args.get("format") or "pdf").lower()
    if report_type not in {"html", "pdf", "json"}:
        return jsonify({"error": "Report type must be one of: html, pdf, json"}), 400

    report_row = (
        Reporting.query.filter_by(scan_id=scan_id, report_type=report_type)
        .order_by(Reporting.id.desc())
        .first()
    )
    if not report_row or not _os.path.exists(report_row.file_path):
        return jsonify({"error": "No generated report found. Run POST /api/report/<id> first."}), 404

    mime = {
        "html": "text/html",
        "pdf": "application/pdf",
        "json": "application/json",
    }[report_type]
    return send_file(report_row.file_path, mimetype=mime, as_attachment=True,
                     download_name=f"api_shield_report_{scan_id}.{report_type}")


@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Dashboard stats: projects, endpoints, scans, severity totals."""
    from collections import Counter

    projects = Project.query.all()
    endpoints = Endpoint.query.all()
    scans = Scan.query.all()
    findings = Finding.query.all()

    severity = Counter()
    for f in findings:
        severity[str(f.severity)] += 1

    latest_scan = Scan.query.order_by(Scan.started_at.desc()).first()
    latest_target = Target.query.get(latest_scan.target_id) if latest_scan else None

    return jsonify({
        "projects": len(projects),
        "endpoints": len(endpoints),
        "scans": len(scans),
        "findings": len(findings),
        "severity": dict(severity),
        "latest_scan": {
            "id": latest_scan.id,
            "score": latest_scan.score,
            "target": latest_target.name if latest_target else None,
            "base_url": latest_target.base_url if latest_target else None,
            "started_at": _ts_to_iso(latest_scan.started_at),
        } if latest_scan else None,
        "projects_list": [
            {
                "id": p.id, "name": p.name, "base_url": p.base_url,
                "last_scan": p.last_scan.isoformat() if p.last_scan else None,
                "endpoints": Endpoint.query.filter_by(project_id=p.id).count(),
            } for p in Project.query.order_by(Project.created_date.desc()).all()
        ],
    }), 200


# ── Scan history helpers ────────────────────────────────────────────
import os as _os
import json as _json
from datetime import datetime as _dt_module, timezone

def _ts_to_iso(ts):
    if ts is None:
        return None
    try:
        return _dt_module.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (TypeError, OSError, ValueError):
        return str(ts)


def _safe_json(raw):
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return _json.loads(raw)
    except (TypeError, ValueError):
        return {}


def _score_to_grade(score):
    if score is None:
        return None
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ═══════════════════════════════════════════════════════════════
# Phase 16 — Dedicated Risk Report Endpoint
# Retrieves current risk posture and inventory status from DB.
# ═══════════════════════════════════════════════════════════════
@api_bp.route('/projects/<int:project_id>/risk', methods=['GET'])
def get_project_risk(project_id):
    """
    Returns the current security risk posture for a project, including:
      - Total endpoints by risk tier (CRITICAL, HIGH, MEDIUM, LOW, SECURE)
      - Detailed list of endpoints with their risk ratings and last_tested dates
      - Security grade (A through F)
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found."}), 400

    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0, "Unknown": 0}
    for ep in endpoints:
        tier = ep.risk_level or "Unknown"
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    # Approximate posture score based on database risk tiers
    total = len(endpoints)
    penalty = (tier_counts.get("CRITICAL", 0) * 25) + \
              (tier_counts.get("HIGH", 0) * 15) + \
              (tier_counts.get("MEDIUM", 0) * 8) + \
              (tier_counts.get("LOW", 0) * 2)

    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return jsonify({
        "project": project.name,
        "base_url": project.base_url,
        "last_scan": project.last_scan.isoformat() if project.last_scan else None,
        "total_endpoints": total,
        "security_score": score,
        "grade": grade,
        "risk_breakdown": tier_counts,
        "endpoints": [ep.to_dict() for ep in endpoints]
    }), 200


# ═══════════════════════════════════════════════════════════════
# Phase 17 — Remediation & Security Advisory Endpoint
# Generates developer guides, root cause analysis, code diffs,
# and OWASP/CWE references.
# ═══════════════════════════════════════════════════════════════
from scanner.remediation_engine import RemediationEngine

@api_bp.route('/projects/<int:project_id>/advisories', methods=['GET'])
def get_project_advisories(project_id):
    """
    Returns prioritized remediation advisories for the project,
    complete with vulnerable/remediated code patches, root-cause
    diagnostics, and list of affected endpoints.
    """
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return jsonify({"error": "No endpoints found."}), 400

    engine = RemediationEngine()
    sample_findings = []

    # 1. TLS advisory if base_url is HTTP
    if project.base_url.startswith("http://"):
        sample_findings.append({
            "title": "API Served Over HTTP (No TLS)",
            "endpoint": project.base_url,
            "method": "N/A",
            "severity": "HIGH",
            "owasp": "API7:2023 - Security Misconfiguration"
        })

    # 2. Check each endpoint's architecture and risk
    for ep in endpoints:
        if '{' in ep.path:
            sample_findings.append({
                "title": "Broken Object Level Authorization (BOLA)",
                "endpoint": project.base_url.rstrip('/') + ep.path,
                "method": ep.method,
                "severity": "HIGH",
                "owasp": "API1:2023 - Broken Object Level Authorization"
            })
        if ep.has_body or ep.method in {"POST", "PUT", "PATCH"}:
            sample_findings.append({
                "title": "Improper Input Validation & Mass Assignment",
                "endpoint": project.base_url.rstrip('/') + ep.path,
                "method": ep.method,
                "severity": "HIGH",
                "owasp": "API3:2023 - Broken Object Property Level Authorization"
            })
        if ep.risk_level in {"HIGH", "MEDIUM", "LOW"}:
            sample_findings.append({
                "title": "Missing Security Configuration Headers",
                "endpoint": project.base_url.rstrip('/') + ep.path,
                "method": ep.method,
                "severity": "MEDIUM",
                "owasp": "API7:2023 - Security Misconfiguration"
            })

    advisories = engine.generate_advisories_for_findings(sample_findings)

    return jsonify({
        "project": project.name,
        "base_url": project.base_url,
        "total_advisories": len(advisories),
        "advisories": advisories
    }), 200


# ═══════════════════════════════════════════════════════════════
# Phase 18 — Executive Report Endpoints (HTML, Markdown, JSON)
# ═══════════════════════════════════════════════════════════════
from scanner.report_generator import ReportGenerator
from scanner.risk_engine import RiskEngine
from scanner.remediation_engine import RemediationEngine
from flask import Response

def _build_project_report_generator(project_id: int):
    """Helper to collect project data, run risk evaluation, and build a ReportGenerator."""
    project = Project.query.get(project_id)
    if not project:
        return None, "Project not found"

    endpoints = Endpoint.query.filter_by(project_id=project_id).all()
    if not endpoints:
        return None, "No endpoints found."

    risk_engine = RiskEngine()
    remediation_engine = RemediationEngine()

    # Reconstruct sample findings from endpoint statuses and specs
    sample_findings = []
    if project.base_url.startswith("http://"):
        sample_findings.append({
            "title": "API Served Over HTTP (No TLS)",
            "endpoint": project.base_url,
            "method": "N/A",
            "severity": "HIGH",
            "owasp": "API7:2023 - Security Misconfiguration",
            "evidence": f"Base URL uses HTTP scheme: {project.base_url}",
            "recommendation": "Deploy behind HTTPS with a valid TLS certificate."
        })

    for ep in endpoints:
        ep_url = project.base_url.rstrip('/') + ep.path
        if '{' in ep.path:
            sample_findings.append({
                "title": "Broken Object Level Authorization (BOLA)",
                "endpoint": ep_url,
                "method": ep.method,
                "severity": "HIGH",
                "owasp": "API1:2023 - Broken Object Level Authorization",
                "evidence": f"Endpoint {ep.method} {ep.path} accepts user-controlled ID parameter.",
                "recommendation": "Enforce object-level ownership checks server-side."
            })
        if ep.has_body or ep.method in {"POST", "PUT", "PATCH"}:
            sample_findings.append({
                "title": "Improper Input Validation & Mass Assignment",
                "endpoint": ep_url,
                "method": ep.method,
                "severity": "HIGH",
                "owasp": "API3:2023 - Broken Object Property Level Authorization",
                "evidence": f"Endpoint {ep.method} {ep.path} accepts request body without schema enforcement.",
                "recommendation": "Use strict DTOs and field allowlists."
            })
        if ep.risk_level in {"HIGH", "MEDIUM", "LOW"}:
            sample_findings.append({
                "title": "Missing Security Configuration Headers",
                "endpoint": ep_url,
                "method": ep.method,
                "severity": "MEDIUM",
                "owasp": "API7:2023 - Security Misconfiguration",
                "evidence": "Recommended security headers (HSTS, CSP, nosniff) missing.",
                "recommendation": "Add standard HTTP security headers to all responses."
            })

    risk_report = risk_engine.evaluate_project(endpoints=endpoints, all_findings=sample_findings)
    advisories = remediation_engine.generate_advisories_for_findings(sample_findings)

    generator = ReportGenerator(
        project_data=project.to_dict(),
        risk_data=risk_report,
        advisories=advisories,
        findings=sample_findings
    )
    return generator, None


@api_bp.route('/projects/<int:project_id>/report/html', methods=['GET'])
def get_html_report(project_id):
    """Returns standalone styled HTML security audit report."""
    generator, err = _build_project_report_generator(project_id)
    if err:
        return jsonify({"error": err}), 404 if "not found" in err else 400
    html_content = generator.generate_html_report()
    return Response(html_content, mimetype='text/html')


@api_bp.route('/projects/<int:project_id>/report/markdown', methods=['GET'])
def get_markdown_report(project_id):
    """Returns Markdown security audit report."""
    generator, err = _build_project_report_generator(project_id)
    if err:
        return jsonify({"error": err}), 404 if "not found" in err else 400
    md_content = generator.generate_markdown_report()
    return Response(md_content, mimetype='text/markdown')


@api_bp.route('/projects/<int:project_id>/report/json', methods=['GET'])
def get_json_report(project_id):
    """Returns structured JSON security audit package."""
    generator, err = _build_project_report_generator(project_id)
    if err:
        return jsonify({"error": err}), 404 if "not found" in err else 400
    return jsonify(generator.generate_json_report()), 200
