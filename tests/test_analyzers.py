"""Live analyzer tests against the bundled training API (localhost, authorized)."""

import json
import re

from scanner.orchestrator import load_allowed_hosts
from scanner.request_engine import SafeRequestEngine
from tests_engine.authentication import AuthenticationAnalyzer
from tests_engine.cors import CORSAnalyzer, TEST_ORIGIN
from tests_engine.cookies import CookieAnalyzer
from tests_engine.headers import SecurityHeaderAnalyzer
from tests_engine.validation import InputValidationAnalyzer

URL = "http://127.0.0.1:5001/api/users"


def _engine():
    return SafeRequestEngine(allowed_hosts=load_allowed_hosts())


def _get_headers(path=URL):
    resp = _engine().send_request("GET", path)
    assert not resp.get("error"), resp.get("error")
    return resp.get("headers", {})


def test_headers_analyzer_flags_missing_security_headers(lab_server):
    findings = SecurityHeaderAnalyzer(_get_headers(), URL, "GET").analyze()
    titles = {f.get("title") for f in findings}
    assert len(findings) >= 3
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_cors_analyzer_flags_reflected_origin(lab_server):
    resp = _engine().send_request("GET", URL, headers={"Origin": TEST_ORIGIN})
    findings = CORSAnalyzer(resp.get("headers", {}), URL, "GET").analyze()
    assert findings, "reflective CORS should not pass silently"
    assert any(f.get("severity") in {"LOW", "MEDIUM", "HIGH"} for f in findings)


def test_cookie_analyzer_runs(lab_server):
    findings = CookieAnalyzer(_get_headers(), URL, "GET").analyze()
    # The lab may or may not set cookies, but the analyzer must not raise.
    assert isinstance(findings, list)


def test_auth_analyzer_flags_missing_authentication(lab_server):
    resp = _engine().send_request("GET", URL)
    findings = AuthenticationAnalyzer(
        endpoint_url=URL, method="GET", response_no_auth=resp,
        endpoint_spec_requires_auth=True,
    ).analyze()
    severities = [f.get("severity") for f in findings]
    assert "HIGH" in severities or any("auth" in f.get("title", "").lower() for f in findings)


def test_validation_analyzer_safe_payloads(lab_server):
    engine = _engine()
    result = InputValidationAnalyzer(
        endpoint_url=URL, method="POST", request_engine=engine,
    ).analyze()
    assert "findings" in result and "test_results" in result


def test_safe_engine_blocks_out_of_scope_targets():
    engine = _engine()
    resp = engine.send_request("GET", "http://evil.example.com/api/x")
    assert resp.get("error")
    assert "Out of Scope" in resp["error"]