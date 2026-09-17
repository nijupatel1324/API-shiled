"""Unit tests for core scanner modules (masking, scoring, discovery, parser,
request engine, remediation, TLS and error analysis). No live network needed."""

import re

import pytest

from scanner import ScanContext, mask_string, mask_sensitive_response, truncate
from scanner.scoring import (
    compute_score, compute_severity_counts, grade, risk_level, summary,
    SEVERITY_WEIGHTS as SCORING_WEIGHTS,
)
from scanner.request_engine import SafeRequestEngine
from scanner.discovery import (
    Endpoint, parse_openapi, validate_target_url, discover_from_spec_file,
)
from scanner.openapi_parser import OpenAPIParser
from scanner.remediation_engine import RemediationEngine
from tests_engine.tls import TLSAnalyzer
from tests_engine.error_analysis import ErrorAnalyzer, SENSITIVE_PATTERNS


# ── Masking & context helpers ─────────────────────────────────────────
class TestMasking:
    def test_mask_short_value_fully_masked(self):
        assert mask_string("abc") == "***"

    def test_mask_keeps_short_prefix(self):
        value = "sk-1234567890abcdef"
        masked = mask_string(value)
        assert masked.startswith("sk-12345")
        assert "*" in masked
        assert value not in masked

    def test_mask_sensitive_response_redacts_pairs(self):
        text = '{"password": "hunter2", "token": "abcdefghijkl"}'
        out = mask_sensitive_response(text)
        assert "hunter2" not in out
        assert "abcdefghijkl" not in out
        assert "password" in out

    def test_mask_sensitive_response_redacts_long_secret_tokens(self):
        text = "leak sk-abcdefghijklmnopqrstuvwxyz here"
        out = mask_sensitive_response(text)
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in out

    def test_mask_sensitive_response_handles_empty(self):
        assert mask_sensitive_response("") == ""
        assert mask_sensitive_response(None) is None

    def test_truncate_limits_length(self):
        assert truncate("x" * 1000, limit=100) == "x" * 100 + "..."


class TestScanContext:
    def test_add_finding_builds_structure(self):
        ctx = ScanContext(base_url="http://127.0.0.1:5001")
        ctx.add_finding(
            title="T", severity="HIGH", endpoint="/api/x", method="GET",
            category="API8", description="d", evidence="e", recommendation="r",
        )
        f = ctx.findings[0]
        assert f["title"] == "T" and f["severity"] == "HIGH"
        assert f["endpoint"] == "/api/x" and f["method"] == "GET"
        assert f["category"] == "API8"

    def test_add_finding_defaults(self):
        ctx = ScanContext(base_url="http://127.0.0.1:5001")
        ctx.add_finding(title="T", severity="LOW")
        f = ctx.findings[0]
        assert f["endpoint"] == "" and f["evidence"] == ""


# ── Scoring module ────────────────────────────────────────────────────
class TestScoringModule:
    def test_counts_treats_missing_severity_as_info(self):
        findings = [{"severity": "CRITICAL"}, {"severity": "BOGUS"}, {"severity": None}]
        counts = compute_severity_counts(findings)
        assert counts["CRITICAL"] == 1
        assert counts["INFO"] == 1  # None coerced to INFO

    def test_score_uses_scoring_weights(self):
        score, counts = compute_score([{"severity": "HIGH"}, {"severity": "MEDIUM"}])
        assert counts["HIGH"] == 1 and counts["MEDIUM"] == 1
        assert score == 100 - SCORING_WEIGHTS["HIGH"] - SCORING_WEIGHTS["MEDIUM"]

    def test_score_clamps_at_zero(self):
        score, _ = compute_score([{"severity": "CRITICAL"} for _ in range(50)])
        assert score == 0

    def test_grade_boundaries(self):
        assert grade(90) == "A"
        assert grade(85) == "A"
        assert grade(84) == "B"
        assert grade(70) == "B"
        assert grade(69) == "C"
        assert grade(50) == "C"
        assert grade(49) == "D"
        assert grade(30) == "D"
        assert grade(0) == "F"

    def test_risk_level_priority(self):
        assert risk_level({"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 1}) == "HIGH"
        assert risk_level({"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0}) == "CRITICAL"
        assert risk_level({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}) == "LOW RISK"

    def test_summary_shape(self):
        s = summary([{"severity": "LOW"}], tests_completed=3, endpoints_count=2)
        assert s["grade"] == "A" or s["grade"] == "B"
        assert s["total_findings"] == 1
        assert s["tests_completed"] == 3 and s["endpoints_count"] == 2


# ── Request engine ────────────────────────────────────────────────────
class TestRequestEngine:
    def test_out_of_scope_blocked(self):
        engine = SafeRequestEngine(allowed_hosts=["127.0.0.1"])
        resp = engine.send_request("GET", "http://evil.example.com/x")
        assert resp.get("error")
        assert "Out of Scope" in resp["error"] or "not in allowlist" in resp["error"]

    def test_subdomain_allowed_by_suffix(self):
        engine = SafeRequestEngine(allowed_hosts=["example.com"])
        assert engine._is_allowed("http://api.example.com/x") is True
        assert engine._is_allowed("http://notexample.com/x") is False

    def test_unsupported_method_rejected_without_network(self):
        engine = SafeRequestEngine(allowed_hosts=["127.0.0.1"], timeout=1)
        resp = engine.send_request("TRACE", "http://127.0.0.1:5001/x")
        assert resp.get("error")
        assert "method" in resp["error"].lower()


# ── Discovery & OpenAPI parsing ───────────────────────────────────────
class TestDiscovery:
    def test_validate_target_url_requires_scheme(self):
        with pytest.raises(ValueError):
            validate_target_url("127.0.0.1:5001")

    def test_validate_target_url_rejects_external_host(self):
        with pytest.raises(ValueError):
            validate_target_url("http://evil.example.com/api")

    def test_validate_target_url_allows_localhost(self):
        assert validate_target_url("http://127.0.0.1:5001/") == "http://127.0.0.1:5001"

    def test_endpoint_url_join(self):
        ep = Endpoint("GET", "/api/users")
        assert ep.url("http://127.0.0.1:5001") == "http://127.0.0.1:5001/api/users"


YAML_SPEC = """\
openapi: 3.0.0
info: {title: YAML API, version: "1.0"}
servers:
  - url: http://127.0.0.1:5001
paths:
  /api/items:
    get:
      responses:
        "200": {description: ok}
    post:
      responses:
        "201": {description: ok}
"""


class TestOpenAPIParsing:
    def test_parse_openapi_json(self):
        spec = '{"openapi":"3.0.0","info":{"title":"J","version":"1"},"paths":{"/ping":{"get":{"responses":{"200":{"description":"ok"}}}}}}'
        endpoints = parse_openapi(spec)
        assert any(e.method == "GET" and e.path == "/ping" for e in endpoints)

    def test_parse_openapi_yaml(self):
        endpoints = parse_openapi(YAML_SPEC)
        methods = {(e.method, e.path) for e in endpoints}
        assert ("GET", "/api/items") in methods
        assert ("POST", "/api/items") in methods
        assert all(e.source == "openapi" for e in endpoints)

    def test_parse_openapi_invalid(self):
        with pytest.raises(ValueError):
            parse_openapi("this is : not: valid: [yaml")

    def test_openapi_parser_class(self):
        parser = OpenAPIParser(YAML_SPEC)
        parsed = parser.parse()
        assert parsed["title"] == "YAML API"
        assert parsed["servers"] == ["http://127.0.0.1:5001"]
        lens = {e["path"]: e["method"] for e in parsed["endpoints"]}
        assert lens["/api/items"] == "GET" or "GET" in [
            e["method"] for e in parsed["endpoints"]
        ]

    def test_openapi_parser_invalid(self):
        with pytest.raises(ValueError):
            OpenAPIParser("garbage: [").parse()

    def test_openapi_parser_empty(self):
        with pytest.raises(ValueError):
            OpenAPIParser("").parse()

    def test_discover_from_spec_file_storage(self):
        class Storage:
            def read(self):
                return YAML_SPEC.encode("utf-8")

        endpoints, base_url = discover_from_spec_file(Storage())
        assert base_url == "http://127.0.0.1:5001"
        assert len(endpoints) == 2


# ── Remediation engine ────────────────────────────────────────────────
class TestRemediationEngine:
    def test_maps_bola_finding(self):
        adv = RemediationEngine().map_finding_to_advisory(
            {"title": "Broken Object Level Authorization", "endpoint": "/api/x", "method": "GET"}
        )
        assert adv["advisory_key"] == "BOLA"
        assert "API1" in adv["owasp"]

    def test_maps_tls_finding(self):
        adv = RemediationEngine().map_finding_to_advisory(
            {"title": "API Served Over HTTP (No TLS)", "endpoint": "N/A", "method": "GET"}
        )
        assert adv["advisory_key"] == "TLS_HTTP"
        assert "API7" in adv["owasp"]

    def test_maps_cors_finding(self):
        adv = RemediationEngine().map_finding_to_advisory(
            {"title": "Permissive CORS misconfiguration", "endpoint": "x", "method": "GET"}
        )
        assert adv["advisory_key"] == "CORS"

    def test_maps_error_finding(self):
        adv = RemediationEngine().map_finding_to_advisory(
            {"title": "Information Disclosure in Error Handling", "endpoint": "x", "method": "GET"}
        )
        assert adv["advisory_key"] == "ERROR_HANDLING"

    def test_generates_deduplicated_advisories(self):
        findings = [
            {"title": "BOLA", "severity": "HIGH", "endpoint": "/a", "method": "GET"},
            {"title": "BOLA on another object", "severity": "HIGH", "endpoint": "/b", "method": "POST"},
            {"title": "Missing security headers", "severity": "MEDIUM", "endpoint": "/a", "method": "GET"},
        ]
        advisories = RemediationEngine().generate_advisories_for_findings(findings)
        keys = {a["advisory_key"] for a in advisories}
        assert "BOLA" in keys and "SECURITY_HEADERS" in keys
        bola = next(a for a in advisories if a["advisory_key"] == "BOLA")
        assert len(bola["affected_endpoints"]) == 2

    def test_ignores_findings_without_severity(self):
        advisories = RemediationEngine().generate_advisories_for_findings(
            [{"title": "No severity", "endpoint": "/a"}]
        )
        assert advisories == []


# ── TLS analyzer (offline paths only) ─────────────────────────────────
class TestTLSAnalyzer:
    def test_http_scheme_reports_high(self, monkeypatch):
        # Avoid real network in the redirect check by raising a caught exception
        # (ConnectionError/Timeout are handled inside _check_http_to_https_redirect).
        import requests as _rq

        def _no_net(*args, **kwargs):
            raise _rq.exceptions.ConnectionError("skip net")

        monkeypatch.setattr("tests_engine.tls.requests.get", _no_net)
        analyzer = TLSAnalyzer(base_url="http://127.0.0.1:5001")
        findings = analyzer.analyze()
        titles = {f["title"] for f in findings}
        assert "API Served Over HTTP (No TLS)" in titles
        assert any(f["severity"] == "HIGH" for f in findings)
        assert all(f["owasp"].startswith("API7") for f in findings)

    def test_unrecognized_scheme_medium(self):
        analyzer = TLSAnalyzer(base_url="ftp://127.0.0.1:21")
        findings = analyzer.analyze()
        titles = {f["title"] for f in findings}
        assert "Unrecognized URL Scheme" in titles


# ── Error analyzer (mocked engine) ────────────────────────────────────
class _FakeEngine:
    """Minimal SafeRequestEngine stand-in that never touches the network."""

    def __init__(self, responses):
        self.responses = responses
        self.timeout = 1

    def send_request(self, method, url, headers=None):
        # Rotate through configured responses.
        return self.responses.pop(0) if self.responses else {"error": "no more responses"}

    def _is_allowed(self, url):
        return True

    def _enforce_rate_limit(self):
        pass


class TestErrorAnalyzer:
    def test_detects_secret_key_disclosure(self):
        body = '{"SECRET_KEY=sk-abcdef123456", "status": "internal error"}'
        engine = _FakeEngine([
            {"status_code": 500, "text": body, "url": "http://127.0.0.1:5001/x", "headers": {}},
            {"status_code": 200, "text": body, "url": "http://127.0.0.1:5001/x", "headers": {}},
        ])
        analyzer = ErrorAnalyzer(
            base_url="http://127.0.0.1:5001",
            endpoint_url="http://127.0.0.1:5001/api/users",
            method="POST",
            request_engine=engine,
        )
        findings = analyzer.analyze()
        assert findings, "SECRET_KEY should trigger a finding"
        assert any("SECRET_KEY" in f["title"] or "Secret Key" in f["title"] for f in findings)
        # Evidence must be sanitized.
        for f in findings:
            assert "sk-abcdef123456" not in f["evidence"]

    def test_only_error_status_codes_analyzed(self):
        engine = _FakeEngine([
            {"status_code": 200, "text": "traceback (most recent call last)", "url": "u", "headers": {}},
            {"status_code": 204, "text": "SECRET_KEY=x", "url": "u", "headers": {}},
        ])
        analyzer = ErrorAnalyzer(
            base_url="http://127.0.0.1:5001",
            endpoint_url="http://127.0.0.1:5001/api/users",
            method="GET",
            request_engine=engine,
        )
        findings = analyzer.analyze()
        assert findings == []

    def test_sensitive_patterns_catalog_well_formed(self):
        for pattern, name, sev in SENSITIVE_PATTERNS:
            re.compile(pattern)
            assert isinstance(name, str) and name
            assert sev in {"HIGH", "MEDIUM", "CRITICAL"}