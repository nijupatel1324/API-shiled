"""Unit tests for legacy scanner modules (injection, sensitive data, rate limit)
using fake sessions so no network is touched."""

import pytest

from scanner import ScanContext
from scanner.discovery import Endpoint
from scanner.injection import run_injection_checks, _classify
from scanner.sensitive_data import (
    run_sensitive_data_analysis, _check_secret_keys_in_json, _snippet,
)
from scanner.rate_limit import run_rate_limit_check, _extract_limit, _pick_endpoint


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, url="http://127.0.0.1:5001/x"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.elapsed = type("E", (), {"total_seconds": lambda self: 0.01})()


class FakeSession:
    """Records calls and returns scripted responses."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def _next(self):
        if len(self.responses) == 1:
            return self.responses[0]
        return self.responses.pop(0) if self.responses else FakeResponse(status_code=404)

    def get(self, url, params=None, timeout=None, **kw):
        self.calls.append(("GET", url, params))
        return self._next()

    def post(self, url, json=None, data=None, timeout=None, **kw):
        self.calls.append(("POST", url, json))
        return self._next()

    def request(self, method, url, timeout=None, **kw):
        self.calls.append((method, url))
        return self._next()


def _ctx(url="http://127.0.0.1:5001", endpoints=None, session=None):
    ctx = ScanContext(
        base_url=url,
        findings=[],
        session=session or FakeSession(),
        test_credentials={},
    )
    ctx.endpoints = list(endpoints or [])
    return ctx


def _endpoints(*paths):
    return [Endpoint("GET", p) for p in paths]


# ── Injection module ──────────────────────────────────────────────────
class TestInjection:
    def test_classify_detects_sql_error(self):
        resp = FakeResponse(text="sql syntax error near '1'")
        result = _classify(resp)
        assert "Potential SQL Injection" in result

    def test_classify_detects_traceback(self):
        resp = FakeResponse(text="ValueError ... traceback (most recent call last)")
        result = _classify(resp)
        assert any("verbose error" in k.lower() or "trace" in k.lower() for k in result)

    def test_classify_clean_response(self):
        resp = FakeResponse(text='{"items": []}')
        assert _classify(resp) == {}

    def test_run_injection_sql_finding(self):
        session = FakeSession(responses=[
            FakeResponse(text="sqlalchemy.exc.OperationalError sql syntax error near '1'"),
            FakeResponse(text="ok"),
        ])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/users")], session=session)
        findings = run_injection_checks(ctx)
        assert findings
        assert any("SQL" in f["title"] for f in findings)
        assert any(f["title"] not in ("",) for f in findings)

    def test_run_injection_clean_no_findings(self):
        session = FakeSession(responses=[FakeResponse(text="ok")])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/users")], session=session)
        findings = run_injection_checks(ctx)
        assert findings == []


# ── Sensitive data module ─────────────────────────────────────────────
class TestSensitiveData:
    def test_detects_secret_key_in_json(self):
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/admin")])
        ep = ctx.endpoints[0]
        body = '{"user": {"password": "hunter2", "email": "a@b.c"}}'
        _check_secret_keys_in_json(ctx, ep, body)
        assert ctx.findings
        f = ctx.findings[0]
        assert "Sensitive Data in API Response" == f["title"]
        # Evidence is masked, never the real secret.
        assert "hunter2" not in f["evidence"]

    def test_detects_private_key_block(self):
        session = FakeSession(responses=[
            FakeResponse(text="-----BEGIN RSA PRIVATE KEY-----\nAAAA"),
        ])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/debug")], session=session)
        findings = run_sensitive_data_analysis(ctx)
        assert any("Private Key" in f["title"] for f in findings)

    def test_detects_stack_trace(self):
        session = FakeSession(responses=[
            FakeResponse(text='{"error": "ValueError", "trace": "Traceback (most recent call last)"}'),
        ])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/debug")], session=session)
        findings = run_sensitive_data_analysis(ctx)
        assert any("Stack Trace" in f["title"] for f in findings)

    def test_detects_internal_ip(self):
        session = FakeSession(responses=[
            FakeResponse(text="server at 192.168.1.50 is reachable"),
        ])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/debug")], session=session)
        findings = run_sensitive_data_analysis(ctx)
        assert any("Internal IP" in f["title"] for f in findings)

    def test_clean_body_no_findings(self):
        session = FakeSession(responses=[
            FakeResponse(text='{"ok": true, "data": [1, 2, 3]}', headers={"Content-Type": "application/json"}),
        ])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/users")], session=session)
        assert run_sensitive_data_analysis(ctx) == []

    def test_snippet_extracts_context(self):
        snippet = _snippet("xx" * 40 + "Traceback (most recent call last) here", __import__("re").compile("traceback", __import__("re").IGNORECASE))
        assert "Traceback" in snippet


# ── Rate limit module ─────────────────────────────────────────────────
class TestRateLimit:
    def test_pick_prefers_login_post(self):
        ctx = _ctx(endpoints=[
            Endpoint("GET", "/api/users"),
            Endpoint("POST", "/api/login"),
        ])
        ep = _pick_endpoint(ctx)
        assert ep.path == "/api/login" and ep.method == "POST"

    def test_pick_falls_back_to_first(self):
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/users")])
        assert _pick_endpoint(ctx).path == "/api/users"

    def test_pick_empty_returns_none(self):
        assert _pick_endpoint(_ctx(endpoints=[])) is None

    def test_429_detected(self):
        session = FakeSession(responses=[FakeResponse(status_code=429, headers={"x-ratelimit-limit": "100"})])
        ctx = _ctx(endpoints=[Endpoint("POST", "/api/login")], session=session)
        findings = run_rate_limit_check(ctx, burst=3)
        assert any("Rate Limit Detected" == f["title"] for f in findings)

    def test_no_rate_limit_reported_medium(self):
        session = FakeSession(responses=[FakeResponse(status_code=200)])
        ctx = _ctx(endpoints=[Endpoint("GET", "/api/users")], session=session)
        findings = run_rate_limit_check(ctx, burst=3)
        assert findings
        assert findings[0]["severity"] == "MEDIUM"
        assert "Not Detected" in findings[0]["title"]

    def test_extract_limit_parses_headers(self):
        from scanner.rate_limit import RATE_LIMIT_HEADERS
        assert RATE_LIMIT_HEADERS
        resp = FakeResponse(headers={"x-ratelimit-limit": "5000"})
        assert _extract_limit(resp) == "5000 requests/min"
        resp2 = FakeResponse(headers={})
        assert _extract_limit(resp2) is None