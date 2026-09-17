"""Unit tests for the RateLimiting & Payload Size analyzer (tests_engine.rate_limit)."""

from scanner.discovery import Endpoint
from tests_engine.rate_limit import (
    RateLimitAnalyzer,
    PAYLOAD_PROBE_FIELD,
)


class SequenceEngine:
    """Replays preset responses in order; no network access."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send_request(self, method, url, headers=None, params=None, json_data=None):
        self.calls.append({"method": method, "url": url, "json_data": json_data})
        if not self.responses:
            return {"error": "no more responses"}
        return self.responses.pop(0)


def _resp(status=200, headers=None):
    return {"status_code": status, "headers": headers or {}, "text": ""}


def _analyzer(engine, endpoints=None, base_url="http://127.0.0.1:5001", burst=3):
    if endpoints is None:
        endpoints = [
            Endpoint("GET", "/api/users"),
            Endpoint("POST", "/api/login"),
            Endpoint("DELETE", "/api/users/{id}"),
        ]
    return RateLimitAnalyzer(
        base_url=base_url,
        endpoints=endpoints,
        request_engine=engine,
        burst=burst,
    )


def _titles(findings):
    return {f.get("title") for f in findings}


def test_429_detected_reports_enforced():
    # 3 burst attempts (2xx, 2xx, 429) then the payload probe (413 -> enforced).
    engine = SequenceEngine([_resp(200), _resp(200), _resp(429), _resp(413)])
    findings = _analyzer(engine).analyze()
    titles = _titles(findings)
    assert any("Rate Limiting Enforced" in t for t in titles)
    assert any("Payload Size Limit Enforced" in t for t in titles)
    assert all(f.get("owasp") == "API4:2023 - Unrestricted Resource Consumption" for f in findings)


def test_headers_without_429_reports_partial():
    engine = SequenceEngine(
        [
            _resp(200),
            _resp(200, {"Ratelimit-Limit": "10"}),
            _resp(200),
            _resp(400),  # payload probe inconclusive -> no finding
        ]
    )
    findings = _analyzer(engine).analyze()
    assert any("Rate Limiting Partially Detected" in t for t in _titles(findings))
    assert not any("Rate Limiting Not Detected" in t for t in _titles(findings))


def test_no_rate_limit_control_reports_missing():
    engine = SequenceEngine([_resp(200), _resp(200), _resp(200), _resp(201)])
    findings = _analyzer(engine).analyze()
    titles = _titles(findings)
    assert any("Rate Limiting Not Detected" in t for t in titles)
    assert any("No Request Payload Size Limit Detected" in t for t in titles)
    missing = next(f for f in findings if "Not Detected" in f["title"])
    assert missing["severity"] == "MEDIUM"


def test_analyzer_prefers_login_endpoint():
    engine = SequenceEngine([_resp(200), _resp(200), _resp(429)])
    # Payload check skipped -> no POST/PUT/PATCH? login is POST, still present.
    _analyzer(engine).analyze()
    first_post = next(c for c in engine.calls if c["method"] == "POST")
    assert "/api/login" in first_post["url"]
    assert first_post["json_data"] == {"username": "test", "password": "test"}


def test_path_params_resolved_to_id_one():
    engine = SequenceEngine([_resp(200), _resp(200), _resp(429)])
    an = _analyzer(engine, endpoints=[Endpoint("GET", "/api/users/{userId}")])
    an.analyze()
    assert any(c["url"].endswith("/api/users/1") for c in engine.calls)


def test_payload_probe_uses_large_bounded_body():
    engine = SequenceEngine([_resp(200), _resp(200), _resp(200), _resp(413)])
    _analyzer(engine).analyze()
    probe_call = next(
        c for c in engine.calls
        if isinstance(c["json_data"], dict) and PAYLOAD_PROBE_FIELD in c["json_data"]
    )
    assert len(probe_call["json_data"][PAYLOAD_PROBE_FIELD]) == 256 * 1024


def test_no_endpoints_returns_no_findings():
    engine = SequenceEngine([])
    findings = _analyzer(engine, endpoints=[]).analyze()
    assert findings == []


def test_get_only_endpoints_skip_payload_analysis():
    engine = SequenceEngine([_resp(200), _resp(200), _resp(429)])
    an = _analyzer(engine, endpoints=[Endpoint("GET", "/api/health")])
    findings = an.analyze()
    assert any("Rate Limiting Enforced" in t for t in _titles(findings))
    assert not any("Payload" in t for t in _titles(findings))