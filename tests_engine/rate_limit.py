"""
Phase 12 — Rate Limiting & Payload Size Analyzer

Detects whether an API enforces controls that protect it from resource
exhaustion (OWASP API4:2023 — Unrestricted Resource Consumption). Two checks
are performed:

1. Rate limiting
   A small, bounded burst of lightweight requests is sent to a single
   candidate endpoint (preferring a login/token endpoint). The analyzer
   observes:
     - HTTP 429 (Too Many Requests) responses
     - Standard rate-limit response headers (RateLimit-*, X-RateLimit-*,
       Retry-After)
   A bounded burst never floods the target and is capped by config.

2. Request payload size limiting
   A single oversized (but bounded) JSON body is sent to a write endpoint
   (POST/PUT/PATCH). If the server accepts and processes it with a 2xx
   response, no request body size limit appears to be enforced.

SAFETY:
  - The burst length is capped by Config.DEFAULT_RATE_LIMIT_TEST_REQUESTS.
  - The payload probe is capped by Config.MAX_PAYLOAD_SIZE.
  - No destructive requests, credential brute forcing, or DoS behavior.

OWASP Mapping:
  - OWASP API Security Top 10: API4:2023 - Unrestricted Resource Consumption
  - CWE-770: Allocation of Resources Without Limits or Throttling
  - CWE-400: Uncontrolled Resource Consumption
"""

import logging
import time

from config import Config

logger = logging.getLogger('api-shield.rate_limit')

RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "ratelimit-policy",
    "x-ratelimit-window",
    "retry-after",
)

_METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}
_SUCCESS_CODES = {200, 201, 202, 204}
# Server rejected the oversized body for a reason unrelated to size
_INCONCLUSIVE_CODES = {400, 401, 403, 404, 405, 422}
_PAYLOAD_TOO_LARGE_CODES = {413}
_REJECTED_SIZE_CODES = {413, 431}

PAYLOAD_PROBE_BYTES = 256 * 1024  # 256 KiB — bounded, non-destructive
PAYLOAD_PROBE_FIELD = "api_shield_probe"

OWASP = "API4:2023 - Unrestricted Resource Consumption"


class RateLimitAnalyzer:
    def __init__(self, base_url, endpoints, request_engine=None, burst=None):
        """
        :param base_url:       Base URL of the target project.
        :param endpoints:      Iterable of endpoint objects exposing .path/.method.
        :param request_engine: A SafeRequestEngine instance. If omitted, one is
                               created using the configured scan allowlist.
        :param burst:          Number of requests for the rate-limit probe.
        """
        self.base_url = (base_url or "").rstrip("/")
        self.endpoints = list(endpoints or [])
        if request_engine is None:
            from scanner.request_engine import SafeRequestEngine
            from scanner.orchestrator import load_allowed_hosts

            request_engine = SafeRequestEngine(allowed_hosts=load_allowed_hosts())
        self.engine = request_engine

        cap = Config.DEFAULT_RATE_LIMIT_TEST_REQUESTS
        requested = cap if burst is None else int(burst)
        self.burst = max(1, min(requested, cap))
        self.findings = []

    # ─────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────
    def _add_finding(self, title, severity, description, evidence, recommendation,
                     endpoint="", method=""):
        self.findings.append({
            "title": title,
            "endpoint": endpoint,
            "method": method,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp": OWASP,
        })

    def _resolve_url(self, path):
        import re

        resolved = re.sub(r"\{[^}]+\}", "1", path or "/")
        if not resolved.startswith("/"):
            resolved = "/" + resolved
        return f"{self.base_url}{resolved}"

    def _pick_rate_limit_candidate(self):
        """Prefer a login endpoint (must be rate limited); else a write endpoint."""
        for ep in self.endpoints:
            if ep.method in _METHODS_WITH_BODY and "login" in (ep.path or "").lower():
                return ep
        for ep in self.endpoints:
            if ep.method in _METHODS_WITH_BODY:
                return ep
        return self.endpoints[0] if self.endpoints else None

    def _pick_body_candidate(self):
        for ep in self.endpoints:
            if ep.method in _METHODS_WITH_BODY:
                return ep
        return None

    # ─────────────────────────────────────────────────────────────
    # Check 1: Rate limiting
    # ─────────────────────────────────────────────────────────────
    def _check_rate_limiting(self):
        candidate = self._pick_rate_limit_candidate()
        if candidate is None:
            logger.debug("Rate-limit check skipped: no endpoints to test")
            return

        url = self._resolve_url(candidate.path)
        login_like = "login" in (candidate.path or "").lower()
        body = {"username": "test", "password": "test"} if candidate.method in _METHODS_WITH_BODY else None

        statuses = {}
        headers_seen = set()
        seen_429 = False
        responses = 0

        for i in range(self.burst):
            if candidate.method == "GET":
                resp = self.engine.send_request("GET", url)
            else:
                resp = self.engine.send_request(candidate.method, url, json_data=body)

            if resp.get("error"):
                logger.debug("Rate-limit probe %d failed: %s", i, resp.get("error"))
                continue

            responses += 1
            status = resp.get("status_code", 0)
            statuses[status] = statuses.get(status, 0) + 1
            if status == 429:
                seen_429 = True
            for header in RATE_LIMIT_HEADERS:
                lowered = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
                if header in lowered:
                    headers_seen.add(header)

        limit_value = self._extract_limit(resp) if responses else None
        evidence = (
            f"Endpoint: {candidate.method} {url}\n"
            f"Requests sent: {self.burst}\n"
            f"Responses observed: {responses}\n"
            f"Status codes: {dict(sorted(statuses.items())) or 'none'}\n"
            f"Rate-limit headers: {', '.join(sorted(headers_seen)) or 'none'}"
        )

        if seen_429:
            self._add_finding(
                title="Rate Limiting Enforced (HTTP 429 Observed)",
                severity="INFO",
                description=(
                    "The endpoint began returning HTTP 429 (Too Many Requests) during a "
                    "bounded burst, indicating active rate limiting."
                ),
                evidence=evidence + (f"\nLimit: {limit_value}" if limit_value else ""),
                recommendation="None — rate limiting is enforced. Verify limits suit your load profile.",
                endpoint=candidate.path,
                method=candidate.method,
            )
        elif headers_seen:
            self._add_finding(
                title="Rate Limiting Partially Detected (Headers Only)",
                severity="LOW",
                description=(
                    "Rate-limit headers are present but no HTTP 429 was observed within the "
                    "bounded test burst. The limit may be high, or enforcement may be missing."
                ),
                evidence=evidence + (f"\nLimit: {limit_value}" if limit_value else ""),
                recommendation=(
                    "Confirm that rate limiting is actually enforced, not just advertised via "
                    "headers. Lower login/authentication limits and return HTTP 429 when exceeded."
                ),
                endpoint=candidate.path,
                method=candidate.method,
            )
        else:
            self._add_finding(
                title="Rate Limiting Not Detected",
                severity="MEDIUM",
                description=(
                    "No HTTP 429 responses and no rate-limit headers were observed for a bounded "
                    "burst. The endpoint may be unprotected against request flooding, credential "
                    "stuffing, or resource exhaustion."
                ),
                evidence=evidence,
                recommendation=(
                    "Implement rate limiting (per-user and per-IP) on sensitive endpoints, "
                    "especially login/token issuance. Return HTTP 429 with a Retry-After header "
                    "when limits are exceeded. Consider an API gateway or middleware limiter."
                ),
                endpoint=candidate.path,
                method=candidate.method,
            )

        logger.info(
            "Rate limiting %s on %s (%s)",
            "DETECTED" if seen_429 else ("headers-only" if headers_seen else "NOT detected"),
            url,
            limit_value or "limit unknown",
        )

    @staticmethod
    def _extract_limit(resp):
        """Try to read a numeric rate limit from response headers."""
        import re

        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        for header in ("x-ratelimit-limit", "ratelimit-limit", "ratelimit-policy"):
            value = headers.get(header)
            if value:
                match = re.search(r"\d+", str(value))
                if match:
                    return f"{match.group(0)} requests (advertised)"
        return None

    # ─────────────────────────────────────────────────────────────
    # Check 2: Request payload size limiting
    # ─────────────────────────────────────────────────────────────
    def _check_payload_size(self):
        candidate = self._pick_body_candidate()
        if candidate is None:
            logger.debug("Payload-size check skipped: no POST/PUT/PATCH endpoints")
            return

        probe_bytes = min(PAYLOAD_PROBE_BYTES, Config.MAX_PAYLOAD_SIZE)
        url = self._resolve_url(candidate.path)
        oversized = {PAYLOAD_PROBE_FIELD: "A" * probe_bytes}

        resp = self.engine.send_request(candidate.method, url, json_data=oversized)
        if resp.get("error"):
            logger.debug("Payload-size probe failed: %s", resp.get("error"))
            return

        status = resp.get("status_code", 0)
        evidence = (
            f"Endpoint: {candidate.method} {url}\n"
            f"Payload size sent: ~{probe_bytes} bytes\n"
            f"Response status: {status}"
        )

        if status in _PAYLOAD_TOO_LARGE_CODES:
            self._add_finding(
                title="Request Payload Size Limit Enforced",
                severity="INFO",
                description=(
                    "The server rejected an oversized request body with HTTP 413 "
                    "(Payload Too Large), indicating a request size limit is enforced."
                ),
                evidence=evidence,
                recommendation="None — request body size limiting is enforced.",
                endpoint=candidate.path,
                method=candidate.method,
            )
        elif status in _SUCCESS_CODES:
            self._add_finding(
                title="No Request Payload Size Limit Detected",
                severity="MEDIUM",
                description=(
                    "An oversized JSON body was accepted and processed with a successful "
                    "response. Without a request size limit, attackers may exhaust memory or "
                    "storage by submitting very large bodies."
                ),
                evidence=evidence,
                recommendation=(
                    "Enforce a maximum request body size at the web server/gateway "
                    "(e.g., client_max_body_size in Nginx, MaxRequestSize in Flask) and reject "
                    "oversized bodies with HTTP 413 before they reach application logic."
                ),
                endpoint=candidate.path,
                method=candidate.method,
            )
        else:
            logger.info(
                "Payload-size check inconclusive on %s (status %s)", url, status
            )

    # ─────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────
    def analyze(self):
        """Run the rate limiting and payload size checks."""
        logger.info("Analyzing resource-consumption controls for %s", self.base_url)
        self._check_rate_limiting()
        self._check_payload_size()
        return self.findings
