"""Rate-limit detection.

Sends a small, bounded burst of lightweight requests to a single endpoint and
observes:

  * HTTP 429 responses (Too Many Requests)
  * rate limiting headers (RateLimit-*, X-RateLimit-*)

The module respects a configurable request cap and never floods the target.
If no 429 appears it reports a finding only at LOW/MEDIUM severity because deep
rate-limit testing on real-world APIs is intentionally avoided.
"""

import logging
import re

import requests

from config import Config
from scanner import ScanContext

logger = logging.getLogger("api_shield.rate_limit")

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


def run_rate_limit_check(ctx, burst=25, pause=0.01):
    """Burst-test one candidate endpoint.

    burst is capped by config (default 25). A single 429 anywhere in the burst
    marks rate limiting as detected.
    """
    session = ctx.get_session()
    findings_before = len(ctx.findings)
    if not ctx.endpoints:
        return []

    # Prefer a login/token endpoint since these are the ones that must be rate
    # limited; fall back to the first POST endpoint then the first endpoint.
    candidate = _pick_endpoint(ctx)
    if candidate is None:
        return []

    burst = min(int(burst), Config.DEFAULT_RATE_LIMIT_TEST_REQUESTS)
    url = candidate.url(ctx.base_url)
    if "{id}" in url:
        url = url.replace("{id}", "1")

    seen_429 = False
    headers_seen = set()
    statuses = {}

    for i in range(burst):
        ctx.tests_completed += 1
        try:
            if candidate.method == "GET":
                resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
            else:
                resp = session.post(
                    url, json={"username": "test", "password": "test"},
                    timeout=Config.REQUEST_TIMEOUT,
                )
        except requests.RequestException as exc:
            logger.debug("Rate-limit probe %d failed: %s", i, exc)
            continue

        statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
        if resp.status_code == 429:
            seen_429 = True
        for h in RATE_LIMIT_HEADERS:
            if h in resp.headers:
                headers_seen.add(h)

    limit_value = _extract_limit(resp) if seen_429 else None

    if seen_429:
        ctx.add_finding(
            title="Rate Limit Detected",
            severity="INFO",
            endpoint=candidate.path,
            method=candidate.method,
            category="API4",
            description="Rate limiting responded with HTTP 429 during burst testing.",
            evidence=f"429 observed within {burst} requests.",
            recommendation="None — rate limiting is enforced.",
        )
        logger.info("Rate limit: DETECTED on %s (%s)", url, limit_value or "unknown")
    else:
        if limit_value:
            ctx.add_finding(
                title="Rate Limit Partially Detected",
                severity="INFO",
                endpoint=candidate.path,
                method=candidate.method,
                category="API4",
                description="Rate-limit headers are present but no 429 was triggered in the test burst.",
                evidence=f"Headers: {', '.join(sorted(headers_seen)) or 'none'}",
                recommendation="Verify limits trigger under real load.",
            )
        else:
            ctx.add_finding(
                title="Rate Limit Not Detected",
                severity="MEDIUM",
                endpoint=candidate.path,
                method=candidate.method,
                category="API4",
                description=(
                    "No HTTP 429 responses or rate-limit headers were observed "
                    "for a bounded test burst. The endpoint may be unprotected."
                ),
                evidence=f"HTTP statuses seen: {dict(sorted(statuses.items())) or 'no responses'}",
                recommendation="Implement rate limiting to protect against abuse.",
            )
    return ctx.findings[findings_before:]


def _pick_endpoint(ctx):
    """Prefer a login endpoint (must be rate-limited); else any POST; else first."""
    for ep in ctx.endpoints:
        if ep.method in ("POST", "PUT", "PATCH") and "login" in ep.path.lower():
            return ep
    for ep in ctx.endpoints:
        if ep.method in ("POST", "PUT", "PATCH"):
            return ep
    return ctx.endpoints[0] if ctx.endpoints else None


def _extract_limit(resp):
    """Try to read a numeric rate limit from headers."""
    for header in ("x-ratelimit-limit", "ratelimit-limit", "ratelimit-policy"):
        value = resp.headers.get(header)
        if value:
            m = re.search(r"\d+", value)
            if m:
                return f"{m.group(0)} requests/min"
    return None