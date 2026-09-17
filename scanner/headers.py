"""HTTP security header analysis.

Evaluates a set of recommended security headers on observed responses and
reports PASS / FAIL / WARNING for each. Findings are only produced for FAIL
(or WARNING) states; PASS states are folded into the findings as an INFO note
only when explicitly requested via include_passes.
"""

import logging

import requests

from config import Config
from scanner import ScanContext

logger = logging.getLogger("api_shield.headers")

RECOMMENDED_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Cache-Control",
    "Referrer-Policy",
    "X-Frame-Options",
    "Permissions-Policy",
)

# Headers that are valuable but not strictly security-critical for all APIs.
SOFT_HEADERS = ("X-Frame-Options", "Permissions-Policy")


def run_header_analysis(ctx, include_passes=True):
    session = ctx.get_session()
    findings_before = len(ctx.findings)
    if not ctx.endpoints:
        return []

    # Analyse a representative response. Prefer a GET endpoint.
    ep = _pick_endpoint(ctx)
    url = ep.url(ctx.base_url)
    if "{id}" in url:
        url = url.replace("{id}", "1")

    ctx.tests_completed += 1
    try:
        resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.debug("Header analysis failed for %s: %s", url, exc)
        return []
    ctx.tests_completed += 1

    headers = {k.lower(): v for k, v in resp.headers.items()}
    for name in RECOMMENDED_HEADERS:
        low = name.lower()
        value = headers.get(low)
        is_soft = name in SOFT_HEADERS

        if name == "Cache-Control":
            status = _assess_cache_control(value)
        elif name == "Content-Security-Policy":
            status = _assess_csp(value)
        elif value:
            status = "PASS"
        elif is_soft:
            status = "WARNING"
        else:
            status = "FAIL"

        if status == "PASS" and not include_passes:
            continue
        if status == "PASS":
            continue  # PASS states are good hygiene; not stored as findings

        severity = {"FAIL": "LOW", "WARNING": "LOW"}.get(status, "LOW")
        ctx.add_finding(
            title=f"{name} Header {'Missing' if not value else 'Misconfigured'}",
            severity=severity,
            endpoint=ep.path,
            method="GET",
            category="API8",
            description=(
                f"HTTP header {name} is {status.lower()} on the analysed response."
                if value
                else f"HTTP header {name} is missing from the analysed response."
            ),
            evidence=f"Header {name}: {value or 'not present'}",
            recommendation=_recommendation(name, value, is_soft),
        )
    return ctx.findings[findings_before:]


def _assess_cache_control(value):
    if not value:
        return "FAIL"
    no_store = "no-store" in value or "no-cache" in value or "private" in value
    return "PASS" if no_store else "WARNING"


def _assess_csp(value):
    if not value:
        return "FAIL"
    bad = "unsafe-inline" in value or "unsafe-eval" in value or value == "'*'" or value == "*"
    return "FAIL" if bad else "PASS"


def _recommendation(name, value, is_soft):
    mapping = {
        "Strict-Transport-Security": "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        "Content-Security-Policy": "Define an explicit Content-Security-Policy and avoid unsafe-inline/unsafe-eval.",
        "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
        "Cache-Control": "Set Cache-Control: no-store or no-cache for API responses.",
        "Referrer-Policy": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
        "X-Frame-Options": "Set X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors).",
        "Permissions-Policy": "Restrict browser features with a Permissions-Policy header.",
    }
    return mapping.get(name, "Configure the appropriate security header.")


def _pick_endpoint(ctx):
    for ep in ctx.endpoints:
        if ep.method == "GET":
            return ep
    return ctx.endpoints[0]