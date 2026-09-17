"""Sensitive information exposure detection.

Scans observed response bodies for evidence of secrets, stack traces,
internal paths and internal IP addresses. Evidence is masked before it is
stored so secrets never land in reports, logs or the database in plaintext.
"""

import logging
import re

import requests

from config import Config
from scanner import ScanContext, mask_string, mask_sensitive_response, truncate
from scanner import SENSITIVE_KEY_PATTERN, SECRET_VALUE_PATTERN, INTERNAL_IP_PATTERN

logger = logging.getLogger("api_shield.sensitive_data")

DEBUG_PATTERNS = {
    "stack": re.compile(r"traceback|stacktrace|at\s+\w+\.[A-Z]\w+\(|File\s+\"[^\"]+\",\s*line", re.IGNORECASE),
    "debug": re.compile(r"debugmode|debug\s*=\s*true|werkzeug|flask\s*debug", re.IGNORECASE),
    "internal_path": re.compile(r"([A-Za-z]:\\|\/)?(home|var|etc|usr|opt)(\\|\/)\w+|\bC:\\\\Users\\\\", re.IGNORECASE),
    "database_error": re.compile(r"database\s+error|sqlalchemy\.exc|psycopg2|mysql\.connector|operationalerror", re.IGNORECASE),
    "aws_keys": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN\s+(RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "internal_ip": INTERNAL_IP_PATTERN,
}

SENSITIVE_KEYS = (
    "password", "passwd", "secret", "api_key", "apikey", "access_token",
    "refresh_token", "authorization", "private_key", "client_secret",
    "password_hash", "client_id", "connectionstring", "connection_string",
)

MASKABLE_KEYS = ("password", "passwd", "secret", "api_key", "apikey", "access_token",
                 "refresh_token", "authorization", "private_key", "client_secret")


def run_sensitive_data_analysis(ctx):
    session = ctx.get_session()
    findings_before = len(ctx.findings)

    for ep in ctx.endpoints[: Config.MAX_ENDPOINTS_PER_SCAN]:
        ctx.tests_completed += 1
        url = ep.url(ctx.base_url)
        if "{id}" in url:
            url = url.replace("{id}", "1")
        try:
            resp = session.request(ep.method, url, timeout=Config.REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        ctx.tests_completed += 1

        body = resp.text or ""
        if not body:
            continue

        _check_headers(ctx, ep, resp.headers)
        _check_body(ctx, ep, body)

    return ctx.findings[findings_before:]


def _check_headers(ctx, ep, headers):
    for name, value in headers.items():
        if re.search(r"authorization|token|api[_-]?key|secret", name, re.IGNORECASE):
            if name.lower() != "authorization" or value:
                ctx.add_finding(
                    title="Sensitive Value in HTTP Header",
                    severity="MEDIUM",
                    endpoint=ep.path,
                    method=ep.method,
                    category="API3",
                    description=(
                        f"Response header '{name}' contains a value that may expose "
                        "sensitive material."
                    ),
                    evidence=f"{name}: {mask_string(value)}",
                    recommendation=(
                        "Do not return credentials or tokens in HTTP headers; use "
                        "short-lived, scoped tokens when required."
                    ),
                )
                break


def _check_body(ctx, ep, body):
    """Look for secret-looking values and debug fingerprints in a body."""
    evidence_bits = []

    if SECRET_VALUE_PATTERN.search(body):
        evidence_bits.append("Secret-like token value detected in response body.")

    if DEBUG_PATTERNS["stack"].search(body):
        evidence_bits.append("Stack trace detected in response body.")
        ctx.add_finding(
            title="Stack Trace Exposure",
            severity="MEDIUM",
            endpoint=ep.path,
            method=ep.method,
            category="API8",
            description="A server-side stack trace was returned to the client.",
            evidence=mask_sensitive_response(truncate(_snippet(body, DEBUG_PATTERNS["stack"]))),
            recommendation="Disable debug mode and log stack traces server-side only.",
        )
    if DEBUG_PATTERNS["debug"].search(body):
        ctx.add_finding(
            title="Debug Information Exposed",
            severity="MEDIUM",
            endpoint=ep.path,
            method=ep.method,
            category="API8",
            description="Debug/verbose error information is exposed to clients.",
            evidence=mask_sensitive_response(truncate(_snippet(body, DEBUG_PATTERNS["debug"]))),
            recommendation="Turn off debug mode in production responses.",
        )
    if DEBUG_PATTERNS["internal_path"].search(body):
        ctx.add_finding(
            title="Internal Path Disclosure",
            severity="LOW",
            endpoint=ep.path,
            method=ep.method,
            category="API8",
            description="Internal filesystem paths are disclosed in the response.",
            evidence=mask_sensitive_response(truncate(_snippet(body, DEBUG_PATTERNS["internal_path"]))),
            recommendation="Strip internal path details from client-facing responses.",
        )
    if DEBUG_PATTERNS["database_error"].search(body):
        ctx.add_finding(
            title="Database Error Disclosure",
            severity="HIGH",
            endpoint=ep.path,
            method=ep.method,
            category="API8",
            description="Database error details are returned to the client.",
            evidence=mask_sensitive_response(truncate(_snippet(body, DEBUG_PATTERNS["database_error"]))),
            recommendation="Return generic error messages and log details internally.",
        )
    if DEBUG_PATTERNS["private_key"].search(body):
        ctx.add_finding(
            title="Private Key Exposure",
            severity="CRITICAL",
            endpoint=ep.path,
            method=ep.method,
            category="API3",
            description="A private key block appears in the response body.",
            evidence="PEM private key block detected (removed from report).",
            recommendation="Immediately rotate the key and remove the file from public paths.",
        )
    if DEBUG_PATTERNS["internal_ip"].search(body):
        ctx.add_finding(
            title="Internal IP Address Disclosure",
            severity="LOW",
            endpoint=ep.path,
            method=ep.method,
            category="API8",
            description="Internal / private IP addresses are visible in the response.",
            evidence="Internal IP address pattern detected (value masked).",
            recommendation="Remove internal addressing from client-facing output.",
        )

    _check_secret_keys_in_json(ctx, ep, body)


def _check_secret_keys_in_json(ctx, ep, body):
    import json

    data = None
    try:
        data = json.loads(body)
    except Exception:
        return
    if isinstance(data, dict):
        _walk_json(ctx, ep, data, "")


def _walk_json(ctx, ep, obj, path):
    if isinstance(obj, dict):
        for key, value in obj.items():
            joined = f"{path}.{key}".lower()
            if any(sk in joined for sk in SENSITIVE_KEYS):
                display = mask_string(value)
                ctx.add_finding(
                    title="Sensitive Data in API Response",
                    severity="MEDIUM" if key in ("access_token", "refresh_token", "private_key", "password") else "LOW",
                    endpoint=ep.path,
                    method=ep.method,
                    category="API3",
                    description=f"JSON field '{joined}' was returned in the API response.",
                    evidence=f"{key}: {display}",
                    recommendation="Remove sensitive fields from API responses or mask them.",
                )
            if isinstance(value, (dict, list)):
                _walk_json(ctx, ep, value, joined)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:5]):
            _walk_json(ctx, ep, item, f"{path}[{i}]")


def _snippet(body, pattern):
    m = pattern.search(body)
    if not m:
        return body[:300]
    start = max(0, m.start() - 60)
    return body[start : m.end() + 120]