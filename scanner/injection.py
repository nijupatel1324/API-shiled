"""Safe injection indicator detection.

Sends only safe, non-destructive probe payloads to parameterised endpoints and
flags *indicators* (error fingerprints, status differences, verbose exceptions).
It never executes destructive commands nor mutates data.
"""

import logging
import re

import requests

from config import Config
from scanner import ScanContext

logger = logging.getLogger("api_shield.injection")

# Error fingerprints that commonly indicate unsanitised input reaching a backend.
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql|postgres|sqlite|oracle|mssql",
    r"unclosed quotation mark",
    r"database error",
    r"unknown column",
    r"pg_|postgresql",
    r"warning: mysql",
    r"sqlalchemy",
]
COMMAND_ERROR_PATTERNS = [
    r"sh:\s|bash:|command not found",
    r"/bin/sh|/bin/bash",
    r"Traceback.*subprocess",
    r"OSError.*No such file",
    r"Errno 2",
]
NOSQL_ERROR_PATTERNS = [
    r"mongodberror|mongo.*error",
    r"unexpected token.*mongo",
    r"objectid",
]
LDAP_ERROR_PATTERNS = [
    r"ldap_error|invalid dn syntax|directory.*error",
    r"javax.naming|invalid filter",
]

# Safe, non-destructive probes. Single quotes and arithmetic only -- no sleep,
# no file writes, no system calls.
PROBES = {
    "sqli": ["'", "1' OR '1'='1' --", "1 AND 1=1", "1 AND 2=1"],
    "nosqli": ['"', '{"$gt":""}'],
    "cmdinj": [";", "|", "&&", "`"],
    "ldapi": ["*", "()(|(objectClass=*))"],
}


def run_injection_checks(ctx, parameters=None):
    """Probe GET query params / small JSON bodies with safe payloads."""
    session = ctx.get_session()
    findings_before = len(ctx.findings)

    for ep in ctx.endpoints[: Config.MAX_ENDPOINTS_PER_SCAN]:
        if ep.method not in ("GET", "POST", "PUT", "PATCH"):
            continue
        param_names = parameters or _guess_parameters(ep.path)
        if not param_names:
            param_names = ["id", "search", "name", "query", "username", "q"]

        for probe_type, payloads in PROBES.items():
            hit = False
            for payload in payloads[:2]:
                if hit:
                    break
                for param in param_names[:2]:
                    ctx.tests_completed += 1
                    response = _send_probe(session, ctx.base_url, ep, param, payload)
                    if response is None:
                        continue
                    indicators = _classify(response)
                    if indicators:
                        _report(ctx, ep, param, probe_type, payload, response, indicators)
                        hit = True
                        break
    return ctx.findings[findings_before:]


def _guess_parameters(path):
    """Extract path parameter names for substitution."""
    import re

    return re.findall(r"\{(\w+)\}", path)


def _send_probe(session, base_url, ep, param, payload):
    url = ep.url(base_url)
    try:
        if ep.method == "GET":
            return session.get(
                url, params={param: payload}, timeout=Config.REQUEST_TIMEOUT
            )
        return session.request(
            ep.method,
            url,
            json={param: payload},
            timeout=Config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.debug("Injection probe failed for %s: %s", ep.path, exc)
        return None


def _classify(response):
    """Return a map of detection type -> evidence string, or empty dict."""
    body = (response.text or "").lower()
    headers = str(dict(response.headers)).lower()
    found = {}

    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, body):
            found["Potential SQL Injection"] = "Database-related error message detected in the response."
            break

    for pattern in NOSQL_ERROR_PATTERNS:
        if re.search(pattern, body):
            found["Potential NoSQL Injection"] = "NoSQL error signature observed in the response."
            break

    for pattern in COMMAND_ERROR_PATTERNS:
        if re.search(pattern, body):
            found["Potential Command Injection"] = "Shell/command error signature observed in the response."
            break

    for pattern in LDAP_ERROR_PATTERNS:
        if re.search(pattern, body):
            found["Potential LDAP Injection"] = "LDAP error signature observed in the response."
            break

    if "traceback" in body or "stacktrace" in body:
        found["Potential Injection (verbose error)"] = "Verbose stack trace returned on crafted input."
    return found


def _report(ctx, ep, param, probe_type, payload, response, indicators):
    for title, evidence in indicators.items():
        severity = "HIGH" if "SQL" in title or "Command" in title else ("MEDIUM" if "NoSQL" in title else "LOW")
        ctx.add_finding(
            title=title,
            severity=severity,
            endpoint=ep.path,
            method=ep.method,
            category=_owasp_category(title),
            description=(
                f"Input for parameter '{param}' appears to be processed without "
                "safe parameterisation (based on response differences)."
            ),
            evidence=f"{evidence} Probe payload: {payload}",
            recommendation=(
                "Use parameterized queries, prepared statements and strict input validation."
                if "SQL" in title
                else "Validate and sanitise all input; reject control characters."
            ),
        )


def _owasp_category(title):
    if "SQL" in title or "NoSQL" in title or "LDAP" in title or "Command" in title:
        return "API8"
    return "API8"