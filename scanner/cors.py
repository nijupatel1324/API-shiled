"""CORS misconfiguration analysis.

Sends OPTIONS pre-flight style requests to discovered endpoints and inspects
Access-Control-* response headers for risky configurations.
"""

import logging
import re

import requests

from config import Config
from scanner import ScanContext

logger = logging.getLogger("api_shield.cors")

WILDCARD_ORIGIN = "*"


def run_cors_analysis(ctx):
    session = ctx.get_session()
    findings_before = len(ctx.findings)
    reported = set()

    for ep in ctx.endpoints[: Config.MAX_ENDPOINTS_PER_SCAN]:
        ctx.tests_completed += 1
        url = ep.url(ctx.base_url)
        try:
            resp = session.options(
                url,
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "GET",
                },
                timeout=Config.REQUEST_TIMEOUT,
            )
        except requests.RequestException:
            continue

        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        allow_credentials = resp.headers.get("Access-Control-Allow-Credentials")

        finding = None
        if allow_credentials and allow_origin and allow_origin != WILDCARD_ORIGIN:
            finding = (
                "cors_reflected_credentials",
                "CORS Misconfiguration (Credentials + Reflected Origin)",
                "HIGH",
                (
                    "The API reflects arbitrary origins together with "
                    "Access-Control-Allow-Credentials: true, allowing cross-origin "
                    "authenticated requests."
                ),
                (
                    f"Allow-Origin: {allow_origin}; "
                    f"Allow-Credentials: {allow_credentials}"
                ),
                "Only echo allow-listed origins and avoid credentials with wildcard sources.",
            )
        elif allow_origin == WILDCARD_ORIGIN:
            severity = "HIGH" if allow_credentials else "MEDIUM"
            finding = (
                "cors_wildcard",
                "CORS Wildcard Origin",
                severity,
                (
                    "The API returns Access-Control-Allow-Origin: * "
                    + ("combined with credentials." if allow_credentials else ".")
                ),
                f"Access-Control-Allow-Origin: {allow_origin}",
                "Restrict allowed origins to trusted applications.",
            )

        if not finding:
            continue
        key = finding[0]
        if key in reported:
            continue
        reported.add(key)
        ctx.add_finding(
            title=finding[1],
            severity=finding[2],
            endpoint=ep.path,
            method="OPTIONS",
            category="API8",
            description=finding[3],
            evidence=finding[4],
            recommendation=finding[5],
        )
    return ctx.findings[findings_before:]