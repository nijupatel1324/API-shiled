"""TLS / HTTPS security checks.

* Verifies the target scheme (http vs https).
* For https targets, attempts to validate the certificate chain and expiry
  using Python's ssl module.

Local development APIs that run plain http are reported as development
warnings, not production vulnerabilities.
"""

import datetime
import logging
import socket
import ssl

import requests

from urllib.parse import urlparse

from config import Config
from scanner import ScanContext, mask_string

logger = logging.getLogger("api_shield.tls")


def run_tls_check(ctx):
    session = ctx.get_session()
    findings_before = len(ctx.findings)
    parsed = urlparse(ctx.base_url)

    if parsed.scheme == "http":
        if parsed.hostname in ("127.0.0.1", "localhost", "::1"):
            ctx.add_finding(
                title="HTTP in Use (Development Environment)",
                severity="INFO",
                endpoint=parsed.netloc,
                method="GET",
                category="API8",
                description=(
                    "The target uses plain HTTP. For local development APIs this is "
                    "expected and is reported as an informational note only."
                ),
                evidence=f"Target scheme: {parsed.scheme}",
                recommendation="Enable HTTPS in production; consider a self-signed cert for local TLS testing.",
            )
        else:
            ctx.add_finding(
                title="HTTPS Not Enforced",
                severity="MEDIUM",
                endpoint=parsed.netloc,
                method="GET",
                category="API8",
                description="The API is served over plain HTTP and may expose data in transit.",
                evidence="Target URL starts with http://",
                recommendation="Serve the API exclusively over HTTPS.",
            )
        return ctx.findings[findings_before:]

    if parsed.scheme == "https":
        cert_info = _inspect_certificate(parsed.hostname, parsed.port or 443)
        if cert_info is None:
            ctx.add_finding(
                title="TLS Certificate Not Verifiable",
                severity="MEDIUM",
                endpoint=parsed.netloc,
                method="GET",
                category="API8",
                description="The TLS certificate could not be validated against the target host.",
                evidence="Certificate verification failed during handshake.",
                recommendation="Install a valid certificate signed by a trusted CA.",
            )
        else:
            not_before, not_after = cert_info
            now = datetime.datetime.utcnow()
            if not_before > now.replace(tzinfo=None):
                ctx.add_finding(
                    title="TLS Certificate Not Yet Valid",
                    severity="HIGH",
                    endpoint=parsed.netloc,
                    method="GET",
                    category="API8",
                    description="The server certificate is not valid yet.",
                    evidence=f"notBefore: {not_before}",
                    recommendation="Resynchronise the server clock or install the correct certificate.",
                )
            elif not_after < now.replace(tzinfo=None):
                ctx.add_finding(
                    title="TLS Certificate Expired",
                    severity="HIGH",
                    endpoint=parsed.netloc,
                    method="GET",
                    category="API8",
                    description="The server certificate has expired.",
                    evidence=f"notAfter: {not_after}",
                    recommendation="Renew the TLS certificate immediately.",
                )
            else:
                ctx.add_finding(
                    title="TLS Certificate Valid",
                    severity="INFO",
                    endpoint=parsed.netloc,
                    method="GET",
                    category="API8",
                    description="The HTTPS certificate is currently valid.",
                    evidence=f"Valid from {not_before} to {not_after}",
                    recommendation="None.",
                )
    return ctx.findings[findings_before:]


def _inspect_certificate(hostname, port):
    """Return (not_before, not_after) tuples for the presented certificate."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                if not cert:
                    return None
                not_before = ssl.cert_time_to_seconds(cert.get("notBefore", ""))
                not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                nb = datetime.datetime.fromtimestamp(not_before)
                na = datetime.datetime.fromtimestamp(not_after)
                return nb, na
    except Exception as exc:
        logger.debug("TLS certificate inspection failed: %s", exc)
        return None