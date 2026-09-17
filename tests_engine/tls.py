"""
Phase 8 — TLS/HTTPS Analyzer

Checks whether the API is served over HTTPS and analyzes basic TLS configuration.
This module performs SAFE checks only — it does NOT attempt certificate bypasses,
SSL stripping attacks, or any form of active attack against the TLS layer.

Checks performed:
  1. Is the base URL using HTTPS?
  2. If HTTP, does the server redirect to HTTPS?
  3. Is the certificate valid (basic check via requests library)?

OWASP Mapping:
  - OWASP API Security Top 10: API7:2023 - Security Misconfiguration
  - CWE-319: Cleartext Transmission of Sensitive Information
"""

import logging
import requests
import ssl
import socket
from urllib.parse import urlparse

logger = logging.getLogger('api-shield.tls')


class TLSAnalyzer:
    def __init__(self, base_url: str, timeout: int = 10):
        """
        :param base_url: The base URL of the API project (e.g., http://127.0.0.1:5001).
        :param timeout:  Max seconds to wait for a connection.
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.parsed = urlparse(self.base_url)

    def _add_finding(self, title, severity, description, evidence, recommendation):
        self.findings.append({
            "title": title,
            "endpoint": self.base_url,
            "method": "N/A",
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp": "API7:2023 - Security Misconfiguration"
        })

    def _check_uses_https(self):
        """Finding 1: Is the base URL using HTTPS at all?"""
        scheme = self.parsed.scheme.lower()
        if scheme == "http":
            self._add_finding(
                title="API Served Over HTTP (No TLS)",
                severity="HIGH",
                description=(
                    "The API is accessed via plain HTTP, which transmits all data — "
                    "including authentication tokens and sensitive payloads — in cleartext. "
                    "An attacker on the same network can intercept and read this traffic (Man-in-the-Middle attack)."
                ),
                evidence=f"Base URL uses HTTP scheme: '{self.base_url}'",
                recommendation=(
                    "Deploy the API behind HTTPS using a valid TLS certificate. "
                    "In production, use a certificate from a trusted CA (e.g., Let's Encrypt). "
                    "Note: HTTP is acceptable for local development environments only."
                )
            )
            return False  # Signal to other checks that we are on HTTP
        elif scheme == "https":
            logger.info(f"[PASS] HTTPS scheme confirmed for {self.base_url}")
            return True
        else:
            self._add_finding(
                title="Unrecognized URL Scheme",
                severity="MEDIUM",
                description=f"URL scheme '{scheme}' is not a standard HTTP/HTTPS scheme.",
                evidence=f"Base URL: '{self.base_url}'",
                recommendation="Ensure the API uses 'https://' as its scheme."
            )
            return False

    def _check_http_to_https_redirect(self):
        """Finding 2: If HTTP, does it at least redirect to HTTPS?"""
        http_url = self.base_url
        if not http_url.startswith("http://"):
            return  # Only relevant for HTTP URLs

        try:
            # Follow redirects manually to see if it redirects to HTTPS
            response = requests.get(
                http_url,
                allow_redirects=True,
                timeout=self.timeout,
                verify=False  # Intentionally ignore SSL errors here since we're testing HTTP→HTTPS redirect
            )
            final_url = response.url

            if final_url.startswith("https://"):
                logger.info(f"[PASS] HTTP->HTTPS redirect confirmed: {http_url} -> {final_url}")
                # This is good, but we still note it — HSTS would be better
                self.findings.append({
                    "title": "HTTP to HTTPS Redirect Detected",
                    "endpoint": self.base_url,
                    "method": "N/A",
                    "severity": "LOW",
                    "description": (
                        "The server redirects HTTP requests to HTTPS. This is a positive security control, "
                        "but consider adding HSTS so browsers never make the initial HTTP request at all."
                    ),
                    "evidence": f"HTTP request to '{http_url}' redirected to '{final_url}'",
                    "recommendation": "Add 'Strict-Transport-Security' header and consider HSTS preloading.",
                    "owasp": "API7:2023 - Security Misconfiguration"
                })
            else:
                self._add_finding(
                    title="No HTTP to HTTPS Redirect",
                    severity="MEDIUM",
                    description=(
                        "The server does not redirect HTTP traffic to HTTPS. "
                        "Clients connecting over HTTP receive responses in cleartext."
                    ),
                    evidence=f"HTTP request to '{http_url}' did not redirect to HTTPS. Final URL: '{final_url}'",
                    recommendation="Configure the server to issue a 301 redirect from HTTP to HTTPS."
                )
        except requests.exceptions.SSLError:
            self._add_finding(
                title="SSL Certificate Error",
                severity="HIGH",
                description="The server's TLS certificate could not be verified.",
                evidence=f"SSL verification failed when connecting to '{http_url}'",
                recommendation="Install a valid TLS certificate from a trusted Certificate Authority."
            )
        except requests.exceptions.ConnectionError:
            logger.warning(f"Could not connect to {http_url} for redirect check.")
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout when checking redirect for {http_url}")

    def _check_certificate_validity(self):
        """Finding 3: Basic TLS certificate validation for HTTPS URLs."""
        host = self.parsed.hostname
        port = self.parsed.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    logger.info(f"[PASS] Valid TLS certificate found. Protocol: {tls_version}")

                    # Flag old TLS versions as a finding
                    if tls_version in ["TLSv1", "TLSv1.1"]:
                        self._add_finding(
                            title=f"Deprecated TLS Version in Use: {tls_version}",
                            severity="HIGH",
                            description=(
                                f"The server is using {tls_version}, which is deprecated and has known vulnerabilities "
                                "(e.g., POODLE, BEAST). Modern browsers and clients are dropping support for these versions."
                            ),
                            evidence=f"TLS handshake negotiated: {tls_version}",
                            recommendation="Configure the server to use TLS 1.2 at minimum, preferably TLS 1.3."
                        )

        except ssl.SSLCertVerificationError as e:
            self._add_finding(
                title="Invalid or Self-Signed TLS Certificate",
                severity="HIGH",
                description=(
                    "The server's TLS certificate could not be verified against trusted Certificate Authorities. "
                    "This could indicate a self-signed certificate or an expired certificate."
                ),
                evidence=f"SSL verification error: {str(e)}",
                recommendation=(
                    "Use a certificate issued by a trusted CA (e.g., Let's Encrypt, DigiCert). "
                    "Self-signed certificates are acceptable only in internal development environments."
                )
            )
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.warning(f"Could not perform TLS certificate check for {host}:{port} — {str(e)}")

    def analyze(self):
        """Run all TLS checks and return structured findings."""
        logger.info(f"Starting TLS/HTTPS analysis for {self.base_url}")

        is_https = self._check_uses_https()

        if not is_https:
            # If HTTP, check if there is at least a redirect
            self._check_http_to_https_redirect()
        else:
            # If HTTPS, validate the certificate
            self._check_certificate_validity()

        return self.findings
