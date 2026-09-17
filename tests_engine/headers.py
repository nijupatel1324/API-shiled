"""
Phase 7 — Security Header Analyzer

Analyzes HTTP response headers for the presence and correct configuration of
industry-recommended security headers. Each finding is contextual — a missing
header is NOT automatically a vulnerability; it is flagged for analyst review.

OWASP Mapping:
  - OWASP API Security Top 10: API7:2023 - Security Misconfiguration
"""

import logging

logger = logging.getLogger('api-shield.headers')

# ─────────────────────────────────────────────────────────────
# Security Header Definitions
# Each entry defines:
#   - description  : What the header does
#   - severity     : If MISSING, what risk do we assign?
#   - context_note : Important context to give the analyst
# ─────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Tells browsers to only connect via HTTPS, preventing protocol downgrade attacks.",
        "severity": "MEDIUM",
        "context_note": "Only relevant if the API is served over HTTPS in production. Low/Info for HTTP-only lab environments."
    },
    "Content-Security-Policy": {
        "description": "Controls which resources (scripts, styles, etc.) a browser can load, mitigating XSS attacks.",
        "severity": "MEDIUM",
        "context_note": "More critical for APIs that return HTML. For JSON-only APIs the impact is lower."
    },
    "X-Content-Type-Options": {
        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "severity": "LOW",
        "context_note": "Should be set to 'nosniff' on all responses."
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent with requests.",
        "severity": "LOW",
        "context_note": "Recommended value: 'no-referrer' or 'strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "description": "Restricts which browser features (camera, microphone, geolocation) can be used.",
        "severity": "LOW",
        "context_note": "Mostly relevant for web apps; less critical for pure JSON APIs."
    },
    "X-Frame-Options": {
        "description": "Prevents the page from being embedded in an iframe (Clickjacking protection).",
        "severity": "LOW",
        "context_note": "Important for HTML UIs. Less relevant for JSON-only APIs."
    },
}

# Headers that are considered dangerous if configured incorrectly
DANGEROUS_HEADER_VALUES = {
    "X-Powered-By": {
        "description": "Reveals backend technology (e.g., PHP/7.4, Express). Aids attacker fingerprinting.",
        "severity": "LOW",
        "context_note": "This header should be removed from production responses."
    },
    "Server": {
        "description": "Reveals the web server type and version (e.g., Apache/2.4.51). Aids attacker fingerprinting.",
        "severity": "LOW",
        "context_note": "Should be suppressed or genericized in production (e.g., just 'Server: nginx')."
    }
}


class SecurityHeaderAnalyzer:
    def __init__(self, response_headers: dict, endpoint_url: str, method: str):
        """
        :param response_headers: dict of HTTP response headers from the target API.
        :param endpoint_url: The URL of the endpoint that was tested.
        :param method: HTTP method used (GET, POST, etc.).
        """
        # Normalize all header names to lowercase for consistent lookups
        self.response_headers = {k.lower(): v for k, v in response_headers.items()}
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.findings = []

    def _add_finding(self, title, severity, description, evidence, recommendation, owasp="API7:2023 - Security Misconfiguration"):
        """Helper to create a structured finding dictionary."""
        self.findings.append({
            "title": title,
            "endpoint": self.endpoint_url,
            "method": self.method,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp": owasp
        })

    def _check_missing_security_headers(self):
        """Check for absence of recommended security headers."""
        for header_name, config in SECURITY_HEADERS.items():
            if header_name.lower() not in self.response_headers:
                self._add_finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=config["severity"],
                    description=config["description"],
                    evidence=f"Header '{header_name}' was not found in the HTTP response from {self.endpoint_url}.",
                    recommendation=f"Add the '{header_name}' response header. Note: {config['context_note']}"
                )
            else:
                logger.debug(f"[PASS] {header_name} present on {self.endpoint_url}")

    def _check_information_disclosure_headers(self):
        """Check for headers that reveal sensitive server information."""
        for header_name, config in DANGEROUS_HEADER_VALUES.items():
            header_value = self.response_headers.get(header_name.lower())
            if header_value:
                self._add_finding(
                    title=f"Information Disclosure via Response Header: {header_name}",
                    severity=config["severity"],
                    description=config["description"],
                    evidence=f"Header '{header_name}: {header_value}' was found in the response. This reveals server technology details.",
                    recommendation=f"Remove or suppress the '{header_name}' header in production. {config['context_note']}"
                )

    def analyze(self):
        """Run all header checks and return findings."""
        logger.info(f"Analyzing security headers for {self.method} {self.endpoint_url}")
        self._check_missing_security_headers()
        self._check_information_disclosure_headers()
        return self.findings
