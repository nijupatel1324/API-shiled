"""
Phase 9 — CORS (Cross-Origin Resource Sharing) Analyzer

Analyzes the CORS configuration of API endpoints by sending an HTTP OPTIONS
preflight request (or checking GET/POST responses) and inspecting the
Access-Control-* headers returned.

IMPORTANT CONTEXT:
  A wildcard CORS policy (Access-Control-Allow-Origin: *) is NOT automatically
  a vulnerability. It depends entirely on context:
    - A public, read-only, unauthenticated API? Wildcard is often intentional.
    - A wildcard COMBINED with Access-Control-Allow-Credentials: true? DANGEROUS.
  API-SHIELD always provides contextual findings, never blind severity ratings.

OWASP Mapping:
  - OWASP API Security Top 10: API7:2023 - Security Misconfiguration
"""

import logging

logger = logging.getLogger('api-shield.cors')

# The origin we will send in the preflight request to see what the server reflects back
TEST_ORIGIN = "http://evil-test.api-shield.local"
TEST_METHODS = "GET, POST, PUT, DELETE"


class CORSAnalyzer:
    def __init__(self, response_headers: dict, endpoint_url: str, method: str):
        """
        :param response_headers: Headers from the API response (after sending a preflight/request).
        :param endpoint_url:     The full URL of the endpoint that was tested.
        :param method:           HTTP method used.
        """
        # Normalize all header keys to lowercase for consistent lookups
        self.headers = {k.lower(): v for k, v in response_headers.items()}
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.findings = []

    def _add_finding(self, title, severity, description, evidence, recommendation):
        self.findings.append({
            "title": title,
            "endpoint": self.endpoint_url,
            "method": self.method,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp": "API7:2023 - Security Misconfiguration"
        })

    # ─────────────────────────────────────────────────────────────
    # Check 1: Is CORS even configured?
    # ─────────────────────────────────────────────────────────────
    def _check_cors_present(self):
        acao = self.headers.get('access-control-allow-origin')
        if not acao:
            logger.debug(f"No CORS headers on {self.endpoint_url} — not necessarily an issue.")
            return False  # No CORS configured; nothing to analyze
        return True

    # ─────────────────────────────────────────────────────────────
    # Check 2: Wildcard Origin
    # ─────────────────────────────────────────────────────────────
    def _check_wildcard_origin(self):
        acao = self.headers.get('access-control-allow-origin', '')
        acac = self.headers.get('access-control-allow-credentials', '').lower()

        if acao == '*':
            if acac == 'true':
                # This is the dangerous combination
                self._add_finding(
                    title="Dangerous CORS: Wildcard Origin with Credentials Allowed",
                    severity="HIGH",
                    description=(
                        "The API allows requests from ANY origin ('*') AND allows credentials "
                        "(cookies, Authorization headers) to be included. This is a dangerous "
                        "combination. Although browsers typically block this per the CORS spec, "
                        "it indicates a misconfigured policy that should be reviewed immediately. "
                        "A malicious website could attempt to exploit this to make authenticated "
                        "cross-origin requests on behalf of a victim user."
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    recommendation=(
                        "Never combine wildcard origin ('*') with 'Access-Control-Allow-Credentials: true'. "
                        "Replace the wildcard with an explicit whitelist of trusted origins "
                        "(e.g., 'https://your-app.example.com')."
                    )
                )
            else:
                # Wildcard without credentials — may be intentional for public APIs
                self._add_finding(
                    title="CORS: Wildcard Origin Policy Detected",
                    severity="LOW",
                    description=(
                        "The API allows requests from any origin ('*'). This is acceptable for "
                        "fully public, read-only, unauthenticated APIs (e.g., a public data feed). "
                        "It becomes a risk if this endpoint returns sensitive data or is used with credentials."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    recommendation=(
                        "Review whether this endpoint truly needs to be accessible from all origins. "
                        "If the endpoint returns sensitive data or is used with authentication, "
                        "restrict the ACAO header to specific trusted origins."
                    )
                )

    # ─────────────────────────────────────────────────────────────
    # Check 3: Origin Reflection
    # ─────────────────────────────────────────────────────────────
    def _check_origin_reflection(self):
        """
        Checks if the server blindly reflects the 'Origin' header back.
        This means ANY origin is allowed, equivalent to '*' but bypassing some restrictions.
        """
        acao = self.headers.get('access-control-allow-origin', '')
        acac = self.headers.get('access-control-allow-credentials', '').lower()

        if acao == TEST_ORIGIN:
            # The server reflected our test origin back — it allows any origin
            if acac == 'true':
                self._add_finding(
                    title="Critical CORS Misconfiguration: Arbitrary Origin Reflected with Credentials",
                    severity="CRITICAL",
                    description=(
                        "The API reflects any arbitrary Origin header back in the "
                        "Access-Control-Allow-Origin response AND allows credentials. "
                        "This means any malicious website can make authenticated requests "
                        "to this API on behalf of a logged-in user — effectively a full CORS bypass."
                    ),
                    evidence=(
                        f"Test Origin sent: '{TEST_ORIGIN}'\n"
                        f"Access-Control-Allow-Origin reflected: '{acao}'\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    recommendation=(
                        "Implement a strict origin allowlist. Validate the incoming 'Origin' header "
                        "against a hardcoded list of trusted origins. Never reflect the incoming "
                        "Origin value directly back in the response."
                    )
                )
            else:
                self._add_finding(
                    title="CORS: Arbitrary Origin Reflected (No Credentials)",
                    severity="MEDIUM",
                    description=(
                        "The API reflects any arbitrary Origin header back, allowing any website "
                        "to make cross-origin requests. Without credentials this limits the immediate "
                        "impact, but represents a policy misconfiguration worth reviewing."
                    ),
                    evidence=(
                        f"Test Origin sent: '{TEST_ORIGIN}'\n"
                        f"Access-Control-Allow-Origin reflected: '{acao}'"
                    ),
                    recommendation=(
                        "Implement a strict origin whitelist instead of reflecting the incoming Origin header."
                    )
                )

    # ─────────────────────────────────────────────────────────────
    # Check 4: Overly Permissive Allowed Methods
    # ─────────────────────────────────────────────────────────────
    def _check_allowed_methods(self):
        acam = self.headers.get('access-control-allow-methods', '')
        if not acam:
            return

        dangerous_methods = ['DELETE', 'PUT', 'PATCH']
        found_dangerous = [m for m in dangerous_methods if m in acam.upper()]

        if found_dangerous:
            self._add_finding(
                title="CORS: Permissive Cross-Origin Methods Allowed",
                severity="LOW",
                description=(
                    f"The CORS policy allows state-changing methods ({', '.join(found_dangerous)}) "
                    "from cross-origin requests. This increases the attack surface if other CORS "
                    "controls are also misconfigured."
                ),
                evidence=f"Access-Control-Allow-Methods: {acam}",
                recommendation=(
                    "Restrict allowed methods to only those required by legitimate cross-origin clients. "
                    "Combine with a strict origin allowlist."
                )
            )

    def analyze(self):
        """Run all CORS checks and return structured findings."""
        logger.info(f"Analyzing CORS configuration for {self.method} {self.endpoint_url}")

        if not self._check_cors_present():
            # No CORS headers — nothing to flag, return empty
            return []

        self._check_wildcard_origin()
        self._check_origin_reflection()
        self._check_allowed_methods()

        return self.findings
