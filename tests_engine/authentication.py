"""
Phase 11 — Authentication Security Analyzer

Performs safe, non-destructive authentication checks on API endpoints.
The analyzer tests whether:
  1. Endpoints marked as requiring authentication actually enforce it
     (i.e., reject unauthenticated requests with 401/403).
  2. Endpoints NOT marked as requiring authentication are truly public
     (informational observation).
  3. The authentication scheme used is identifiable (Bearer, API Key, Basic).
  4. Basic authentication is in use (flagged as weak for modern APIs).

CRITICAL SAFETY RULES:
  - This module does NOT brute-force credentials.
  - This module does NOT attempt to crack or bypass authentication.
  - It only makes ONE unauthenticated request per endpoint to observe behavior.
  - Test credentials, if supplied, are used ONLY for the authorized lab.

OWASP Mapping:
  - OWASP API Security Top 10: API2:2023 - Broken Authentication
  - CWE-306: Missing Authentication for Critical Function
  - CWE-798: Use of Hard-coded Credentials
"""

import logging
import json

logger = logging.getLogger('api-shield.authentication')

# HTTP status codes that clearly indicate authentication is being enforced
AUTH_ENFORCED_CODES = {401, 403}

# HTTP status codes that suggest authentication is NOT enforced
AUTH_MISSING_CODES = {200, 201, 202, 204}


class AuthenticationAnalyzer:
    def __init__(self, endpoint_url: str, method: str,
                 response_no_auth: dict,
                 endpoint_spec_requires_auth: bool):
        """
        :param endpoint_url:                The URL that was tested.
        :param method:                      HTTP method used.
        :param response_no_auth:            The response dict from SafeRequestEngine
                                            WITHOUT any auth headers.
        :param endpoint_spec_requires_auth: Whether the OpenAPI spec declares
                                            this endpoint as requiring auth.
        """
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.response = response_no_auth
        self.spec_requires_auth = endpoint_spec_requires_auth
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
            "owasp": "API2:2023 - Broken Authentication"
        })

    # ─────────────────────────────────────────────────────────────
    # Check 1: Missing Authentication on Protected Endpoint
    # ─────────────────────────────────────────────────────────────
    def _check_missing_authentication(self):
        """
        The core check: if the spec says auth is required, but the server
        returns a success code without any credentials, that's a vulnerability.
        """
        status = self.response.get("status_code", 0)

        if self.spec_requires_auth and status in AUTH_MISSING_CODES:
            self._add_finding(
                title="Missing Authentication on Protected Endpoint",
                severity="HIGH",
                description=(
                    "This endpoint is documented as requiring authentication in the API "
                    "specification, but it returned a successful response (2xx) when "
                    "accessed without any authentication credentials. This means the "
                    "endpoint is effectively public, exposing potentially sensitive data "
                    "or operations to unauthenticated users."
                ),
                evidence=(
                    f"Endpoint: {self.method} {self.endpoint_url}\n"
                    f"Auth Required (per spec): Yes\n"
                    f"Request sent WITHOUT authentication headers.\n"
                    f"Response Status Code: {status}"
                ),
                recommendation=(
                    "Implement server-side authentication enforcement on this endpoint. "
                    "Validate an authentication token (e.g., JWT Bearer token) on every request. "
                    "Return HTTP 401 Unauthorized for missing/invalid credentials. "
                    "Never rely solely on the API spec to enforce security — the server must "
                    "always enforce it regardless."
                )
            )
        elif not self.spec_requires_auth and status in AUTH_MISSING_CODES:
            # Endpoint is intentionally public — informational only
            logger.info(
                f"[INFO] {self.method} {self.endpoint_url} is publicly accessible "
                f"(as expected per spec). Status: {status}"
            )
        elif status in AUTH_ENFORCED_CODES:
            logger.info(
                f"[PASS] Authentication enforced on {self.method} {self.endpoint_url}. "
                f"Status: {status}"
            )

    # ─────────────────────────────────────────────────────────────
    # Check 2: Identify Authentication Scheme from WWW-Authenticate
    # ─────────────────────────────────────────────────────────────
    def _check_auth_scheme(self):
        """
        When a server returns 401, it SHOULD include a WWW-Authenticate header
        indicating the expected auth scheme. Analyze this header.
        """
        status = self.response.get("status_code", 0)
        headers = {k.lower(): v for k, v in self.response.get("headers", {}).items()}

        www_auth = headers.get("www-authenticate", "")

        if status == 401 and not www_auth:
            self._add_finding(
                title="Missing WWW-Authenticate Header on 401 Response",
                severity="LOW",
                description=(
                    "The server returned a 401 Unauthorized response but did not include "
                    "a 'WWW-Authenticate' header. RFC 7235 requires this header to indicate "
                    "the authentication scheme the client should use."
                ),
                evidence=f"HTTP 401 response received. No 'WWW-Authenticate' header present.",
                recommendation=(
                    "Add a 'WWW-Authenticate' header to 401 responses. "
                    "Example: WWW-Authenticate: Bearer realm=\"api-shield\""
                )
            )
        elif www_auth:
            # Check for Basic auth — considered weak for modern APIs
            if www_auth.lower().startswith("basic"):
                self._add_finding(
                    title="Weak Authentication Scheme: HTTP Basic Authentication Detected",
                    severity="MEDIUM",
                    description=(
                        "The server is using HTTP Basic Authentication, which transmits "
                        "credentials as a Base64-encoded string (NOT encrypted). "
                        "While Base64 is not encryption, the credentials are trivially decoded. "
                        "Basic Auth over HTTPS is acceptable in some internal/machine-to-machine "
                        "contexts but is not recommended for user-facing APIs."
                    ),
                    evidence=f"WWW-Authenticate: {www_auth}",
                    recommendation=(
                        "Replace HTTP Basic Authentication with a modern, token-based scheme such as "
                        "OAuth 2.0 / JWT Bearer tokens. If Basic Auth is retained for internal use, "
                        "ensure it is ALWAYS transmitted over HTTPS."
                    )
                )
            else:
                logger.info(
                    f"[INFO] Auth scheme detected on {self.endpoint_url}: {www_auth}"
                )

    # ─────────────────────────────────────────────────────────────
    # Check 3: Sensitive Data in Unauthenticated Error Response
    # ─────────────────────────────────────────────────────────────
    def _check_auth_error_info_disclosure(self):
        """
        When authentication fails, the error message itself should be generic.
        Detailed error messages can help attackers understand the auth mechanism.
        """
        status = self.response.get("status_code", 0)
        body = self.response.get("text", "")

        if status in {401, 403} and body:
            try:
                data = json.loads(body)
                # Look for verbose debug-style keys in the error response
                verbose_keys = {"stack", "trace", "exception", "debug", "internal"}
                found = [k for k in data.keys() if k.lower() in verbose_keys]
                if found:
                    self._add_finding(
                        title="Verbose Information in Authentication Error Response",
                        severity="LOW",
                        description=(
                            "The authentication error response contains verbose internal "
                            f"fields ({', '.join(found)}) that may aid an attacker in "
                            "understanding the backend authentication system."
                        ),
                        evidence=f"Authentication error body contains fields: {found}",
                        recommendation=(
                            "Return a generic error message for authentication failures "
                            "(e.g., {\"error\": \"Unauthorized\"}). "
                            "Log detailed diagnostics server-side only."
                        )
                    )
            except (json.JSONDecodeError, AttributeError):
                pass  # Non-JSON responses are fine to skip

    def analyze(self):
        """Run all authentication checks and return structured findings."""
        logger.info(
            f"Analyzing authentication for {self.method} {self.endpoint_url} "
            f"(spec requires auth: {self.spec_requires_auth})"
        )

        if self.response.get("error"):
            logger.warning(
                f"Skipping auth analysis for {self.endpoint_url}: {self.response['error']}"
            )
            return []

        self._check_missing_authentication()
        self._check_auth_scheme()
        self._check_auth_error_info_disclosure()

        return self.findings
