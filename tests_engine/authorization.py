"""
Phase 12 — Authorization / BOLA (Broken Object Level Authorization) Analyzer

BOLA is the #1 vulnerability in the OWASP API Security Top 10.

Simple Explanation:
  Authentication answers "WHO are you?"
  Authorization answers "WHAT are you ALLOWED to do?"

BOLA occurs when an API verifies that a user is logged in (authentication PASS)
but DOES NOT verify whether the logged-in user actually has permission to
access the specific resource they are requesting (authorization FAIL).

Classic BOLA Pattern:
  User John (ID=2) is logged in with a valid token.
  John sends: GET /api/users/1   ← Requesting admin's (ID=1) profile
  The server checks: "Is John logged in?" → Yes ✓
  The server DOES NOT check: "Is John allowed to view user 1's data?" → Missing!
  Result: John receives admin's profile. → BOLA Vulnerability.

CRITICAL SAFETY RULES:
  - This module ONLY tests against the LOCAL AUTHORIZED LAB.
  - It uses ONLY test accounts that were pre-created specifically for this exercise.
  - It does NOT test third-party APIs or real production systems.
  - It does NOT automate real credential theft or unauthorized access.
  - Test accounts and their Base64-encoded tokens are configured in the scan request.

OWASP Mapping:
  - OWASP API Security Top 10: API1:2023 - Broken Object Level Authorization (BOLA)
  - CWE-639: Authorization Bypass Through User-Controlled Key
"""

import logging
import json
import base64

logger = logging.getLogger('api-shield.authorization')


class AuthorizationAnalyzer:
    def __init__(self,
                 endpoint_url: str,
                 method: str,
                 path_template: str,
                 user_a_token: str,
                 user_b_token: str,
                 resource_id_a: str,
                 request_engine):
        """
        Tests BOLA by checking if User B can access User A's resource.

        :param endpoint_url:    Full URL with User A's resource ID substituted
                                (e.g., http://127.0.0.1:5001/api/users/1)
        :param method:          HTTP method (GET, PUT, DELETE)
        :param path_template:   OpenAPI path template (e.g., /api/users/{id})
        :param user_a_token:    Bearer token for User A (the resource owner).
        :param user_b_token:    Bearer token for User B (the unauthorized requester).
        :param resource_id_a:   The resource ID belonging to User A.
        :param request_engine:  Instance of SafeRequestEngine.
        """
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.path_template = path_template
        self.user_a_token = user_a_token
        self.user_b_token = user_b_token
        self.resource_id_a = resource_id_a
        self.engine = request_engine
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
            "owasp": "API1:2023 - Broken Object Level Authorization (BOLA)"
        })

    def _make_request(self, token: str) -> dict:
        """Send an authorized request with the given Bearer token."""
        headers = {"Authorization": f"Bearer {token}"}
        return self.engine.send_request(self.method, self.endpoint_url, headers=headers)

    def analyze(self) -> list:
        """
        Core BOLA test:
          Step 1: User A accesses their OWN resource (should succeed → baseline).
          Step 2: User B accesses User A's resource (should be denied → if it succeeds, BOLA!).
        """
        logger.info(
            f"BOLA test on {self.method} {self.endpoint_url} "
            f"(resource owned by User A, requested by User B)"
        )

        # ── Step 1: Baseline — User A accesses their own resource ──────────
        response_a = self._make_request(self.user_a_token)

        if response_a.get("error"):
            logger.warning(
                f"Could not complete baseline request for BOLA test: {response_a['error']}"
            )
            return []

        status_a = response_a.get("status_code", 0)

        if status_a not in {200, 201, 202}:
            # If even the owner can't access the resource, the test is inconclusive
            logger.warning(
                f"BOLA baseline failed: User A received {status_a} for their own resource. "
                f"Skipping BOLA analysis."
            )
            return []

        logger.info(f"[BASELINE] User A accessed own resource. Status: {status_a} ✓")

        # ── Step 2: BOLA Check — User B accesses User A's resource ─────────
        response_b = self._make_request(self.user_b_token)

        if response_b.get("error"):
            logger.warning(f"Could not complete User B request: {response_b['error']}")
            return []

        status_b = response_b.get("status_code", 0)

        if status_b in {200, 201, 202}:
            # User B successfully accessed User A's resource → BOLA confirmed!
            # Safely extract partial response body as evidence (do not log entire body)
            body_preview = response_b.get("text", "")[:200]  # First 200 chars only

            self._add_finding(
                title="Potential Broken Object Level Authorization (BOLA)",
                severity="HIGH",
                description=(
                    "User B was able to access a resource that belongs to User A by "
                    "simply changing the object identifier in the URL. The API verified "
                    "that User B had a valid token (authentication PASS) but did NOT verify "
                    "whether User B had permission to access User A's specific resource "
                    "(authorization FAIL). This is BOLA — the #1 API vulnerability."
                ),
                evidence=(
                    f"Endpoint: {self.method} {self.endpoint_url}\n"
                    f"Resource ID (belongs to User A): {self.resource_id_a}\n"
                    f"User A request  -> Status: {status_a} (baseline - expected)\n"
                    f"User B request  -> Status: {status_b} (BOLA - should be 403)\n"
                    f"Response preview (first 200 chars): {body_preview}"
                ),
                recommendation=(
                    "Implement server-side object-level authorization checks on EVERY endpoint "
                    "that accesses a specific object by ID. After authenticating the user, "
                    "verify that the authenticated user's ID matches the owner of the requested "
                    "resource before returning any data. "
                    "Example: if request.user.id != resource.owner_id: return 403 Forbidden\n"
                    "Never rely on client-provided IDs alone as an authorization control."
                )
            )
            logger.warning(
                f"[BOLA DETECTED] {self.method} {self.endpoint_url} — "
                f"User B accessed User A's resource. Status: {status_b}"
            )

        elif status_b in {401, 403}:
            logger.info(
                f"[PASS] BOLA test passed on {self.endpoint_url} — "
                f"User B correctly received {status_b}."
            )
        else:
            logger.info(
                f"[INFO] BOLA test inconclusive on {self.endpoint_url} — "
                f"User B received unexpected status: {status_b}"
            )

        return self.findings
