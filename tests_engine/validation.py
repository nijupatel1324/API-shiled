"""
Phase 13 — Input Validation Analyzer

Tests whether API endpoints safely handle unexpected, boundary, and invalid inputs.
The goal is to observe how the API RESPONDS to bad input — not to exploit the API.

WHAT THIS MODULE DOES:
  - Sends safe, non-destructive test payloads to API endpoints that accept input.
  - Analyzes the response status code and body for signs of unsafe error handling,
    input acceptance, or information disclosure.
  - Records the input, response status, response behavior, and generates findings.

WHAT THIS MODULE DOES NOT DO:
  - Does NOT generate weaponized SQLi, XSS, or RCE payloads.
  - Does NOT attempt to dump databases or steal data.
  - Does NOT try to crash the server intentionally.
  - All test inputs are safe strings that would only cause problems if the API
    has a fundamental design flaw (e.g., passing user input directly to a shell).

Test Categories:
  1. Empty Input      — How does the API handle missing required fields?
  2. Type Mismatch    — What if a string is sent where an integer is expected?
  3. Boundary Values  — Very long strings, zero, negative numbers.
  4. Invalid Format   — Wrong email format, wrong date format.
  5. Unexpected Fields— Sending extra/unknown fields (Mass Assignment probe).

OWASP Mapping:
  - OWASP API Security Top 10: API3:2023 - Broken Object Property Level Authorization
  - OWASP API Security Top 10: API6:2023 - Unrestricted Access to Sensitive Business Flows
  - CWE-20: Improper Input Validation
"""

import logging
import json

logger = logging.getLogger('api-shield.validation')

# ─────────────────────────────────────────────────────────────
# Safe Test Case Definitions
# Each test case has:
#   name        : Human-readable name
#   payload     : The JSON body to send
#   description : What we are testing
#   expected    : What a SECURE API should return
# ─────────────────────────────────────────────────────────────
SAFE_TEST_CASES = [
    {
        "name": "Empty Body",
        "payload": {},
        "description": "API receives a completely empty JSON object.",
        "expected_safe_statuses": {400, 422},
        "finding_if_accepted": "API accepted an empty request body without validation error."
    },
    {
        "name": "Missing Required Field",
        "payload": {"email": "test@test.com"},  # Missing 'username'
        "description": "API receives a body missing a commonly required field ('username').",
        "expected_safe_statuses": {400, 422},
        "finding_if_accepted": "API accepted a request with a missing required field."
    },
    {
        "name": "Type Mismatch — Integer as String",
        "payload": {"username": 12345, "email": "test@test.com"},
        "description": "API receives an integer where a string is expected for 'username'.",
        "expected_safe_statuses": {400, 422},
        "finding_if_accepted": "API accepted an integer value for a field expecting a string."
    },
    {
        "name": "Very Long String Input",
        "payload": {"username": "A" * 1000, "email": "test@test.com"},
        "description": "API receives a 1000-character string for 'username' (boundary test).",
        "expected_safe_statuses": {400, 422},
        "finding_if_accepted": "API accepted an excessively long string without length validation."
    },
    {
        "name": "Invalid Email Format",
        "payload": {"username": "testuser", "email": "not-an-email"},
        "description": "API receives a malformed email address.",
        "expected_safe_statuses": {400, 422},
        "finding_if_accepted": "API accepted a malformed email address without format validation."
    },
    {
        "name": "Negative Number",
        "payload": {"username": "testuser", "id": -1},
        "description": "API receives a negative number for an ID field.",
        "expected_safe_statuses": {400, 404, 422},
        "finding_if_accepted": "API accepted a negative number for an ID field."
    },
    {
        "name": "Unexpected/Extra Fields (Mass Assignment Probe)",
        "payload": {
            "username": "newuser",
            "email": "new@test.com",
            "role": "admin",       # <-- Should NOT be accepted
            "is_admin": True,      # <-- Should NOT be accepted
            "id": 9999             # <-- Should NOT be accepted
        },
        "description": (
            "API receives extra fields that should not be accepted from the client "
            "(role elevation, ID override). A secure API should strip or reject these."
        ),
        "expected_safe_statuses": {201, 200, 400},  # 201 is OK only if the extra fields are IGNORED
        "finding_if_accepted": "API may accept unexpected fields (potential Mass Assignment vulnerability).",
        "check_response_for": ["role", "is_admin"]  # If these appear in the response, it's a finding
    },
    {
        "name": "Null Value Input",
        "payload": {"username": None, "email": None},
        "description": "API receives null values for required fields.",
        "expected_safe_statuses": {400, 422},
        "finding_if_accepted": "API accepted null values for required fields without validation."
    },
]


def _analyze_response_for_mass_assignment(payload: dict, response_body: str,
                                           check_fields: list) -> bool:
    """
    Checks if unexpected fields sent in the payload appeared in the response body.
    If the response contains 'role: admin' when we sent it, mass assignment is likely.
    """
    try:
        resp_data = json.loads(response_body)
        for field in check_fields:
            if field in resp_data and resp_data[field] == payload.get(field):
                return True  # The server echoed back the attacker-controlled field value
    except (json.JSONDecodeError, TypeError):
        pass
    return False


class InputValidationAnalyzer:
    def __init__(self, endpoint_url: str, method: str, request_engine):
        """
        :param endpoint_url:    Full URL of the endpoint to test.
        :param method:          HTTP method (POST, PUT, PATCH — body-accepting methods only).
        :param request_engine:  Instance of SafeRequestEngine.
        """
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.engine = request_engine
        self.findings = []
        self.test_results = []  # Record of all test runs for evidence

    def _add_finding(self, title, severity, description, evidence, recommendation):
        self.findings.append({
            "title": title,
            "endpoint": self.endpoint_url,
            "method": self.method,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp": "API3:2023 - Broken Object Property Level Authorization / CWE-20"
        })

    def _run_test_case(self, test_case: dict):
        """Execute a single safe test case and record the result."""
        payload = test_case["payload"]
        logger.debug(
            f"Running input validation test '{test_case['name']}' on {self.endpoint_url}"
        )

        response = self.engine.send_request(
            self.method,
            self.endpoint_url,
            json_data=payload
        )

        if response.get("error"):
            logger.warning(
                f"Test '{test_case['name']}' failed to connect: {response['error']}"
            )
            return

        status = response.get("status_code", 0)
        body = response.get("text", "")
        body_preview = body[:300]  # Limit evidence body size

        # Record this test run regardless of result
        self.test_results.append({
            "test_name": test_case["name"],
            "input_sent": str(payload)[:200],
            "status_code": status,
            "response_preview": body_preview,
            "description": test_case["description"]
        })

        expected_safe = test_case.get("expected_safe_statuses", {400, 422})

        # ── Special check for Mass Assignment ──────────────────────────────
        if "check_response_for" in test_case and status in {200, 201}:
            if _analyze_response_for_mass_assignment(
                payload, body, test_case["check_response_for"]
            ):
                self._add_finding(
                    title="Potential Mass Assignment Vulnerability",
                    severity="HIGH",
                    description=(
                        "The API appears to accept and process fields that should not be "
                        "assignable by the client (e.g., 'role', 'is_admin', 'id'). "
                        "This is a Mass Assignment vulnerability, which can allow an attacker "
                        "to escalate privileges by setting 'role: admin' in the request body."
                    ),
                    evidence=(
                        f"Test: {test_case['name']}\n"
                        f"Payload sent: {str(payload)[:300]}\n"
                        f"Response Status: {status}\n"
                        f"Suspicious fields found in response: {test_case['check_response_for']}\n"
                        f"Response preview: {body_preview}"
                    ),
                    recommendation=(
                        "Implement an explicit allowlist (whitelist) of fields that the client "
                        "is permitted to set. Reject or strip any fields not in the allowlist. "
                        "Never use mass-assignment patterns like object.update(**request.json). "
                        "Use Data Transfer Objects (DTOs) or schema validation (e.g., marshmallow, pydantic)."
                    )
                )
                return  # Already created a finding for this test

        # ── Standard Validation Check ───────────────────────────────────────
        # If the status is 2xx but the API should have rejected it → finding
        if status in {200, 201} and expected_safe not in [{200, 201}] and 200 not in expected_safe:
            self._add_finding(
                title=f"Missing Input Validation: {test_case['name']}",
                severity="MEDIUM",
                description=(
                    f"The API accepted input that should have been rejected by a validation layer. "
                    f"{test_case['description']}"
                ),
                evidence=(
                    f"Test: {test_case['name']}\n"
                    f"Input sent: {str(payload)[:300]}\n"
                    f"Expected status: one of {expected_safe}\n"
                    f"Actual status: {status}\n"
                    f"Response preview: {body_preview}"
                ),
                recommendation=(
                    "Implement server-side input validation for all API parameters. "
                    "Validate type, format, length, and range for every field. "
                    "Use schema validation libraries (pydantic, marshmallow, jsonschema). "
                    "Return HTTP 400 Bad Request with a generic message for validation failures. "
                    "Never rely on client-side validation alone."
                )
            )

        # ── Check for Verbose Error (500 on bad input) ──────────────────────
        if status == 500:
            self._add_finding(
                title=f"Server Error on Invalid Input: {test_case['name']}",
                severity="MEDIUM",
                description=(
                    "The API returned a 500 Internal Server Error when it received unexpected input. "
                    "A robust API should handle all input gracefully and return 400/422, "
                    "never 500. A 500 error may indicate the application crashed or "
                    "an unhandled exception was raised — which can leak internal details."
                ),
                evidence=(
                    f"Test: {test_case['name']}\n"
                    f"Input sent: {str(payload)[:300]}\n"
                    f"Response Status: 500\n"
                    f"Response preview: {body_preview}"
                ),
                recommendation=(
                    "Add proper exception handling around input parsing and processing. "
                    "Return HTTP 400 Bad Request for invalid inputs. "
                    "Log the full exception server-side; never expose it in the response."
                )
            )

    def analyze(self) -> dict:
        """
        Run all safe test cases against this endpoint.
        Returns a dict with findings and test_results (the full test log).
        """
        if self.method not in {"POST", "PUT", "PATCH"}:
            logger.debug(
                f"Skipping input validation for {self.method} {self.endpoint_url} "
                f"— only POST/PUT/PATCH endpoints accept a request body."
            )
            return {"findings": [], "test_results": []}

        logger.info(
            f"Running {len(SAFE_TEST_CASES)} input validation tests on "
            f"{self.method} {self.endpoint_url}"
        )

        for test_case in SAFE_TEST_CASES:
            self._run_test_case(test_case)

        return {
            "findings": self.findings,
            "test_results": self.test_results
        }
