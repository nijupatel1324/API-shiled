"""
Phase 14 — Error Handling / Information Disclosure Analyzer

Analyzes API error responses for excessive information that could aid an attacker.
When an API encounters an error, it should ALWAYS return a generic, safe message
to the client and ONLY log the detailed diagnostics server-side.

WHAT WE LOOK FOR IN ERROR RESPONSES:
  - Stack traces (reveals internal code structure & line numbers)
  - File system paths (reveals server file layout)
  - Database error messages (reveals DB type, schema, query structure)
  - Framework/library names and versions (aids fingerprinting)
  - Internal IP addresses and hostnames
  - Debug mode indicators
  - Environment variable names
  - Exception class names

HOW WE TRIGGER ERRORS SAFELY:
  - Send requests to non-existent endpoints (404 triggers)
  - Send malformed JSON body (parse error triggers)
  - Send requests with invalid auth formats (auth error triggers)
  - Observe responses to normal invalid inputs from Phase 13

OWASP Mapping:
  - OWASP API Security Top 10: API8:2023 - Security Misconfiguration
  - CWE-209: Generation of Error Message Containing Sensitive Information
  - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import logging
import json
import re

logger = logging.getLogger('api-shield.error_analysis')

# ─────────────────────────────────────────────────────────────
# Patterns that indicate information disclosure in error responses
# Each entry: (regex_pattern, finding_name, severity)
# ─────────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    # Stack traces / exception info
    (r'traceback \(most recent call last\)', "Python Stack Trace", "HIGH"),
    (r'at\s+\w+\.\w+\([\w\.]+:\d+\)',       "Java Stack Trace",   "HIGH"),
    (r'Exception in thread',                  "Java Exception",     "HIGH"),
    (r'System\.Web\.',                        ".NET Stack Trace",   "HIGH"),
    (r'Uncaught\s+\w+Error:',               "JavaScript Error",   "HIGH"),

    # Framework / technology fingerprinting
    (r'Flask/[\d\.]+',                   "Flask Version Disclosure",   "MEDIUM"),
    (r'Django/[\d\.]+',                  "Django Version Disclosure",  "MEDIUM"),
    (r'Express[\s/][\d\.]+',             "Express Version Disclosure", "MEDIUM"),
    (r'Werkzeug/[\d\.]+',                "Werkzeug Version Disclosure","MEDIUM"),
    (r'"powered_by"\s*:\s*"[^"]{3,}"',   "Powered-By Disclosure",     "MEDIUM"),

    # Database errors
    (r'sqlite3\.\w+Error',               "SQLite Error Disclosure",    "HIGH"),
    (r'mysql\.connector\.\w+Error',      "MySQL Error Disclosure",     "HIGH"),
    (r'psycopg2\.\w+',                   "PostgreSQL Error Disclosure","HIGH"),
    (r'OperationalError',                "DB Operational Error",       "HIGH"),
    (r'sql syntax error',                "SQL Syntax Error Disclosure","HIGH"),
    (r'ORA-\d{5}',                       "Oracle DB Error Code",       "HIGH"),

    # File system paths
    (r'[A-Za-z]:\\[\w\\]+\.py',         "Windows File Path Disclosure","MEDIUM"),
    (r'/home/\w+/[\w/]+\.py',           "Linux File Path Disclosure",  "MEDIUM"),
    (r'/var/www/[\w/]+',                 "Web Root Path Disclosure",    "MEDIUM"),
    (r'/app/[\w/]+\.py',                 "App Path Disclosure",         "MEDIUM"),

    # Internal network info
    (r'192\.168\.\d+\.\d+',             "Internal IP Disclosure",     "MEDIUM"),
    (r'10\.\d+\.\d+\.\d+',             "Internal IP Disclosure",     "MEDIUM"),
    (r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+', "Internal IP Disclosure", "MEDIUM"),

    # Debug indicators
    (r'"debug"\s*:\s*true',              "Debug Mode Enabled",         "HIGH"),
    (r'debug=True',                      "Debug Mode Enabled",         "HIGH"),
    (r'"environment"\s*:\s*"development"',"Dev Environment Disclosed", "MEDIUM"),

    # Environment variables / config leaks
    (r'SECRET_KEY\s*=',                  "Secret Key Disclosure",      "CRITICAL"),
    (r'DATABASE_URL\s*=',                "Database URL Disclosure",    "CRITICAL"),
    (r'API_KEY\s*=',                     "API Key Disclosure",         "CRITICAL"),
    (r'PASSWORD\s*=',                    "Password Disclosure",        "CRITICAL"),
]

# Specific trigger requests to intentionally elicit error responses
ERROR_TRIGGER_CASES = [
    {
        "name": "Non-existent Endpoint (404 Trigger)",
        "path_suffix": "/nonexistent-endpoint-apishield-probe",
        "method": "GET",
        "headers": {},
        "body": None,
        "description": "Requests a path that does not exist to trigger a 404 error response."
    },
    {
        "name": "Malformed JSON Body (Parse Error Trigger)",
        "path_suffix": "",  # Use the actual endpoint
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": "{ this is not valid json !@#",
        "description": "Sends a malformed JSON body to trigger a parse/validation error."
    },
    {
        "name": "Invalid Authorization Header Format",
        "path_suffix": "",
        "method": "GET",
        "headers": {"Authorization": "Bearer INVALID_TOKEN_FORMAT_!!!"},
        "body": None,
        "description": "Sends a malformed Bearer token to trigger an auth error response."
    },
]


class ErrorAnalyzer:
    def __init__(self, base_url: str, endpoint_url: str, method: str,
                 request_engine):
        """
        :param base_url:        Project base URL (for constructing probe URLs).
        :param endpoint_url:    Full URL of the specific endpoint being tested.
        :param method:          HTTP method of the endpoint.
        :param request_engine:  Instance of SafeRequestEngine.
        """
        self.base_url = base_url.rstrip('/')
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.engine = request_engine
        self.findings = []

    def _add_finding(self, title, severity, description, evidence, recommendation,
                     trigger_name=""):
        self.findings.append({
            "title": title,
            "endpoint": self.endpoint_url,
            "method": self.method,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "trigger": trigger_name,
            "owasp": "API8:2023 - Security Misconfiguration"
        })

    def _scan_body_for_sensitive_patterns(self, body: str, trigger_name: str,
                                           response_url: str, status_code: int):
        """
        Scans the response body against all SENSITIVE_PATTERNS.
        Generates one finding per unique pattern matched.
        """
        if not body:
            return

        body_lower = body.lower()
        matched_patterns = set()

        for pattern, finding_name, severity in SENSITIVE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if finding_name not in matched_patterns:
                    matched_patterns.add(finding_name)

                    # Extract a safe snippet of context (not the whole body)
                    match = re.search(pattern, body, re.IGNORECASE)
                    start = max(0, match.start() - 50)
                    end = min(len(body), match.end() + 100)
                    snippet = body[start:end].strip()

                    # Mask any potential credential values in the snippet
                    snippet = re.sub(
                        r'(SECRET_KEY|PASSWORD|API_KEY|DATABASE_URL)\s*=\s*\S+',
                        r'\1=<REDACTED>',
                        snippet,
                        flags=re.IGNORECASE
                    )

                    self._add_finding(
                        title=f"Information Disclosure in Error Response: {finding_name}",
                        severity=severity,
                        description=(
                            f"The API error response contains sensitive information that could "
                            f"aid an attacker. Pattern detected: '{finding_name}'.\n"
                            f"This was triggered by: {trigger_name}."
                        ),
                        evidence=(
                            f"Trigger: {trigger_name}\n"
                            f"URL: {response_url}\n"
                            f"HTTP Status: {status_code}\n"
                            f"Matched Pattern: {finding_name}\n"
                            f"Context snippet (sanitized): ...{snippet}..."
                        ),
                        recommendation=(
                            "Configure the API to return only generic error messages in production "
                            "(e.g., {\"error\": \"An internal error occurred\"}).\n"
                            "Log all detailed diagnostic information server-side only.\n"
                            "Disable debug mode in production environments.\n"
                            "Use an error handler middleware that catches all exceptions before "
                            "they are serialized into the HTTP response."
                        ),
                        trigger_name=trigger_name
                    )

    def analyze(self) -> list:
        """
        Run error-triggering requests and scan responses for sensitive patterns.
        """
        logger.info(f"Starting error analysis for {self.endpoint_url}")

        for trigger in ERROR_TRIGGER_CASES:
            method = trigger["method"]
            suffix = trigger["path_suffix"]

            # Build the probe URL
            if suffix:
                url = self.base_url + suffix
            else:
                if method == "POST":
                    url = self.endpoint_url  # Use the actual endpoint for POST
                else:
                    url = self.endpoint_url

            # Skip if method doesn't match well (e.g., don't POST to GET-only endpoints)
            if method == "POST" and self.method == "GET" and not suffix:
                continue

            # Prepare body
            body_raw = trigger.get("body")
            headers = trigger.get("headers", {})

            if body_raw is not None:
                # Send raw string body (intentionally malformed JSON)
                import requests as req_lib
                try:
                    from urllib.parse import urlparse as _up
                    parsed = _up(url)
                    host = parsed.hostname

                    # Use the engine's scope check first
                    if not self.engine._is_allowed(url):
                        continue
                    self.engine._enforce_rate_limit()

                    raw_response = req_lib.post(
                        url,
                        data=body_raw.encode('utf-8'),
                        headers=headers,
                        timeout=self.engine.timeout
                    )
                    response = {
                        "status_code": raw_response.status_code,
                        "headers": dict(raw_response.headers),
                        "text": raw_response.text[:5000],
                        "url": raw_response.url
                    }
                except Exception as e:
                    logger.warning(f"Error trigger request failed: {str(e)}")
                    continue
            else:
                response = self.engine.send_request(
                    method=method,
                    url=url,
                    headers=headers
                )

            if response.get("error"):
                continue

            status = response.get("status_code", 0)
            body = response.get("text", "")

            logger.debug(
                f"Error trigger '{trigger['name']}' -> "
                f"{method} {url} -> Status: {status}"
            )

            # Only analyze error responses (4xx, 5xx)
            if status >= 400:
                self._scan_body_for_sensitive_patterns(
                    body=body,
                    trigger_name=trigger["name"],
                    response_url=url,
                    status_code=status
                )

        return self.findings
