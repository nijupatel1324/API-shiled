"""
Phase 10 — Cookie Security Analyzer

Parses and analyzes Set-Cookie headers in API responses.
Checks for missing security flags that protect session cookies
from common attacks like XSS, MITM, and CSRF.

Cookie Security Flags Explained:
  - Secure     : Cookie is ONLY sent over HTTPS. Without it, cookies are
                 sent over HTTP too, exposing them to network interception.
  - HttpOnly   : JavaScript CANNOT access this cookie. Without it, an XSS
                 attack can steal the cookie: document.cookie
  - SameSite   : Controls whether the cookie is sent with cross-site requests.
                 Values: Strict | Lax | None
                 'None' without 'Secure' is dangerous (allows cross-site with
                  no TLS protection).

OWASP Mapping:
  - OWASP API Security Top 10: API7:2023 - Security Misconfiguration
  - CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  - CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
"""

import logging
import re

logger = logging.getLogger('api-shield.cookies')


def _parse_set_cookie(set_cookie_value: str) -> dict:
    """
    Parses a single Set-Cookie header string into a structured dictionary.
    Example input:
      "session_id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com"
    Example output:
      {
        "name": "session_id",
        "value": "abc123",
        "secure": True,
        "httponly": True,
        "samesite": "Lax",
        "path": "/",
        "domain": "example.com"
      }
    """
    parts = [p.strip() for p in set_cookie_value.split(';')]
    
    cookie = {
        "name": None,
        "value": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "path": None,
        "domain": None,
        "raw": set_cookie_value
    }

    for i, part in enumerate(parts):
        if i == 0:
            # First part is always name=value
            if '=' in part:
                name, _, value = part.partition('=')
                cookie["name"] = name.strip()
                cookie["value"] = value.strip()
        else:
            part_lower = part.lower()
            if part_lower == 'secure':
                cookie["secure"] = True
            elif part_lower == 'httponly':
                cookie["httponly"] = True
            elif part_lower.startswith('samesite='):
                cookie["samesite"] = part.split('=', 1)[1].strip()
            elif part_lower.startswith('path='):
                cookie["path"] = part.split('=', 1)[1].strip()
            elif part_lower.startswith('domain='):
                cookie["domain"] = part.split('=', 1)[1].strip()

    return cookie


class CookieAnalyzer:
    def __init__(self, response_headers: dict, endpoint_url: str, method: str):
        """
        :param response_headers: Full dict of response headers.
        :param endpoint_url:     The URL that was requested.
        :param method:           HTTP method used.
        """
        self.raw_headers = response_headers
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.findings = []
        self.cookies = self._extract_cookies()

    def _extract_cookies(self) -> list:
        """Extract all Set-Cookie headers from the response."""
        cookies = []
        for key, value in self.raw_headers.items():
            if key.lower() == 'set-cookie':
                # Value might be a list (multiple cookies) or a single string
                if isinstance(value, list):
                    for v in value:
                        cookies.append(_parse_set_cookie(v))
                else:
                    cookies.append(_parse_set_cookie(value))
        return cookies

    def _add_finding(self, title, severity, description, evidence, recommendation, cookie_name=""):
        self.findings.append({
            "title": title,
            "endpoint": self.endpoint_url,
            "method": self.method,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp": "API7:2023 - Security Misconfiguration",
            "cookie_name": cookie_name
        })

    # ─────────────────────────────────────────────────────────────
    # Check 1: Missing Secure Flag
    # ─────────────────────────────────────────────────────────────
    def _check_secure_flag(self, cookie: dict):
        if not cookie["secure"]:
            self._add_finding(
                title=f"Cookie Missing 'Secure' Flag: {cookie['name']}",
                severity="MEDIUM",
                description=(
                    "The 'Secure' flag is not set on this cookie. Without it, the cookie will "
                    "be transmitted over plain HTTP connections, making it vulnerable to "
                    "interception by a Man-in-the-Middle attacker on the network."
                ),
                evidence=f"Set-Cookie header found without 'Secure' flag: {cookie['name']}=<value>",
                recommendation=(
                    f"Add the 'Secure' attribute to the '{cookie['name']}' cookie: "
                    f"Set-Cookie: {cookie['name']}=<value>; Secure; ..."
                ),
                cookie_name=cookie["name"]
            )

    # ─────────────────────────────────────────────────────────────
    # Check 2: Missing HttpOnly Flag
    # ─────────────────────────────────────────────────────────────
    def _check_httponly_flag(self, cookie: dict):
        if not cookie["httponly"]:
            self._add_finding(
                title=f"Cookie Missing 'HttpOnly' Flag: {cookie['name']}",
                severity="MEDIUM",
                description=(
                    "The 'HttpOnly' flag is not set on this cookie. This means the cookie's "
                    "value is accessible to JavaScript via 'document.cookie'. If the application "
                    "has any XSS vulnerability, an attacker's injected script could steal this cookie."
                ),
                evidence=f"Set-Cookie header found without 'HttpOnly' flag: {cookie['name']}=<value>",
                recommendation=(
                    f"Add the 'HttpOnly' attribute to the '{cookie['name']}' cookie: "
                    f"Set-Cookie: {cookie['name']}=<value>; HttpOnly; ..."
                ),
                cookie_name=cookie["name"]
            )

    # ─────────────────────────────────────────────────────────────
    # Check 3: SameSite Configuration
    # ─────────────────────────────────────────────────────────────
    def _check_samesite(self, cookie: dict):
        samesite = cookie.get("samesite")

        if samesite is None:
            self._add_finding(
                title=f"Cookie Missing 'SameSite' Attribute: {cookie['name']}",
                severity="LOW",
                description=(
                    "The 'SameSite' attribute is not set. Modern browsers default to "
                    "'SameSite=Lax' when it's missing, but it is best practice to set it "
                    "explicitly to avoid inconsistent browser behavior."
                ),
                evidence=f"Set-Cookie header has no SameSite attribute: {cookie['name']}",
                recommendation=(
                    "Explicitly set SameSite=Lax (recommended for most cases) or "
                    "SameSite=Strict (for stricter protection). "
                    "Avoid SameSite=None unless cross-site cookie sharing is explicitly required."
                ),
                cookie_name=cookie["name"]
            )
        elif samesite.lower() == "none":
            if not cookie["secure"]:
                # SameSite=None without Secure is rejected by modern browsers
                self._add_finding(
                    title=f"Cookie SameSite=None Without Secure Flag: {cookie['name']}",
                    severity="HIGH",
                    description=(
                        "'SameSite=None' requires the 'Secure' flag. Without it, "
                        "modern browsers will reject the cookie entirely, and the "
                        "configuration indicates a broken or insecure policy."
                    ),
                    evidence=f"Cookie '{cookie['name']}' has SameSite=None but is missing the Secure flag.",
                    recommendation="If cross-site cookie access is required, set both 'SameSite=None' AND 'Secure'.",
                    cookie_name=cookie["name"]
                )
            else:
                # SameSite=None with Secure is valid but worth noting
                self._add_finding(
                    title=f"Cookie Set with SameSite=None (Cross-Site Access Allowed): {cookie['name']}",
                    severity="LOW",
                    description=(
                        "'SameSite=None' allows the cookie to be sent with cross-site requests. "
                        "This is necessary for some embedded / third-party use cases but increases "
                        "CSRF risk if not combined with other controls."
                    ),
                    evidence=f"Cookie '{cookie['name']}' has SameSite=None; Secure.",
                    recommendation=(
                        "Verify that cross-site cookie sharing is genuinely required. "
                        "If not, change to SameSite=Lax or SameSite=Strict."
                    ),
                    cookie_name=cookie["name"]
                )

    # ─────────────────────────────────────────────────────────────
    # Check 4: Overly Broad Domain Scope
    # ─────────────────────────────────────────────────────────────
    def _check_domain_scope(self, cookie: dict):
        domain = cookie.get("domain")
        if domain and domain.startswith("."):
            self._add_finding(
                title=f"Cookie Has Broad Domain Scope: {cookie['name']}",
                severity="LOW",
                description=(
                    f"The cookie is scoped to '{domain}', which includes ALL subdomains. "
                    "If any subdomain is compromised or contains an XSS vulnerability, "
                    "it can access cookies from the main domain."
                ),
                evidence=f"Set-Cookie: {cookie['name']}=<value>; Domain={domain}",
                recommendation=(
                    "Scope cookies to the most specific domain possible. "
                    "Avoid leading-dot domain scopes unless cross-subdomain access is required."
                ),
                cookie_name=cookie["name"]
            )

    def analyze(self):
        """Run all cookie security checks and return structured findings."""
        logger.info(f"Analyzing cookies for {self.method} {self.endpoint_url}")

        if not self.cookies:
            logger.debug(f"No Set-Cookie headers found on {self.endpoint_url}")
            return []  # No cookies to analyze — not a finding

        for cookie in self.cookies:
            if not cookie.get("name"):
                continue  # Skip malformed cookie entries
            logger.debug(f"Analyzing cookie: {cookie['name']}")
            self._check_secure_flag(cookie)
            self._check_httponly_flag(cookie)
            self._check_samesite(cookie)
            self._check_domain_scope(cookie)

        return self.findings
