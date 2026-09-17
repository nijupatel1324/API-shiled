"""Shared context and helpers for the scanner modules."""

import re

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"authorization|private[_-]?key|client[_-]?secret|auth[_-]?token)",
    re.IGNORECASE,
)

SECRET_VALUE_PATTERN = re.compile(
    r"\b(sk|pk|ak|ghp|glpat|eyJ)[A-Za-z0-9_\-]{8,}\b"
)

INTERNAL_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


def mask_string(value, prefix_chars=8):
    """Mask a sensitive value, keeping at most a short prefix."""
    value = str(value)
    if len(value) <= prefix_chars:
        return "*" * len(value)
    return f"{value[:prefix_chars]}{'*' * min(12, max(4, len(value) - prefix_chars))}"


def mask_sensitive_response(text):
    """Mask likely secret values inside response text for evidence/logs.

    Never stores real secrets in reports or logs -- only masked evidence.
    """
    if not text:
        return text
    text = SECRET_VALUE_PATTERN.sub(lambda m: mask_string(m.group(0)), text)

    def _mask_pair(match):
        key = match.group(1)
        return f'{key}="{mask_string(match.group(2), prefix_chars=4)}"'

    text = re.sub(
        r"(password|passwd|secret|api[_-]?key|token|authorization)\"?\s*[:=]\s*"
        r"[\"']?([^&\"'\s,;}]+)[\"']?",
        _mask_pair,
        text,
        flags=re.IGNORECASE,
    )
    return text


def truncate(text, limit=600):
    text = str(text or "")
    return text[:limit] + ("..." if len(text) > limit else "")


class ScanContext:
    """Carries state through a scan run."""

    def __init__(self, base_url, findings=None, session=None, test_credentials=None):
        self.base_url = base_url
        self.findings = findings if findings is not None else []
        self.session = session
        self.test_credentials = test_credentials or {}
        self.endpoints = []
        self.tests_completed = 0

    def add_finding(
        self,
        title,
        severity,
        endpoint="",
        method="",
        category="",
        description="",
        evidence="",
        recommendation="",
    ):
        self.findings.append(
            {
                "title": title,
                "severity": severity,
                "endpoint": endpoint,
                "method": method,
                "category": category,
                "description": description,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    def get_session(self):
        if self.session is None:
            import requests

            self.session = requests.Session()
        return self.session