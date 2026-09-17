"""Authorization / access control checks (BOLA / IDOR / privilege escalation).

Runs only against test accounts and safe test data supplied by the operator.
It compares what a low-privileged user can reach versus what a high-privileged
user can reach, and flags resource access that crosses permission boundaries.
"""

import logging

import requests

from config import Config
from scanner import ScanContext

logger = logging.getLogger("api_shield.authorization")

ROLE_LEVELS = {"guest": 0, "user": 1, "admin": 2}


def run_authorization_checks(ctx, test_credentials):
    """Compare access across test roles for object endpoints.

    test_credentials: {"guest": (user, pass), "user": (...), "admin": (...)}
    """
    session = ctx.get_session()
    findings_before = len(ctx.findings)

    role_tokens = _obtain_tokens(ctx, session, test_credentials)
    if not role_tokens:
        logger.info("No usable test credentials — skipping authorization module.")
        return []

    object_endpoints = [ep for ep in ctx.endpoints if "{id}" in ep.path]
    resource = None

    if object_endpoints:
        resource = object_endpoints[0]
    else:
        for ep in ctx.endpoints:
            if re_hint_id(ep.path):
                resource = ep
                break

    if not resource:
        return []

    ctx.tests_completed += 1
    guest_access = _access_resource(session, ctx.base_url, resource, role_tokens.get("guest"))
    ctx.tests_completed += 1
    user_access = _access_resource(session, ctx.base_url, resource, role_tokens.get("user"))

    base_resp = user_access or guest_access
    if base_resp is None:
        return []

    status = base_resp.status_code
    if status < 400:
        msg = (
            "A lower-privileged test user may access this resource in place of an "
            "owner or administrator."
        )
        title = "BOLA / IDOR"
        finding = {
            "title": title,
            "severity": "HIGH",
            "endpoint": resource.path,
            "method": resource.method,
            "category": "API1",
            "description": msg,
            "evidence": f"Test user received HTTP {status} accessing {resource.path}.",
            "recommendation": "Validate object ownership and authorization on every request.",
        }
        ctx.findings.append(finding)

    _check_admin_escalation(ctx, session, role_tokens)

    return ctx.findings[findings_before:]


def re_hint_id(path):
    return "{id}" in path or path.rstrip("/").endswith("id")


def _obtain_tokens(ctx, session, test_credentials):
    """Log in with each configured role and store its auth header."""
    result = {}
    login_endpoint = _find_login_endpoint(ctx)
    if not login_endpoint:
        logger.info("No /api/login endpoint discovered; authz scan skipped.")
        return result

    url = login_endpoint.url(ctx.base_url)
    for role, (username, password) in test_credentials.items():
        ctx.tests_completed += 1
        try:
            resp = session.post(
                url,
                json={"username": username, "password": password},
                timeout=Config.REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.debug("Login for %s failed: %s", role, exc)
            continue

        if resp.status_code >= 400:
            continue

        headers = {}
        token = None
        try:
            data = resp.json()
            token = data.get("access_token") or data.get("token")
        except Exception:
            token = None

        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            cookie = resp.cookies.get_dict()
            if cookie:
                headers = {}

        result[role] = headers
    return result


def _find_login_endpoint(ctx):
    for ep in ctx.endpoints:
        if ep.path.lower().endswith("/login") or ep.path.lower().endswith("/signin"):
            return ep
    return None


def _access_resource(session, base_url, resource, auth_headers):
    """Request the resource with a role's credentials, substituting a test id."""
    url = resource.url(base_url)
    if "{id}" in url:
        url = url.replace("{id}", "1")
    try:
        return session.request(
            resource.method,
            url,
            headers=auth_headers or {},
            timeout=Config.REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return None


def _check_admin_escalation(ctx, session, role_tokens):
    """Try the guest header against admin-ish endpoints."""
    guest_headers = role_tokens.get("guest")
    if not guest_headers:
        return
    for ep in ctx.endpoints:
        if "/admin" not in ep.path.lower():
            continue
        ctx.tests_completed += 1
        try:
            resp = session.request(
                ep.method,
                ep.url(ctx.base_url),
                headers=guest_headers,
                timeout=Config.REQUEST_TIMEOUT,
            )
        except requests.RequestException:
            continue
        if resp.status_code in (200, 201, 202, 204):
            ctx.add_finding(
                title="Privilege Escalation",  # matches module example context
                severity="CRITICAL",
                endpoint=ep.path,
                method=ep.method,
                category="API5",
                description=(
                    "A guest test account reached an administrative endpoint "
                    "expected to require elevated privileges."
                ),
                evidence=f"Guest credentials returned HTTP {resp.status_code}.",
                recommendation="Enforce role-based access control on every admin endpoint.",
            )