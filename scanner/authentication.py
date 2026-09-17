"""Authentication security checks.

Detects the *absence* of authentication and weak token handling using only
non-intrusive probes. This module never attempts credential theft or access
to protected systems without authorization.
"""

import logging
import re

import jwt
import requests

from config import Config
from scanner import ScanContext

logger = logging.getLogger("api_shield.authentication")

# Endpoint types that normally must require authentication.
PROTECTED_HINTS = (
    "admin", "profile", "account", "settings", "user", "users", "order", "orders",
    "billing", "payment", "private", "internal", "config", "export", "token",
    "refresh", "password", "roles", "permissions", "audit", "logs", "webhook",
)

JWT_SECRET_PATTERN = re.compile(r"secret|key", re.IGNORECASE)
JWT_CLAIM_PATTERNS = {
    "no_expiry": ("exp", None),
    "algorithm_none": ("alg", "none"),
}


def run_authentication_checks(ctx):
    """Scan endpoints for missing authentication and JWT weaknesses.

    ctx: ScanContext with .endpoints, .session and .base_url.
    """
    session = ctx.get_session()
    findings_before = len(ctx.findings)

    for ep in ctx.endpoints:
        ctx.tests_completed += 1
        url = ep.url(ctx.base_url)
        try:
            resp = session.request(
                ep.method, url, timeout=Config.REQUEST_TIMEOUT, allow_redirects=False
            )
            ctx.tests_completed += 1
        except requests.RequestException as exc:
            logger.debug("Auth probe %s failed: %s", url, exc)
            continue

        # Only consider the endpoint protected if it hints at sensitive scope
        # and does not look like a public login/health resource.
        if not _looks_protected(ep.path):
            continue
        if _is_public_resource(ep.path):
            continue

        if resp.status_code in (401, 403):
            continue  # authentication appears enforced

        status_allows_unauthenticated = resp.status_code in (200, 201, 202, 204)
        if status_allows_unauthenticated:
            ctx.add_finding(
                title="Authentication Missing",
                severity="HIGH",
                endpoint=ep.path,
                method=ep.method,
                category="API2",
                description=(
                    "The endpoint appears accessible without authentication despite "
                    "being part of a protected resource space."
                ),
                evidence=f"Request without credentials returned HTTP {resp.status_code}.",
                recommendation=(
                    "Require authentication before processing requests on this endpoint."
                ),
            )
        elif resp.status_code == 404:
            # 404 on a hint path: could be "not found" masking (good practice)
            # or simply a wrong route guess. Report nothing for 404.
            continue

    _check_jwt_usage(ctx, session)
    return ctx.findings[findings_before:]


def _looks_protected(path):
    return any(hint in path.lower() for hint in PROTECTED_HINTS)


def _is_public_resource(path):
    public = ("/login", "/register", "/health", "/status", "/version", "/swagger", "/openapi")
    return path.lower().startswith(public)


def _check_jwt_usage(ctx, session):
    """Analyse JWT behaviour of token endpoints when offered by the target."""
    token_paths = [
        ep
        for ep in ctx.endpoints
        if "token" in ep.path.lower() or "login" in ep.path.lower()
        or "signin" in ep.path.lower()
    ]
    for ep in token_paths:
        if ep.method != "POST":
            continue
        ctx.tests_completed += 1
        url = ep.url(ctx.base_url)

        # Try each supplied test credential to obtain a real token.
        for username, password in _ordered_credentials(ctx):
            try:
                resp = session.post(
                    url,
                    json={"username": username, "password": password},
                    timeout=Config.REQUEST_TIMEOUT,
                )
                ctx.tests_completed += 1
            except requests.RequestException:
                continue
            if resp.status_code >= 400:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "json" not in content_type:
                continue
            payload = None
            try:
                payload = resp.json()
            except Exception:
                continue

            _analyse_token_payload(ctx, payload, ep, url)
            return  # one successful login is enough for claim analysis
    return None


def _ordered_credentials(ctx):
    for role in ("admin", "user", "guest"):
        creds = ctx.test_credentials.get(role)
        if creds:
            yield creds


def _analyse_token_payload(ctx, payload, ep, url):
    token = _extract_token(payload)
    if not token:
        return

    ctx.tests_completed += 1
    decoded = _decode_token(token)
    if decoded is None:
        ctx.add_finding(
            title="Invalid Token Issued",
            severity="MEDIUM",
            endpoint=ep.path,
            method=ep.method,
            category="API2",
            description="The token endpoint issued a token that cannot be decoded/verified.",
            evidence="Token could not be validated on issuance.",
            recommendation="Issue cryptographically signed, standards-compliant tokens.",
        )
        return

    if "exp" not in decoded:
        ctx.add_finding(
            title="JWT Missing Expiry",
            severity="HIGH",
            endpoint=ep.path,
            method=ep.method,
            category="API2",
            description="The issued JWT has no exp claim and may be valid indefinitely.",
            evidence="Decoded JWT claims: %s" % {k: "***" if k == "alg" else mask_claim(v) for k, v in list(decoded.items())[:6]},
            recommendation="Include short-lived exp and jti claims in issued JWTs.",
        )

    if decoded.get("alg") == "none":
        ctx.add_finding(
            title="JWT Algorithm Confusion (alg=none)",
            severity="CRITICAL",
            endpoint=ep.path,
            method=ep.method,
            category="API2",
            description="The token header declares alg=none which bypasses signature checks.",
            evidence="JWT header contained alg:none.",
            recommendation="Reject alg:none and pin trusted signing algorithms.",
        )

    return None


def _extract_token(payload):
    if isinstance(payload, dict):
        for key in ("access_token", "refresh_token", "token", "id_token", "jwt"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _decode_token(token):
    """Decode a JWT without verifying the signature -- claim inspection only."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return None


def mask_claim(value):
    if isinstance(value, str) and len(value) > 6:
        return value[:4] + "***"
    return value