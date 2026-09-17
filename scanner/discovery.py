"""API endpoint discovery.

Supports two inputs:
  1. A base URL -- loads common endpoint paths and probes the server.
  2. An OpenAPI/Swagger file (JSON or YAML) -- extracts paths and methods.

Discovery only builds a catalogue of endpoints to test; it does not guess
credentials or bypass any access controls.
"""

import io
import json
import logging
import re

import requests
import yaml

from config import Config

logger = logging.getLogger("api_shield.discovery")

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

# Common endpoint paths used when probing a base URL without a spec file.
COMMON_PATHS = [
    "/api/users", "/api/users/{id}", "/api/products", "/api/products/{id}",
    "/api/orders", "/api/orders/{id}", "/api/admin", "/api/settings",
    "/api/profile", "/api/login", "/api/logout", "/api/health", "/api/version",
    "/api/config", "/swagger.json", "/openapi.json", "/v1/users", "/v1/products",
    "/health", "/status", "/metrics", "/api/register", "/api/token",
    "/api/refresh", "/api/export", "/api/import", "/api/webhooks", "/api/roles",
    "/api/permissions", "/api/audit", "/api/logs", "/api/notifications",
]


class Endpoint:
    """A discovered API endpoint."""

    def __init__(self, method, path, source="manual"):
        self.method = method
        self.path = path
        self.source = source

    def url(self, base_url):
        base_url = base_url.rstrip("/")
        if not self.path.startswith("/"):
            path = "/" + self.path
        else:
            path = self.path
        return f"{base_url}{path}"

    def to_dict(self):
        return {"method": self.method, "path": self.path, "source": self.source}


def _normalize_path(path):
    """Normalize a path from an OpenAPI spec into a scanable form."""
    if not path.startswith("/"):
        path = "/" + path
    return path


def _parse_yaml(data):
    try:
        return yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}")


def parse_openapi(spec_content):
    """Extract endpoints (method, path) from an OpenAPI / Swagger document.

    Accepts raw JSON or YAML text. Returns a list of Endpoint objects.
    """
    spec_content = spec_content.strip()
    if spec_content.startswith(("{", "[")):
        try:
            spec = json.loads(spec_content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON spec: {exc}")
    else:
        spec = _parse_yaml(spec_content)

    if not isinstance(spec, dict):
        raise ValueError("OpenAPI document must be a JSON/YAML object.")

    paths = spec.get("paths") or {}
    endpoints = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        path = _normalize_path(path)
        for method in HTTP_METHODS:
            if item.get(method.lower()):
                endpoints.append(Endpoint(method, path, source="openapi"))

    if not endpoints:
        raise ValueError("No API endpoints found in the provided document.")

    return endpoints


def _is_allowed_host(host):
    """Return True when the host is a local / private / explicitly allowed target."""
    import ipaddress

    allowed = [h.strip() for h in Config.ALLOWED_TARGET_HOSTS.split(",") if h.strip()]
    for entry in allowed:
        if entry == host:
            return True
        if "/" in entry:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
    return False


def validate_target_url(url):
    """Validate that a target URL is well formed and points at an allowed host."""
    from urllib.parse import urlparse

    if not url or len(url) > 2000:
        raise ValueError("The target URL is invalid.")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("The target URL must start with http:// or https://.")

    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("The target URL has no hostname.")

    if parsed.hostname not in ("localhost",):
        resolved = _is_allowed_host(parsed.hostname)
        if not resolved:
            try:
                import socket

                ip = socket.gethostbyname(parsed.hostname)
            except Exception:
                ip = parsed.hostname
            if not _is_allowed_host(ip):
                raise ValueError(
                    "Target host is not in the allowlist of authorized/local targets."
                )
    return url.rstrip("/")


def discover_from_url(base_url, session=None, limit=50):
    """Probe common endpoint paths against a base URL.

    Requests that return any HTTP status are treated as candidate endpoints.
    The scan never sends payloads during discovery.
    """
    session = session or requests.Session()
    base_url = validate_target_url(base_url)
    discovered = [Endpoint("GET", "/")]

    for path in COMMON_PATHS:
        if len(discovered) >= limit:
            break
        url = Endpoint("GET", path).url(base_url)
        try:
            resp = session.get(url, timeout=Config.REQUEST_TIMEOUT, allow_redirects=False)
            if resp.status_code:
                discovered.append(Endpoint("GET", path, source="probe"))
        except requests.RequestException as exc:
            logger.debug("Discovery probe %s -> %s", url, exc)
            continue

    return discovered


def discover_from_spec_file(file_storage, session=None, base_url=None, limit=50):
    """Parse an uploaded OpenAPI/Swagger file and return endpoints.

    Returns (endpoints, base_url). When the spec declares a 'servers' or
    'host'+"schemes" value and no base_url was supplied, that value is used.
    """
    raw = file_storage.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    endpoints = parse_openapi(raw)

    spec = None
    try:
        if raw.lstrip().startswith(("{", "[")):
            spec = json.loads(raw)
        else:
            spec = yaml.safe_load(raw)
    except Exception:
        spec = None

    resolved_base = base_url
    if not resolved_base and spec and isinstance(spec, dict):
        servers = spec.get("servers")
        if isinstance(servers, list) and servers:
            url = servers[0].get("url")
            if url and url != "/":
                resolved_base = url.replace("{", "").replace("}", "")
        if not resolved_base:
            host = spec.get("host")
            schemes = spec.get("schemes") or ["http"]
            if host:
                resolved_base = f"{schemes[0]}://{host}"
        if not resolved_base and spec.get("basePath"):
            resolved_base = spec.get("basePath")

    endpoints = endpoints[:limit]
    return endpoints, resolved_base