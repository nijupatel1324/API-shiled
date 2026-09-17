"""
Phase 17 — Remediation & Security Advisory Engine

Provides developers and security engineers with actionable, framework-specific
remediation guidance, before/after code patches, root-cause explanations,
and official OWASP/CWE references for every finding discovered by API-SHIELD.
"""

import logging

logger = logging.getLogger('api-shield.remediation')

ADVISORY_CATALOG = {
    "BOLA": {
        "title": "Broken Object Level Authorization (BOLA / IDOR)",
        "owasp": "API1:2023 - Broken Object Level Authorization",
        "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "severity": "HIGH",
        "impact": (
            "Attackers can access, modify, or delete sensitive data belonging to other users "
            "simply by manipulating object identifiers (e.g., user IDs, order IDs) in the request URL or body."
        ),
        "root_cause": (
            "The application verifies that the requester is authenticated, but fails to check whether "
            "the authenticated identity actually owns or has permission to view the requested object."
        ),
        "remediation_steps": [
            "Implement an authorization check on EVERY request that accesses an object by ID.",
            "Never trust IDs supplied in the URL or request body as proof of authorization.",
            "Bind the query directly to the authenticated user's session/token identity.",
            "Use unpredictable, non-sequential IDs (such as UUIDv4) to reduce enumeration risk as defense-in-depth."
        ],
        "code_patch": {
            "vulnerable": (
                "# VULNERABLE (Flask):\n"
                "@app.route('/api/users/<int:user_id>', methods=['GET'])\n"
                "def get_user(user_id):\n"
                "    # Flaw: Checks authentication token, but never checks if current_user.id == user_id!\n"
                "    user = User.query.get(user_id)\n"
                "    return jsonify(user.to_dict())\n"
            ),
            "remediated": (
                "# REMEDIATED (Flask):\n"
                "@app.route('/api/users/<int:user_id>', methods=['GET'])\n"
                "@require_auth\n"
                "def get_user(user_id):\n"
                "    current_user = get_current_authenticated_user()\n"
                "    if current_user.id != user_id and not current_user.is_admin:\n"
                "        return jsonify({'error': 'Forbidden: Access denied to requested resource'}), 403\n"
                "    user = User.query.get_or_404(user_id)\n"
                "    return jsonify(user.to_dict())\n"
            )
        },
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
        ]
    },

    "TLS_HTTP": {
        "title": "Unencrypted API Transmission (Cleartext HTTP)",
        "owasp": "API7:2023 - Security Misconfiguration",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "severity": "HIGH",
        "impact": (
            "Credentials, authorization tokens, personal identifiable information (PII), "
            "and sensitive business data are transmitted in cleartext and can be intercepted by "
            "anyone on the same network (e.g., public Wi-Fi, malicious proxies, compromised routers)."
        ),
        "root_cause": "The API endpoint does not require HTTPS or terminate TLS.",
        "remediation_steps": [
            "Configure TLS 1.2 or TLS 1.3 on your reverse proxy (Nginx, Caddy, Cloudflare, AWS ALB).",
            "Automatically redirect all HTTP traffic to HTTPS using a 301 Permanent Redirect.",
            "Deploy the Strict-Transport-Security (HSTS) header to force clients to use HTTPS.",
            "Obtain automated free certificates from Let's Encrypt or your cloud provider."
        ],
        "code_patch": {
            "vulnerable": (
                "# VULNERABLE (Nginx configuration):\n"
                "server {\n"
                "    listen 80;\n"
                "    server_name api.example.com;\n"
                "    location / { proxy_pass http://backend:5000; }\n"
                "}\n"
            ),
            "remediated": (
                "# REMEDIATED (Nginx configuration with TLS & HTTP->HTTPS redirect):\n"
                "server {\n"
                "    listen 80;\n"
                "    server_name api.example.com;\n"
                "    return 301 https://$host$request_uri;\n"
                "}\n\n"
                "server {\n"
                "    listen 443 ssl http2;\n"
                "    server_name api.example.com;\n"
                "    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;\n"
                "    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;\n"
                "    add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;\n"
                "    location / { proxy_pass http://backend:5000; }\n"
                "}\n"
            )
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        ]
    },

    "INPUT_VALIDATION_MASS_ASSIGNMENT": {
        "title": "Improper Input Validation & Mass Assignment",
        "owasp": "API3:2023 - Broken Object Property Level Authorization",
        "cwe": "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "severity": "HIGH",
        "impact": (
            "Clients can inject privileged fields (e.g. `role: admin`, `verified: true`, `balance: 99999`) "
            "directly into backend data structures, leading to privilege escalation or state tampering."
        ),
        "root_cause": (
            "The backend blindly binds user-submitted JSON payload keys to internal models without an explicit allowlist."
        ),
        "remediation_steps": [
            "Use strict Data Transfer Objects (DTOs) or schema validation libraries (Pydantic, Marshmallow, Joi, Zod).",
            "Explicitly allowlist only the fields that clients are allowed to create or modify.",
            "Reject or strip unexpected properties from request payloads before passing them to the database model."
        ],
        "code_patch": {
            "vulnerable": (
                "# VULNERABLE (Flask):\n"
                "@app.route('/api/users', methods=['POST'])\n"
                "def create_user():\n"
                "    data = request.get_json()\n"
                "    # Attacker controls 'role' and 'is_admin' directly!\n"
                "    new_user = User(**data)\n"
                "    db.session.add(new_user)\n"
                "    db.session.commit()\n"
            ),
            "remediated": (
                "# REMEDIATED (Flask with explicit allowlist):\n"
                "ALLOWED_FIELDS = {'username', 'email', 'password'}\n\n"
                "@app.route('/api/users', methods=['POST'])\n"
                "def create_user():\n"
                "    data = request.get_json()\n"
                "    # Filter out any non-whitelisted keys:\n"
                "    clean_data = {k: data[k] for k in ALLOWED_FIELDS if k in data}\n"
                "    clean_data['role'] = 'user'  # Enforce server-managed default\n"
                "    new_user = User(**clean_data)\n"
                "    db.session.add(new_user)\n"
                "    db.session.commit()\n"
            )
        },
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
        ]
    },

    "SECURITY_HEADERS": {
        "title": "Missing Security Configuration Headers",
        "owasp": "API7:2023 - Security Misconfiguration",
        "cwe": "CWE-16: Configuration",
        "severity": "MEDIUM",
        "impact": (
            "Without defense-in-depth security headers, browser clients are susceptible to MIME-sniffing, "
            "clickjacking, protocol downgrade attacks, and cross-site scripting."
        ),
        "root_cause": "The web server or API gateway does not append standard HTTP security headers to responses.",
        "remediation_steps": [
            "Set `X-Content-Type-Options: nosniff` on all responses.",
            "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`).",
            "Set `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on JSON APIs.",
            "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS APIs.",
            "Remove identifying banners like `Server` and `X-Powered-By`."
        ],
        "code_patch": {
            "vulnerable": (
                "# VULNERABLE (Flask default - no security headers applied)\n"
            ),
            "remediated": (
                "# REMEDIATED (Flask after_request middleware):\n"
                "@app.after_request\n"
                "def set_security_headers(response):\n"
                "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                "    response.headers['X-Frame-Options'] = 'DENY'\n"
                "    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
                "    response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                "    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n"
                "    response.headers.pop('X-Powered-By', None)\n"
                "    return response\n"
            )
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#security-headers"
        ]
    },

    "CORS": {
        "title": "Permissive Cross-Origin Resource Sharing (CORS) Misconfiguration",
        "owasp": "API7:2023 - Security Misconfiguration",
        "cwe": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        "severity": "MEDIUM",
        "impact": (
            "Malicious websites can issue authenticated requests on behalf of victims and read sensitive "
            "API response data via the victim's browser."
        ),
        "root_cause": (
            "The API returns `Access-Control-Allow-Origin: *` on endpoints returning sensitive data, "
            "or dynamically reflects the incoming `Origin` header with `Access-Control-Allow-Credentials: true`."
        ),
        "remediation_steps": [
            "Explicitly allowlist trusted origins only (e.g., `https://app.example.com`).",
            "Never dynamically reflect the `Origin` header if credentials are supported.",
            "Avoid wildcard `*` origins on endpoints containing private user data."
        ],
        "code_patch": {
            "vulnerable": (
                "# VULNERABLE (Flask-CORS):\n"
                "from flask_cors import CORS\n"
                "CORS(app, resources={r'/api/*': {'origins': '*'}}, supports_credentials=True)\n"
            ),
            "remediated": (
                "# REMEDIATED (Flask-CORS with strict allowlist):\n"
                "from flask_cors import CORS\n"
                "TRUSTED_DOMAINS = ['https://dashboard.example.com', 'https://admin.example.com']\n"
                "CORS(app, resources={r'/api/*': {'origins': TRUSTED_DOMAINS}}, supports_credentials=True)\n"
            )
        },
        "references": [
            "https://portswigger.net/web-security/cors",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html"
        ]
    },

    "ERROR_HANDLING": {
        "title": "Information Disclosure in Error Handling",
        "owasp": "API8:2023 - Security Misconfiguration",
        "cwe": "CWE-209: Generation of Error Message Containing Sensitive Information",
        "severity": "MEDIUM",
        "impact": (
            "Stack traces, database dialect errors, line numbers, and file paths leak to attackers, "
            "providing the exact blueprints required to construct targeted exploits."
        ),
        "root_cause": (
            "Debug mode is enabled in production or uncaught exceptions are directly returned to the HTTP client."
        ),
        "remediation_steps": [
            "Ensure `debug=False` or `FLASK_ENV=production` in all production deployments.",
            "Implement a global exception handler that logs detailed diagnostics internally but returns a generic JSON error.",
            "Never display raw database error messages or stack traces in HTTP responses."
        ],
        "code_patch": {
            "vulnerable": (
                "# VULNERABLE (Flask):\n"
                "@app.errorhandler(500)\n"
                "def handle_500(err):\n"
                "    return jsonify({'error': str(err)}), 500  # Leaks traceback / db error\n"
            ),
            "remediated": (
                "# REMEDIATED (Flask):\n"
                "@app.errorhandler(Exception)\n"
                "def handle_exception(e):\n"
                "    # Log the full exception with traceback server-side ONLY:\n"
                "    logger.exception('Unhandled exception occurred while processing request')\n"
                "    # Return a safe, sanitized message to the client:\n"
                "    return jsonify({\n"
                "        'error': 'An internal server error occurred.',\n"
                "        'status_code': 500\n"
                "    }), 500\n"
            )
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
        ]
    }
}


class RemediationEngine:
    def __init__(self, catalog: dict = None):
        self.catalog = catalog or ADVISORY_CATALOG

    def map_finding_to_advisory(self, finding: dict) -> dict:
        """
        Determines the most applicable advisory for a given finding based on
        title, OWASP tag, or severity.
        """
        title = finding.get("title", "").lower()
        owasp = finding.get("owasp", "").lower()

        if "bola" in title or "broken object level" in title or "api1" in owasp:
            key = "BOLA"
        elif "tls" in title or "http" in title or "cwe-319" in title:
            key = "TLS_HTTP"
        elif "validation" in title or "mass assignment" in title or "api3" in owasp:
            key = "INPUT_VALIDATION_MASS_ASSIGNMENT"
        elif "header" in title or "security header" in title:
            key = "SECURITY_HEADERS"
        elif "cors" in title:
            key = "CORS"
        elif "error" in title or "disclosure" in title or "traceback" in title:
            key = "ERROR_HANDLING"
        else:
            key = "SECURITY_HEADERS"

        advisory_data = self.catalog.get(key, {})
        return {
            "finding_title": finding.get("title"),
            "endpoint": finding.get("endpoint"),
            "method": finding.get("method"),
            "severity": finding.get("severity"),
            "advisory_key": key,
            "advisory_title": advisory_data.get("title"),
            "owasp": advisory_data.get("owasp"),
            "cwe": advisory_data.get("cwe"),
            "impact": advisory_data.get("impact"),
            "remediation_steps": advisory_data.get("remediation_steps", []),
            "code_patch": advisory_data.get("code_patch", {}),
            "references": advisory_data.get("references", [])
        }

    def generate_advisories_for_findings(self, findings: list) -> list:
        """
        Takes a list of findings and returns a deduplicated list of remediation
        advisories grouped by vulnerability category.
        """
        categories_seen = {}
        for f in findings:
            if "severity" not in f:
                continue
            adv = self.map_finding_to_advisory(f)
            key = adv["advisory_key"]
            if key not in categories_seen:
                categories_seen[key] = {
                    "advisory_key": key,
                    "title": adv["advisory_title"],
                    "owasp": adv["owasp"],
                    "cwe": adv["cwe"],
                    "impact": adv["impact"],
                    "remediation_steps": adv["remediation_steps"],
                    "code_patch": adv["code_patch"],
                    "references": adv["references"],
                    "affected_endpoints": []
                }
            ep_info = f"{f.get('method', 'N/A')} {f.get('endpoint', 'N/A')}"
            if ep_info not in categories_seen[key]["affected_endpoints"]:
                categories_seen[key]["affected_endpoints"].append(ep_info)

        return list(categories_seen.values())
