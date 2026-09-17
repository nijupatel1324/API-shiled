"""DELIBERATELY VULNERABLE LOCAL TEST API — SECURITY TRAINING ONLY.

Run:  py app.py        # serves http://127.0.0.1:5001

This API simulates common API security weaknesses so that API-SHIELD's
scanners have a safe in-scope target to demonstrate against. It is not
production code. Do not expose it to the internet or put real data in it.

Simulated weaknesses:
  * Missing authentication on /api/users, /api/admin, /api/config, ...
  * Missing authorization / IDOR on /api/users/<id>
  * JWT issued without an exp claim (weak token handling)
  * Unparameterised SQL in /api/products?search=
  * Missing rate limiting everywhere
  * Missing security headers
  * CORS Access-Control-Allow-Origin: *
  * Verbose errors, debug configuration and internal detail leaks
  * Sensitive fields (password hashes, api_key) in responses
"""

import json
import os
import uuid

import jwt
from flask import Flask, jsonify, request

import database
import data as store

app = Flask(__name__)

JWT_SECRET = os.environ.get("TEST_API_JWT_SECRET", "test-api-weak-secret-do-not-use")
TOKEN_TTL_DAYS = 3650  # deliberately absurd lifetime (no exp claim emitted)

ACCOUNTS = {
    "admin": "admin123",
    "user": "user123",
    "guest": "guest123",
}


def _make_token(user):
    """Issues a JWT WITHOUT an exp claim to demonstrate weak token handling."""
    return jwt.encode(
        {"sub": str(user["id"]), "role": user["role"], "username": user["username"]},
        JWT_SECRET,
        algorithm="HS256",
    )


def _extract_user():
    """Never blocks access — that is the point of this training API."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = jwt.decode(
                auth.split(" ", 1)[1], JWT_SECRET, algorithms=["HS256"]
            )
            return store.find_user_by_username(payload.get("username", ""))
        except Exception:
            return None
    return None


@app.after_request
def add_cors(response):
    """Wildcard CORS — training demonstration of a misconfiguration."""
    # If an origin is supplied, echo it (reflective CORS is also a demo).
    origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"] = origin or "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.errorhandler(Exception)
def verbose_error(exc):
    """Verbose 500 handler that leaks internals — universal in this demo."""
    return jsonify(
        {
            "error": "internal_server_error",
            "message": str(exc),
            "traceback_module": type(exc).__module__,
            "traceback_type": type(exc).__name__,
            "hint": "This verbose error is intentional for training purposes.",
        }
    ), 500


# ---------------------------------------------------------------- public


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "test_api", "version": "0.1.0"})


@app.route("/api/version", methods=["GET"])
def version():
    return jsonify({"version": "0.1.0", "build": "training-build", "host": "127.0.0.1"})


@app.route("/api/login", methods=["POST"])
def login():
    """No rate limiting, no lockout, no exp claim in token."""
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    if username in ACCOUNTS and ACCOUNTS[username] == password:
        user = store.find_user_by_username(username)
        return jsonify({"access_token": _make_token(user), "token_type": "Bearer"})
    return jsonify({"error": "invalid_credentials"}), 401


@app.route("/api/register", methods=["POST"])
def register():
    """Accepts weak input with no validation."""
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    if len(username) < 3:
        return jsonify({"error": "username must be at least 3 characters"}), 400
    return jsonify({"ok": True, "message": "account created (training only)"}), 201


# ---------------------------------------------------------------- users


@app.route("/api/users", methods=["GET", "POST"])
def users_collection():
    """GET: no authentication, returns all users.
    POST: no authentication, no validation."""
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        new_user = {
            "id": max(u["id"] for u in store.USERS) + 1,
            "username": str(body.get("username", "")),
            "password": str(body.get("password", "")),
            "role": "user",
            "email": str(body.get("email", "")),
            "api_key": "sk_live_new_" + uuid.uuid4().hex[:24],
        }
        store.USERS.append(new_user)
        return jsonify(store.public_user(new_user)), 201
    return jsonify({"users": [store.public_user(u) for u in store.USERS]})


@app.route("/api/users/<int:uid>", methods=["GET", "PUT", "DELETE"])
def users_item(uid):
    """IDOR / BOLA: no ownership check — any caller can read or mutate."""
    user = store.find_user_by_id(uid)
    if user is None:
        return jsonify({"error": "not_found"}), 404
    if request.method == "DELETE":
        if user["username"] in store.SEED_USERNAMES:
            # Protect the built-in training accounts from destructive BOLA probes
            # so the lab remains usable after authorization tests.
            return jsonify({"error": "builtin_account_protected"}), 403
        store.USERS.remove(user)
        return jsonify({"ok": True, "deleted": uid})
    if request.method == "PUT":
        body = request.get_json(silent=True) or {}
        for key in ("email", "role", "username"):
            if key in body:
                user[key] = body[key]
        return jsonify(store.public_user(user))
    return jsonify(store.public_user(user))


# ---------------------------------------------------------------- admin


@app.route("/api/admin", methods=["GET"])
def admin():
    """No role check whatsoever (broken function-level authorization)."""
    return jsonify(
        {
            "admin_only_data": True,
            "notes": store.ADMIN_NOTES,
            "whoami": (request.headers.get("Authorization") or "anonymous")[:24],
        }
    )


@app.route("/api/settings", methods=["GET"])
def settings():
    return jsonify({"debug": True, "maintenance_mode": False})


# ---------------------------------------------------------------- products


@app.route("/api/products", methods=["GET", "POST"])
def products():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", ""))
        price = body.get("price", 0)
        if not isinstance(name, str) or name == "":
            return jsonify({"error": "missing required parameter"}), 400
        product = {"id": len(store.PRODUCTS) + 1, "name": name, "price": price}
        store.PRODUCTS.append(product)
        return jsonify(product), 201

    search = request.args.get("search", "")
    if search:
        try:
            rows = database.search_products_by_name_untrusted(search)
            return jsonify({"products": rows})
        except ValueError as exc:
            # Deliberately surfaces a database-ish error to mimic a bad filter.
            return jsonify({"error": str(exc), "debug_trace": "sqlite3.OperationalError"}), 500
    return jsonify({"products": store.PRODUCTS})


@app.route("/api/products/<int:pid>", methods=["GET", "PUT", "DELETE"])
def products_item(pid):
    product = next((p for p in store.PRODUCTS if p["id"] == pid), None)
    if product is None:
        return jsonify({"error": "not_found"}), 404
    if request.method == "DELETE":
        store.PRODUCTS.remove(product)
        return jsonify({"ok": True, "deleted": pid})
    if request.method == "PUT":
        body = request.get_json(silent=True) or {}
        product.update({k: v for k, v in body.items() if k in ("name", "price")})
        return jsonify(product)
    return jsonify(product)


# ---------------------------------------------------------------- profile / config


@app.route("/api/profile", methods=["GET"])
def profile():
    """Intentionally leaks password hash, api_key and phone number."""
    user = _extract_user() or store.USERS[0]
    return jsonify(
        {
            "username": user["username"],
            "email": user["email"],
            "phone": user["phone"],
            "role": user["role"],
            "password_hash": user["password_hash"],
            "api_key": user["api_key"],
            "internal_id": "internal/user-" + str(user["id"]),
        }
    )


@app.route("/api/config", methods=["GET"])
def config():
    """Unrestricted access to internal configuration."""
    return jsonify(store.INTERNAL_CONFIG)


@app.route("/api/orders", methods=["GET"])
def orders():
    return jsonify({"orders": store.ORDERS})


@app.route("/api/orders/<int:oid>", methods=["GET"])
def orders_item(oid):
    order = next((o for o in store.ORDERS if o["id"] == oid), None)
    if order is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(order)


@app.route("/api/logs", methods=["GET"])
def logs():
    return jsonify(
        {
            "logs": [
                {"level": "DEBUG", "msg": "user_service internal_host=10.1.2.3 started"},
                {"level": "INFO", "msg": "db connect ok db=/opt/test_api/data/test_api.db"},
            ]
        }
    )


@app.route("/swagger.json", methods=["GET"])
def swagger():
    from flask import current_app

    return jsonify(
        {
            "openapi": "3.0.0",
            "info": {"title": "Test API (training)", "version": "1.0.0",
                     "description": "Deliberately vulnerable training API."},
            "servers": [{"url": "http://127.0.0.1:5001"}],
            "paths": {
                "/api/users": {"get": {"responses": {"200": {"description": "ok"}}},
                               "post": {"responses": {"201": {"description": "created"}}}},
                "/api/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}},
                                    "put": {"responses": {"200": {"description": "ok"}}},
                                    "delete": {"responses": {"200": {"description": "ok"}}}},
                "/api/admin": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/products": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/products/{id}": {"get": {"responses": {"200": {"description": "ok"}}},
                                       "put": {"responses": {"200": {"description": "ok"}}},
                                       "delete": {"responses": {"200": {"description": "ok"}}}},
                "/api/login": {"post": {"responses": {"200": {"description": "ok"}}}},
                "/api/profile": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/config": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/api/orders": {"get": {"responses": {"200": {"description": "ok"}}}},
            },
        }
    )


if __name__ == "__main__":
    database.init_db()
    print("=" * 62)
    print(" TEST API (SECURITY TRAINING ONLY) -> http://127.0.0.1:5001")
    print(" accounts: admin/admin123  user/user123  guest/guest123")
    print("=" * 62)
    app.run(host="127.0.0.1", port=5001, debug=False)