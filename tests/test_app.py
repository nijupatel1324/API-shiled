"""Web-UI behaviour tests: auth flow, CSRF, security headers, error pages."""

import re


def _login_token(client):
    page = client.get("/login")
    assert page.status_code == 200
    match = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match, "login page must render a CSRF token"
    return match.group(1)


def test_index_redirects_to_login(client):
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_security_headers_on_pages(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_login_redirects_back_to_dashboard(client):
    r = client.get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_bad_login_returns_401(client):
    token = _login_token(client)
    r = client.post("/login", data={
        "username": "admin", "password": "wrong", "_csrf_token": token,
    })
    assert r.status_code == 401
    assert "Invalid username or password".encode() in r.data


def test_valid_login_flow(client):
    token = _login_token(client)
    r = client.post("/login", data={
        "username": "admin", "password": "Admin@123", "_csrf_token": token,
    })
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/dashboard")

    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert b"API-SHIELD" in dash.data
    assert b"admin" in dash.data  # user chip


def test_csrf_required_for_forms(client):
    # login first so a session token exists
    token = _login_token(client)
    client.post("/login", data={
        "username": "admin", "password": "Admin@123", "_csrf_token": token,
    })
    # submit a scan start without a CSRF token -> rejected
    r = client.post("/scan/start", data={"target_name": "x", "target_url": "http://127.0.0.1:5001"})
    assert r.status_code == 400


def test_static_assets_served(client):
    css = client.get("/static/css/style.css")
    assert css.status_code == 200
    js = client.get("/static/js/dashboard.js")
    assert js.status_code == 200


def test_api_404_is_json(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404
    assert r.is_json
    assert r.get_json()["error"]["code"] == "NOT_FOUND"