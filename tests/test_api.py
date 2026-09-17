"""REST API tests (Flask test client, no network required)."""

MINI_SPEC = """\
openapi: 3.0.0
info:
  title: Mini
  version: 1.0.0
servers:
  - url: http://127.0.0.1:5001
paths:
  /api/users:
    get:
      responses:
        "200": {description: ok}
      security:
        - {}
    post:
      responses:
        "201": {description: ok}
  /api/users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: string}
    get:
      responses:
        "200": {description: ok}
      security:
        - ApiKeyAuth: []
"""


def _create_project(client, name="Demo", url="http://127.0.0.1:5001"):
    r = client.post("/api/projects", json={"name": name, "base_url": url})
    assert r.status_code == 201
    return r.get_json()["project"]["id"]


def test_create_and_list_projects(client):
    pid = _create_project(client, "Alpha", "http://127.0.0.1:5001")
    r = client.get("/api/projects")
    assert r.status_code == 200
    assert any(p["id"] == pid for p in r.get_json())


def test_create_project_requires_fields(client):
    r = client.post("/api/projects", json={"name": "No URL"})
    assert r.status_code == 400
    r = client.post("/api/projects", json={"base_url": "http://x"})
    assert r.status_code == 400


def test_get_missing_project_is_404(client):
    r = client.get("/api/projects/99999")
    assert r.status_code == 404


def test_upload_spec_populates_endpoints(client):
    pid = _create_project(client)
    r = client.post(f"/api/projects/{pid}/spec", data=MINI_SPEC)
    assert r.status_code == 200
    assert r.get_json()["metadata"]["endpoints_found"] == 3

    r = client.get(f"/api/projects/{pid}/endpoints")
    eps = r.get_json()
    assert len(eps) == 3
    assert any(e["path"] == "/api/users/{id}" for e in eps)


def test_upload_invalid_spec_returns_400(client):
    pid = _create_project(client)
    r = client.post(f"/api/projects/{pid}/spec", data="not-a-spec: [}")
    assert r.status_code in (400, 500)


def test_full_scan_requires_endpoints(client):
    pid = _create_project(client, "Empty")
    r = client.post(f"/api/projects/{pid}/scan/full")
    assert r.status_code in (400, 404)


def test_single_module_scan_without_spec(client):
    pid = _create_project(client, "Empty2")
    r = client.post(f"/api/projects/{pid}/scan/headers")
    assert r.status_code == 400


def test_stats_endpoint(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    body = r.get_json()
    assert "projects" in body and "severity" in body and "scans" in body


def test_risk_endpoint_returns_breakdown(client):
    pid = _create_project(client)
    client.post(f"/api/projects/{pid}/spec", data=MINI_SPEC)
    r = client.get(f"/api/projects/{pid}/risk")
    assert r.status_code == 200
    body = r.get_json()
    assert "risk_breakdown" in body and "security_score" in body