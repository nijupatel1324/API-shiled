"""Tests for the score-trend dashboard view and CSV export."""

import csv
import io
import re

from database.models import db
from models import Scan, Target


def _login(client):
    page = client.get("/login")
    token = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    r = client.post("/login", data={
        "username": "admin", "password": "Admin@123", "_csrf_token": token,
    })
    assert r.status_code == 302


def _seed_scan(app, score, started_at, base_url="http://127.0.0.1:5001",
               name="Lab", status="completed"):
    target = Target(name=name, base_url=base_url, scan_type="full")
    db.session.add(target)
    db.session.flush()
    scan = Scan(
        target_id=target.id,
        status=status,
        started_at=started_at,
        completed_at=started_at + 1,
        score=score,
        endpoints_count=3,
        tests_completed=5,
        severity_counts='{"HIGH": 1, "MEDIUM": 2}',
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def test_trends_page_requires_login(client):
    r = client.get("/trends")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_trends_page_renders_grouped_scores(client, app):
    _seed_scan(app, 90, 1000.0)
    _seed_scan(app, 72, 2000.0, base_url="http://127.0.0.1:5002", name="Other")
    _login(client)
    r = client.get("/trends")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert b"90" in r.data and b"72" in r.data
    assert "Lab" in body and "Other" in body
    assert "/trends/export" in body


def test_trends_csv_export_columns_and_rows(client, app):
    s1 = _seed_scan(app, 90, 1000.0)
    s2 = _seed_scan(app, 55, 2000.0, base_url="http://127.0.0.1:5002", name="Other")
    _login(client)
    r = client.get("/trends/export")
    assert r.status_code == 200
    assert "text/csv" in r.headers["Content-Type"]
    assert 'attachment; filename=score_trend.csv' in r.headers["Content-Disposition"]

    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    assert rows[0] == [
        "target", "base_url", "scan_id", "scan_date_utc", "score",
        "status", "endpoints", "findings", "critical", "high", "medium", "low", "info",
    ]
    assert len(rows) == 3  # header + two scans
    body_rows = [row for row in rows[1:] if row]
    assert {row[2] for row in body_rows} == {str(s1.id), str(s2.id)}
    scores = sorted(int(float(row[4])) for row in body_rows)
    assert scores == [55, 90]
    # high/medium counts come from the seeded severity_counts payload
    high_row = next(r for r in body_rows if r[2] == str(s1.id))
    assert high_row[9] == "1" and high_row[10] == "2"


def test_trends_csv_excludes_failed_scans_without_score(client, app):
    _seed_scan(app, 90, 1000.0)
    _seed_scan(app, None, 1500.0, status="failed")
    _login(client)
    r = client.get("/trends/export")
    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    assert len(rows) == 2  # header + only the scored scan