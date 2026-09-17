"""Tests for rescan actions and recurring scan scheduling."""

import re
import time
from unittest import mock

from database.models import db, Project
from models import Scan, ScanSchedule, Target


def _login(client):
    page = client.get("/login")
    token = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    r = client.post("/login", data={
        "username": "admin", "password": "Admin@123", "_csrf_token": token,
    })
    assert r.status_code == 302


def _csrf(client):
    page = client.get("/schedules")
    token = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    return token.group(1) if token else None


def _seed_target(app):
    target = Target(name="Lab", base_url="http://127.0.0.1:5001", scan_type="full")
    db.session.add(target)
    db.session.flush()
    db.session.commit()
    return target


def _seed_project_scan(app, target=None):
    target = target or _seed_target(app)
    project = Project(name="Lab", base_url=target.base_url)
    db.session.add(project)
    db.session.commit()
    scan = Scan(target_id=target.id, status="completed", started_at=time.time(),
                completed_at=time.time(), score=88)
    db.session.add(scan)
    db.session.commit()
    return scan


def test_schedules_page_requires_login(client):
    r = client.get("/schedules")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_create_and_list_schedule(client, app):
    target = _seed_target(app)
    _login(client)
    token = _csrf(client)
    r = client.post("/schedules/new", data={
        "target_id": str(target.id),
        "interval_hours": "6",
        "_csrf_token": token,
    })
    assert r.status_code == 302
    sched = ScanSchedule.query.first()
    assert sched is not None
    assert sched.target_id == target.id and sched.interval_hours == 6 and sched.enabled

    page = client.get("/schedules")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert target.base_url in body
    assert "every 6h" in body


def test_toggle_schedule(client, app):
    target = _seed_target(app)
    sched = ScanSchedule(target_id=target.id, interval_hours=24, enabled=True)
    db.session.add(sched)
    db.session.commit()
    _login(client)
    token = _csrf(client)
    r = client.post(f"/schedules/{sched.id}/toggle", data={"_csrf_token": token})
    assert r.status_code == 302
    assert ScanSchedule.query.get(sched.id).enabled is False
    r = client.post(f"/schedules/{sched.id}/toggle", data={"_csrf_token": token})
    assert ScanSchedule.query.get(sched.id).enabled is True


def test_delete_schedule(client, app):
    target = _seed_target(app)
    sched = ScanSchedule(target_id=target.id, interval_hours=24, enabled=True)
    db.session.add(sched)
    db.session.commit()
    _login(client)
    token = _csrf(client)
    r = client.post(f"/schedules/{sched.id}/delete", data={"_csrf_token": token})
    assert r.status_code == 302
    assert ScanSchedule.query.get(sched.id) is None


def test_schedule_new_bad_input_returns_400(client, app):
    _seed_target(app)
    _login(client)
    token = _csrf(client)
    r = client.post("/schedules/new", data={
        "target_id": "not-a-number", "interval_hours": "6", "_csrf_token": token,
    })
    assert r.status_code == 400


def test_rescan_creates_new_scan(client, app):
    import api.web as web_module

    scan = _seed_project_scan(app)
    _login(client)
    token = _csrf(client)

    def _stub_start_async(app_obj, project_id, bola=None):
        from database.models import db as _db
        from models import Scan as _Scan
        from models import Target as _Target
        target = _Target.query.filter_by(base_url=scan.target.base_url).first()
        now = time.time()
        s = _Scan(target_id=target.id, status="running", started_at=now, completed_at=now)
        _db.session.add(s)
        _db.session.commit()
        return s.id

    with mock.patch.object(web_module, "start_async_scan", _stub_start_async):
        r = client.post(f"/scans/{scan.id}/rescan", data={"_csrf_token": token})
    assert r.status_code == 302
    loc = r.headers["Location"]
    new_scan_id = int(loc.rstrip("/").split("/")[-1])
    assert new_scan_id != scan.id
    new_scan = Scan.query.get(new_scan_id)
    assert new_scan.status == "running"
    assert new_scan.target_id == scan.target_id


def test_promise_due_schedules(tmp_path):
    """Scheduler helper marks due/unset schedules correctly (unit, no network)."""
    from scanner.scheduler import promise_due_schedules
    from app import create_app

    flask_app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "sched.db").replace("\\", "/"),
    })
    with flask_app.app_context():
        db.create_all()
        target = _seed_target(app=flask_app)
        future = ScanSchedule(target_id=target.id, interval_hours=24, enabled=True,
                              next_run_at=time.time() + 9999)
        due = ScanSchedule(target_id=target.id, interval_hours=24, enabled=True,
                           next_run_at=time.time() - 5)
        disabled = ScanSchedule(target_id=target.id, interval_hours=24, enabled=False,
                                next_run_at=time.time() - 5)
        unset = ScanSchedule(target_id=target.id, interval_hours=24, enabled=True,
                             next_run_at=None)
        for s in (future, due, disabled, unset):
            db.session.add(s)
        db.session.commit()
        due_ids = {s.id for s in promise_due_schedules()}
        assert due_ids == {due.id, unset.id}