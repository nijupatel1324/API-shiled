"""Pytest fixtures for API-SHIELD.

Every test runs against an isolated SQLite database (tmp_path) and reuses or
spawns the bundled training API (test_api) on port 5001 so analyses can run
live but do not require any external network beyond localhost.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
os.chdir(REPO)
os.environ.setdefault("APP_ADMIN_PASSWORD", "Admin@123")

LAB_URL = "http://127.0.0.1:5001"


def _port_open(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


@pytest.fixture(scope="session")
def lab_server():
    """Reuses a running training API on 5001, otherwise spawns one."""
    if _port_open(5001):
        yield LAB_URL
        return

    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=str(REPO / "test_api"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            if _port_open(5001):
                break
            time.sleep(0.5)
        yield LAB_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


@pytest.fixture()
def app(tmp_path):
    """A fresh API-SHIELD app on its own sqlite file per test."""
    from app import create_app

    db_file = tmp_path / "test.db"
    uri = "sqlite:///" + str(db_file).replace("\\", "/")
    flask_app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": uri,
    })
    with flask_app.app_context():
        from database.models import db
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()