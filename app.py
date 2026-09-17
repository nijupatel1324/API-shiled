"""
API-SHIELD - Advanced API Security Scanner & Protection Platform
Main Flask application factory.

Usage:
    py app.py                 # development server on http://127.0.0.1:5000
"""

import os
import secrets
import logging
from pathlib import Path

from flask import Flask, jsonify, request, render_template
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("api-shield")

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def _normalize_sqlite_uri(uri: str) -> str:
    """Resolve relative sqlite URIs to absolute, forward-slash paths (Windows-safe)."""
    if uri.startswith("sqlite:////"):  # absolute path form
        return uri
    if uri.startswith("sqlite:///"):
        rel = uri[len("sqlite:///"):]
        if os.path.isabs(rel):
            return "sqlite:///" + rel.replace("\\", "/")
        return "sqlite:///" + os.path.join(BASEDIR, *[p for p in rel.split("/") if p]).replace("\\", "/")
    return uri


def _setup_logging(level: str = "INFO", log_file: str = "logs/api_shield.log") -> logging.Logger:
    os.makedirs(os.path.join(BASEDIR, "logs"), exist_ok=True)
    log_path = os.path.join(BASEDIR, log_file)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8"), logging.StreamHandler()],
    )
    return logging.getLogger("api-shield")


def create_app(test_config: dict = None) -> Flask:
    """Application factory. Pass a dict to override config for tests."""
    global logger

    app = Flask(__name__)
    app.config.from_object("config.Config")
    if test_config:
        app.config.update(test_config)

    app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_sqlite_uri(
        app.config["SQLALCHEMY_DATABASE_URI"]
    )

    from database.models import db
    db.init_app(app)

    # SQLite needs WAL + a busy timeout for the background scan thread to
    # write findings while the web thread serves progress polls. The listener
    # is registered once per process: a fresh registration per app would get
    # unregistered during teardown while a background worker is mid-connect,
    # raising "deque mutated during iteration".
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        if not globals().get("_sqlite_pragmas_registered"):
            @event.listens_for(Engine, "connect")
            def _sqlite_pragmas(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA busy_timeout=30000")
                except Exception:
                    pass
                finally:
                    cursor.close()

            globals()["_sqlite_pragmas_registered"] = True

    # Register model layer (scan history) so all tables are created.
    import models  # noqa: F401

    from api.routes import api_bp
    from api.web import register_web_routes
    app.register_blueprint(api_bp)
    register_web_routes(app)

    logger = _setup_logging(
        level=app.config.get("LOG_LEVEL", "INFO"),
        log_file=app.config.get("LOG_FILE", "logs/api_shield.log"),
    )

    # ── Security response headers for the API-SHIELD app itself ────────
    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'",
        )
        return resp

    # ── DB init + admin seeding ─────────────────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_admin(app)

    # ── Error handlers (no stack traces exposed) ────────────────────────
    @app.errorhandler(404)
    def _not_found(err):
        if request.path.startswith("/api/"):
            return jsonify({"success": False,
                            "error": {"code": "NOT_FOUND", "message": "Resource not found."}}), 404
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(405)
    def _method_not_allowed(err):
        return jsonify({"success": False,
                        "error": {"code": "METHOD_NOT_ALLOWED", "message": "Method not allowed."}}), 405

    @app.errorhandler(500)
    def _internal_error(err):
        logger.exception("Unhandled exception: %s", err)
        if request.path.startswith("/api/"):
            return jsonify({"success": False,
                            "error": {"code": "INTERNAL_ERROR",
                                      "message": "An internal server error occurred."}}), 500
        return render_template("error.html", code=500, message="An internal server error occurred."), 500

    @app.errorhandler(413)
    def _payload_too_large(err):
        return jsonify({"success": False,
                        "error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request payload too large."}}), 413

    logger.info("API-SHIELD application initialized (db=%s)",
                app.config["SQLALCHEMY_DATABASE_URI"])
    return app


def _seed_admin(app: Flask):
    """Create the default admin account on first run (password from env or demo default)."""
    from models import User
    from database.models import db

    if User.query.first() is not None:
        return

    username = os.environ.get("APP_ADMIN_USERNAME", "admin").strip()
    password = os.environ.get("APP_ADMIN_PASSWORD", "Admin@123")

    from_demo = not os.environ.get("APP_ADMIN_PASSWORD")
    user = User(username=username, email=f"{username}@api-shield.local", is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    if from_demo:
        logger.warning(
            "Created default demo admin '%s' with password '%s' - set "
            "APP_ADMIN_PASSWORD in .env for production use.", username, password,
        )
    else:
        logger.info("Created default admin account '%s' from environment.", username)


app = create_app()


if __name__ == "__main__":
    from scanner.scheduler import start_scheduler

    start_scheduler(app)
    logger.info("Starting API-SHIELD on http://127.0.0.1:5000 ...")
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
        use_reloader=False,
    )