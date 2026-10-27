"""Flask application factory and local-only security defaults."""

from __future__ import annotations

import ipaddress
import json
import logging
import secrets
from pathlib import Path

from flask import Flask, abort, g, jsonify, request, session
from sqlalchemy import event, text
from sqlalchemy.exc import SQLAlchemyError

from .extensions import db, migrate
from . import models  # noqa: F401 — register all models before migration setup.


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "bluewatch", None)
        if isinstance(extra, dict):
            payload["bluewatch"] = extra
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def create_app(test_config: dict | None = None) -> Flask:
    """Create an app instance with independently configurable extensions."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object("app.config.Config")
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        # Random per-process fallback for local demo use. Set BLUEWATCH_SECRET_KEY
        # for stable cookies across restarts; the value is never logged or shown.
        app.config["SECRET_KEY"] = secrets.token_urlsafe(48)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    with app.app_context():
        if db.engine.dialect.name == "sqlite":
            event.listen(db.engine, "connect", _enable_sqlite_foreign_keys)
    migrate.init_app(app, db)

    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    @app.before_request
    def local_access_and_csrf():
        remote = request.remote_addr or ""
        try:
            if not ipaddress.ip_address(remote).is_loopback:
                abort(403)
        except ValueError:
            abort(403)

        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        g.csrf_token = token
        if request.method == "POST":
            import hmac
            supplied = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token, supplied):
                abort(400, description="CSRF validation failed")

    @app.context_processor
    def inject_template_globals():
        return {"csrf_token": getattr(g, "csrf_token", "")}

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.get("/health")
    def health():
        try:
            db.session.execute(text("SELECT 1")).scalar_one()
        except SQLAlchemyError:
            db.session.rollback()
            return jsonify(status="error", database="unavailable"), 503
        return jsonify(status="ok", database="ok"), 200

    from .web import bp
    app.register_blueprint(bp)

    @app.errorhandler(400)
    def bad_request(error):
        if request.accept_mimetypes.best == "application/json":
            return jsonify(error="bad_request", message=getattr(error, "description", "Invalid request")), 400
        return app.make_response(("Bad request. Check the submitted form and try again.", 400))

    @app.errorhandler(403)
    def forbidden(_error):
        return app.make_response(("BlueWatch is restricted to local loopback access.", 403))

    @app.errorhandler(404)
    def not_found(_error):
        return app.make_response(("Page not found.", 404))

    @app.errorhandler(413)
    def too_large(_error):
        return app.make_response(("Upload exceeds the 5 MB limit.", 413))

    return app





