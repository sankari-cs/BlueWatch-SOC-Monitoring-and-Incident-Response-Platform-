"""Shared in-memory database fixtures."""

import pytest

from app import create_app
from app.extensions import db


@pytest.fixture()
def app():
    test_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-session-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "FAILED_AUTH_THRESHOLD": 5,
        "FAILED_AUTH_WINDOW_MINUTES": 10,
        "AUTH_SEQUENCE_WINDOW_MINUTES": 15,
        "CORRELATION_WINDOW_MINUTES": 60,
        "ANALYST_NAME": "test-analyst",
    })
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
