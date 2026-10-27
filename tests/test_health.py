from sqlalchemy import inspect, text

from app.extensions import db
from app.models import Event


def test_health_reports_database_ready(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "database": "ok"}


def test_database_initialization_creates_registered_tables(app):
    with app.app_context():
        tables = set(inspect(db.engine).get_table_names())
    assert {"events", "alerts", "cases", "audit_logs", "ingestion_runs"} <= tables
    with app.app_context():
        assert db.session.execute(text("PRAGMA foreign_keys")).scalar_one() == 1


def test_unique_event_fingerprint_constraint(app):
    from sqlalchemy.exc import IntegrityError
    from datetime import datetime

    with app.app_context():
        event = Event(event_uid="same", source_name="test", origin="imported",
                      occurred_at=datetime(2026, 1, 1), event_type="login",
                      original_fields_json="{}")
        db.session.add(event)
        db.session.commit()
        db.session.add(Event(event_uid="same", source_name="test", origin="imported",
                             occurred_at=datetime(2026, 1, 1), event_type="login",
                             original_fields_json="{}"))
        try:
            db.session.commit()
            assert False, "unique event fingerprint should reject a duplicate"
        except IntegrityError:
            db.session.rollback()
        assert Event.query.count() == 1



