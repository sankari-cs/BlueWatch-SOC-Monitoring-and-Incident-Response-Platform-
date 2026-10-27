import json
from datetime import datetime, timedelta

from app.extensions import db
from app.models import Alert, Correlation, Event
from app.services.correlation import correlate_alert
from app.services.detection import run_detections
from app.services.ingestion import ingest_records


def auth_event(index, outcome="failure", **overrides):
    value = {
        "source": "auth-lab", "source_id": f"auth-{index}", "origin": "imported",
        "timestamp": f"2026-10-27T10:{index:02d}:00Z", "event_type": "authentication",
        "outcome": outcome, "username": "test-user", "source_ip": "203.0.113.15",
        "host": "host-01", "message": "Synthetic unit-test record",
    }
    value.update(overrides)
    return value


def test_repeated_failures_create_explainable_high_alert_with_evidence(app):
    with app.app_context():
        ingest_records([auth_event(i) for i in range(5)], "auth-lab")
        created = run_detections()
        assert len(created) == 1
        alert = created[0]
        assert alert.rule_id == "BW-AUTH-001"
        assert alert.severity == "high"
        assert len(alert.events) == 5
        assert "5 failed authentications" in alert.reasoning
        assert "does not confirm compromise" in alert.reasoning
        assert run_detections() == []


def test_failures_followed_by_success_create_medium_alert(app):
    with app.app_context():
        events = [auth_event(i) for i in range(3)] + [auth_event(4, "success")]
        ingest_records(events, "auth-lab")
        created = run_detections()
        sequence = next(alert for alert in created if alert.rule_id == "BW-AUTH-002")
        assert sequence.severity == "medium"
        assert len(sequence.events) == 4
        assert "followed by a successful" in sequence.reasoning


def test_negative_detection_cases_and_origin_separation(app):
    with app.app_context():
        records = [auth_event(i) for i in range(4)]
        records.extend(auth_event(i + 10, origin="synthetic", source="synthetic-lab") for i in range(4))
        records.extend(auth_event(i + 20, username=None) for i in range(2))
        ingest_records(records, "mixed")
        assert run_detections() == []
        assert Alert.query.count() == 0


def test_correlation_requires_two_matching_entity_fields(app):
    with app.app_context():
        base = datetime(2026, 10, 27, 10)
        def make_alert(n, host, username, ip, time=base):
            item = Alert(alert_key=f"key-{n}", rule_id="test", rule_version="1", title="Test alert",
                         summary="Test", severity="low", status="new", reasoning="test",
                         mitre_json="[]", first_seen=time, last_seen=time, host=host,
                         username=username, source_ip=ip)
            db.session.add(item)
            db.session.flush()
            return item
        first = make_alert(1, "host-a", "alice", "203.0.113.1")
        shared_ip_only = make_alert(2, "host-b", "bob", "203.0.113.1")
        assert correlate_alert(shared_ip_only) == []
        assert Correlation.query.count() == 0
        matching = make_alert(3, "host-a", "alice", "203.0.113.9")
        links = correlate_alert(matching)
        assert len(links) == 1
        criteria = json.loads(links[0].criteria_json)
        assert criteria["matched_fields"] == ["host", "username"]
        assert criteria["matched_values"] == {"host": "host-a", "username": "alice"}
        assert criteria["correlation_window_minutes"] == 60
        far = make_alert(4, "host-a", "alice", "203.0.113.9", base + timedelta(days=2))
        assert correlate_alert(far) == []

def test_synthetic_and_imported_alerts_are_not_correlated(app):
    with app.app_context():
        imported = [auth_event(i) for i in range(5)]
        synthetic = [auth_event(i + 10, source="auth-lab", origin="synthetic") for i in range(5)]
        ingest_records(imported + synthetic, "mixed-source")
        created = run_detections()
        assert len([alert for alert in created if alert.rule_id == "BW-AUTH-001"]) == 2
        assert Correlation.query.count() == 0

