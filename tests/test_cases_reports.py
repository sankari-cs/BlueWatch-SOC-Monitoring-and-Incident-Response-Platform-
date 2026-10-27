import re

from app.extensions import db
from app.models import Alert, AuditLog, Case, CaseNote, Event, ResponseAction
from app.services.ingestion import ingest_records
from app.services.reports import build_case_report


def csrf(client):
    client.get("/incidents")
    with client.session_transaction() as session:
        return session["csrf_token"]


def seed_alert(app):
    record = {"source": "case-test", "source_id": "e-1", "origin": "imported",
              "timestamp": "2026-10-27T10:00:00Z", "event_type": "authentication",
              "outcome": "failure", "username": "case-user", "source_ip": "203.0.113.12",
              "host": "case-host", "message": "test evidence"}
    with app.app_context():
        ingest_records([record], "case-test")
        event = Event.query.first()
        alert = Alert(alert_key="case-alert-key", rule_id="BW-AUTH-001", rule_version="1.0.0",
                      title="Repeated authentication failures", summary="test", severity="high",
                      status="new", reasoning="test reasoning", mitre_json='["T1110"]',
                      first_seen=event.occurred_at, last_seen=event.occurred_at, events=[event])
        db.session.add(alert)
        db.session.commit()
        return alert.id


def test_case_create_status_audit_and_required_resolution_rationale(client, app):
    alert_id = seed_alert(app)
    token = csrf(client)
    response = client.post("/incidents", data={"_csrf_token": token, "title": "Auth review",
                               "severity": "high", "owner": "analyst", "alert_ids": str(alert_id)})
    assert response.status_code == 302
    with app.app_context():
        case = Case.query.one()
        case_id = case.id
        assert len(case.alerts) == 1
        assert AuditLog.query.filter_by(action="case.created").count() == 1
    response = client.post(f"/incidents/{case_id}/status", data={"_csrf_token": token, "status": "investigating",
                               "owner": "analyst", "severity": "high"})
    assert response.status_code == 302
    client.post(f"/incidents/{case_id}/status", data={"_csrf_token": token, "status": "closed",
                "owner": "analyst", "severity": "high"})
    with app.app_context():
        assert db.session.get(Case, case_id).status == "investigating"
    client.post(f"/incidents/{case_id}/status", data={"_csrf_token": token, "status": "closed",
                "owner": "analyst", "severity": "high", "resolution_rationale": "Reviewed test evidence"})
    with app.app_context():
        case = db.session.get(Case, case_id)
        assert case.status == "closed"
        assert case.resolution_rationale == "Reviewed test evidence"
        assert AuditLog.query.filter_by(entity_type="case", entity_id=str(case_id)).count() >= 3


def test_csrf_and_non_loopback_access_are_rejected(client):
    assert client.post("/incidents", data={"title": "Missing token"}).status_code == 400
    assert client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.9"}).status_code == 403


def test_case_notes_actions_and_report_are_stored_from_records(client, app):
    alert_id = seed_alert(app)
    token = csrf(client)
    client.post("/incidents", data={"_csrf_token": token, "title": "Report case", "severity": "high",
                "owner": "analyst", "alert_ids": str(alert_id)})
    with app.app_context():
        case_id = Case.query.one().id
    client.post(f"/incidents/{case_id}/notes", data={"_csrf_token": token, "body": "Checked source event."})
    client.post(f"/incidents/{case_id}/actions", data={"_csrf_token": token,
                "description": "Contact the service owner for verification."})
    with app.app_context():
        case = db.session.get(Case, case_id)
        report = build_case_report(case)
        action = ResponseAction.query.one()
        action_id = action.id
        assert len(report["events"]) == 1
        assert report["notes"][0].body == "Checked source event."
        assert report["mitre"] == ["T1110"]
        assert ResponseAction.query.one().status == "proposed"
    html = client.get(f"/reports/cases/{case_id}")
    assert html.status_code == 200
    assert b"Report case" in html.data
    assert b"test evidence" in html.data
    assert b"does not perform containment" in html.data
    client.post(f"/incidents/{case_id}/actions/{action_id}", data={"_csrf_token": token, "status": "approved",
                "approval_by": "SOC lead", "approval_note": "Authorized for the owner to proceed."})
    with app.app_context():
        action = db.session.get(ResponseAction, action_id)
        assert action.status == "approved"
        assert action.approval_by == "SOC lead"

def test_case_rejects_mixed_synthetic_and_imported_alerts(client, app):
    from datetime import datetime
    with app.app_context():
        imported = Event(event_uid="origin-imported", source_name="test", origin="imported",
                         occurred_at=datetime(2026, 1, 1), event_type="auth", original_fields_json="{}")
        synthetic = Event(event_uid="origin-synthetic", source_name="test", origin="synthetic",
                          occurred_at=datetime(2026, 1, 1), event_type="auth", original_fields_json="{}")
        db.session.add_all([imported, synthetic])
        db.session.flush()
        alerts = []
        for key, event in [("origin-alert-imported", imported), ("origin-alert-synthetic", synthetic)]:
            alert = Alert(alert_key=key, rule_id="test", rule_version="1", title="Origin test",
                          summary="test", severity="low", status="new", reasoning="test", mitre_json="[]",
                          first_seen=event.occurred_at, last_seen=event.occurred_at, events=[event])
            db.session.add(alert)
            alerts.append(alert)
        db.session.commit()
        alert_ids = [str(alert.id) for alert in alerts]
    client.get("/incidents")
    with client.session_transaction() as session:
        token = session["csrf_token"]
    client.post("/incidents", data={"_csrf_token": token, "title": "Separate origins",
                "severity": "low", "alert_ids": alert_ids})
    with app.app_context():
        assert Case.query.count() == 0
