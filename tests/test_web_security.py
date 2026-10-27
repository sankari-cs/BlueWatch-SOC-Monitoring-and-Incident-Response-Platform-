from app.extensions import db
from app.models import Alert, AuditLog, Case


def get_token(client):
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_all_primary_pages_render_in_empty_state(client):
    for path in ["/", "/health", "/ingest", "/events", "/alerts", "/incidents",
                 "/rules", "/playbooks", "/reports", "/audit", "/settings"]:
        response = client.get(path)
        assert response.status_code == 200, path
    assert client.get("/health").headers["X-Content-Type-Options"] == "nosniff"


def test_false_positive_requires_rationale_and_is_audited(client, app):
    from datetime import datetime
    with app.app_context():
        alert = Alert(alert_key="triage-key", rule_id="BW-AUTH-001", rule_version="1.0.0",
                      title="Test alert", summary="Test", severity="high", status="new",
                      reasoning="test", mitre_json="[]", first_seen=datetime(2026, 1, 1),
                      last_seen=datetime(2026, 1, 1))
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id
    token = get_token(client)
    client.post(f"/alerts/{alert_id}/update", data={"_csrf_token": token, "status": "false_positive"})
    with app.app_context():
        assert db.session.get(Alert, alert_id).status == "new"
    client.post(f"/alerts/{alert_id}/update", data={"_csrf_token": token,
                "status": "false_positive", "rationale": "Expected lab activity."})
    with app.app_context():
        updated = db.session.get(Alert, alert_id)
        assert updated.status == "false_positive"
        assert updated.closure_rationale == "Expected lab activity."
        assert AuditLog.query.filter_by(action="alert.updated").count() == 1


def test_user_content_is_autoescaped_in_reports(client, app):
    token = get_token(client)
    client.post("/incidents", data={"_csrf_token": token, "title": "<script>alert(1)</script>",
                "severity": "low", "owner": "analyst"})
    with app.app_context():
        case_id = Case.query.one().id
    response = client.get(f"/reports/cases/{case_id}")
    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>alert(1)</script>" not in response.data
