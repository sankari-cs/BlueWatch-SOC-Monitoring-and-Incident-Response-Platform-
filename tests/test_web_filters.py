from datetime import datetime, timedelta

from app.extensions import db
from app.models import Alert


def test_alert_search_filters_and_pagination(client, app):
    base = datetime(2026, 10, 27, 10)
    with app.app_context():
        for index in range(25):
            db.session.add(Alert(
                alert_key=f"page-key-{index}", rule_id="BW-TEST", rule_version="1",
                title=f"Page test alert {index}", summary="needle" if index == 24 else "other summary",
                severity="low" if index < 24 else "high", status="new", reasoning="test",
                mitre_json="[]", first_seen=base + timedelta(minutes=index),
                last_seen=base + timedelta(minutes=index),
            ))
        db.session.commit()
    second_page = client.get("/alerts?page=2&severity=low")
    assert second_page.status_code == 200
    assert b"Page 2 of 2" in second_page.data
    filtered = client.get("/alerts?q=needle&severity=high")
    assert filtered.status_code == 200
    assert b"Page test alert 24" in filtered.data
    assert b"Page test alert 0" not in filtered.data
