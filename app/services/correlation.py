"""Explainable pairwise correlation for alerts."""

import json
from datetime import timedelta

from flask import current_app

from ..extensions import db
from ..models import Alert, Correlation, utcnow


def _criteria(left: Alert, right: Alert) -> list[str]:
    matches = []
    for field in ("host", "username", "source_ip"):
        left_value = getattr(left, field)
        right_value = getattr(right, field)
        if left_value and right_value and left_value.casefold() == right_value.casefold():
            matches.append(field)
    return matches


def correlate_alert(alert: Alert) -> list[Correlation]:
    """Link alerts only when two entity attributes match within the time window."""
    origins = {event.origin for event in alert.events}
    window_minutes = int(current_app.config.get("CORRELATION_WINDOW_MINUTES", 60))
    window = timedelta(minutes=window_minutes)
    start = alert.first_seen - window
    end = alert.last_seen + window
    candidates = (
        Alert.query.filter(Alert.id != alert.id)
        .filter(Alert.last_seen >= start, Alert.first_seen <= end)
        .all()
    )
    created = []
    for other in candidates:
        other_origins = {event.origin for event in other.events}
        if origins and other_origins and origins != other_origins:
            continue
        matched = _criteria(alert, other)
        if len(matched) < 2:
            continue
        left_id, right_id = sorted((alert.id, other.id))
        if Correlation.query.filter_by(left_alert_id=left_id, right_alert_id=right_id).first():
            continue
        evidence = {
            "matched_fields": matched,
            "matched_values": {field: getattr(alert, field) for field in matched},
            "correlation_window_minutes": window_minutes,
            "alert_time_ranges_utc": {
                str(alert.id): {"first_seen": alert.first_seen.isoformat() + "Z", "last_seen": alert.last_seen.isoformat() + "Z"},
                str(other.id): {"first_seen": other.first_seen.isoformat() + "Z", "last_seen": other.last_seen.isoformat() + "Z"},
            },
            "explanation": "At least two entity fields match and the alert time ranges fall within the configured window.",
        }
        link = Correlation(
            left_alert_id=left_id,
            right_alert_id=right_id,
            criteria_json=json.dumps(evidence, ensure_ascii=False, sort_keys=True),
            created_at=utcnow(),
        )
        db.session.add(link)
        created.append(link)
    return created


def correlations_for_alert(alert_id: int):
    return Correlation.query.filter(
        (Correlation.left_alert_id == alert_id) | (Correlation.right_alert_id == alert_id)
    ).order_by(Correlation.created_at.desc()).all()
