"""Evidence-backed incident report assembly."""

import json

from ..models import Case


LIMITATIONS = (
    "Detection alerts are investigative leads and do not confirm compromise. "
    "Imported data may be incomplete, delayed, malformed, or scoped to the sources listed below. "
    "Severity is the stored analyst or detection-rule value; validate it against organizational policy."
)


def build_case_report(case: Case) -> dict:
    alerts = sorted(case.alerts, key=lambda item: item.first_seen)
    events = sorted(
        {event.id: event for alert in alerts for event in alert.events}.values(),
        key=lambda item: (item.occurred_at, item.id),
    )
    entities = {"hosts": set(), "usernames": set(), "source_ips": set()}
    for alert in alerts:
        if alert.host:
            entities["hosts"].add(alert.host)
        if alert.username:
            entities["usernames"].add(alert.username)
        if alert.source_ip:
            entities["source_ips"].add(alert.source_ip)
    for event in events:
        if event.host:
            entities["hosts"].add(event.host)
        if event.username:
            entities["usernames"].add(event.username)
        if event.source_ip:
            entities["source_ips"].add(event.source_ip)

    timeline = []
    for alert in alerts:
        timeline.append({
            "time": alert.created_at,
            "kind": "alert",
            "title": alert.title,
            "detail": f"{alert.rule_id} · {alert.severity} · {alert.status}",
            "reference": f"Alert #{alert.id}", "origin": alert.origin,
        })
    for event in events:
        timeline.append({
            "time": event.occurred_at,
            "kind": "event",
            "title": event.event_type,
            "detail": f"Origin: {event.origin}. " + (event.message or "No message was present in the source record."),
            "reference": f"{event.source_name}:{event.source_identifier or event.event_uid[:12]}", "origin": event.origin,
        })
    for note in case.notes:
        timeline.append({
            "time": note.created_at, "kind": "analyst note", "title": note.author,
            "detail": note.body, "reference": f"Note #{note.id}",
        })
    timeline.sort(key=lambda entry: entry["time"])

    return {
        "case": case,
        "alerts": alerts,
        "events": events,
        "timeline": timeline,
        "entities": {key: sorted(value) for key, value in entities.items()},
        "notes": case.notes,
        "actions": case.actions,
        "severity_rationale": "Severity is an analyst-assigned case value; linked detection severities are shown separately.",
        "limitations": LIMITATIONS,
        "mitre": sorted({technique for alert in alerts for technique in json.loads(alert.mitre_json or "[]")}),
    }


