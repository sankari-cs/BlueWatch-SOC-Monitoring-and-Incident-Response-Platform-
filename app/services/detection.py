"""Explainable, versioned authentication detection rules."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path

from flask import current_app

from ..extensions import db
from ..models import Alert, Event, utcnow
from .common import audit
from .correlation import correlate_alert


def load_rules() -> list[dict]:
    configured = current_app.config.get("RULES_PATH")
    path = Path(configured) if configured else Path(current_app.root_path).parent / "rules" / "detection_rules.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _rule(rule_id: str) -> dict:
    return next(rule for rule in load_rules() if rule["id"] == rule_id)


def _alert_key(rule_id: str, events: list[Event]) -> str:
    value = rule_id + ":" + ":".join(sorted(event.event_uid for event in events))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _finding(rule_id: str, events: list[Event], reasoning: str, summary: str) -> Alert | None:
    rule = _rule(rule_id)
    key = _alert_key(rule_id, events)
    if Alert.query.filter_by(alert_key=key).first():
        return None
    ordered = sorted(events, key=lambda event: event.occurred_at)
    usernames = {event.username for event in ordered if event.username}
    source_ips = {event.source_ip for event in ordered if event.source_ip}
    hosts = {event.host for event in ordered if event.host}
    sources = {event.source_name for event in ordered if event.source_name}
    alert = Alert(
        alert_key=key,
        rule_id=rule["id"],
        rule_version=rule["version"],
        title=rule["name"],
        summary=summary,
        severity=rule["severity"],
        status="new",
        source_name=next(iter(sources)) if len(sources) == 1 else None,
        host=next(iter(hosts)) if len(hosts) == 1 else None,
        username=next(iter(usernames)) if len(usernames) == 1 else None,
        source_ip=next(iter(source_ips)) if len(source_ips) == 1 else None,
        reasoning=reasoning + " This is an investigative lead and does not confirm compromise.",
        mitre_json=json.dumps(rule.get("mitre_attack", [])),
        first_seen=ordered[0].occurred_at,
        last_seen=ordered[-1].occurred_at,
        created_at=utcnow(),
        updated_at=utcnow(),
        events=ordered,
    )
    db.session.add(alert)
    db.session.flush()
    audit("alert", alert.id, "alert.detected", {
        "rule_id": rule["id"], "rule_version": rule["version"],
        "severity": rule["severity"], "evidence_count": len(ordered),
    })
    correlate_alert(alert)
    return alert


def run_detections() -> list[Alert]:
    """Evaluate all stored events so thresholds can span separate import runs."""
    events = Event.query.order_by(Event.occurred_at.asc(), Event.id.asc()).all()
    alerts: list[Alert] = []
    threshold = int(current_app.config["FAILED_AUTH_THRESHOLD"])
    burst_window = timedelta(minutes=int(current_app.config["FAILED_AUTH_WINDOW_MINUTES"]))
    sequence_window = timedelta(minutes=int(current_app.config["AUTH_SEQUENCE_WINDOW_MINUTES"]))

    # Source and origin are part of the identity so synthetic and imported events
    # can never be combined into one detection result.
    failures: dict[tuple[str, str, str, str], list[Event]] = {}
    for event in events:
        if event.event_type == "authentication" and event.outcome == "failure" and event.username and event.source_ip:
            key = (event.origin, event.source_name, event.username.casefold(), event.source_ip)
            failures.setdefault(key, []).append(event)

    for (_origin, _source, _username, source_ip), group in failures.items():
        group.sort(key=lambda item: item.occurred_at)
        index = 0
        while index < len(group):
            end = index + 1
            until = group[index].occurred_at + burst_window
            while end < len(group) and group[end].occurred_at <= until:
                end += 1
            if end - index >= threshold:
                evidence = group[index:end]
                first, last = evidence[0].occurred_at, evidence[-1].occurred_at
                seconds = int((last - first).total_seconds())
                reasoning = (
                    f"Observed {len(evidence)} failed authentications for the same recorded "
                    f"username and source IP within {int(burst_window.total_seconds() // 60)} minutes. "
                    f"The evidence spans {seconds} seconds."
                )
                summary = f"{len(evidence)} failed authentications for {evidence[0].username} from {source_ip}."
                alert = _finding("BW-AUTH-001", evidence, reasoning, summary)
                if alert:
                    alerts.append(alert)
                index = end
            else:
                index += 1

    for success in events:
        if success.event_type != "authentication" or success.outcome != "success" or not success.username or not success.source_ip:
            continue
        failure_key = (success.origin, success.source_name, success.username.casefold(), success.source_ip)
        start = success.occurred_at - sequence_window
        prior = [event for event in failures.get(failure_key, []) if start <= event.occurred_at < success.occurred_at]
        if not prior:
            continue
        evidence = prior + [success]
        reasoning = (
            f"Observed {len(prior)} failed authentication event(s) followed by a successful "
            f"authentication for the same recorded username and source IP within "
            f"{int(sequence_window.total_seconds() // 60)} minutes."
        )
        summary = f"Authentication success followed {len(prior)} failure(s) for {success.username} from {success.source_ip}."
        alert = _finding("BW-AUTH-002", evidence, reasoning, summary)
        if alert:
            alerts.append(alert)

    db.session.commit()
    return alerts
