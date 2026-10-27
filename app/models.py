"""Relational data model for BlueWatch investigations and evidence."""

from __future__ import annotations

from datetime import datetime, timezone

from .extensions import db


def utcnow() -> datetime:
    """Return naive UTC for consistent SQLite DateTime storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


alert_events = db.Table(
    "alert_events",
    db.Column("alert_id", db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    db.Column("event_id", db.Integer, db.ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
)

case_alerts = db.Table(
    "case_alerts",
    db.Column("case_id", db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
    db.Column("alert_id", db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)


class AppMetadata(db.Model):
    __tablename__ = "app_metadata"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(255), nullable=False)


class Event(db.Model):
    __tablename__ = "events"
    __table_args__ = (
        db.Index("ix_events_auth_identity_time", "event_type", "username", "source_ip", "occurred_at"),
        db.Index("ix_events_occurred_at", "occurred_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    event_uid = db.Column(db.String(64), unique=True, nullable=False)
    schema_version = db.Column(db.String(16), nullable=False, default="1")
    source_name = db.Column(db.String(128), nullable=False)
    source_identifier = db.Column(db.String(255))
    origin = db.Column(db.String(16), nullable=False, default="imported")
    occurred_at = db.Column(db.DateTime, nullable=False)
    ingested_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    event_type = db.Column(db.String(80), nullable=False)
    outcome = db.Column(db.String(16))
    username = db.Column(db.String(255))
    source_ip = db.Column(db.String(64))
    host = db.Column(db.String(255))
    rule_id = db.Column(db.String(128))
    message = db.Column(db.Text)
    original_fields_json = db.Column(db.Text, nullable=False)

    alerts = db.relationship("Alert", secondary=alert_events, back_populates="events")

    @property
    def original_fields(self) -> dict:
        import json
        return json.loads(self.original_fields_json)


class Alert(db.Model):
    __tablename__ = "alerts"
    __table_args__ = (
        db.Index("ix_alerts_status_severity_time", "status", "severity", "last_seen"),
    )

    id = db.Column(db.Integer, primary_key=True)
    alert_key = db.Column(db.String(64), unique=True, nullable=False)
    rule_id = db.Column(db.String(64), nullable=False)
    rule_version = db.Column(db.String(32), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="new")
    source_name = db.Column(db.String(128))
    host = db.Column(db.String(255))
    username = db.Column(db.String(255))
    source_ip = db.Column(db.String(64))
    reasoning = db.Column(db.Text, nullable=False)
    mitre_json = db.Column(db.Text, nullable=False, default="[]")
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    assigned_to = db.Column(db.String(80))
    closure_rationale = db.Column(db.Text)

    events = db.relationship("Event", secondary=alert_events, back_populates="alerts")
    cases = db.relationship("Case", secondary=case_alerts, back_populates="alerts")


    @property
    def origin(self) -> str:
        values = {event.origin for event in self.events}
        if not values:
            return "unknown"
        return next(iter(values)) if len(values) == 1 else "mixed"


class Correlation(db.Model):
    __tablename__ = "correlations"
    __table_args__ = (
        db.UniqueConstraint("left_alert_id", "right_alert_id", name="uq_correlation_pair"),
        db.CheckConstraint("left_alert_id < right_alert_id", name="ck_correlation_sorted_pair"),
    )

    id = db.Column(db.Integer, primary_key=True)
    left_alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    right_alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    criteria_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    left_alert = db.relationship("Alert", foreign_keys=[left_alert_id])
    right_alert = db.relationship("Alert", foreign_keys=[right_alert_id])


class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(40), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(16), nullable=False, default="medium")
    status = db.Column(db.String(24), nullable=False, default="open")
    owner = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    closed_at = db.Column(db.DateTime)
    resolution_rationale = db.Column(db.Text)

    alerts = db.relationship("Alert", secondary=case_alerts, back_populates="cases")
    notes = db.relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.created_at")
    actions = db.relationship("ResponseAction", back_populates="case", cascade="all, delete-orphan", order_by="ResponseAction.created_at")


class CaseNote(db.Model):
    __tablename__ = "case_notes"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author = db.Column(db.String(80), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    case = db.relationship("Case", back_populates="notes")


class ResponseAction(db.Model):
    __tablename__ = "response_actions"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(24), nullable=False, default="proposed")
    approval_by = db.Column(db.String(80))
    approval_note = db.Column(db.Text)
    outcome = db.Column(db.Text)
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    case = db.relationship("Case", back_populates="actions")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    entity_type = db.Column(db.String(40), nullable=False, index=True)
    entity_id = db.Column(db.String(80), nullable=False, index=True)
    action = db.Column(db.String(80), nullable=False)
    actor = db.Column(db.String(80), nullable=False)
    details_json = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class IngestionRun(db.Model):
    __tablename__ = "ingestion_runs"
    id = db.Column(db.Integer, primary_key=True)
    source_name = db.Column(db.String(128), nullable=False)
    origin = db.Column(db.String(16), nullable=False)
    accepted = db.Column(db.Integer, nullable=False, default=0)
    rejected = db.Column(db.Integer, nullable=False, default=0)
    skipped = db.Column(db.Integer, nullable=False, default=0)
    duplicates = db.Column(db.Integer, nullable=False, default=0)
    errors_json = db.Column(db.Text, nullable=False, default="[]")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


