"""Common persistence helpers for audit and user actions."""

import json
from datetime import date, datetime
from typing import Any

from flask import current_app

from ..extensions import db
from ..models import AuditLog


def json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat() + ("Z" if isinstance(value, datetime) and value.tzinfo is None else "")
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def audit(entity_type: str, entity_id: Any, action: str, details: dict | None = None) -> AuditLog:
    entry = AuditLog(
        entity_type=entity_type,
        entity_id=str(entity_id),
        action=action,
        actor=current_app.config.get("ANALYST_NAME", "local-analyst"),
        details_json=json.dumps(json_safe(details or {}), sort_keys=True),
    )
    db.session.add(entry)
    return entry
