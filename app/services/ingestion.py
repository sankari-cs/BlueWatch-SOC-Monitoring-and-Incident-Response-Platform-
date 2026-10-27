"""Validated, idempotent telemetry ingestion."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from flask import current_app
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import Event, IngestionRun
from .common import audit
from .normalization import ValidationError, normalize_record, parse_upload


def ingest_upload(filename: str, payload: bytes, source_name: str | None = None) -> dict:
    records, skipped, parse_errors = parse_upload(
        filename,
        payload,
        current_app.config["UPLOAD_MAX_RECORDS"],
        current_app.config["UPLOAD_MAX_LINE_BYTES"],
    )
    source = source_name or filename.rsplit(".", 1)[0][:128]
    return ingest_records(records, source, skipped=skipped, initial_errors=parse_errors)


def ingest_records(
    records: list[Any],
    source_name: str,
    *,
    skipped: int = 0,
    initial_errors: list[dict] | None = None,
) -> dict:
    """Persist valid records; exact retries and source-ID repeats are counted."""
    accepted = duplicates = 0
    rejected = len(initial_errors or [])
    errors = list(initial_errors or [])[:100]
    origins: Counter[str] = Counter()
    inserted_ids: list[int] = []

    for index, record in enumerate(records, start=1):
        try:
            normalized = normalize_record(record)
        except ValidationError as exc:
            rejected += 1
            if len(errors) < 100:
                errors.append({"record": index, "error": str(exc)})
            continue

        if db.session.query(Event.id).filter_by(event_uid=normalized.event_uid).first():
            duplicates += 1
            continue

        event = Event(
            event_uid=normalized.event_uid,
            schema_version=normalized.schema_version,
            source_name=normalized.source_name,
            source_identifier=normalized.source_identifier,
            origin=normalized.origin,
            occurred_at=normalized.occurred_at,
            event_type=normalized.event_type,
            outcome=normalized.outcome,
            username=normalized.username,
            source_ip=normalized.source_ip,
            host=normalized.host,
            rule_id=normalized.rule_id,
            message=normalized.message,
            original_fields_json=normalized.original_fields_json,
        )
        try:
            with db.session.begin_nested():
                db.session.add(event)
                db.session.flush()
        except IntegrityError:
            duplicates += 1
            continue
        accepted += 1
        origins[normalized.origin] += 1
        inserted_ids.append(event.id)

    run_origin = next(iter(origins)) if len(origins) == 1 else ("mixed" if origins else "unknown")
    run = IngestionRun(
        source_name=source_name[:128],
        origin=run_origin,
        accepted=accepted,
        rejected=rejected,
        skipped=skipped,
        duplicates=duplicates,
        errors_json=json.dumps(errors, ensure_ascii=False),
    )
    db.session.add(run)
    audit_entry = audit(
        "ingestion_run",
        "pending",
        "ingestion.completed",
        {"source": source_name[:128], "accepted": accepted, "rejected": rejected,
         "skipped": skipped, "duplicates": duplicates, "origin": run_origin},
    )
    db.session.flush()
    audit_entry.entity_id = str(run.id)
    db.session.commit()

    current_app.logger.info(
        "ingestion.completed",
        extra={"bluewatch": {"run_id": run.id, "accepted": accepted, "rejected": rejected,
                             "skipped": skipped, "duplicates": duplicates}},
    )
    return {
        "run_id": run.id,
        "accepted": accepted,
        "rejected": rejected,
        "skipped": skipped,
        "duplicates": duplicates,
        "errors": errors,
        "event_ids": inserted_ids,
        "origin": run_origin,
        "source": source_name,
    }






