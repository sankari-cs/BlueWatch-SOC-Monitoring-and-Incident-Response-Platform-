"""Timestamp parsing and versioned event normalization."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ValidationError(ValueError):
    """An input record cannot be safely normalized."""


@dataclass(frozen=True)
class NormalizedEvent:
    event_uid: str
    schema_version: str
    source_name: str
    source_identifier: str | None
    origin: str
    occurred_at: datetime
    event_type: str
    outcome: str | None
    username: str | None
    source_ip: str | None
    host: str | None
    rule_id: str | None
    message: str | None
    original_fields_json: str


def _reject_json_constant(value: str):
    raise ValueError(f"non-standard JSON constant {value}")


def _json_loads(value: str):
    return json.loads(value, parse_constant=_reject_json_constant)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("timestamp is required as an ISO 8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError("timestamp is not a valid ISO 8601 value") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("timestamp must include a timezone offset")
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _optional_string(value: Any, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string when provided")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > limit:
        raise ValidationError(f"{field} exceeds {limit} characters")
    return normalized


def _nested(record: dict, *path: str) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def normalize_record(record: Any) -> NormalizedEvent:
    """Map a documented BlueWatch v1 record or Wazuh alert to normalized v1."""
    if not isinstance(record, dict):
        raise ValidationError("record must be a JSON object")

    wrapper_source = record.get("__bluewatch_source")
    if wrapper_source in {"wazuh-indexer", "wazuh-indexer-export"}:
        original_record = record.get("__bluewatch_record")
        if not isinstance(original_record, dict):
            raise ValidationError("Wazuh wrapper record is malformed")
        wrapper_id = record.get("__bluewatch_source_id")
        record = original_record
    else:
        original_record = record
        wrapper_source = None
        wrapper_id = None

    is_wazuh = wrapper_source is not None or (isinstance(record.get("rule"), dict) and "timestamp" in record)
    if is_wazuh:
        source_name = _optional_string(wrapper_source or record.get("_source_name", "wazuh"), "source", 128)
        source_identifier = wrapper_id if wrapper_id is not None else record.get("_wazuh_alert_id", record.get("id"))
        timestamp = record.get("timestamp")
        event_type = "wazuh_alert"
        outcome = record.get("outcome", _nested(record, "data", "outcome"))
        username = (
            _nested(record, "data", "dstuser")
            or _nested(record, "data", "srcuser")
            or _nested(record, "data", "user")
        )
        source_ip = _nested(record, "data", "srcip") or _nested(record, "data", "src_ip")
        host = _nested(record, "agent", "name")
        rule_id = _nested(record, "rule", "id")
        message = _nested(record, "rule", "description")
        origin = "imported"
    else:
        if record.get("schema_version", "1") != "1":
            raise ValidationError("unsupported event schema_version; expected 1")
        source_name = _optional_string(record.get("source"), "source", 128)
        if source_name is None:
            raise ValidationError("source is required")
        source_identifier = record.get("source_id", record.get("id"))
        timestamp = record.get("timestamp")
        event_type = _optional_string(record.get("event_type"), "event_type", 80)
        if event_type is None:
            raise ValidationError("event_type is required")
        outcome = record.get("outcome")
        username = record.get("username", record.get("user"))
        source_ip = record.get("source_ip")
        host = record.get("host")
        rule_id = record.get("rule_id")
        message = record.get("message")
        origin = record.get("origin", "imported")

    if not isinstance(source_identifier, (str, int)) or isinstance(source_identifier, bool):
        if source_identifier is not None:
            raise ValidationError("source_id must be a string or integer")
    source_identifier = str(source_identifier) if source_identifier is not None else None
    if source_identifier is not None and len(source_identifier) > 255:
        raise ValidationError("source_id exceeds 255 characters")
    if not source_name:
        raise ValidationError("source is required")

    parsed_time = parse_timestamp(timestamp)
    event_type = _optional_string(event_type, "event_type", 80)
    if not event_type:
        raise ValidationError("event_type is required")
    event_type = event_type.lower()
    outcome = _optional_string(outcome, "outcome", 16)
    if outcome is not None:
        outcome = outcome.lower()
        if outcome not in {"success", "failure", "unknown"}:
            raise ValidationError("outcome must be success, failure, or unknown")
    if origin not in {"imported", "synthetic"}:
        raise ValidationError("origin must be imported or synthetic")

    normalized_username = _optional_string(username, "username", 255)
    normalized_host = _optional_string(host, "host", 255)
    normalized_rule_id = _optional_string(rule_id, "rule_id", 128)
    normalized_message = _optional_string(message, "message", 4096)
    normalized_ip = _optional_string(source_ip, "source_ip", 64)
    if normalized_ip is not None:
        try:
            normalized_ip = ipaddress.ip_address(normalized_ip).compressed
        except ValueError as exc:
            raise ValidationError("source_ip must be a valid IPv4 or IPv6 address") from exc

    if not is_wazuh:
        fields = record.get("fields", {})
        if not isinstance(fields, dict):
            raise ValidationError("fields must be a JSON object when provided")

    identity = {"source": source_name, "source_id": source_identifier}
    if source_identifier is None:
        identity["record"] = record
    event_uid = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return NormalizedEvent(
        event_uid=event_uid,
        schema_version="1",
        source_name=source_name,
        source_identifier=source_identifier,
        origin=origin,
        occurred_at=parsed_time,
        event_type=event_type,
        outcome=outcome,
        username=normalized_username,
        source_ip=normalized_ip,
        host=normalized_host,
        rule_id=normalized_rule_id,
        message=normalized_message,
        original_fields_json=canonical_json(original_record),
    )


def parse_upload(filename: str, payload: bytes, max_records: int, max_line_bytes: int):
    """Decode JSON/JSONL without saving or executing uploaded content."""
    suffix = Path(filename or "").suffix.lower()
    if suffix not in {".json", ".jsonl", ".ndjson"}:
        raise ValidationError("upload must be a .json, .jsonl, or .ndjson file")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("upload must be UTF-8 encoded") from exc

    records: list[dict] = []
    errors: list[dict] = []
    skipped = 0
    if suffix in {".jsonl", ".ndjson"}:
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                skipped += 1
                continue
            if len(line.encode("utf-8")) > max_line_bytes:
                errors.append({"record": line_no, "error": "line exceeds size limit"})
                continue
            try:
                item = _json_loads(line)
            except (json.JSONDecodeError, ValueError, RecursionError):
                errors.append({"record": line_no, "error": "malformed JSON"})
                continue
            if not isinstance(item, dict):
                errors.append({"record": line_no, "error": "record must be a JSON object"})
                continue
            records.append(item)
    else:
        try:
            root = _json_loads(text)
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise ValidationError("upload is not valid JSON") from exc
        if isinstance(root, list):
            records = [item for item in root if isinstance(item, dict)]
            errors.extend(
                {"record": i, "error": "record must be a JSON object"}
                for i, item in enumerate(root, start=1)
                if not isinstance(item, dict)
            )
        elif isinstance(root, dict) and isinstance(root.get("events"), list):
            records = [item for item in root["events"] if isinstance(item, dict)]
            errors.extend(
                {"record": i, "error": "record must be a JSON object"}
                for i, item in enumerate(root["events"], start=1)
                if not isinstance(item, dict)
            )
        elif isinstance(root, dict) and isinstance(_nested(root, "hits", "hits"), list):
            for i, hit in enumerate(_nested(root, "hits", "hits"), start=1):
                if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                    errors.append({"record": i, "error": "Wazuh search hit is malformed"})
                    continue
                source = dict(hit["_source"])
                source["_wazuh_alert_id"] = hit.get("_id")
                source["_source_name"] = "wazuh-indexer-export"
                records.append({"__bluewatch_source": "wazuh-indexer-export",
                                "__bluewatch_source_id": hit.get("_id"),
                                "__bluewatch_record": hit["_source"]})
        elif isinstance(root, dict):
            records = [root]
        else:
            raise ValidationError("JSON root must be an object or array")

    if len(records) + len(errors) > max_records:
        raise ValidationError(f"upload exceeds the {max_records} record limit")
    return records, skipped, errors





