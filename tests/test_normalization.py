from datetime import datetime, timezone

import pytest

from app.services.normalization import ValidationError, normalize_record, parse_timestamp


def record(**overrides):
    value = {
        "schema_version": "1", "source": "auth-test", "source_id": "evt-1",
        "timestamp": "2026-10-27T10:00:00+05:30", "event_type": "authentication",
        "outcome": "failure", "username": "alice", "source_ip": "203.0.113.4",
        "host": "host-a", "fields": {"extra": "kept"},
    }
    value.update(overrides)
    return value


def test_timestamp_offsets_convert_to_utc_naive():
    value = parse_timestamp("2026-10-27T10:00:00+05:30")
    assert value == datetime(2026, 10, 27, 4, 30)
    assert value.tzinfo is None


def test_timestamp_z_is_accepted_and_naive_timestamp_is_rejected():
    assert parse_timestamp("2026-10-27T10:00:00Z") == datetime(2026, 10, 27, 10)
    with pytest.raises(ValidationError, match="timezone offset"):
        parse_timestamp("2026-10-27T10:00:00")


def test_normalization_preserves_optional_missing_fields_and_original_record():
    source = record(username=None, source_ip=None, outcome=None)
    normalized = normalize_record(source)
    assert normalized.username is None
    assert normalized.source_ip is None
    assert normalized.outcome is None
    assert '"extra":"kept"' in normalized.original_fields_json
    assert normalized.source_identifier == "evt-1"


def test_invalid_timestamp_outcome_and_ip_are_rejected():
    with pytest.raises(ValidationError, match="timestamp"):
        normalize_record(record(timestamp="yesterday"))
    with pytest.raises(ValidationError, match="outcome"):
        normalize_record(record(outcome="maybe"))
    with pytest.raises(ValidationError, match="IPv4 or IPv6"):
        normalize_record(record(source_ip="attacker.example"))


def test_unsupported_schema_and_non_object_are_rejected():
    with pytest.raises(ValidationError, match="unsupported"):
        normalize_record(record(schema_version="9"))
    with pytest.raises(ValidationError, match="JSON object"):
        normalize_record([1, 2])


def test_wazuh_alert_mapping_keeps_id_and_does_not_infer_outcome():
    raw = {
        "_wazuh_alert_id": "alert-1", "timestamp": "2026-10-27T10:00:00.000Z",
        "rule": {"id": "5710", "description": "Synthetic ssh alert", "level": 5},
        "agent": {"id": "004", "name": "demo-host"},
        "data": {"srcip": "2001:db8::1", "dstuser": "demo"},
    }
    normalized = normalize_record(raw)
    assert normalized.source_name == "wazuh"
    assert normalized.source_identifier == "alert-1"
    assert normalized.event_type == "wazuh_alert"
    assert normalized.outcome is None
    assert normalized.source_ip == "2001:db8::1"
    assert normalized.rule_id == "5710"
