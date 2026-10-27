import json

from app.models import Event, IngestionRun
from app.services.ingestion import ingest_records, ingest_upload


def event_record(source_id="evt-1", **overrides):
    value = {
        "schema_version": "1", "source": "unit-test", "source_id": source_id,
        "timestamp": "2026-10-27T10:00:00Z", "event_type": "authentication",
        "outcome": "failure", "username": "alice", "source_ip": "203.0.113.8",
        "host": "test-host", "fields": {"safe": True},
    }
    value.update(overrides)
    return value


def test_deduplication_is_idempotent_across_retries(app):
    with app.app_context():
        first = ingest_records([event_record()], "unit-test")
        second = ingest_records([event_record()], "unit-test")
        assert first["accepted"] == 1
        assert first["duplicates"] == 0
        assert second["accepted"] == 0
        assert second["duplicates"] == 1
        assert Event.query.count() == 1
        assert IngestionRun.query.count() == 2


def test_ingestion_reports_rejected_skipped_and_duplicate_records(app):
    content = "\n".join([
        json.dumps(event_record()),
        "",
        "{not-json}",
        json.dumps(event_record(source_id="evt-2", timestamp="2026-10-27T10:00:00")),
        json.dumps(event_record()),
    ]).encode()
    with app.app_context():
        result = ingest_upload("events.jsonl", content, "test-run")
        assert result["accepted"] == 1
        assert result["rejected"] == 2
        assert result["skipped"] == 1
        assert result["duplicates"] == 1
        assert len(result["errors"]) == 2


def test_json_and_wazuh_search_export_parsing(client, app):
    export = {
        "hits": {"hits": [{"_id": "wazuh-1", "_source": {
            "timestamp": "2026-10-27T10:00:00Z", "rule": {"id": "5710", "description": "Synthetic alert"}
        }}]}
    }
    with app.app_context():
        result = ingest_upload("wazuh.json", json.dumps(export).encode())
        assert result["accepted"] == 1
    assert client.get("/events").status_code == 200


def test_unsupported_upload_type_is_rejected(app):
    from app.services.normalization import ValidationError
    import pytest
    with app.app_context(), pytest.raises(ValidationError, match="upload must be"):
        ingest_upload("events.csv", b"a,b")


def test_nonstandard_json_constant_is_rejected(app):
    content = b'{"schema_version":"1","source":"test","timestamp":"2026-10-27T10:00:00Z","event_type":"authentication","fields":{"bad":NaN}}'
    with app.app_context():
        result = ingest_upload("strict.jsonl", content)
        assert result["accepted"] == 0
        assert result["rejected"] == 1
        assert result["errors"][0]["error"] == "malformed JSON"
