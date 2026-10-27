# BlueWatch normalized event schema v1

BlueWatch accepts UTF-8 JSON Lines (`.jsonl`/`.ndjson`) with one JSON object per line, JSON arrays of event objects, a JSON object with an `events` array, Wazuh `alerts.json` style records, or a Wazuh Indexer `_search` response containing `hits.hits`.

## BlueWatch input fields

Required on every event:

| Field | Type | Meaning |
|---|---|---|
| `source` | string | Name of the originating system or export. |
| `timestamp` | ISO 8601 string with timezone | Event occurrence time. Converted to UTC for storage. Naive timestamps are rejected because their timezone is unknown. |
| `event_type` | string | Event class. Use `authentication` for the included authentication rules. |

Optional fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Must be `1` when provided. |
| `source_id` or `id` | string/integer | Original source identifier. Used with source name for deduplication. |
| `origin` | string | `imported` by default, or `synthetic` for clearly labeled test data. |
| `outcome` | string | `success`, `failure`, or `unknown`; omitted means no outcome was present. |
| `username` or `user` | string | Explicit account field. |
| `source_ip` | IP address | IPv4 or IPv6 source address. |
| `host` | string | Explicit host name. |
| `rule_id` | string | Source rule identifier, if present. |
| `message` | string | Source message, if present. |
| `fields` | object | Additional source fields; the full original record is preserved regardless. |

Example:

```json
{"schema_version":"1","source":"linux-auth","source_id":"evt-001","timestamp":"2026-10-27T10:00:00Z","event_type":"authentication","outcome":"failure","username":"analyst","source_ip":"203.0.113.5","host":"server-01","message":"login failed","fields":{"facility":"sshd"}}
```

## Validation and provenance

- The parser requires UTF-8 and JSON objects per record. Files are processed in memory only.
- Timestamp offsets are mandatory. Values are converted to UTC; the original timestamp remains in `original_fields_json`.
- Optional fields remain `NULL` when absent. BlueWatch does not fill in missing identities, outcomes, timestamps, or source IDs.
- Source records are retained as JSON alongside normalized columns. Each event has a schema version, source name, original source identifier, ingestion timestamp, and stable deduplication fingerprint.
- If no source identifier is supplied, a fingerprint of the source and canonical original record is used. Repeating that record is counted as a duplicate.
- Import-run counters report accepted, rejected, skipped blank lines, and duplicates. Rejection feedback contains record positions and validation messages, not uploaded file contents.
- An upload can contain both origins; each event remains individually labeled, and synthetic and imported events are not combined by detection rules.

## Wazuh exports

Wazuh alert documents with `timestamp`, `rule`, and optional `agent`/`data` objects are mapped to source `wazuh` or `wazuh-indexer-export`. Rule descriptions, agent names, selected explicit user/IP fields, Wazuh alert IDs, and original documents are retained. A Wazuh rule level is not treated as BlueWatch severity. Authentication outcomes are recognized only when the source explicitly provides one of the allowed `outcome` values.
