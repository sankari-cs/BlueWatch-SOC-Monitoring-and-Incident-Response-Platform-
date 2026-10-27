# BlueWatch SOC Platform

BlueWatch is a local-first SOC monitoring and incident investigation application built with Flask, SQLAlchemy, SQLite, server-rendered HTML, and vanilla CSS. It imports validated event exports, preserves source evidence, evaluates explainable authentication rules, and supports analyst triage, correlation, cases, response documentation, audit history, and evidence-backed HTML reports.

This is a local demo and interview project. It is not a production SIEM, does not confirm compromise, and never performs disruptive containment or remediation.

## Current capabilities

- Validates JSON, JSONL, and NDJSON exports in memory; enforces a 5 MB upload limit, 10,000-record limit, record-size limits, and strict UTF-8 JSON parsing.
- Supports the BlueWatch normalized event schema v1, Wazuh `alerts.json` style records, Wazuh Indexer search-result exports, and an explicitly labeled synthetic training fixture.
- Converts timezone-aware timestamps to UTC, retains original source fields and identifiers, fingerprints events for safe retry, and reports accepted, rejected, skipped, and duplicate records.
- Runs two explainable authentication detections: repeated failures and failures followed by success. Rules include versions, required fields, configured thresholds, severity, false-positive limits, and ATT&CK references.
- Supports alert filtering, evidence review, acknowledgement, assignment, escalation, investigation, false-positive closure with rationale, and resolution.
- Correlates alerts only when at least two recorded entity fields match within a configurable time window. A matching username or IP by itself is insufficient.
- Supports case ownership, severity, alert links, analyst notes, status transitions, evidence timeline, proposed response actions, approval records, and outcome notes.
- Builds HTML incident reports from stored case, alert, and event records. Reports include evidence references, entity summaries, rule reasoning, notes, approvals, limitations, and closure details.
- Provides a read-only, optional Wazuh Indexer pull integration using HTTPS, Basic authentication, certificate verification, timeouts, bounded retries, and bounded `search_after` pagination.
- Keeps synthetic events labeled and counted separately from imported telemetry. No sample data is automatically loaded.

## Architecture and data flow

```text
Validated export or optional Wazuh Indexer search
                     |
                     v
       In-memory parser and schema validation
                     |
                     v
 UTC normalization + source provenance + deduplication
                     |
                     v
 SQLite events -> versioned detection engine -> alerts
                                          |              |
                                          v              v
                                   correlations      analyst triage
                                          |              |
                                          +-----> incident cases
                                                       |
                                   notes, evidence, response approvals
                                                       |
                                                       v
                                      audit history + HTML report
```

The Flask application factory is in `app/__init__.py`; SQLAlchemy models are in `app/models.py`; ingestion, normalization, detection, correlation, reporting, and Wazuh access are separate services under `app/services/`. Database schema changes use Flask-Migrate/Alembic. The web interface is server-rendered from `app/templates/` and styled locally from `app/static/style.css`.

## Windows 10/11 setup (PowerShell)

Run from the repository root:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` before running. Set `BLUEWATCH_SECRET_KEY` to a fresh value. Generate one with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Apply the checked-in database migrations and start the local server:

```powershell
python -m flask --app run.py db upgrade
python -m flask --app run.py run
```

Flask binds to `127.0.0.1:5000` by default. Open `http://127.0.0.1:5000`. The health endpoint is `http://127.0.0.1:5000/health`. The default database is `instance/bluewatch.sqlite3`; `.env` and database files are excluded from Git.

If PowerShell blocks environment activation, use a process-scoped policy for that terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Import events

Open **Data ingestion** and select a `.json`, `.jsonl`, or `.ndjson` file. Accepted records are normalized, deduplicated, stored with original fields, and evaluated by the detection engine. Blank JSONL lines count as skipped. Malformed or invalid records count as rejected. Duplicate fingerprints count separately and are not stored again. Validation errors are capped in the displayed feedback so a large bad file cannot flood the interface.

A synthetic training fixture is available as an explicit action on the ingestion page. It uses documentation-only IP space and is marked `synthetic`; the app never imports it on startup. Do not treat this fixture as real telemetry.

The full input contract and examples are in [docs/event-schema-v1.md](docs/event-schema-v1.md).

## Investigate and report

1. Review the overview metrics; they come from database queries.
2. Search events in **Investigation** or filter alerts in **Alerts**.
3. Open an alert to review its exact evidence, reasoning, rule version, source references, and correlation criteria.
4. Record an allowed status transition, assignment, and rationale. False-positive or resolved alert states require a rationale.
5. Create a case, link alerts, assign an owner, add notes, and document proposed response actions.
6. Record approver name and rationale before marking a response action approved. Record an outcome before marking it completed.
7. Open **Reports** and view the case HTML report. Use the browser's print function to save a local PDF if needed.
8. Review **Audit history** for recorded changes.

BlueWatch does not execute response actions. Account disabling, host isolation, and firewall changes must be performed through an organization's approved tools and procedures by authorized personnel.

## Detection rules and false positives

Rules are defined in `rules/detection_rules.json`; implementation is in `app/services/detection.py`.

- `BW-AUTH-001` groups explicit failed authentication events for the same source, origin, username, and source IP. The default threshold is 5 events in 10 minutes. Both identity fields and a timezone-aware timestamp are required.
- `BW-AUTH-002` finds one or more explicit failures followed by an explicit success for the same source, origin, username, and source IP within 15 minutes.

Thresholds and windows can be changed in `.env`. Detection severity is the rule's configured value. Password managers, mistyped passwords, shared NAT addresses, stale service credentials, incomplete records, and normal user activity can cause false positives. Alerts are investigative leads, not proof of compromise. ATT&CK references used here are [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) and [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/).

## Wazuh configuration

The preferred first integration path is a validated export. The optional live connector queries the **Wazuh Indexer** alert index with a read-only search request; it does not use the Wazuh Manager API to fetch alert documents. Wazuh documents `wazuh-alerts-*` as the index pattern for alerts and demonstrates querying it through the Indexer API ([index descriptions](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html), [alert search use case](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)).

Set these values in the local `.env`:

```text
WAZUH_INDEXER_URL=https://your-indexer.example:9200
WAZUH_INDEXER_USERNAME=read_only_account
WAZUH_INDEXER_PASSWORD=stored_outside_source_control
WAZUH_INDEX_PATTERN=wazuh-alerts-*
WAZUH_CA_BUNDLE=C:\path\to\trusted-ca.pem
WAZUH_TIMEOUT_SECONDS=10
WAZUH_PAGE_SIZE=100
WAZUH_MAX_PAGES=10
```

Use an Indexer account restricted to read/search on the alert indices. TLS certificate verification is on by default; provide the trusted CA bundle for a private certificate. The connector verifies the URL scheme, restricts the index pattern, makes read-only search calls, uses timeouts and bounded retries, and stops at a configurable page cap. Re-running a pull is safe because event IDs/fingerprints are deduplicated. A capped pull may require another sync. Never set certificate verification off to bypass a certificate problem.

No live Wazuh instance or credentials were available in this workspace, so the connector has not been tested against an actual Wazuh deployment. The optional integration should be treated as unverified until tested against an authorized accessible instance with a read-only account. The UI does not display credentials or response bodies.

## Tests

With the virtual environment active:

```powershell
python -m pytest -q
```

The tests use temporary in-memory SQLite databases and mocked Wazuh HTTP responses; they do not require live Wazuh, do not send network requests, and do not contain real logs or secrets.

## Configuration and local security

- The app rejects non-loopback client addresses and binds to localhost by default. It has a single local analyst identity, not user authentication or multi-user role-based access.
- Every POST form is protected by a session CSRF token. Session cookies are HttpOnly and SameSite=Lax. Set `BLUEWATCH_COOKIE_SECURE=true` only when serving over HTTPS.
- A random process-local secret is generated if `BLUEWATCH_SECRET_KEY` is not set; sessions then expire when the process restarts. Set a secret in `.env` for stable local sessions.
- SQLAlchemy uses bound query parameters. Jinja templates autoescape user-provided data. Uploads are parsed in memory, restricted by size/type, and never executed or saved under a user-controlled path.
- Logs include structured operational metadata and counts, not raw event payloads or credentials. SQLite files are local and unencrypted.
- This application has not received a production security review. Do not expose it to a network or load sensitive production telemetry without an independent security and privacy review.

## Known limitations

- Authentication outcome normalization is deliberately strict; missing outcome fields do not become success or failure.
- Current detections cover two authentication patterns, not all attack behaviors. The rule logic is local Python and its metadata is versioned in JSON.
- Correlation is intentionally conservative and uses only matching host, username, and source-IP combinations; relationships are leads, not attribution.
- The Wazuh Indexer integration is optional and unverified against a live deployment. Supported Wazuh exports can be imported without connecting to an API.
- There is no multi-user authentication, role management, PDF-generation service, automatic containment, or production deployment profile.
