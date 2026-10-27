"""Server-rendered BlueWatch analyst workflows."""

from __future__ import annotations

import json
import secrets

from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy import or_

from .extensions import db
from .models import Alert, AuditLog, Case, CaseNote, Correlation, Event, IngestionRun, ResponseAction, utcnow
from .services.common import audit
from .services.correlation import correlations_for_alert
from .services.detection import load_rules, run_detections
from .services.ingestion import ingest_records, ingest_upload
from .services.normalization import ValidationError
from .services.reports import build_case_report
from .services.wazuh import WazuhIndexerClient, WazuhIntegrationError

bp = Blueprint("web", __name__)
SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALERT_TRANSITIONS = {
    "new": {"acknowledged", "assigned", "investigating", "escalated", "false_positive", "resolved"},
    "acknowledged": {"assigned", "investigating", "escalated", "false_positive", "resolved"},
    "assigned": {"acknowledged", "investigating", "escalated", "false_positive", "resolved"},
    "investigating": {"acknowledged", "assigned", "escalated", "false_positive", "resolved"},
    "escalated": {"acknowledged", "assigned", "investigating", "false_positive", "resolved"},
    "false_positive": {"investigating"},
    "resolved": {"investigating"},
}
CASE_TRANSITIONS = {
    "open": {"investigating", "resolved", "closed"},
    "investigating": {"resolved", "closed"},
    "resolved": {"closed"},
    "closed": set(),
}


def _page_arg() -> int:
    return max(1, request.args.get("page", 1, type=int) or 1)


def _actor() -> str:
    return current_app.config.get("ANALYST_NAME", "local-analyst")


def _find_case(case_id: int) -> Case:
    case = db.session.get(Case, case_id)
    if case is None:
        abort(404)
    return case


def _find_alert(alert_id: int) -> Alert:
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        abort(404)
    return alert


def _safe_commit(message: str) -> None:
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("database.commit_failed", extra={"bluewatch": {"operation": message}})
        flash("The change could not be saved. No change was recorded.", "error")
        raise


@bp.get("/")
def overview():
    counts = {
        "events": Event.query.count(),
        "imported_events": Event.query.filter_by(origin="imported").count(),
        "synthetic_events": Event.query.filter_by(origin="synthetic").count(),
        "open_alerts": Alert.query.filter(Alert.status.notin_(["resolved", "false_positive"])).count(),
        "cases_open": Case.query.filter(Case.status.in_(["open", "investigating"])).count(),
        "incidents_closed": Case.query.filter(Case.status.in_(["resolved", "closed"])).count(),
    }
    severity_counts = {name: Alert.query.filter_by(severity=name).count() for name in sorted(SEVERITIES)}
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(8).all()
    recent_runs = IngestionRun.query.order_by(IngestionRun.created_at.desc()).limit(5).all()
    return render_template("overview.html", counts=counts, severity_counts=severity_counts,
                           recent_alerts=recent_alerts, recent_runs=recent_runs)


@bp.route("/ingest", methods=["GET", "POST"])
def ingest():
    if request.method == "POST":
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose a JSON, JSONL, or NDJSON export to import.", "error")
            return redirect(url_for("web.ingest"))
        payload = upload.stream.read(current_app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(payload) > current_app.config["MAX_CONTENT_LENGTH"]:
            abort(413)
        try:
            result = ingest_upload(upload.filename, payload)
            created = run_detections()
        except ValidationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("web.ingest"))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("ingestion.failed")
            flash("Import failed safely. Review the application log for a sanitized error entry.", "error")
            return redirect(url_for("web.ingest"))
        flash(
            f"Import complete: {result['accepted']} accepted, {result['rejected']} rejected, "
            f"{result['skipped']} skipped, {result['duplicates']} duplicates; {len(created)} new alert(s).",
            "success",
        )
        return redirect(url_for("web.ingest", run=result["run_id"]))

    run_id = request.args.get("run", type=int)
    run = db.session.get(IngestionRun, run_id) if run_id else None
    return render_template("ingest.html", result=run, errors=json.loads(run.errors_json) if run else [])


@bp.post("/ingest/sample")
def ingest_sample():
    path = Path(current_app.root_path).parent / "fixtures" / "synthetic_auth_burst.jsonl"
    try:
        result = ingest_upload(path.name, path.read_bytes(), source_name="synthetic-lab")
        created = run_detections()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("synthetic_fixture.import_failed")
        flash("Synthetic sample import failed.", "error")
        return redirect(url_for("web.ingest"))
    flash(
        f"Synthetic fixture imported: {result['accepted']} accepted, {result['duplicates']} duplicates; "
        f"{len(created)} new alert(s). Synthetic data remains labeled separately.",
        "success",
    )
    return redirect(url_for("web.ingest", run=result["run_id"]))


@bp.get("/events")
def investigation():
    query = Event.query
    term = request.args.get("q", "").strip()[:160]
    origin = request.args.get("origin", "")
    if term:
        like = f"%{term}%"
        query = query.filter(or_(Event.username.ilike(like), Event.host.ilike(like), Event.source_ip.ilike(like),
                                 Event.source_name.ilike(like), Event.message.ilike(like), Event.rule_id.ilike(like)))
    if origin in {"imported", "synthetic"}:
        query = query.filter_by(origin=origin)
    page = query.order_by(Event.occurred_at.desc(), Event.id.desc()).paginate(
        page=_page_arg(), per_page=25, error_out=False
    )
    return render_template("investigation.html", page=page, term=term, origin=origin)


@bp.get("/alerts")
def alerts():
    query = Alert.query
    term = request.args.get("q", "").strip()[:160]
    status = request.args.get("status", "")
    severity = request.args.get("severity", "")
    if term:
        like = f"%{term}%"
        query = query.filter(or_(Alert.title.ilike(like), Alert.summary.ilike(like), Alert.rule_id.ilike(like),
                                 Alert.username.ilike(like), Alert.source_ip.ilike(like), Alert.host.ilike(like),
                                 Alert.source_name.ilike(like)))
    if status:
        query = query.filter_by(status=status)
    if severity in SEVERITIES:
        query = query.filter_by(severity=severity)
    page = query.order_by(Alert.created_at.desc(), Alert.id.desc()).paginate(
        page=_page_arg(), per_page=current_app.config["ALERTS_PER_PAGE"], error_out=False
    )
    return render_template("alerts.html", page=page, term=term, status=status, severity=severity)


@bp.get("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    alert = _find_alert(alert_id)
    links = correlations_for_alert(alert.id)
    related = []
    for link in links:
        peer = link.right_alert if link.left_alert_id == alert.id else link.left_alert
        related.append((peer, json.loads(link.criteria_json)))
    allowed = sorted(ALERT_TRANSITIONS.get(alert.status, set()))
    return render_template("alert_detail.html", alert=alert, related=related, allowed_statuses=allowed,
                           mitre=json.loads(alert.mitre_json or "[]"))


@bp.post("/alerts/<int:alert_id>/update")
def update_alert(alert_id: int):
    alert = _find_alert(alert_id)
    status = request.form.get("status", "").strip()
    assigned_to = request.form.get("assigned_to", "").strip()[:80]
    rationale = request.form.get("rationale", "").strip()[:4000]
    previous_status = alert.status
    changes = {}
    if status:
        if status not in ALERT_TRANSITIONS.get(alert.status, set()):
            flash("That alert status transition is not allowed.", "error")
            return redirect(url_for("web.alert_detail", alert_id=alert.id))
        if status in {"false_positive", "resolved"} and not rationale:
            flash("A closure rationale is required for false-positive or resolved status.", "error")
            return redirect(url_for("web.alert_detail", alert_id=alert.id))
        changes["status"] = [alert.status, status]
        alert.status = status
        if status in {"false_positive", "resolved"}:
            changes["closure_rationale"] = [alert.closure_rationale, rationale]
            alert.closure_rationale = rationale
        elif status == "investigating" and alert.closure_rationale:
            changes["closure_rationale"] = [alert.closure_rationale, None]
            alert.closure_rationale = None
    if assigned_to and assigned_to != (alert.assigned_to or ""):
        if len(assigned_to) < 2:
            flash("Assignment must contain at least two characters.", "error")
            return redirect(url_for("web.alert_detail", alert_id=alert.id))
        changes["assigned_to"] = [alert.assigned_to, assigned_to]
        alert.assigned_to = assigned_to
        if not status and alert.status not in {"false_positive", "resolved"}:
            alert.status = "assigned"
            changes["status"] = [previous_status, "assigned"]
    if not changes:
        flash("No alert changes were submitted.", "error")
        return redirect(url_for("web.alert_detail", alert_id=alert.id))
    alert.updated_at = utcnow()
    audit("alert", alert.id, "alert.updated", changes)
    db.session.commit()
    flash("Alert update recorded in the audit history.", "success")
    return redirect(url_for("web.alert_detail", alert_id=alert.id))


@bp.get("/incidents")
def incidents():
    query = Case.query
    status = request.args.get("status", "")
    term = request.args.get("q", "").strip()[:160]
    if status in {"open", "investigating", "resolved", "closed"}:
        query = query.filter_by(status=status)
    if term:
        like = f"%{term}%"
        query = query.filter(or_(Case.case_number.ilike(like), Case.title.ilike(like), Case.owner.ilike(like)))
    page = query.order_by(Case.updated_at.desc(), Case.id.desc()).paginate(page=_page_arg(), per_page=20, error_out=False)
    open_alerts = Alert.query.filter(Alert.status.notin_(["resolved", "false_positive"])).order_by(Alert.created_at.desc()).limit(100).all()
    return render_template("incidents.html", page=page, status=status, term=term, open_alerts=open_alerts)


@bp.post("/incidents")
def create_case():
    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "medium").strip()
    owner = request.form.get("owner", _actor()).strip()[:80]
    alert_ids = request.form.getlist("alert_ids")
    if not title or len(title) > 255 or severity not in SEVERITIES:
        flash("Provide a case title under 256 characters and a valid severity.", "error")
        return redirect(url_for("web.incidents"))
    try:
        ids = [int(value) for value in alert_ids]
    except ValueError:
        flash("Invalid alert selection.", "error")
        return redirect(url_for("web.incidents"))
    linked = Alert.query.filter(Alert.id.in_(ids)).all() if ids else []
    if len(linked) != len(set(ids)):
        flash("One or more selected alerts do not exist.", "error")
        return redirect(url_for("web.incidents"))
    origins = {event.origin for alert in linked for event in alert.events}
    if len(origins) > 1:
        flash("A case cannot mix synthetic and imported alert evidence. Create separate cases.", "error")
        return redirect(url_for("web.incidents"))
    case = Case(case_number=f"BW-{utcnow():%Y%m%d}-{secrets.token_hex(3).upper()}",
                title=title, severity=severity, owner=owner or None, alerts=linked)
    db.session.add(case)
    db.session.flush()
    audit("case", case.id, "case.created", {"case_number": case.case_number, "severity": severity,
                                               "linked_alert_ids": [alert.id for alert in linked]})
    db.session.commit()
    flash(f"Case {case.case_number} created.", "success")
    return redirect(url_for("web.case_detail", case_id=case.id))


@bp.get("/incidents/<int:case_id>")
def case_detail(case_id: int):
    case = _find_case(case_id)
    linked_ids = [alert.id for alert in case.alerts]
    available_alerts = Alert.query.filter(~Alert.id.in_(linked_ids)).order_by(Alert.created_at.desc()).limit(200).all() if linked_ids else Alert.query.order_by(Alert.created_at.desc()).limit(200).all()
    history = AuditLog.query.filter_by(entity_type="case", entity_id=str(case.id)).order_by(AuditLog.created_at.asc()).all()
    return render_template("case_detail.html", case=case, available_alerts=available_alerts, history=history)


@bp.post("/incidents/<int:case_id>/status")
def update_case(case_id: int):
    case = _find_case(case_id)
    status = request.form.get("status", "").strip()
    owner = request.form.get("owner", case.owner or "").strip()[:80]
    severity = request.form.get("severity", case.severity).strip()
    rationale = request.form.get("resolution_rationale", "").strip()[:4000]
    changes = {}
    if status:
        if status not in CASE_TRANSITIONS.get(case.status, set()):
            flash("That case status transition is not allowed.", "error")
            return redirect(url_for("web.case_detail", case_id=case.id))
        if status in {"resolved", "closed"} and not rationale:
            flash("A resolution rationale is required to resolve or close a case.", "error")
            return redirect(url_for("web.case_detail", case_id=case.id))
        changes["status"] = [case.status, status]
        case.status = status
        if status in {"resolved", "closed"}:
            changes["resolution_rationale"] = [case.resolution_rationale, rationale]
            case.closed_at = utcnow()
            case.resolution_rationale = rationale
        else:
            case.closed_at = None
            case.resolution_rationale = None
    if severity not in SEVERITIES:
        flash("Invalid case severity.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    if severity != case.severity:
        changes["severity"] = [case.severity, severity]
        case.severity = severity
    if owner != (case.owner or ""):
        changes["owner"] = [case.owner, owner or None]
        case.owner = owner or None
    if not changes:
        flash("No case changes were submitted.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    case.updated_at = utcnow()
    audit("case", case.id, "case.updated", changes)
    db.session.commit()
    flash("Case update recorded in the audit history.", "success")
    return redirect(url_for("web.case_detail", case_id=case.id))


@bp.post("/incidents/<int:case_id>/alerts")
def link_alert(case_id: int):
    case = _find_case(case_id)
    alert_id = request.form.get("alert_id", type=int)
    alert = db.session.get(Alert, alert_id) if alert_id else None
    if alert is None:
        flash("Choose an existing alert.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    existing_origins = {event.origin for linked in case.alerts for event in linked.events}
    new_origins = {event.origin for event in alert.events}
    if existing_origins and new_origins and existing_origins != new_origins:
        flash("Synthetic and imported alert evidence must remain in separate cases.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    if alert in case.alerts:
        flash("That alert is already linked to this case.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    case.alerts.append(alert)
    case.updated_at = utcnow()
    audit("case", case.id, "case.alert_linked", {"alert_id": alert.id})
    db.session.commit()
    flash("Alert linked to the case.", "success")
    return redirect(url_for("web.case_detail", case_id=case.id))


@bp.post("/incidents/<int:case_id>/notes")
def add_case_note(case_id: int):
    case = _find_case(case_id)
    body = request.form.get("body", "").strip()
    if not body or len(body) > 8000:
        flash("Note must contain 1 to 8,000 characters.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    note = CaseNote(case=case, author=_actor(), body=body)
    db.session.add(note)
    audit("case", case.id, "case.note_added", {"note_length": len(body)})
    db.session.commit()
    flash("Analyst note added.", "success")
    return redirect(url_for("web.case_detail", case_id=case.id))


@bp.post("/incidents/<int:case_id>/actions")
def add_response_action(case_id: int):
    case = _find_case(case_id)
    description = request.form.get("description", "").strip()
    if not description or len(description) > 4000:
        flash("Action description must contain 1 to 4,000 characters.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    action = ResponseAction(case=case, description=description, created_by=_actor(), status="proposed")
    db.session.add(action)
    db.session.flush()
    audit("response_action", action.id, "response_action.proposed", {"case_id": case.id})
    db.session.commit()
    flash("Response action documented as proposed. BlueWatch did not execute it.", "success")
    return redirect(url_for("web.case_detail", case_id=case.id))


@bp.post("/incidents/<int:case_id>/actions/<int:action_id>")
def update_response_action(case_id: int, action_id: int):
    case = _find_case(case_id)
    action = db.session.get(ResponseAction, action_id)
    if action is None or action.case_id != case.id:
        abort(404)
    status = request.form.get("status", "").strip()
    approval_by = request.form.get("approval_by", "").strip()[:80]
    approval_note = request.form.get("approval_note", "").strip()[:2000]
    outcome = request.form.get("outcome", "").strip()[:4000]
    allowed = {"proposed", "approved", "in_progress", "completed", "rejected"}
    transitions = {"proposed": {"approved", "rejected"}, "approved": {"in_progress", "completed", "rejected"},
                    "in_progress": {"completed", "rejected"}, "completed": set(), "rejected": set()}
    if status not in allowed or status not in transitions.get(action.status, set()):
        flash("Invalid response action status.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    if status == "rejected" and not approval_note:
        flash("Record a reason when rejecting a proposed action.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    if status == "approved" and (len(approval_by) < 2 or not approval_note):
        flash("Approval requires the approver's name and rationale.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    if status == "completed" and not (outcome or action.outcome):
        flash("Record an outcome before marking an action completed.", "error")
        return redirect(url_for("web.case_detail", case_id=case.id))
    old = action.status
    action.status = status
    if approval_by:
        action.approval_by = approval_by
        action.approval_note = approval_note
    if outcome:
        action.outcome = outcome
    action.updated_at = utcnow()
    audit("response_action", action.id, "response_action.updated", {"status": [old, status], "case_id": case.id})
    db.session.commit()
    flash("Response action documentation updated. No operational action was performed.", "success")
    return redirect(url_for("web.case_detail", case_id=case.id))


@bp.get("/rules")
def rules():
    return render_template("rules.html", rules=load_rules(), config=current_app.config)


@bp.get("/playbooks")
def playbooks():
    configured = current_app.config.get("PLAYBOOKS_PATH")
    path = Path(configured) if configured else Path(current_app.root_path).parent / "playbooks" / "playbooks.json"
    return render_template("playbooks.html", playbooks=json.loads(path.read_text(encoding="utf-8-sig")))


@bp.get("/reports")
def reports():
    page = Case.query.order_by(Case.updated_at.desc()).paginate(page=_page_arg(), per_page=20, error_out=False)
    return render_template("reports.html", page=page)


@bp.get("/reports/cases/<int:case_id>")
def case_report(case_id: int):
    case = _find_case(case_id)
    return render_template("case_report.html", report=build_case_report(case))


@bp.get("/audit")
def audit_history():
    query = AuditLog.query
    entity_type = request.args.get("entity", "")
    term = request.args.get("q", "").strip()[:120]
    if entity_type:
        query = query.filter_by(entity_type=entity_type)
    if term:
        like = f"%{term}%"
        query = query.filter(or_(AuditLog.action.ilike(like), AuditLog.actor.ilike(like), AuditLog.entity_id.ilike(like)))
    page = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).paginate(page=_page_arg(), per_page=30, error_out=False)
    return render_template("audit.html", page=page, entity_type=entity_type, term=term)


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    sync_result = None
    if request.method == "POST":
        try:
            client = WazuhIndexerClient()
            records, truncated = client.fetch_alerts()
            result = ingest_records(records, "wazuh-indexer")
            created = run_detections()
            sync_result = {**result, "new_alerts": len(created), "truncated": truncated}
            audit("integration", "wazuh-indexer", "integration.sync_completed", {
                "accepted": result["accepted"], "duplicates": result["duplicates"],
                "truncated": truncated,
            })
            db.session.commit()
            flash(
                f"Wazuh pull complete: {result['accepted']} alerts imported, {result['duplicates']} duplicates, "
                f"{len(created)} BlueWatch detections created.", "success"
            )
        except WazuhIntegrationError as exc:
            db.session.rollback()
            current_app.logger.warning("wazuh.sync_failed", extra={"bluewatch": {"reason": str(exc)}})
            flash(str(exc), "error")
        except Exception:
            db.session.rollback()
            current_app.logger.exception("wazuh.sync_failed")
            flash("Wazuh sync failed. No credentials or response data were shown.", "error")
    configured = bool(current_app.config.get("WAZUH_INDEXER_URL")
                       and current_app.config.get("WAZUH_INDEXER_USERNAME")
                       and current_app.config.get("WAZUH_INDEXER_PASSWORD"))
    return render_template("settings.html", configured=configured,
                           pattern=current_app.config.get("WAZUH_INDEX_PATTERN"),
                           ca_configured=bool(current_app.config.get("WAZUH_CA_BUNDLE")),
                           sync_result=sync_result)









