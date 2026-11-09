import io
import threading
from collections import Counter
from datetime import datetime

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template, request, send_file,
                   url_for)

import config
from app import ai, dash, db, evidence, graph, pipeline, reports, scanner, settings
from app.scope import ScopeError, validate_target

bp = Blueprint("main", __name__)

PRIORITY_ORDER = dash.ORDER


def _duration(scan) -> str:
    try:
        start = datetime.fromisoformat(scan["started_at"])
        end = datetime.fromisoformat(scan["finished_at"]) if scan["finished_at"] else None
    except (TypeError, ValueError):
        return ""
    if not end:
        return ""
    secs = int((end - start).total_seconds())
    return f"{secs // 60}m {secs % 60}s"


def _completed_scan_or_redirect(scan_id):
    """Return (scan, None) for a completed scan, otherwise (None, redirect response)."""
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    if scan["status"] != "completed":
        flash("This assessment has not completed, so it has no results to analyse or report.", "error")
        return None, redirect(url_for("main.scan_detail", scan_id=scan_id))
    return scan, None


# ------------------------------------------------------------------ dashboard
@bp.get("/")
def index():
    latest = db.get_latest_completed_scan()
    data = {}
    if latest:
        data = dash.build_dashboard(db.get_findings(latest["id"]), db.get_trend())
    return render_template("index.html", latest=latest, recent=db.list_scans()[:5], **data)


@bp.get("/assessments")
def assessments():
    return render_template("assessments.html", scans=db.list_scans())


@bp.post("/scan")
def start_scan():
    raw = request.form.get("target", "")
    active = request.form.get("mode") == "active"
    confirmed = request.form.get("confirm") == "on"

    if not confirmed:
        flash("You must confirm you are authorized to test this target.", "error")
        return redirect(url_for("main.assessments"))
    try:
        target = validate_target(raw)
    except ScopeError as exc:
        db.audit("scan_rejected", raw, str(exc))
        flash(str(exc), "error")
        return redirect(url_for("main.assessments"))

    running = db.get_running_scan()
    if running:
        flash(f"Assessment #{running['id']} is still running. Wait for it to finish before starting another.", "error")
        return redirect(url_for("main.scan_detail", scan_id=running["id"]))

    mode = "active" if active else "passive"
    scan_id = db.create_scan(target, mode)
    db.audit("scan_started", target, f"scan_id={scan_id} mode={mode}")
    threading.Thread(target=pipeline.run_job, args=(scan_id, target, active), daemon=True).start()
    return redirect(url_for("main.scan_detail", scan_id=scan_id))


@bp.get("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    findings = db.get_findings(scan_id)
    counts = Counter(f["priority_label"] for f in findings)
    summary = {
        "total": len(findings),
        "counts": [(label, counts.get(label, 0)) for label in PRIORITY_ORDER],
    }
    return render_template(
        "scan.html", scan=scan, findings=findings, summary=summary, duration=_duration(scan)
    )


@bp.get("/api/scan/<int:scan_id>")
def scan_json(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    return jsonify(scan=dict(scan), findings=[dict(f) for f in db.get_findings(scan_id)])


# --------------------------------------------------------------- attack surface
@bp.get("/surface")
def surface_latest():
    latest = db.get_latest_completed_scan()
    if not latest:
        flash("Run and finish an assessment first, then the 3D attack surface will be available.", "error")
        return redirect(url_for("main.assessments"))
    return redirect(url_for("main.surface", scan_id=latest["id"]))


@bp.get("/scan/<int:scan_id>/surface")
def surface(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("surface.html", scan=scan, total=len(db.get_findings(scan_id)))


@bp.get("/api/scan/<int:scan_id>/graph")
def graph_json(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    return jsonify(graph.build_graph(scan["target"], db.get_findings(scan_id)))


# ------------------------------------------------------------------ AI analysis
@bp.get("/analysis")
def analysis_latest():
    latest = db.get_latest_completed_scan()
    if not latest:
        flash("Run and finish an assessment first, then AI analysis will be available.", "error")
        return redirect(url_for("main.assessments"))
    return redirect(url_for("main.analysis", scan_id=latest["id"]))


@bp.get("/scan/<int:scan_id>/analysis")
def analysis(scan_id):
    scan, redirect_response = _completed_scan_or_redirect(scan_id)
    if redirect_response:
        return redirect_response
    findings = db.get_findings(scan_id)
    if findings and not db.get_analyses(scan_id):
        ai.generate_rules(scan_id)  # scans that finished before this feature existed
    analyses = db.get_analyses(scan_id)
    cards = [{"g": g, "a": analyses.get(g["key"])} for g in ai.group_findings(findings)]
    return render_template(
        "analysis.html", scan=scan, cards=cards, total=len(findings),
        prog=ai.PROGRESS.get(scan_id), ai_mode=settings.get("ai_mode"), model=settings.get("ollama_model"),
    )


@bp.post("/scan/<int:scan_id>/analysis/run")
def analysis_run(scan_id):
    scan, redirect_response = _completed_scan_or_redirect(scan_id)
    if redirect_response:
        return redirect_response
    ai.generate_rules(scan_id)
    if settings.get("ai_mode") == "ollama":
        if ai.start_enhancement(scan_id):
            flash("The local AI is writing explanations. This page updates as it goes.", "ok")
        else:
            flash("The local AI is already working on this assessment.", "error")
    else:
        flash("Rules-based analysis is up to date. To add model-written explanations, switch AI mode to Local AI in Settings.", "ok")
    return redirect(url_for("main.analysis", scan_id=scan_id))


# ---------------------------------------------------------------------- reports
@bp.get("/reports")
def reports_list():
    done = [s for s in db.list_scans() if s["status"] == "completed"]
    return render_template("reports.html", scans=done, pdf_ok=reports.pdf_available())


@bp.get("/scan/<int:scan_id>/report")
def report_view(scan_id):
    scan, redirect_response = _completed_scan_or_redirect(scan_id)
    if redirect_response:
        return redirect_response
    return render_template("report.html", report=reports.build_report(scan_id), pdf_ok=reports.pdf_available())


@bp.get("/scan/<int:scan_id>/report.pdf")
def report_pdf(scan_id):
    scan, redirect_response = _completed_scan_or_redirect(scan_id)
    if redirect_response:
        return redirect_response
    if not reports.pdf_available():
        flash("PDF export needs the reportlab package. Run: pip install reportlab (you can also use Print / Save as PDF).", "error")
        return redirect(url_for("main.report_view", scan_id=scan_id))
    pdf = reports.build_pdf(reports.build_report(scan_id))
    db.audit("report_generated", scan["target"], f"scan_id={scan_id} format=pdf")
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"AEGIS-AI-report-scan-{scan_id}.pdf")


# --------------------------------------------------------------------- evidence
@bp.get("/evidence")
def evidence_page():
    done = [s for s in db.list_scans() if s["status"] == "completed"]
    return render_template("evidence.html", scans=done, exports=db.get_audit_by_action("evidence_exported", 8), result=None)


@bp.get("/scan/<int:scan_id>/evidence.zip")
def evidence_download(scan_id):
    scan, redirect_response = _completed_scan_or_redirect(scan_id)
    if redirect_response:
        return redirect_response
    data, sha = evidence.build_bundle(scan_id)
    response = send_file(io.BytesIO(data), mimetype="application/zip", as_attachment=True,
                         download_name=f"AEGIS-AI-evidence-scan-{scan_id}.zip")
    response.headers["X-Manifest-SHA256"] = sha
    return response


@bp.post("/evidence/verify")
def evidence_verify():
    upload = request.files.get("bundle")
    if not upload or not upload.filename:
        flash("Choose an evidence bundle (.zip) to verify.", "error")
        return redirect(url_for("main.evidence_page"))
    data = upload.read()
    result = evidence.verify_bundle(data)
    db.audit("evidence_verified", "", f"result={'pass' if result['ok'] else 'fail'} manifest_sha256={result['manifest_sha256'] or 'n/a'}")
    done = [s for s in db.list_scans() if s["status"] == "completed"]
    return render_template("evidence.html", scans=done, exports=db.get_audit_by_action("evidence_exported", 8), result=result)


# --------------------------------------------------------------------- settings
@bp.route("/settings", methods=["GET", "POST"], endpoint="settings")
def settings_page():
    if request.method == "POST":
        clean, errors = settings.validate(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
        else:
            changed = settings.save(clean)
            if changed:
                db.audit("settings_changed", "", "keys=" + ",".join(sorted(changed)))
            flash("Settings saved.", "ok")
        return redirect(url_for("main.settings"))
    return render_template(
        "settings.html", s=settings.get_all(), allowed=sorted(config.ALLOWED_TARGETS),
        chain_ok=db.verify_audit_chain(), pdf_ok=reports.pdf_available(),
    )


@bp.post("/settings/test-zap")
def test_zap():
    try:
        flash(f"Connected to ZAP {scanner._api('core/view/version')['version']}.", "ok")
    except (scanner.ScannerError, KeyError) as exc:
        flash(str(exc), "error")
    return redirect(url_for("main.settings"))


@bp.post("/settings/test-ollama")
def test_ollama():
    try:
        flash(f"Ollama is reachable and model '{ai.check_ollama()}' is installed.", "ok")
    except RuntimeError as exc:
        flash(str(exc), "error")
    return redirect(url_for("main.settings"))


@bp.get("/audit")
def audit_view():
    return render_template("audit.html", entries=db.get_audit_log(), intact=db.verify_audit_chain())
