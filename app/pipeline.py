"""Scan job: scanner -> normalize -> prioritize -> store."""
from app import ai, db, prioritizer, scanner


def run_job(scan_id: int, target: str, active: bool):
    try:
        findings = scanner.run_scan(target, active=active)
        findings = [prioritizer.score_finding(f) for f in findings]
        db.save_findings(scan_id, findings)
        try:
            ai.generate_rules(scan_id)  # instant, deterministic explanations for the AI analysis page
        except Exception:
            pass  # never let the explanation layer fail a scan
        db.finish_scan(scan_id, "completed")
        db.audit("scan_completed", target, f"scan_id={scan_id} findings={len(findings)}")
    except Exception as exc:  # keep the dashboard informative instead of crashing the thread
        db.finish_scan(scan_id, "failed", str(exc))
        db.audit("scan_failed", target, f"scan_id={scan_id} error={exc}")
