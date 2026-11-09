"""Forensic evidence export and verification.

An evidence bundle is a ZIP holding one assessment's findings, timeline and the full audit-log hash
chain, plus a manifest listing the SHA-256 of every file and a chain-of-custody record.

Tamper evidence works in three layers:
  1. every file's SHA-256 is listed in manifest.json;
  2. every finding carries its own evidence hash, re-computed on verification;
  3. the SHA-256 of manifest.json is written into AEGIS AI's own hash-chained audit log at export time,
     so a bundle that was modified after export can be recognised by the installation that issued it.
"""
import csv
import hashlib
import io
import json
import re
import zipfile

from app import db, settings

FORMAT = "aegis-evidence-bundle/1"
MAX_ENTRIES = 30
MAX_UNPACKED = 60 * 1024 * 1024
FINDING_COLUMNS = ["id", "title", "priority_label", "priority_score", "risk", "confidence", "url", "param",
                   "cwe", "plugin_id", "evidence", "description", "solution", "evidence_hash"]

VERIFY_SCRIPT = '''#!/usr/bin/env python3
"""Offline verifier for an AEGIS AI evidence bundle (standard library only).

Run it from inside the extracted bundle folder:   python verify_bundle.py
It checks every file hash, every finding's evidence hash, and the audit-log hash chain.
Finally compare the printed manifest SHA-256 with the 'evidence_exported' entry in AEGIS AI's Audit log.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HASH_FIELDS = ("title", "risk", "confidence", "url", "param", "description", "solution", "cwe",
               "plugin_id", "evidence", "priority_score", "priority_label")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def finding_hash(f):
    payload = {k: (int(f[k]) if k == "priority_score" else ("" if f[k] is None else str(f[k]))) for k in HASH_FIELDS}
    return sha256(json.dumps(payload, sort_keys=True).encode())


def read(name):
    with open(os.path.join(HERE, name), "rb") as fh:
        return fh.read()


def main():
    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print(("PASS  " if ok else "FAIL  ") + name + (" - " + detail if detail else ""))

    try:
        manifest_bytes = read("manifest.json")
        manifest = json.loads(manifest_bytes)
    except Exception as exc:
        print("FAIL  manifest.json could not be read: %s" % exc)
        return 1

    bad = []
    for entry in manifest.get("files", []):
        name = entry.get("name", "")
        if os.path.basename(name) != name or not name:
            bad.append("%r (unsafe name)" % name)
        elif not os.path.isfile(os.path.join(HERE, name)):
            bad.append(name + " (missing)")
        elif sha256(read(name)) != entry.get("sha256"):
            bad.append(name + " (hash mismatch)")
    check("File hashes match the manifest", not bad, "; ".join(bad) or "%d files" % len(manifest.get("files", [])))

    try:
        findings = json.loads(read("findings.json"))
        mismatched = [str(f.get("id")) for f in findings if finding_hash(f) != f.get("evidence_hash")]
        check("Finding evidence hashes", not mismatched,
              ("changed finding ids: " + ", ".join(mismatched)) if mismatched else "%d findings" % len(findings))
    except Exception as exc:
        check("Finding evidence hashes", False, str(exc))

    try:
        rows = json.loads(read("audit_log.json"))
        prev, intact = "GENESIS", True
        for r in rows:
            payload = "%s|%s|%s|%s|%s" % (prev, r["ts"], r["action"], r["target"], r["detail"])
            if r["prev_hash"] != prev or sha256(payload.encode()) != r["entry_hash"]:
                intact = False
                break
            prev = r["entry_hash"]
        check("Audit-log hash chain is intact", intact, "%d entries" % len(rows))
        check("Chain head matches the manifest", prev == manifest.get("audit_chain_head"))
    except Exception as exc:
        check("Audit-log hash chain is intact", False, str(exc))

    print()
    print("Manifest SHA-256: " + sha256(manifest_bytes))
    print("Compare it with the 'evidence_exported' entry in AEGIS AI's Audit log.")
    print("RESULT: " + ("ALL CHECKS PASSED" if all(results) else "VERIFICATION FAILED"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(obj) -> bytes:
    return json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")


def _csv_safe(value):
    """Stop spreadsheet formula injection: scanned sites control some of this text."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _findings_csv(findings) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(FINDING_COLUMNS)
    for f in findings:
        writer.writerow([_csv_safe(f[c]) for c in FINDING_COLUMNS])
    return buf.getvalue().encode("utf-8")


def _timeline_csv(scan, audit_rows) -> bytes:
    pattern = re.compile(rf"\bscan_id={scan['id']}\b")
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["utc_time", "event", "target", "detail", "entry_hash_prefix"])
    for r in audit_rows:
        if pattern.search(r["detail"] or ""):
            writer.writerow([r["ts"], _csv_safe(r["action"]), _csv_safe(r["target"]), _csv_safe(r["detail"]), r["entry_hash"][:12]])
    return buf.getvalue().encode("utf-8")


def _custody_text(manifest: dict, payload_entries: list) -> bytes:
    scan = manifest["scan"]
    lines = [
        "AEGIS AI - EVIDENCE BUNDLE - CHAIN OF CUSTODY RECORD",
        "=" * 56, "",
        f"Bundle format        : {manifest['format']}",
        f"Assessment           : #{scan['id']} ({scan['mode']} scan)",
        f"Target               : {scan['target']}",
        f"Scan started (UTC)   : {scan['started_at']}",
        f"Scan finished (UTC)  : {scan['finished_at']}",
        f"Exported (UTC)       : {manifest['generated_utc']}",
        f"Examiner             : {manifest['examiner'] or '(not set in Settings)'}",
        f"Organisation         : {manifest['organisation'] or '(not set in Settings)'}",
        f"Findings in bundle   : {manifest['counts']['findings']}",
        f"Audit entries        : {manifest['counts']['audit_entries']}",
        f"Audit chain verified at export: {'YES' if manifest['audit_chain_verified'] else 'NO - the chain was already broken'}",
        f"Audit chain head     : {manifest['audit_chain_head']}", "",
        "FILES AND SHA-256", "-" * 17,
    ]
    lines += [f"{e['sha256']}  {e['name']}" for e in payload_entries]
    lines += [
        "", "HOW TO VERIFY", "-" * 13,
        "1. Extract this ZIP into a folder and run:  python verify_bundle.py",
        "2. The script re-checks every file hash, every finding's evidence hash and the audit-log hash chain.",
        "3. Compare the manifest SHA-256 it prints with the 'evidence_exported' entry in AEGIS AI's Audit log,",
        "   or upload this ZIP on AEGIS AI's Evidence page. A bundle edited after export will not match.", "",
        "HANDLING NOTES", "-" * 14,
        "- Findings are automated scanner output (OWASP ZAP). They are not confirmed exploits.",
        "- findings.csv is a convenience copy (formula characters are neutralised); findings.json is canonical.",
        "- Keep the original ZIP unmodified. Work on copies.", "",
        "CUSTODY LOG (complete by hand on each transfer)", "-" * 46,
        "Date/time (UTC) | Released by | Received by | Purpose",
        "_" * 56, "_" * 56, "_" * 56, "",
    ]
    return "\n".join(lines).encode("utf-8")


def build_bundle(scan_id: int) -> tuple:
    """Build the evidence ZIP. Returns (zip_bytes, manifest_sha256). Logs the export in the audit chain."""
    scan = dict(db.get_scan(scan_id))
    findings = [dict(f) for f in db.get_findings(scan_id)]
    audit_rows = [dict(r) for r in db.get_audit_chain()]
    chain_ok = db.verify_audit_chain()
    head = audit_rows[-1]["entry_hash"] if audit_rows else "GENESIS"

    files = {
        "scan.json": _json(scan),
        "findings.json": _json(findings),
        "findings.csv": _findings_csv(findings),
        "timeline.csv": _timeline_csv(scan, audit_rows),
        "audit_log.json": _json(audit_rows),
        "verify_bundle.py": VERIFY_SCRIPT.encode("utf-8"),
    }
    payload_entries = [{"name": n, "sha256": _sha(b), "bytes": len(b)} for n, b in files.items()]

    manifest = {
        "format": FORMAT,
        "tool": "AEGIS AI",
        "generated_utc": db.now(),
        "examiner": settings.get("tester_name"),
        "organisation": settings.get("org_name"),
        "scan": {k: scan[k] for k in ("id", "target", "mode", "status", "started_at", "finished_at")},
        "counts": {"findings": len(findings), "audit_entries": len(audit_rows)},
        "audit_chain_head": head,
        "audit_chain_verified": chain_ok,
        "files": [],
    }
    files["chain_of_custody.txt"] = _custody_text(manifest, payload_entries)
    manifest["files"] = payload_entries + [
        {"name": "chain_of_custody.txt", "sha256": _sha(files["chain_of_custody.txt"]), "bytes": len(files["chain_of_custody.txt"])}
    ]
    manifest_bytes = _json(manifest)
    manifest_sha = _sha(manifest_bytes)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        for name, data in files.items():
            zf.writestr(name, data)

    db.audit("evidence_exported", scan["target"],
             f"scan_id={scan_id} manifest_sha256={manifest_sha} files={len(manifest['files'])}")
    return buf.getvalue(), manifest_sha


def verify_bundle(data: bytes) -> dict:
    """Verify an uploaded bundle in memory (nothing is extracted to disk)."""
    checks = []

    def add(name, status, detail=""):
        checks.append({"name": name, "status": status, "detail": detail})

    result = {"checks": checks, "ok": False, "manifest_sha256": "", "scan": None}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        add("Readable ZIP file", "fail", "This is not a valid ZIP file.")
        return result
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_UNPACKED:
        add("Reasonable bundle size", "fail", "The ZIP has too many files or is too large to be an evidence bundle.")
        return result

    def read(name):
        return zf.read(name)

    try:
        manifest_bytes = read("manifest.json")
        manifest = json.loads(manifest_bytes)
        if manifest.get("format") != FORMAT:
            raise ValueError("unknown bundle format")
    except (KeyError, ValueError):
        add("Manifest present and readable", "fail", "manifest.json was not found at the top level of the ZIP, or it is damaged.")
        return result
    result["manifest_sha256"] = _sha(manifest_bytes)
    result["scan"] = manifest.get("scan")
    add("Manifest present and readable", "pass", f"Assessment #{manifest['scan']['id']} of {manifest['scan']['target']}")

    bad = []
    for entry in manifest.get("files", []):
        name = entry.get("name", "")
        try:
            if not name or "/" in name or "\\" in name or ".." in name:
                bad.append(f"{name!r} (unsafe name)")
            elif _sha(read(name)) != entry.get("sha256"):
                bad.append(f"{name} (hash mismatch)")
        except KeyError:
            bad.append(f"{name} (missing)")
    add("File hashes match the manifest", "fail" if bad else "pass", "; ".join(bad) or f"{len(manifest.get('files', []))} files checked")

    try:
        findings = json.loads(read("findings.json"))
        changed = [str(f.get("id")) for f in findings if db.finding_hash(f) != f.get("evidence_hash")]
        add("Finding evidence hashes", "fail" if changed else "pass",
            ("Changed finding ids: " + ", ".join(changed)) if changed else f"{len(findings)} findings re-hashed")
    except (KeyError, ValueError, TypeError) as exc:
        add("Finding evidence hashes", "fail", f"Could not check findings ({exc.__class__.__name__}).")

    try:
        rows = json.loads(read("audit_log.json"))
        prev, intact = "GENESIS", True
        for r in rows:
            payload = f"{prev}|{r['ts']}|{r['action']}|{r['target']}|{r['detail']}"
            if r["prev_hash"] != prev or _sha(payload.encode()) != r["entry_hash"]:
                intact = False
                break
            prev = r["entry_hash"]
        add("Audit-log hash chain is intact", "pass" if intact else "fail", f"{len(rows)} entries")
        add("Chain head matches the manifest", "pass" if prev == manifest.get("audit_chain_head") else "fail")
    except (KeyError, ValueError, TypeError) as exc:
        add("Audit-log hash chain is intact", "fail", f"Could not check the chain ({exc.__class__.__name__}).")

    # Is this exact manifest the one this installation issued?
    scan_id = manifest["scan"]["id"]
    issued = db.get_audit_by_action("evidence_exported", limit=500)
    mine = [r for r in issued if f"scan_id={scan_id} " in (r["detail"] or "")]
    if any(f"manifest_sha256={result['manifest_sha256']}" in (r["detail"] or "") for r in issued):
        add("Issued by this AEGIS AI installation", "pass", "The manifest hash is recorded in this installation's audit log.")
    elif mine:
        add("Issued by this AEGIS AI installation", "fail",
            "This installation exported a bundle for this assessment, but its hash does not match this one. The bundle was changed after export.")
    else:
        add("Issued by this AEGIS AI installation", "warn",
            "No matching export is recorded here. This is expected for a bundle from another machine; the other checks still apply.")

    result["ok"] = all(c["status"] != "fail" for c in checks)
    return result
