"""Core tests for AEGIS AI. Standard library only:  python -m unittest discover -s tests -v"""
import hashlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from app import ai, db, evidence, prioritizer, scanner, scope, settings  # noqa: E402


def make_finding(title="Missing CSP", risk="Medium", confidence="High", cwe="693",
                 url="http://localhost:3000/", solution="Add the header", evidence_text=""):
    return prioritizer.score_finding({
        "title": title, "risk": risk, "confidence": confidence, "url": url, "param": "",
        "description": "<p>Description</p>", "solution": solution, "cwe": cwe,
        "plugin_id": "10038", "evidence": evidence_text,
    })


class TempDbCase(unittest.TestCase):
    """Each test gets its own empty database."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_path = config.DB_PATH
        config.DB_PATH = os.path.join(self._tmp.name, "test.db")
        db.init_db()

    def tearDown(self):
        config.DB_PATH = self._old_path
        self._tmp.cleanup()

    def completed_scan(self, findings):
        scan_id = db.create_scan("http://localhost:3000", "passive")
        db.audit("scan_started", "http://localhost:3000", f"scan_id={scan_id} mode=passive")
        db.save_findings(scan_id, findings)
        db.finish_scan(scan_id, "completed")
        db.audit("scan_completed", "http://localhost:3000", f"scan_id={scan_id} findings={len(findings)}")
        return scan_id


class ScopeGuardTests(unittest.TestCase):
    def test_allowed_target_is_normalized(self):
        self.assertEqual(scope.validate_target("http://localhost:3000/"), "http://localhost:3000")

    def test_unlisted_hosts_ports_and_schemes_are_rejected(self):
        for bad in ("http://example.com", "http://localhost:9999", "ftp://localhost:3000", "localhost:3000", ""):
            with self.assertRaises(scope.ScopeError, msg=bad):
                scope.validate_target(bad)

    def test_localhost_is_rewritten_for_zap_in_docker(self):
        self.assertEqual(scope.zap_target("http://localhost:3000"), "http://juice-shop:3000")


class PrioritizerTests(TempDbCase):
    def test_high_severity_outranks_low(self):
        self.assertGreater(make_finding(risk="High", cwe="89")["priority_score"],
                           make_finding(risk="Low", cwe="16")["priority_score"])

    def test_low_confidence_is_marked_for_verification(self):
        self.assertEqual(make_finding(confidence="Low")["priority_label"], "Requires verification")

    def test_internet_exposure_setting_raises_the_score(self):
        before = make_finding()["priority_score"]
        settings.save({"internet_exposed": "1"})
        self.assertEqual(make_finding()["priority_score"], before + 10)


class AuditChainTests(TempDbCase):
    def test_chain_is_intact_then_detects_tampering(self):
        for i in range(3):
            db.audit("event", "t", f"n={i}")
        self.assertTrue(db.verify_audit_chain())
        conn = sqlite3.connect(config.DB_PATH)
        conn.execute("UPDATE audit_log SET detail='edited' WHERE id=2")
        conn.commit()
        conn.close()
        self.assertFalse(db.verify_audit_chain())


class EvidenceTests(TempDbCase):
    def setUp(self):
        super().setUp()
        self.scan_id = self.completed_scan([
            make_finding("=cmd|' /C calc'!A0", "High", "High", "89", "http://localhost:3000/a", evidence_text="@SUM(1)"),
            make_finding(),
        ])
        self.bundle, self.sha = evidence.build_bundle(self.scan_id)

    def files(self):
        with zipfile.ZipFile(io.BytesIO(self.bundle)) as zf:
            return {n: zf.read(n) for n in zf.namelist()}

    @staticmethod
    def rezip(files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in files.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_good_bundle_verifies_and_is_anchored_in_the_audit_log(self):
        result = evidence.verify_bundle(self.bundle)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["checks"][-1]["status"], "pass")
        self.assertEqual(result["manifest_sha256"], self.sha)

    def test_editing_a_finding_is_detected(self):
        files = self.files()
        findings = json.loads(files["findings.json"])
        findings[0]["title"] = "Nothing to see here"
        files["findings.json"] = json.dumps(findings).encode()
        self.assertFalse(evidence.verify_bundle(self.rezip(files))["ok"])

    def test_fully_rewritten_bundle_is_caught_by_the_audit_log_anchor(self):
        files = self.files()
        findings = json.loads(files["findings.json"])
        findings[0]["title"] = "Nothing to see here"
        findings[0]["evidence_hash"] = db.finding_hash(findings[0])
        files["findings.json"] = json.dumps(findings, indent=2, sort_keys=True).encode()
        manifest = json.loads(files["manifest.json"])
        for entry in manifest["files"]:
            if entry["name"] == "findings.json":
                entry["sha256"] = hashlib.sha256(files["findings.json"]).hexdigest()
        files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
        result = evidence.verify_bundle(self.rezip(files))
        self.assertFalse(result["ok"])
        self.assertEqual(result["checks"][-1]["status"], "fail")

    def test_garbage_and_unsafe_input_is_rejected_safely(self):
        self.assertFalse(evidence.verify_bundle(b"not a zip")["ok"])
        files = self.files()
        manifest = json.loads(files["manifest.json"])
        manifest["files"].append({"name": "../../etc/passwd", "sha256": "0"})
        files["manifest.json"] = json.dumps(manifest).encode()
        self.assertFalse(evidence.verify_bundle(self.rezip(files))["ok"])

    def test_csv_export_neutralises_spreadsheet_formulas(self):
        text = self.files()["findings.csv"].decode()
        self.assertIn("'=cmd|", text)
        self.assertNotIn("\n=cmd", text)


class AIGroundingTests(TempDbCase):
    def setUp(self):
        super().setUp()
        scan_id = self.completed_scan([make_finding(), make_finding(url="http://localhost:3000/ftp"),
                                       make_finding("SQL Injection", "High", "High", "89", "http://localhost:3000/login")])
        self.groups = ai.group_findings(db.get_findings(scan_id))

    def test_related_findings_are_grouped_and_ranked(self):
        self.assertEqual([g["cwe"] for g in self.groups], ["89", "693"])
        self.assertEqual(self.groups[1]["count"], 2)

    def test_rules_analysis_uses_the_knowledge_base(self):
        analysis = ai.rules_analysis(self.groups[0])
        self.assertIn("database query", analysis["explanation"])

    def test_model_output_with_invented_identifiers_is_rejected(self):
        good = {"explanation": "A header is missing.", "impact": "Lower protection.", "remediation": "Add it."}
        self.assertTrue(ai.verify_grounding(good, self.groups[1])[0])
        for bad_text in ("This is CVE-2021-44228.", "See CWE-999.", "Visit http://evil.example/x"):
            bad = dict(good, explanation=bad_text)
            self.assertFalse(ai.verify_grounding(bad, self.groups[1])[0], bad_text)
        self.assertFalse(ai.verify_grounding({"explanation": "only one key"}, self.groups[1])[0])


class ScannerTests(TempDbCase):
    """Runs the scan pipeline against a tiny fake ZAP API."""

    def setUp(self):
        super().setUp()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = self.path.split("?")[0]
                code, body = 200, {}
                if "/core/view/urls" in path:
                    body = {"urls": ["http://juice-shop:3000/"]}
                elif "spider/action/scan" in path:
                    body = {"scan": "0"}
                elif "status" in path:
                    body = {"status": "100"}
                elif "recordsToScan" in path:
                    body = {"recordsToScan": "0"}
                elif "core/view/alerts" in path:
                    body = {"alerts": [{"alert": "Missing CSP", "risk": "Medium", "confidence": "High",
                                        "url": "http://juice-shop:3000/a", "cweid": "693", "pluginId": "10038"}]}
                elif "ascan/action/scan" in path:
                    code, body = 400, {"code": "url_not_found", "message": "URL Not Found in the Scan Tree"}
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._old_url = config.ZAP_URL
        config.ZAP_URL = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        config.ZAP_URL = self._old_url
        super().tearDown()

    def test_passive_scan_returns_normalized_findings_with_original_urls(self):
        findings = scanner.run_scan("http://localhost:3000", active=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "http://localhost:3000/a")
        self.assertEqual(findings[0]["cwe"], "693")

    def test_zap_errors_are_reported_with_the_reason(self):
        with self.assertRaises(scanner.ScannerError) as ctx:
            scanner.run_scan("http://localhost:3000", active=True)
        self.assertIn("URL Not Found in the Scan Tree", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
