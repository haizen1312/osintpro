import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

import server


class QuietHandler(server.Handler):
    def log_message(self, format_string: str, *args: object) -> None:
        return


def fake_domain_report(target: str) -> dict[str, object]:
    domain = server.clean_domain(target)
    return {
        "id": str(uuid.uuid4()),
        "domain": domain,
        "generated_at": server.utc_now(),
        "summary": f"Static test report for {domain}.",
        "score": 88,
        "dns": {
            "addresses": ["203.0.113.10"],
            "mx": [],
            "ns": ["ns1.example.test"],
            "txt": [],
            "caa": [],
            "soa": [],
        },
        "https": {
            "status": 200,
            "server": "test",
            "certificate": {"subject": domain, "expires": "2030-01-01"},
            "security_headers": [
                {
                    "name": name,
                    "present": name == "x-content-type-options",
                    "value": "nosniff" if name == "x-content-type-options" else None,
                    "reason": "" if name == "x-content-type-options" else "Header not found",
                }
                for name in server.SECURITY_HEADERS
            ],
        },
        "email_security": {
            "applicable": False,
            "score": None,
            "scope_note": "No mail use observed.",
            "flags": {},
            "dmarc": [],
            "mta_sts": [],
            "tls_rpt": [],
        },
        "web_presence": {
            "security_txt": {"present": False, "status": 404},
            "robots_txt": {"present": True, "status": 200},
            "sitemap_xml": {"present": False, "status": 404},
            "mta_sts_policy": {"present": False, "status": 404},
        },
        "rdap": {},
        "certificate_transparency": {"subdomains": []},
        "advanced_intel": {"signals": {"dnssec_enabled": False}, "takeover_hints": []},
        "technology": [],
        "findings": [
            {
                "level": "medium",
                "title": "Test finding",
                "detail": "Used to verify the generated export.",
            }
        ],
        "recommendations": ["Add the missing browser security headers."],
        "vulnerability_hypotheses": [],
        "red_team_paths": [],
        "purple_team_controls": [],
    }


class ExportEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_paths = (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        )
        self.original_analyze = server.analyze
        data_dir = Path(self.temp_dir.name)
        server.DATA_DIR = data_dir
        server.DB_PATH = data_dir / "test.sqlite3"
        server.BACKUP_DIR = data_dir / "backups"
        server.SECRET_PATH = data_dir / ".secret"
        server.analyze = fake_domain_report
        server.init_db()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.analyze = self.original_analyze
        (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        ) = self.original_paths
        self.temp_dir.cleanup()

    def post_json(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(request) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)

    def download(self, path: str) -> tuple[bytes, str, str]:
        with self.opener.open(self.base_url + path) as response:
            return (
                response.read(),
                response.headers.get("Content-Type", ""),
                response.headers.get("Content-Disposition", ""),
            )

    def test_guest_pdf_report_csv_and_web_audit_csv_download(self):
        first = self.post_json("/api/analyze", {"target": "first.example"})
        second = self.post_json("/api/analyze", {"target": "second.example"})
        report_id = second["report"]["id"]

        with server.db() as connection:
            count = connection.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"]
        self.assertEqual(count, 1, "Anonymous sessions should retain only their latest domain report.")
        with self.assertRaises(urllib.error.HTTPError) as old_report_error:
            self.download(f"/api/reports/{first['report']['id']}/pdf")
        self.assertEqual(old_report_error.exception.code, 404)
        old_report_error.exception.close()

        pdf, pdf_type, pdf_disposition = self.download(f"/api/reports/{report_id}/pdf")
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))
        self.assertEqual(pdf_type, "application/pdf")
        self.assertIn("attachment", pdf_disposition)
        self.assertIn("second.example.pdf", pdf_disposition)

        report_csv, report_type, report_disposition = self.download("/api/reports.csv")
        report_text = report_csv.decode("utf-8")
        self.assertIn("text/csv", report_type)
        self.assertIn("attachment", report_disposition)
        self.assertIn("second.example", report_text)
        self.assertNotIn(first["report"]["domain"], report_text)

        audit_csv, audit_type, audit_disposition = self.download(
            f"/api/reports/{report_id}/web-audit.csv"
        )
        audit_text = audit_csv.decode("utf-8")
        self.assertIn("text/csv", audit_type)
        self.assertIn("attachment", audit_disposition)
        self.assertIn("content-security-policy", audit_text)
        self.assertIn("osintpro-web-audit-second.example.csv", audit_disposition)


if __name__ == "__main__":
    unittest.main()
