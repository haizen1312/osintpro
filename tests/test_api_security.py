import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import server


class QuietHandler(server.Handler):
    def log_message(self, format_string: str, *args: object) -> None:
        return


class ApiSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_paths = (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        )
        data_dir = Path(self.temp_dir.name)
        server.DATA_DIR = data_dir
        server.DB_PATH = data_dir / "test.sqlite3"
        server.BACKUP_DIR = data_dir / "backups"
        server.SECRET_PATH = data_dir / ".secret"
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
        (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        ) = self.original_paths
        self.temp_dir.cleanup()

    def post_json_expect_error(self, path: str, payload: dict[str, object]) -> urllib.error.HTTPError:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        error.exception.close()
        return error.exception

    def test_security_headers_are_present_on_public_and_api_responses(self):
        with self.opener.open(self.base_url + "/") as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

        with self.opener.open(self.base_url + "/api/health") as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_invalid_domain_and_nickname_are_rejected(self):
        invalid_domain = self.post_json_expect_error(
            "/api/analyze",
            {"target": 'example.com" OR "1"="1'},
        )
        self.assertEqual(invalid_domain.code, 400)

        invalid_nickname = self.post_json_expect_error(
            "/api/auth/register",
            {"nickname": "<script>alert(1)</script>", "password": "pass12345"},
        )
        self.assertEqual(invalid_nickname.code, 400)

    def test_public_meta_and_stripe_webhook_signature_boundary(self):
        with self.opener.open(self.base_url + "/api/meta") as response:
            payload = json.load(response)
        self.assertEqual(payload["product"], "OSINTPRO")
        self.assertIn("no exploit execution", payload["safety_boundary"])
        self.assertIn("no cheat development or anti-cheat bypass guidance", payload["safety_boundary"])
        self.assertIn("game_security_lab", payload["modules"])

        missing_signature = self.post_json_expect_error("/api/stripe/webhook", {})
        self.assertEqual(missing_signature.code, 400)

    def test_risk_findings_include_owner_ready_abuse_context(self):
        report = {
            "dns": {"caa": []},
            "https": {"available": True, "security_headers": [
                {"name": "content-security-policy", "present": False}
            ]},
            "email_security": {
                "applicable": True,
                "flags": {"mx_present": True, "spf_present": False, "dmarc_present": False},
            },
            "web_presence": {"security_txt": {"available": True, "present": False}},
            "advanced_intel": {"signals": {"dnssec_enabled": False}, "takeover_hints": [{}]},
        }

        finding = server.risk_findings(report)[0]
        self.assertIn("abuse_path", finding)
        self.assertIn("business_impact", finding)
        self.assertIn("owner_action", finding)
        self.assertIn("evidence_to_collect", finding)

        hypothesis = server.vulnerability_hypotheses(report)[0]
        self.assertIn("attacker_path", hypothesis)
        self.assertIn("likely_impact", hypothesis)
        self.assertIn("defensive_priority", hypothesis)

    def test_repository_findings_include_business_context(self):
        finding = server.repo_finding(
            severity="high",
            confidence="medium",
            category="Database",
            title="SQL built with string interpolation",
            path="app.py",
            line=10,
            evidence="db.execute(f'SELECT * FROM users WHERE id={user_id}')",
            why="Dynamic SQL construction can create SQL injection.",
            remediation="Use parameterized queries.",
        )

        self.assertIn("attacker may attempt", finding["abuse_path"])
        self.assertIn("Customer data", finding["business_impact"])
        self.assertIn("parameterized", finding["owner_action"])


if __name__ == "__main__":
    unittest.main()
