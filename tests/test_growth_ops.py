import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
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


class GrowthOpsEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_paths = (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        )
        self.original_env = {
            key: os.environ.get(key)
            for key in (
                "OSINTPRO_ADMIN_CODE",
                "OSINTPRO_CRON_SECRET",
                "OSINTPRO_STRIPE_WEBHOOK_SECRET",
            )
        }
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
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        ) = self.original_paths
        self.temp_dir.cleanup()

    def request_json(
        self,
        path: str,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
    ) -> dict[str, object]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method or ("POST" if payload is not None else "GET"),
        )
        with self.opener.open(request) as response:
            self.assertLess(response.status, 400)
            return json.load(response)

    def assert_http_error(
        self,
        code: int,
        path: str,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
    ) -> None:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method or ("POST" if payload is not None else "GET"),
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        self.assertEqual(error.exception.code, code)
        error.exception.close()

    def register(self) -> str:
        nickname = f"ops{uuid.uuid4().hex[:8]}"
        self.request_json(
            "/api/auth/register",
            {"nickname": nickname, "password": "pass12345"},
        )
        return nickname

    def signed_stripe_header(self, payload: bytes, secret: str) -> str:
        timestamp = str(int(time.time()))
        signature = hmac.new(
            secret.encode("utf-8"),
            f"{timestamp}.".encode("utf-8") + payload,
            hashlib.sha256,
        ).hexdigest()
        return f"t={timestamp},v1={signature}"

    def test_feature_flags_and_account_metrics(self):
        flags = self.request_json("/api/feature-flags")
        self.assertFalse(flags["features"]["repo_audit_sarif"]["allowed"])
        self.assertEqual(flags["features"]["repo_audit_sarif"]["required_plan"], "Pro")

        self.assert_http_error(401, "/api/metrics")
        self.register()
        metrics = self.request_json("/api/metrics")
        self.assertEqual(metrics["user_plan"], "Free")
        self.assertIn("resource_counts", metrics)

    def test_admin_metrics_requires_admin_code_header(self):
        os.environ["OSINTPRO_ADMIN_CODE"] = "test-admin-code"

        self.assert_http_error(401, "/admin/metrics")
        metrics = self.request_json(
            "/admin/metrics",
            headers={"X-Admin-Code": "test-admin-code"},
        )
        self.assertIn("mrr_estimate_eur", metrics)
        self.assertIn("conversion_rate_percent", metrics)

    def test_cron_backup_and_monitors_authorization(self):
        self.assert_http_error(503, "/api/cron/monitors", {}, method="POST")
        os.environ["OSINTPRO_CRON_SECRET"] = "cron-secret"

        self.assert_http_error(
            403,
            "/api/cron/monitors",
            {},
            headers={"Authorization": "Bearer wrong"},
            method="POST",
        )
        monitors = self.request_json(
            "/api/cron/monitors",
            {},
            headers={"Authorization": "Bearer cron-secret"},
            method="POST",
        )
        self.assertTrue(monitors["ok"])

        backup = self.request_json(
            "/api/cron/backup",
            {},
            headers={"X-OSINTPRO-CRON": "cron-secret"},
            method="POST",
        )
        self.assertTrue(backup["ok"])

    def test_pdf_missing_report_and_stripe_signature_paths(self):
        self.assert_http_error(404, "/api/reports/not-a-report/pdf")

        self.assert_http_error(400, "/api/stripe/webhook", {}, method="POST")
        os.environ["OSINTPRO_STRIPE_WEBHOOK_SECRET"] = "test-signing-secret"
        payload = json.dumps({
            "id": "evt_missing_reference",
            "type": "checkout.session.completed",
            "data": {"object": {"status": "complete"}},
        }).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/api/stripe/webhook",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Stripe-Signature": self.signed_stripe_header(payload, "test-signing-secret"),
            },
            method="POST",
        )
        with self.opener.open(request) as response:
            result = json.load(response)
        self.assertEqual(result["status"], "missing_reference")


class DependencyAdvisoryTests(unittest.TestCase):
    def test_manifest_parsers_detect_known_old_dependencies(self):
        files = [
            ("package.json", '{"dependencies":{"lodash":"4.17.20","express":"4.18.2"}}'),
            ("requirements.txt", "Django==3.2.10\nrequests==2.30.0\n"),
            ("Cargo.toml", '[dependencies]\ntime = "0.1.45"\n'),
            ("composer.json", '{"require":{"guzzlehttp/guzzle":"6.5.0"}}'),
        ]
        findings = server.dependency_advisories_for_files(files)
        packages = {item["package"] for item in findings}
        self.assertIn("lodash", packages)
        self.assertIn("django", packages)
        self.assertIn("time", packages)
        self.assertIn("guzzlehttp/guzzle", packages)

    def test_repository_audit_embeds_dependency_findings(self):
        audit = server.analyze_repository(
            [
                {
                    "path": "package.json",
                    "content": '{"dependencies":{"lodash":"4.17.20"}}',
                },
                {"path": "app.js", "content": "const ok = true;\n"},
            ],
            "dependency-demo",
        )

        self.assertEqual(len(audit["dependency_advisories"]), 1)
        titles = {item["title"] for item in audit["findings"]}
        self.assertIn("Known vulnerable NPM dependency: lodash", titles)


if __name__ == "__main__":
    unittest.main()
