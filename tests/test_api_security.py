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

        missing_signature = self.post_json_expect_error("/api/stripe/webhook", {})
        self.assertEqual(missing_signature.code, 400)


if __name__ == "__main__":
    unittest.main()
