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


class AuthFlowPageTests(unittest.TestCase):
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

    def request_json(
        self,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(request) as response:
            self.assertLess(response.status, 400)
            return json.load(response)

    def assert_http_error(
        self,
        code: int,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        self.assertEqual(error.exception.code, code)
        error.exception.close()

    def test_auth_pages_are_separate_routes(self):
        for path, marker in (
            ("/login", "Sign in to your workspace"),
            ("/register", "Create a nickname account"),
            ("/forgot-password", "Request a reset link"),
        ):
            with self.opener.open(self.base_url + path) as response:
                html = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn(marker, html)

    def test_security_settings_redirects_when_signed_out(self):
        with self.opener.open(self.base_url + "/settings/security") as response:
            html = response.read().decode("utf-8")
        self.assertTrue(response.geturl().endswith("/login"))
        self.assertIn("Sign in to your workspace", html)

    def test_forgot_password_does_not_enumerate_accounts(self):
        payload = self.request_json(
            "/api/auth/forgot-password",
            {"identifier": "unknown@example.com"},
        )
        self.assertIn("reset link", payload["message"])

    def test_reset_password_invalid_token_expires_cleanly(self):
        self.assert_http_error(410, "/reset-password/invalid-token-123")
        self.assert_http_error(
            410,
            "/api/auth/reset-password",
            {"token": "invalid-token-123", "password": "newpass123"},
        )

    def test_change_password_requires_auth_and_current_password(self):
        self.assert_http_error(
            401,
            "/api/auth/change-password",
            {"current_password": "x", "new_password": "newpass123"},
        )
        nickname = f"flow{uuid.uuid4().hex[:8]}"
        self.request_json(
            "/api/auth/register",
            {"nickname": nickname, "password": "correctpass"},
        )
        self.assert_http_error(
            403,
            "/api/auth/change-password",
            {"current_password": "wrongpass", "new_password": "newpass123"},
        )
        changed = self.request_json(
            "/api/auth/change-password",
            {"current_password": "correctpass", "new_password": "newpass123"},
        )
        self.assertTrue(changed["ok"])


if __name__ == "__main__":
    unittest.main()
