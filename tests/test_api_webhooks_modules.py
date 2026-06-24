import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import auth
import graph
import repo_audit
import server
import utils
import webhooks


class QuietHandler(server.Handler):
    def log_message(self, format_string: str, *args: object) -> None:
        return


def fake_domain_report(target: str) -> dict[str, object]:
    domain = server.clean_domain(target)
    return {
        "id": str(uuid.uuid4()),
        "domain": domain,
        "generated_at": server.utc_now(),
        "summary": f"API test report for {domain}.",
        "score": 90,
        "dns": {"addresses": ["203.0.113.42"], "mx": [], "ns": [], "txt": []},
        "https": {"security_headers": [], "certificate": {}},
        "email_security": {"applicable": False, "flags": {}},
        "web_presence": {},
        "rdap": {},
        "certificate_transparency": {"subdomains": []},
        "advanced_intel": {"signals": {}, "takeover_hints": []},
        "technology": [],
        "findings": [],
        "recommendations": [],
        "vulnerability_hypotheses": [],
        "red_team_paths": [],
        "purple_team_controls": [],
    }


class ModuleFacadeTests(unittest.TestCase):
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

    def tearDown(self):
        (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        ) = self.original_paths
        self.temp_dir.cleanup()

    def test_auth_repo_graph_and_webhook_facades(self):
        with server.db() as connection:
            service = auth.AuthService(connection)
            user = service.register("ModuleUser", "pass12345")
            self.assertEqual(user["nickname"], "moduleuser")
            self.assertIsNotNone(service.authenticate("moduleuser", "pass12345"))
            self.assertIsNone(service.authenticate("moduleuser", "wrongpass"))

        auditor = repo_audit.RepositoryAuditor()
        audit = auditor.audit(
            [{"path": "package.json", "content": '{"dependencies":{"lodash":"4.17.20"}}'}],
            "module-demo",
        )
        self.assertTrue(audit["dependency_advisories"])
        self.assertTrue(auditor.sarif(audit).startswith(b"{"))

        graph_payload = {
            "nodes": [{"id": "site:example.com", "label": "example.com", "type": "domain"}],
            "edges": [],
        }
        self.assertIn(b"@graph", graph.export_jsonld(graph_payload))
        self.assertIn(b"digraph", graph.export_dot(graph_payload))
        self.assertIn(b"source_id", graph.export_csv(graph_payload))

        self.assertEqual(utils.clean_domain("https://www.example.com/path"), "example.com")
        self.assertEqual(webhooks.clean_event("monitor.changed"), "monitor.changed")
        self.assertEqual(webhooks.clean_url("https://example.com/hook"), "https://example.com/hook")
        with self.assertRaises(ValueError):
            webhooks.clean_url("http://127.0.0.1/hook")


class PublicApiAndWebhookEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_paths = (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        )
        self.original_analyze = server.analyze
        self.delivery_patch = mock.patch("server.deliver_webhook", return_value=(True, "HTTP 200"))
        self.delivery_patch.start()
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
        self.delivery_patch.stop()
        server.analyze = self.original_analyze
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

    def assert_http_error(self, code: int, path: str, headers: dict[str, str] | None = None) -> None:
        request = urllib.request.Request(self.base_url + path, headers=headers or {})
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        self.assertEqual(error.exception.code, code)
        error.exception.close()

    def register_paid_user(self, plan: str = "Agency") -> str:
        self.request_json(
            "/api/auth/register",
            {"nickname": f"api{uuid.uuid4().hex[:8]}", "password": "pass12345"},
        )
        with server.db() as connection:
            row = connection.execute("SELECT id FROM users WHERE nickname IS NOT NULL").fetchone()
            user_id = row["id"]
            connection.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, user_id))
        return user_id

    def test_public_api_key_status_and_get_domain_analysis(self):
        self.register_paid_user("Agency")
        created = self.request_json("/api/api-keys", {"name": "integration"})
        token = created["credential"]
        headers = {"Authorization": f"Bearer {token}"}

        status = self.request_json("/api/v1/status", headers=headers)
        self.assertEqual(status["plan"], "Agency")
        self.assertIn("GET /api/v1/domains/analyze?domain=example.com", status["available_endpoints"])

        analyzed = self.request_json("/api/v1/domains/analyze?domain=example.com", headers=headers)
        self.assertEqual(analyzed["report"]["domain"], "example.com")

    def test_webhook_create_test_and_delete_flow(self):
        self.register_paid_user("Pro")
        created = self.request_json(
            "/api/webhooks",
            {"event_type": "monitor.changed", "url": "https://example.com/osintpro"},
        )
        webhook_id = created["webhooks"][0]["id"]
        listed = self.request_json("/api/webhooks")
        self.assertEqual(listed["events"][0], "monitor.changed")
        self.assertTrue(listed["webhooks"][0]["active"])

        tested = self.request_json("/api/notifications/test", {})
        self.assertEqual(tested["webhooks_sent"], 1)
        self.assertEqual(tested["email_status"], "skipped")

        deleted = self.request_json(f"/api/webhooks/{webhook_id}", method="DELETE")
        self.assertFalse(deleted["webhooks"][0]["active"])

    def test_free_plan_cannot_create_webhooks_or_api_keys(self):
        self.register_paid_user("Free")
        request = urllib.request.Request(
            self.base_url + "/api/webhooks",
            data=json.dumps({"event_type": "monitor.changed", "url": "https://example.com/hook"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        self.assertEqual(error.exception.code, 402)
        error.exception.close()


if __name__ == "__main__":
    unittest.main()
