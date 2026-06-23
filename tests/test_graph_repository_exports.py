import json
import tempfile
import threading
import unittest
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

import server


class QuietHandler(server.Handler):
    def log_message(self, format_string: str, *args: object) -> None:
        return


class GraphRepositoryExportEndpointTests(unittest.TestCase):
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

    def post_json(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(request) as response:
            self.assertLess(response.status, 400)
            return json.load(response)

    def get_bytes(self, path: str) -> tuple[bytes, str, str]:
        with self.opener.open(self.base_url + path) as response:
            return (
                response.read(),
                response.headers.get("Content-Type", ""),
                response.headers.get("Content-Disposition", ""),
            )

    def register_and_seed_workspace(self) -> str:
        self.post_json(
            "/api/auth/register",
            {"nickname": f"tester{uuid.uuid4().hex[:8]}", "password": "pass12345"},
        )
        with server.db() as connection:
            row = connection.execute("SELECT id FROM users WHERE nickname IS NOT NULL").fetchone()
            user_id = row["id"]
            domain_report = {
                "id": str(uuid.uuid4()),
                "domain": "example.com",
                "score": 91,
                "summary": "Seeded domain report.",
                "generated_at": server.utc_now(),
                "dns": {"addresses": ["203.0.113.10"], "mx": ["10 mail.example.com"], "ns": []},
                "https": {"server": "nginx", "security_headers": []},
                "email_security": {"applicable": True, "score": 80},
                "rdap": {"registrar": "Example Registrar"},
                "certificate_transparency": {"subdomains": ["app.example.com"]},
                "advanced_intel": {"takeover_hints": []},
                "technology": ["nginx"],
                "findings": [{"title": "Seed finding", "level": "low"}],
            }
            social_report = {
                "id": str(uuid.uuid4()),
                "username": "example",
                "score": 74,
                "summary": "Seeded social report.",
                "generated_at": server.utc_now(),
                "profiles": [{"platform": "GitHub", "present": True, "confidence": "high"}],
                "findings": [],
            }
            wallet_report = {
                "id": str(uuid.uuid4()),
                "chain": "ethereum",
                "address": "0x0000000000000000000000000000000000000000",
                "risk_score": 12,
                "summary": "Seeded wallet report.",
                "generated_at": server.utc_now(),
                "balance": 0,
                "asset": "ETH",
                "tx_count": 0,
                "counterparties": [],
                "transactions": [],
                "findings": [],
            }
            server.store_report(connection, user_id, domain_report)
            server.store_social_report(connection, user_id, social_report)
            server.store_wallet_report(connection, user_id, wallet_report)
        return user_id

    def test_graph_exports_jsonld_dot_and_csv(self):
        self.register_and_seed_workspace()

        jsonld, jsonld_type, jsonld_disposition = self.get_bytes(
            "/api/graphs/current/export?format=jsonld"
        )
        self.assertIn("application/ld+json", jsonld_type)
        self.assertIn("attachment", jsonld_disposition)
        payload = json.loads(jsonld.decode("utf-8"))
        self.assertIn("@graph", payload)
        self.assertIn("site:example.com", jsonld.decode("utf-8"))

        dot, dot_type, _ = self.get_bytes("/api/graphs/current/export?format=dot")
        self.assertIn("text/vnd.graphviz", dot_type)
        self.assertIn(b"digraph OSINTPRO", dot)
        self.assertIn(b"example.com", dot)

        csv_body, csv_type, _ = self.get_bytes("/api/graphs/current/export?format=csv")
        self.assertIn("text/csv", csv_type)
        self.assertIn(b"source_id,source_label", csv_body)
        self.assertIn(b"site:example.com", csv_body)

    def test_repository_audit_persists_and_exports_sarif(self):
        self.post_json(
            "/api/auth/register",
            {"nickname": f"repo{uuid.uuid4().hex[:8]}", "password": "pass12345"},
        )
        data = self.post_json(
            "/api/repository/audit",
            {
                "repository": "client-portal",
                "files": [
                    {"path": ".gitignore", "content": "fixtures/\n"},
                    {"path": "fixtures/ignored.py", "content": "DEBUG = True\n"},
                    {"path": "app.py", "content": "DEBUG = True\n"},
                ],
            },
        )
        audit_id = data["audit"]["id"]
        self.assertEqual(data["audit"]["ignored_files"], 1)

        sarif, sarif_type, sarif_disposition = self.get_bytes(f"/api/reports/{audit_id}/sarif")
        self.assertIn("application/sarif+json", sarif_type)
        self.assertIn("attachment", sarif_disposition)
        payload = json.loads(sarif.decode("utf-8"))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "warning")

        audit_json, audit_type, _ = self.get_bytes(f"/api/reports/{audit_id}/repository.json")
        self.assertIn("application/json", audit_type)
        self.assertEqual(json.loads(audit_json.decode("utf-8"))["repository"], "client-portal")


if __name__ == "__main__":
    unittest.main()
