import json
import tempfile
import threading
import unittest
import urllib.request
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import server


class DynamicI18nEndpointTests(unittest.TestCase):
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
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def tearDown(self):
        self.httpd.shutdown()
        self.thread.join(timeout=3)
        self.httpd.server_close()
        (
            server.DATA_DIR,
            server.DB_PATH,
            server.BACKUP_DIR,
            server.SECRET_PATH,
        ) = self.original_paths
        self.temp_dir.cleanup()

    def post_json(self, path, payload):
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(request, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_domain_social_wallet_and_repo_results_follow_requested_language(self):
        domain_report = {
            "id": "11111111-1111-4111-8111-111111111111",
            "domain": "round7-example.test",
            "generated_at": server.utc_now(),
            "score": 82,
            "summary": "Domain is reachable. Missing 2 observable security headers.",
            "findings": [],
            "vulnerability_hypotheses": [],
        }

        def fake_probe(platform, username):
            present = platform["name"] in {"GitHub", "X", "Telegram", "Instagram", "TikTok"}
            return {
                "platform": platform["name"],
                "url": platform["url"].format(username=username),
                "final_url": platform["url"].format(username=username),
                "status": 200 if present else 404,
                "present": present,
                "confidence": "high" if present else "medium",
            }

        def fake_wallet_json(url):
            if "/api?" in url:
                return {"result": []}
            return {"coin_balance": str(2 * 10**18), "is_contract": True, "metadata": {}, "public_tags": []}

        with mock.patch("server.analyze", return_value=domain_report):
            domain = self.post_json("/api/analyze", {"target": "round7-example.test", "lang": "it"})
        self.assertIn("Manc", domain["report"]["summary"])
        self.assertNotIn("Domain is reachable", domain["report"]["summary"])

        with mock.patch("server.profile_probe", side_effect=fake_probe):
            social = self.post_json("/api/social/analyze", {"username": "round7user", "lang": "fr"})
        self.assertIn("profils", social["report"]["summary"])
        self.assertNotIn("Found ", social["report"]["summary"])
        self.assertNotIn("Username reused", social["report"]["findings"][0]["title"])

        with mock.patch("server.json_get", side_effect=fake_wallet_json):
            wallet = self.post_json(
                "/api/wallet/analyze",
                {"address": "0x0000000000000000000000000000000000000000", "lang": "de"},
            )
        self.assertIn("geschätztem Saldo", wallet["report"]["summary"])
        self.assertNotIn("estimated balance", wallet["report"]["summary"])
        self.assertNotIn("Contract or smart account", wallet["report"]["findings"][0]["title"])

        repo = self.post_json(
            "/api/repository/audit",
            {
                "repository": "round7-repo",
                "lang": "es",
                "files": [{"path": "app.py", "content": "DEBUG = True\n"}],
            },
        )
        self.assertIn("Modo debug", repo["audit"]["findings"][0]["title"])
        self.assertNotIn("Debug mode enabled", repo["audit"]["findings"][0]["title"])


if __name__ == "__main__":
    unittest.main()
