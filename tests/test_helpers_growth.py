import os
import tempfile
import unittest
import uuid
from pathlib import Path

import server


class HelperGrowthTests(unittest.TestCase):
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
                "OSINTPRO_MONITOR_BATCH_LIMIT",
                "OSINTPRO_REGISTRATION_IP_LIMIT",
                "OSINTPRO_BACKUP_RETENTION",
                "OSINTPRO_API_KEY_RATE_LIMIT",
            )
        }
        data_dir = Path(self.temp_dir.name)
        server.DATA_DIR = data_dir
        server.DB_PATH = data_dir / "test.sqlite3"
        server.BACKUP_DIR = data_dir / "backups"
        server.SECRET_PATH = data_dir / ".secret"
        server.init_db()

    def tearDown(self):
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

    def test_redaction_and_csv_helpers_cover_secret_edges(self):
        self.assertIn("[redacted]", server.redact_text("token=" + "sk_live_" + "abcdefghijklmnopqrstuvwxyz"))
        self.assertIn("[redacted]", server.redact_dns_txt('"google-site-verification=abc123"'))
        self.assertTrue(server.csv_cell("=cmd").startswith("\"'="))
        self.assertEqual(server.safe_download_filename("../Bad Name!.PDF", "fallback"), "bad-name-.pdf")
        payload = {"api_key": "abc123", "nested": ["password=secret"]}
        rendered = str(server.redact_data(payload))
        self.assertIn("[redacted]", rendered)
        self.assertNotIn("secret", rendered)

    def test_conversion_event_cleaners_and_storage(self):
        self.assertEqual(server.clean_event_name("checkout-click"), "checkout_click")
        self.assertEqual(server.clean_event_source("Pricing_Card"), "pricing_card")
        self.assertIsNone(server.clean_event_plan(""))
        self.assertEqual(server.clean_event_plan("pro"), "Pro")
        metadata = server.clean_event_metadata({"current_plan": "Free", "ok": True, "extra": object()})
        self.assertEqual(metadata["current_plan"], "Free")
        self.assertTrue(metadata["ok"])
        with self.assertRaises(ValueError):
            server.clean_event_name("<script>")
        with server.db() as connection:
            server.record_conversion_event(
                connection,
                None,
                "checkout_click",
                "Pro",
                "pricing_card",
                {"current_plan": "Free"},
            )
            count = connection.execute("SELECT COUNT(*) AS count FROM conversion_events").fetchone()["count"]
        self.assertEqual(count, 1)

    def test_plan_gates_limits_and_env_fallbacks(self):
        self.assertTrue(server.feature_allowed("Agency", "api_access"))
        self.assertFalse(server.feature_allowed("Pro", "api_access"))
        self.assertTrue(server.feature_allowed("Pro", "repo_audit_sarif"))
        self.assertTrue(server.public_feature_flags("Free")["domain_intel"]["allowed"])

        os.environ["OSINTPRO_MONITOR_BATCH_LIMIT"] = "bad"
        os.environ["OSINTPRO_REGISTRATION_IP_LIMIT"] = "bad"
        os.environ["OSINTPRO_BACKUP_RETENTION"] = "bad"
        os.environ["OSINTPRO_API_KEY_RATE_LIMIT"] = "bad"
        self.assertEqual(server.monitor_batch_limit(), server.DEFAULT_MONITOR_BATCH_LIMIT)
        self.assertEqual(server.registration_ip_limit(), server.DEFAULT_REGISTRATION_IP_LIMIT)
        self.assertEqual(server.backup_retention(), server.DEFAULT_BACKUP_RETENTION)
        self.assertEqual(server.api_key_rate_limit(), server.DEFAULT_API_KEY_RATE_LIMIT)

    def test_stripe_event_nonhappy_paths_and_growth_metrics(self):
        ignored = server.apply_stripe_event({"id": "evt_ignored", "type": "customer.created"})
        incomplete = server.apply_stripe_event({
            "id": "evt_incomplete",
            "type": "checkout.session.completed",
            "data": {"object": {"status": "open"}},
        })
        missing = server.apply_stripe_event({
            "id": "evt_missing",
            "type": "checkout.session.completed",
            "data": {"object": {"status": "complete"}},
        })
        user_not_found = server.apply_stripe_event({
            "id": "evt_user_not_found",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "status": "complete",
                    "client_reference_id": server.checkout_reference(str(uuid.uuid4()), "Agency"),
                }
            },
        })
        self.assertEqual(ignored["status"], "ignored")
        self.assertEqual(incomplete["status"], "incomplete")
        self.assertEqual(missing["status"], "missing_reference")
        self.assertEqual(user_not_found["status"], "user_not_found")

        user_id = str(uuid.uuid4())
        now = server.utc_now()
        with server.db() as connection:
            connection.execute(
                """
                INSERT INTO users (id, nickname, password_hash, plan, credits, created_at, updated_at)
                VALUES (?, 'growthuser', ?, 'Free', 2, ?, ?)
                """,
                (user_id, server.password_hash("pass12345"), now, now),
            )
            for index in range(3):
                report = {
                    "id": str(uuid.uuid4()),
                    "domain": f"example{index}.com",
                    "score": 80,
                    "summary": "test",
                    "generated_at": now,
                }
                server.store_report(connection, user_id, report)
        metrics = server.user_growth_metrics(user_id)
        admin_metrics = server.admin_growth_metrics()
        self.assertTrue(metrics["upsell"])
        self.assertGreaterEqual(admin_metrics["total_users"], 1)


if __name__ == "__main__":
    unittest.main()
