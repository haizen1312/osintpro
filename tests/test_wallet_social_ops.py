import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import server


class TempDatabaseMixin:
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


class WalletSocialOpsTests(TempDatabaseMixin, unittest.TestCase):
    def test_bitcoin_wallet_analysis_from_public_shape(self):
        def fake_json(url: str):
            if url.endswith("/txs"):
                return [
                    {
                        "txid": "ab" * 32,
                        "fee": 1200,
                        "status": {"block_time": 1_700_000_000},
                        "vin": [
                            {
                                "prevout": {
                                    "scriptpubkey_address": "bc1qsource0000000000000000000000000000000",
                                    "value": 100_000_000,
                                }
                            }
                        ],
                        "vout": [
                            {
                                "scriptpubkey_address": "bc1qtest0000000000000000000000000000000000",
                                "value": 70_000_000,
                            },
                            {
                                "scriptpubkey_address": "bc1qchange000000000000000000000000000000",
                                "value": 29_998_800,
                            },
                        ],
                    }
                ]
            return {
                "chain_stats": {
                    "funded_txo_sum": 200_000_000,
                    "spent_txo_sum": 50_000_000,
                    "tx_count": 120,
                },
                "mempool_stats": {},
            }

        with mock.patch("server.json_get", side_effect=fake_json):
            report = server.analyze_wallet("bc1qtest0000000000000000000000000000000000")

        self.assertEqual(report["chain"], "bitcoin")
        self.assertEqual(report["asset"], "BTC")
        self.assertGreater(report["risk_score"], 0)
        self.assertEqual(len(report["transactions"]), 1)
        self.assertTrue(report["counterparties"])
        self.assertIn("High-activity wallet", {item["title"] for item in report["findings"]})

    def test_ethereum_wallet_analysis_from_public_shape(self):
        address = "0x0000000000000000000000000000000000000000"

        def fake_json(url: str):
            if "/api?" in url:
                return {
                    "result": [
                        {
                            "from": "0x1111111111111111111111111111111111111111",
                            "to": address,
                            "value": str(2 * 10**18),
                            "hash": "0x" + "ab" * 32,
                            "timeStamp": "1700000000",
                            "gasUsed": "21000",
                            "gasPrice": "1000000000",
                            "isError": "0",
                            "methodId": "0x",
                        }
                    ]
                }
            return {
                "coin_balance": str(5 * 10**18),
                "is_contract": True,
                "metadata": {"tags": [{"name": "exchange"}]},
                "public_tags": [{"label": "Service"}],
                "ens_domain_name": "example.eth",
            }

        with mock.patch("server.json_get", side_effect=fake_json):
            report = server.analyze_wallet(address)

        self.assertEqual(report["chain"], "ethereum")
        self.assertEqual(report["balance"], 5.0)
        self.assertEqual(report["transactions"][0]["direction"], "incoming")
        self.assertIn("Contract or smart account address", {item["title"] for item in report["findings"]})

    def test_social_username_analysis_with_mocked_profiles(self):
        def fake_probe(platform: dict[str, str], username: str):
            present = platform["name"] in {"GitHub", "X", "Telegram", "Instagram", "TikTok"}
            return {
                "platform": platform["name"],
                "url": platform["url"].format(username=username),
                "final_url": platform["url"].format(username=username),
                "status": 200 if present else 404,
                "present": present,
                "confidence": "high" if present else "medium",
            }

        with mock.patch("server.profile_probe", side_effect=fake_probe):
            report = server.analyze_username("example")

        self.assertEqual(report["username"], "example")
        self.assertGreaterEqual(report["score"], 60)
        titles = {item["title"] for item in report["findings"]}
        self.assertIn("Username reused across many platforms", titles)
        self.assertIn("Observable developer footprint", titles)

    def test_stripe_event_activates_paid_plan_and_dedupes(self):
        user_id = str(uuid.uuid4())
        now = server.utc_now()
        with server.db() as connection:
            connection.execute(
                """
                INSERT INTO users (id, nickname, password_hash, plan, credits, created_at, updated_at)
                VALUES (?, 'paidtest', ?, 'Free', 5, ?, ?)
                """,
                (user_id, server.password_hash("pass12345"), now, now),
            )
        event = {
            "id": "evt_test_paid",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "status": "complete",
                    "client_reference_id": server.checkout_reference(user_id, "Pro"),
                }
            },
        }

        first = server.apply_stripe_event(event)
        second = server.apply_stripe_event(event)

        self.assertEqual(first["status"], "activated")
        self.assertEqual(first["plan"], "Pro")
        self.assertEqual(second["status"], "duplicate")
        with server.db() as connection:
            row = connection.execute("SELECT plan FROM users WHERE id = ?", (user_id,)).fetchone()
        self.assertEqual(row["plan"], "Pro")

    def test_backup_validate_and_restore_rejects_invalid_payload(self):
        backup = server.create_sqlite_backup("unit-test")
        backup_file = server.backup_path(backup["name"])

        counts = server.validate_sqlite_database(backup_file)
        self.assertIn("users", counts)
        self.assertTrue(backup_file.exists())

        with self.assertRaises(ValueError):
            server.restore_sqlite_backup(b"not a sqlite file")

    def test_local_network_snapshot_has_safe_filters(self):
        snapshot = server.local_network_snapshot()

        self.assertIn("capture_filters", snapshot)
        self.assertTrue(any(item["filter"] == "dns" for item in snapshot["capture_filters"]))


if __name__ == "__main__":
    unittest.main()
