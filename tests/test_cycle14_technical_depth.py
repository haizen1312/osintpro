import unittest
from unittest import mock

import server


class Cycle14TechnicalDepthTests(unittest.TestCase):
    def test_dmarc_depth_findings_for_monitoring_policy_and_missing_reports(self):
        report = {
            "dns": {"caa": ["0 issue \"letsencrypt.org\""]},
            "https": {
                "available": False,
                "certificate": {"days_remaining": 90},
                "security_headers": [],
            },
            "email_security": {
                "applicable": True,
                "flags": {
                    "mx_present": True,
                    "spf_present": True,
                    "dmarc_present": True,
                    "dmarc_policy": "none",
                    "dmarc_rua_present": False,
                    "dmarc_ruf_present": False,
                    "tls_rpt_present": False,
                },
            },
            "web_presence": {"security_txt": {"available": True, "present": True}},
            "advanced_intel": {"signals": {"dnssec_enabled": True}, "takeover_hints": []},
            "network_context": [],
        }
        titles = {item["title"] for item in server.risk_findings(report)}
        self.assertIn("DMARC monitoring-only policy", titles)
        self.assertIn("DMARC aggregate reports missing", titles)
        self.assertIn("TLS-RPT missing", titles)

    def test_dmarc_depth_no_false_positive_when_enforced_and_reported(self):
        report = {
            "dns": {"caa": ["0 issue \"letsencrypt.org\""]},
            "https": {"available": False, "certificate": {"days_remaining": 90}, "security_headers": []},
            "email_security": {
                "applicable": True,
                "flags": {
                    "mx_present": True,
                    "spf_present": True,
                    "dmarc_present": True,
                    "dmarc_policy": "reject",
                    "dmarc_reject": True,
                    "dmarc_rua_present": True,
                    "dmarc_ruf_present": True,
                    "tls_rpt_present": True,
                },
            },
            "web_presence": {"security_txt": {"available": True, "present": True}},
            "advanced_intel": {"signals": {"dnssec_enabled": True}, "takeover_hints": []},
            "network_context": [],
        }
        titles = {item["title"] for item in server.risk_findings(report)}
        self.assertNotIn("DMARC monitoring-only policy", titles)
        self.assertNotIn("DMARC aggregate reports missing", titles)
        self.assertNotIn("TLS-RPT missing", titles)

    def test_repository_audit_detects_new_static_rules(self):
        audit = server.analyze_repository(
            [
                {"path": "auth.js", "content": "const token = Math.random().toString(36);\\n"},
                {"path": "crypto.py", "content": "hashlib.md5(password.encode()).hexdigest()\\n"},
                {"path": "files.py", "content": "open(request.args.get('path')).read()\\n"},
            ],
            "cycle14",
        )
        titles = {finding["title"] for finding in audit["findings"]}
        self.assertIn("Insecure randomness for security-sensitive values", titles)
        self.assertIn("Legacy hash function used in security context", titles)
        self.assertIn("Possible path traversal in file handling", titles)

    def test_wallet_dust_and_mixer_proximity_findings(self):
        findings = server.wallet_findings(
            "ethereum",
            {"tx_count": 10, "balance": 0, "tags": []},
            [{"value": "0.00001"}, {"value": "0.00002"}, {"value": "0.00003"}],
            [{"address": "0xabc", "labels": ["Tornado privacy service"]}],
        )
        titles = {finding["title"] for finding in findings}
        self.assertIn("Dust transaction pattern", titles)
        self.assertIn("Proximity to tagged mixer/privacy counterparty", titles)

    @mock.patch("server.json_get")
    def test_ip_network_context_reads_passive_rdap(self, json_get):
        json_get.return_value = {"handle": "AS64496", "name": "Example Hosting", "country": "US"}
        context = server.ip_network_context(["8.8.8.8"])
        self.assertEqual(context[0]["asn"], "AS64496")
        self.assertEqual(context[0]["provider"], "Example Hosting")


if __name__ == "__main__":
    unittest.main()
