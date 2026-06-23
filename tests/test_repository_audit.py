import json
import unittest
from unittest import mock

import server


class RepositoryAuditTests(unittest.TestCase):
    def test_dns_parser_ignores_cname_chain_for_requested_record(self):
        output = (
            "osintpro.example. 300 IN CNAME origin.example.net.\n"
            "origin.example.net. 300 IN CNAME edge.example.net.\n"
            "example.net. 300 IN MX 10 mail.example.net.\n"
        )

        self.assertEqual(
            server.parse_dig_answers(output, "MX"),
            ["10 mail.example.net"],
        )
        self.assertEqual(server.parse_dig_answers(output, "TXT"), [])

    @mock.patch("server.subprocess.run")
    def test_dig_filters_provider_cname_from_empty_mx(self, run):
        run.return_value.stdout = (
            "app.onrender.com. 300 IN CNAME origin.onrender.com.\n"
        )

        self.assertEqual(server.dig("app.onrender.com", "MX"), [])

    def test_detects_security_review_leads(self):
        audit = server.analyze_repository(
            [
                {
                    "path": "app.py",
                    "content": (
                        "DEBUG = " + "True\n"
                        "requests.get(url, verify=" + "False)\n"
                        'cursor.execute(' + 'f"SELECT * FROM users WHERE id={user_id}")\n'
                    ),
                },
                {
                    "path": "frontend.js",
                    "content": "panel.inner" + "HTML = apiResult;\n",
                },
                {
                    "path": "package.json",
                    "content": '{"dependencies":{"express":"^4.0.0"}}',
                },
            ],
            "demo-repository",
        )

        titles = {finding["title"] for finding in audit["findings"]}
        self.assertIn("TLS certificate verification disabled", titles)
        self.assertIn("SQL built with string interpolation", titles)
        self.assertIn("Dynamic innerHTML assignment", titles)
        self.assertIn("JavaScript dependency lockfile not included", titles)
        self.assertEqual(audit["files_scanned"], 3)

    def test_gitignore_rules_reduce_false_positive_noise(self):
        audit = server.analyze_repository(
            [
                {"path": ".gitignore", "content": "fixtures/\n*.generated.js\n"},
                {
                    "path": "fixtures/secret.py",
                    "content": 'TOKEN = "' + "ghp_" + 'abcdefghijklmnopqrstuvwxyz123456"\n',
                },
                {"path": "src/app.py", "content": "DEBUG = True\n"},
                {"path": "src/cache.generated.js", "content": "panel.innerHTML = apiResult;\n"},
            ],
            "gitignore-demo",
        )

        rendered = str(audit)
        self.assertIn("Debug mode enabled", rendered)
        self.assertNotIn("Live service credential pattern", rendered)
        self.assertNotIn("Dynamic innerHTML assignment", rendered)
        self.assertGreaterEqual(audit["ignored_files"], 2)

    def test_sarif_export_contains_rules_results_and_fixes(self):
        audit = server.analyze_repository(
            [{"path": "app.py", "content": "DEBUG = True\n"}],
            "sarif-demo",
        )

        payload = json.loads(server.format_sarif(audit).decode("utf-8"))

        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "OSINTPRO Repository Audit Lab")
        self.assertEqual(len(run["results"]), 1)
        self.assertIn("fixes", run["results"][0])
        self.assertEqual(run["results"][0]["level"], "warning")

    def test_redacts_detected_live_credential(self):
        audit = server.analyze_repository(
            [{"path": "config.py", "content": 'TOKEN = "' + "ghp_" + 'abcdefghijklmnopqrstuvwxyz123456"\n'}],
            "secret-test",
        )

        rendered = str(audit)
        self.assertIn("Live service credential pattern", rendered)
        self.assertNotIn("ghp_" + "abcdefghijklmnopqrstuvwxyz123456", rendered)
        self.assertIn("[redacted]", rendered)

    def test_email_findings_are_contextual_when_mail_is_not_observed(self):
        email = server.email_posture("example.invalid", [], [])
        report = {
            "dns": {"caa": ["letsencrypt.org"]},
            "https": {
                "certificate": {"days_remaining": 90},
                "security_headers": [
                    {"name": name, "present": True}
                    for name in server.SECURITY_HEADERS
                ],
            },
            "email_security": email,
            "web_presence": {"security_txt": {"present": True}},
            "advanced_intel": {
                "signals": {"dnssec_enabled": True},
                "takeover_hints": [],
            },
        }

        titles = {finding["title"] for finding in server.risk_findings(report)}
        hypotheses = {
            finding["title"]
            for finding in server.vulnerability_hypotheses(
                {
                    **report,
                    "web_presence": {
                        "security_txt": {"present": True},
                        "robots_txt": {"present": True},
                        "sitemap_xml": {"present": True},
                    },
                }
            )
        }
        self.assertFalse(email["applicable"])
        self.assertNotIn("SPF missing", titles)
        self.assertNotIn("DMARC missing", titles)
        self.assertNotIn("Email brand spoofing more likely", hypotheses)
        self.assertNotIn("Public map useful for reconnaissance", hypotheses)

    def test_unavailable_https_response_does_not_create_missing_headers(self):
        report = {
            "dns": {"caa": ["0 issue \"letsencrypt.org\""]},
            "https": {
                "available": False,
                "status": None,
                "certificate": {"days_remaining": 90},
                "security_headers": [
                    {
                        "name": name,
                        "assessed": False,
                        "present": False,
                        "reason": "HTTPS response unavailable; header not assessed",
                    }
                    for name in server.SECURITY_HEADERS
                ],
            },
            "email_security": {
                "applicable": False,
                "flags": {},
            },
            "web_presence": {
                "security_txt": {
                    "available": False,
                    "present": False,
                }
            },
            "advanced_intel": {
                "signals": {"dnssec_enabled": True},
                "takeover_hints": [],
            },
        }

        findings = server.risk_findings(report)
        hypotheses = server.vulnerability_hypotheses(report)

        self.assertFalse(any("Missing header" in item["title"] for item in findings))
        self.assertFalse(any("XSS" in item["title"] for item in hypotheses))
        self.assertFalse(any("SSL stripping" in item["title"] for item in hypotheses))


if __name__ == "__main__":
    unittest.main()
