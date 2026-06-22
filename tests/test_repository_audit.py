import unittest

import server


class RepositoryAuditTests(unittest.TestCase):
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
        self.assertFalse(email["applicable"])
        self.assertNotIn("SPF missing", titles)
        self.assertNotIn("DMARC missing", titles)


if __name__ == "__main__":
    unittest.main()
