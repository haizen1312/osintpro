import unittest

import server


def passive_report_without_caa_dnssec() -> dict[str, object]:
    return {
        "id": "test-report",
        "domain": "example.test",
        "generated_at": server.utc_now(),
        "summary": "Synthetic report for finding completeness checks.",
        "score": 100,
        "dns": {"addresses": ["203.0.113.10"], "caa": []},
        "https": {
            "available": False,
            "status": None,
            "certificate": {"days_remaining": 90, "expires": "2030-01-01"},
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
            "score": None,
            "scope_note": "No mail use observed.",
            "flags": {},
            "dmarc": [],
            "mta_sts": [],
            "tls_rpt": [],
        },
        "web_presence": {
            "security_txt": {"available": False, "present": False},
            "robots_txt": {"present": False},
            "sitemap_xml": {"present": False},
        },
        "rdap": {},
        "certificate_transparency": {"subdomains": []},
        "advanced_intel": {
            "signals": {"dnssec_enabled": False},
            "takeover_hints": [],
        },
        "technology": [],
        "recommendations": ["Review certificate governance and DNS integrity controls."],
        "red_team_paths": [],
        "purple_team_controls": [],
    }


class FindingCompletenessTests(unittest.TestCase):
    def test_all_domain_findings_have_owner_ready_context(self):
        report = passive_report_without_caa_dnssec()
        findings = server.risk_findings(report)

        self.assertGreaterEqual(len(findings), 2)
        for finding in findings:
            self.assertTrue(finding.get("abuse_path"))
            self.assertTrue(finding.get("business_impact"))
            self.assertTrue(finding.get("owner_action"))
            self.assertTrue(finding.get("evidence_to_collect"))

    def test_pdf_export_includes_abuse_context_blocks(self):
        report = passive_report_without_caa_dnssec()
        report["findings"] = server.risk_findings(report)
        report["vulnerability_hypotheses"] = server.vulnerability_hypotheses(report)

        pdf = server.report_pdf(report)

        self.assertIn(b"HOW AN ATTACKER MAY ABUSE IT", pdf)
        self.assertIn(b"BUSINESS IMPACT", pdf)
        self.assertIn(b"OWNER ACTION", pdf)
        self.assertIn(b"Score reflects material risk only", pdf)

    def test_findings_csv_includes_owner_ready_context(self):
        report = passive_report_without_caa_dnssec()
        report["findings"] = server.risk_findings(report)
        report["vulnerability_hypotheses"] = server.vulnerability_hypotheses(report)

        csv_text = server.report_findings_csv(report).decode("utf-8")

        self.assertIn("how_attacker_may_abuse_it", csv_text)
        self.assertIn("business_impact", csv_text)
        self.assertIn("owner_action", csv_text)
        self.assertIn("caa", csv_text)
        self.assertIn("dnssec", csv_text)

    def test_caa_and_dnssec_are_not_duplicated_as_hypotheses(self):
        report = passive_report_without_caa_dnssec()
        findings = server.risk_findings(report)
        hypotheses = server.vulnerability_hypotheses(report)

        caa_related = [
            item for item in findings
            if item.get("root_cause") == "caa" or "caa" in item.get("title", "").lower()
        ]
        dnssec_related = [
            item for item in findings
            if item.get("root_cause") == "dnssec" or "dnssec" in item.get("title", "").lower()
        ]

        self.assertEqual([item["title"] for item in caa_related], ["CAA missing"])
        self.assertEqual([item["title"] for item in dnssec_related], ["DNSSEC not observed"])
        self.assertFalse(any("certificate governance" in item["title"].lower() for item in hypotheses))
        self.assertFalse(any("dns integrity" in item["title"].lower() for item in hypotheses))


if __name__ == "__main__":
    unittest.main()
