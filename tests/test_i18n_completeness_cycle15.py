import unittest

import server


class I18nCompletenessCycle15Tests(unittest.TestCase):
    def sample_report(self):
        return {
            "id": "i18n-complete",
            "domain": "example.com",
            "generated_at": "2026-07-05T00:00:00+00:00",
            "summary": "Domain is reachable. Missing 2 observable security headers.",
            "score": 82,
            "dns": {
                "addresses": ["203.0.113.10"],
                "mx": ["10 mail.example.com"],
                "ns": ["ns1.example.com"],
                "caa": [],
            },
            "https": {
                "status": 200,
                "certificate": {
                    "subject": "CN=example.com",
                    "expires": "Aug 29 21:41:26 2026 GMT",
                },
                "security_headers": [
                    {
                        "name": "content-security-policy",
                        "present": False,
                        "assessed": True,
                        "reason": "Header not found in the HTTPS response",
                    },
                    {
                        "name": "x-frame-options",
                        "present": True,
                        "assessed": True,
                        "value": "DENY",
                    },
                ],
            },
            "email_security": {
                "applicable": True,
                "score": 60,
                "scope_note": "Mail service or email authentication records were observed.",
                "flags": {"dmarc_present": True},
                "dmarc": [],
                "mta_sts": [],
                "tls_rpt": [],
            },
            "web_presence": {
                "security_txt": {"available": True, "present": False, "status": 404},
                "robots_txt": {"present": False},
                "sitemap_xml": {"present": False},
                "indexing_note": "robots.txt and sitemap.xml are expected indexing metadata. Their presence is not a vulnerability unless sensitive paths are disclosed.",
            },
            "rdap": {"registrar": "Example Registrar"},
            "certificate_transparency": {"subdomains": []},
            "advanced_intel": {
                "dnssec": {"enabled": False},
                "bimi": {"present": False},
                "well_known": {
                    "openid_configuration": {"present": False, "status": 404},
                },
                "takeover_hints": [],
            },
            "findings": [
                server.public_finding(
                    "medium",
                    "Missing header: content-security-policy",
                    "Reduces the publicly observable browser-side security posture.",
                    "A real attacker would combine missing browser controls with an application bug.",
                    "Customer sessions may become easier to abuse if a separate flaw exists.",
                    "Add the missing header with a staged rollout.",
                    "Collect affected response paths and current header values.",
                    "security_header:content-security-policy",
                    "security_header_missing",
                )
            ],
            "recommendations": [
                "Add or review missing security headers: content-security-policy.",
            ],
            "vulnerability_hypotheses": [
                server.hypothesis(
                    "medium",
                    "high",
                    "Potentially broader XSS surface",
                    "Content-Security-Policy was not observed on the main HTTPS response.",
                    "Validate with authorized application testing and define a CSP for scripts, frames and connect-src.",
                    "If an input-handling bug exists, the absence of CSP gives an attacker more room.",
                    "Session abuse or sensitive page content exposure.",
                    "Deploy a report-only CSP first, then enforce.",
                )
            ],
            "red_team_paths": [
                {
                    "name": "Stack fingerprint",
                    "objective": "Correlate observed technology with hardening and patch policy.",
                    "signal": "Cloudflare edge",
                }
            ],
            "purple_team_controls": [
                {
                    "control": "DNS drift detection",
                    "why": "New MX, NS, CAA or TXT records can indicate infrastructure changes.",
                    "cadence": "daily",
                }
            ],
        }

    def test_non_english_report_outputs_do_not_leak_known_english_ui(self):
        forbidden = [
            "Domain is reachable",
            "Generated:",
            "Analyst:",
            "Recommendations",
            "Security score",
            "Resolved IPs",
            "Findings",
            "Scope summary",
            "Priority actions",
            "Evidence",
            "Methodology and limitations",
            "Interpretation rules",
            "Passive boundary",
            "Missing",
            "Not assessed",
            "not observed",
            "Not applicable",
            "How an attacker may abuse it",
            "Business impact",
            "Owner action",
            "Potentially broader XSS surface",
            "Red team paths",
            "Purple team controls",
            "source,level,title,detail",
            "Add or review missing security headers",
        ]
        for lang in ("it", "es", "fr", "de", "pt"):
            with self.subTest(lang=lang):
                translated = server.translate_report(self.sample_report(), lang)
                html = server.report_document(translated)
                pdf_text = server.report_pdf(translated).decode("latin-1", "ignore")
                csv_text = server.report_findings_csv(translated).decode("utf-8")
                visible_output = "\n".join([html, pdf_text, csv_text])
                leaked = [item for item in forbidden if item in visible_output]
                self.assertEqual([], leaked)
