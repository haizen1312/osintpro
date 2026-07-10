import unittest
from pathlib import Path

import server


class I18nCompletenessCycle15Tests(unittest.TestCase):
    technical_i18n_passthrough = {
        "OSINTPRO",
        "DNS",
        "TLS",
        "SPF",
        "DMARC",
        "BIMI",
        "MTA-STS",
        "TLS-RPT",
        "CAA",
        "RDAP",
        "HTTPS",
        "HTTP",
        "JSON-LD",
        "JSON-LD, DOT, CSV",
        "DOT",
        "CSV",
        "SARIF",
        "API",
        "PDF",
        "Web Audit Lab",
        "Network Lab",
        "Game Security Lab",
        "Burp Suite",
        "XSS",
        "SQL injection",
        "SSRF",
        "CSRF",
        "CSP",
        "CT",
        "GitHub",
        "Stripe",
        "Pro",
        "Agency",
        "Free",
        "Wallet",
        "Bitcoin",
        "Ethereum",
        "Backend",
        "Registrar",
        "Nameserver",
        "Repo Audit Lab",
        "Repository Audit Lab",
        "Network Traffic Lab",
        "Blockchain OSINT",
        "Entity graph",
        "Graph",
        "Core",
        "Position",
        "Boundary",
        "All",
        "Plan",
        "Monitor",
        "Monitors",
        "info",
        "N/D",
        "n/d",
        "OK",
        "report",
        "Dashboard",
        "Account",
        "Logout",
        "Checkout",
        "Monetization",
        "API Preview",
        "Passive API boundary",
        "Public metadata endpoint",
        "API key management",
        "API key name",
        "Create API key",
        "Current API surface",
        "Identity",
        "Guest",
        "Language",
        "Scope",
        "Mail exchange",
        "Workspace Free",
        "Intel social",
        "Analista",
        "Motivo",
        "alta",
        "media",
        "fonte",
        "Metodologia",
        "Grafo",
        "Comando",
        "pronto",
    }

    italian_leak_markers = [
        "punteggio sicurezza",
        "sicurezza email",
        "finding prioritari",
        "nessun",
        "nessuna",
        "il dominio",
        "giornaliera",
        "domini monitorati",
        "modalita",
        "cartella cliente",
        "apri casi",
        "raccogli evidenze",
        "pacchetto evidenze",
        "rumore grezzo",
        "solo engineering",
        "controlli sicurezza",
        "priorita difensiva",
        "controllo...",
        "workflow di revisione",
        "rivedi i lab",
        "nessuno rilevato",
        "regola rilevata",
        "repository auditato",
        "wallet analizzato",
        "ricostruzione frode",
        "storico wallet",
        "indirizzi tracciati",
        "report generati",
        "cancella",
        "dominio da monitorare",
        "cosa sbloccano",
        "crea account",
        "accedi",
        "elimina account",
        "revisione statica",
        "postura codice",
        "contesto rilevato",
        "soglia confidenza",
        "perche",
        "si applica",
        "percorso probabile attaccante",
        "impatto probabile",
        "export fallito",
    ]

    def flatten_locale(self, value, prefix=""):
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else key
                yield from self.flatten_locale(child, path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from self.flatten_locale(child, f"{prefix}[{index}]")
        elif isinstance(value, str):
            yield prefix, value

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

    def test_round2_exact_strings_are_wired_and_translated(self):
        required_static = [
            "Passive only",
            "no exploits",
            "Graph-first",
            "Delivery",
            "Passive collection only: DNS, TLS certificate, public web posture and security headers. No aggressive scanning, exploit execution, credential attacks or brute force.",
            "Certificate Transparency",
            "no data",
            "Not declared",
            "no priority SaaS/cloud CNAME observed",
            "Findings",
            "Possible Vulnerabilities",
            "Red Team Paths",
            "Purple Team Controls",
            "Burp Suite map",
            "What each Burp-style feature means",
            "Exploit concepts",
            "Vulnerability classes explained safely",
            "Builds a site map and scope. In OSINTPRO this becomes a clear list of authorized domains and public evidence.",
            "Untrusted input can run script in a user's browser.",
            "No password guessing, credential stuffing or token theft.",
        ]
        for lang in ("it", "es", "fr", "de", "pt"):
            with self.subTest(lang=lang):
                locale = server.load_locale(lang)
                static = locale.get("static", {})
                missing = [item for item in required_static if static.get(item) in {None, item}]
                self.assertEqual([], missing)

    def test_non_italian_locales_do_not_keep_italian_or_copied_values(self):
        italian = dict(self.flatten_locale(server.load_locale("it")))
        ignored_paths = {
            "ui.language.it",
            "ui.hero.proof.graph_formats",
        }
        for lang in ("es", "fr", "de", "pt"):
            with self.subTest(lang=lang):
                locale = server.load_locale(lang)
                flat_locale = dict(self.flatten_locale(locale))
                italian_leaks = []
                copied_values = []
                for path, value in flat_locale.items():
                    lower_value = value.lower()
                    if any(marker in lower_value for marker in self.italian_leak_markers):
                        italian_leaks.append((path, value))
                    if path in ignored_paths:
                        continue
                    if italian.get(path) == value and value not in self.technical_i18n_passthrough:
                        copied_values.append((path, value))

                self.assertEqual([], italian_leaks)
                self.assertEqual([], copied_values)

    def test_sidebar_and_web_audit_use_runtime_i18n_hooks(self):
        index_html = Path("index.html").read_text()
        app_js = Path("app.js").read_text()
        for key in (
            "nav.group.command",
            "nav.group.evidence",
            "nav.group.defensive_labs",
            "nav.group.operations",
        ):
            self.assertIn(f'data-i18n="{key}"', index_html)
        self.assertIn('root.querySelectorAll?.("[data-i18n]")', app_js)
        for phrase in (
            'translateExactText("What each Burp-style feature means")',
            'translateExactText("Vulnerability classes explained safely")',
            'translateExactText(item.title)',
            'translateExactText(item.risk)',
            'translateExactText(item.safe)',
            'translateExactText(item.blocked)',
            'translateExactText("no priority SaaS/cloud CNAME observed")',
            'translateExactText("Possible Vulnerabilities")',
        ):
            self.assertIn(phrase, app_js)

    def test_italian_pdf_keeps_latin_accents(self):
        report = server.translate_report(self.sample_report(), "it")
        pdf = server.report_pdf(report)
        self.assertIn("Il dominio è raggiungibile".encode("latin-1"), pdf)
        self.assertIn("vulnerabilità".encode("latin-1"), pdf)
        self.assertIn(b"/Encoding /WinAnsiEncoding", pdf)
