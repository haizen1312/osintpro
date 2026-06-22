# OSINTPRO

Live demo: https://osintpro-48j4.onrender.com/

Status: Live demo online | Python backend | SQLite MVP | Stripe Payment Links | Passive-only safety boundary

Sections: [Try It](#try-it) | [Local Setup](#local-development) | [Positioning](#positioning) | [Safety](#safety-boundary) | [Explain It](docs/EXPLAIN_OSINTPRO.md) | [Growth](docs/GITHUB_GROWTH.md)

OSINTPRO is a freemium passive OSINT and defensive review SaaS for client-ready investigation graphs, domain intelligence, brand monitoring, repository security review, social username checks and blockchain wallet tracing.

It is built for consultants, small agencies, fraud analysts, security-minded founders and learners who need fast, readable intelligence from public sources without running aggressive scans.

If this project is useful, star the repository and share the live demo. That helps the project reach more builders, investigators and defenders.

## Try It

Live app:

```text
https://osintpro-48j4.onrender.com/
```

Fast local start:

```bash
git clone https://github.com/haizen1312/osintpro.git
cd osintpro
python3 server.py
```

Then open:

```text
http://127.0.0.1:8765
```

This repository is public for product visibility and deployment transparency, but OSINTPRO is proprietary software. See `LICENSE.md`.

## What It Does

OSINTPRO collects passive public signals and turns them into client-ready reports and relationship graphs:

- Domain OSINT: DNS/IP resolution, A/AAAA/MX/NS/TXT/CAA/SOA, HTTPS certificate, public security headers and RDAP.
- Email posture: SPF, DMARC, MTA-STS, TLS-RPT and brand impersonation signals.
- Web exposure: security.txt, robots.txt, sitemap.xml and public well-known endpoints.
- Certificate Transparency: observable names and subdomains from public CT logs.
- Passive technology fingerprinting from headers and web signals.
- Risk findings, vulnerability hypotheses and Red/Purple Team recommendations derived only from passive evidence.
- Web Audit Lab: Burp-style beginner workflow with safe commands, evidence checklist and technical glossary.
- Repository Audit Lab: static source review with file/line evidence, confidence, applicability and remediation without executing uploaded code.
- Network Traffic Lab: Wireshark-style website traffic mode plus own-network mode for local authorized LAN analysis.
- Social OSINT: public username presence checks across social, developer and community platforms.
- Wallet OSINT: public Bitcoin and Ethereum/EVM balance, recent movements, counterparties and explorer links.
- Entity graph: a workspace view that connects domains, usernames, profiles, DNS, findings, technologies, wallets, transactions and counterparties.
- Monitoring: saved domains can be rechecked for public drift.
- PDF/CSV exports for client delivery and internal case notes.

OSINTPRO does not run exploits, brute force, credential attacks, invasive scans, unauthorized packet capture or wallet transactions. Wallet analysis is limited to public blockchain data and investigative visualization.

## Positioning

OSINTPRO is not trying to be a raw scanner, a Maltego clone or an offensive security toolkit. Its main job is to make passive public evidence easier to understand, connect and deliver to a client.

The core workflow is:

1. Run a passive investigation on a domain, public username or wallet, or review an authorized source repository.
2. Review normalized findings, posture risks and plain-English explanations.
3. Connect assets, identities, wallets, transactions, technologies and findings in the entity graph.
4. Export the case as PDF/CSV or keep it in a client folder for monitoring and follow-up.

That focus makes OSINTPRO useful for small agencies and investigators that need repeatable evidence packages, not just another pile of raw signals.

Strategy docs:

- [Data sources and unit economics](docs/DATA_SOURCES.md)
- [Go-to-market and distribution plan](docs/DISTRIBUTION.md)
- [API preview and integration roadmap](docs/API_PREVIEW.md)
- [How to explain and sell OSINTPRO](docs/EXPLAIN_OSINTPRO.md)

## How OSINTPRO Is Different

OSINTPRO competes on workflow and delivery, not on being the biggest raw-data scanner.

| Feature | OSINTPRO | VirusTotal | Maltego | Shodan | SecurityTrails |
| --- | --- | --- | --- | --- | --- |
| Passive domain OSINT | Yes | Yes | Yes | Limited | Yes |
| Client-ready reports | Yes | Limited | Limited | No | Limited |
| Entity graph | Yes | No | Yes | No | Limited |
| Web Audit Lab | Yes | No | No | No | No |
| Static repository review | Yes | No | No | No | No |
| Wallet tracing | Yes | No | Limited | No | No |
| Monitoring for agencies | Yes | Limited | Limited | Yes | Yes |
| Offensive scanning focus | No | No | No | Yes | No |
| Best for | Small agencies and investigators | Threat intel lookups | Enterprise investigations | Internet-exposed services | Domain intelligence teams |

Pricing changes over time, so the table avoids exact competitor prices. The practical difference is simpler: OSINTPRO is for people who need understandable evidence packages, not only raw lookup results.

## Go-To-Market

Target audience:

- small security consulting agencies
- privacy, GDPR and web agencies
- fraud analysts
- blockchain compliance and scam-research teams
- SaaS founders who need lightweight public exposure checks

First 6-month plan:

| Period | Channel | Goal |
| --- | --- | --- |
| Month 1-2 | GitHub, Product Hunt preparation, Hacker News technical post | Validate positioning and collect feedback. |
| Month 3-4 | LinkedIn outreach to 100 small agencies | Convert report usage into Pro/Agency trials. |
| Month 5-6 | Reddit cybersecurity, OSINT and crypto safety communities | Build repeat visibility with educational workflows. |
| Ongoing | GitHub issues, docs SEO, sanitized examples | Keep searchable product activity alive. |

Current public traction as of June 23, 2026:

- Live demo is online.
- GitHub stars: 2.
- GitHub forks: 0.
- Open public roadmap issues: 1.
- Stripe Payment Links are configured.
- First-party conversion signals are tracked in the private admin panel.
- Agency/Admin API key MVP is available for controlled workflow integrations.
- Verified public signup, paid-conversion and MRR totals are not published yet because production usage is still early and those numbers should not be invented from local development data.

## Quick Links

- [Live demo](https://osintpro-48j4.onrender.com/)
- [Local setup guide](docs/LOCAL_SETUP.md)
- [How to explain OSINTPRO](docs/EXPLAIN_OSINTPRO.md)
- [Web Audit Lab guide](docs/WEB_AUDIT_LAB.md)
- [Repository Audit Lab guide](docs/REPOSITORY_AUDIT_LAB.md)
- [GitHub growth playbook](docs/GITHUB_GROWTH.md)
- [Data sources and unit costs](docs/DATA_SOURCES.md)
- [Distribution plan](docs/DISTRIBUTION.md)
- [Outreach playbook](docs/OUTREACH_PLAYBOOK.md)
- [API preview](docs/API_PREVIEW.md)
- [Production readiness](docs/PRODUCTION_READINESS.md)
- [Architecture](ARCHITECTURE.md)
- [Performance notes](PERFORMANCE.md)
- [AI development guide](docs/AI_DEVELOPMENT_GUIDE.md)
- [Showcase and share copy](docs/SHOWCASE.md)
- [Sanitized example reports](docs/EXAMPLE_REPORTS.md)
- [Product roadmap](ROADMAP.md)
- [Public roadmap issues](https://github.com/haizen1312/osintpro/issues)

## Product Status

- Deployed on Render: `https://osintpro-48j4.onrender.com/`
- Public GitHub repository connected to automatic deploys.
- Python backend with health, auth, analysis, report, monitoring, billing and admin endpoints.
- SQLite persistence with configurable database and backup paths.
- Nickname/password accounts with PBKDF2 password hashes and HTTP-only session cookies.
- Server-side freemium credits and plan limits.
- Agency/Admin API keys for passive JSON report workflows.
- Account-isolated history: users only see their own domain, social and wallet reports.
- History deletion controls for domain, social, wallet and full workspace data.
- Agency client folders for grouping domain, social, wallet and monitoring work by client or case.
- Agency case summaries with asset counts, priority signals and average posture score.
- Entity graph filters for domains, people, wallets and findings.
- Server-side PDF export plus CSV exports for reports, wallet history and Web Audit Lab checklists.
- Guest exports retain only the latest session report and show browser download feedback.
- Report comparison for repeated domain reports.
- Saved Web Audit Lab playbooks for repeatable beginner-safe reviews.
- Wallet case notes, manual tags, transaction timeline and counterparty hop expansion for passive fraud reconstruction.
- Stripe Payment Links and signed webhook activation for Pro/Agency plans.
- Private operational admin panel for production status, plans, backups and Stripe events.
- Cron-protected monitoring and backup endpoints.
- GitHub Actions workflow for free scheduled monitor runs and SQLite backup artifacts.
- Beginner-friendly Web Audit Lab and Network Traffic Lab for authorized passive review.
- Static Repository Audit Lab with client-side filtering, bounded uploads, redacted evidence and no code execution.
- Security-conscious repository hygiene: `.gitignore`, `.env.example`, `SECURITY.md`, no committed secrets.

## Local Development

Full guide: `docs/LOCAL_SETUP.md`

```bash
python3 server.py
```

Open:

```text
http://127.0.0.1:8765
```

The SQLite database is created automatically on first run.

Optional persistent paths:

```bash
OSINTPRO_DB_PATH="/path/to/osintpro.sqlite3" \
OSINTPRO_BACKUP_DIR="/path/to/backups" \
python3 server.py
```

Copy `.env.example` for local configuration. Production secrets should be set in Render environment variables, never committed to GitHub.

## How To Explain The Tool

Short version:

```text
OSINTPRO turns passive public evidence from domains, usernames and blockchain wallets into client-ready investigation graphs, reports and monitoring.
```

Longer explanation:

OSINTPRO is for consultants, agencies, founders and fraud analysts who need to understand public exposure without running aggressive scans. It collects public DNS, HTTPS, email posture, web exposure, username and wallet signals, then converts them into readable findings, graph relationships and exportable reports.

See `docs/EXPLAIN_OSINTPRO.md` for demo scripts, customer pitch, GitHub pitch and safe disclaimers.

## Monetization

Current pricing model:

- Free: 5 starter reports and 1 monitored domain for a 30-day trial.
- Pro: 19 EUR/month, unlimited reports and 5 monitored domains.
- Agency: 79 EUR/month, client reporting workflows and 25 monitored domains.

Free tier experiments can be tested with `OSINTPRO_FREE_TIER_VARIANT`:

| Variant | Reports | Monitors | Purpose |
| --- | --- | --- | --- |
| A | 5 starter reports | 1 for 30 days | Current activation baseline. |
| B | 3 starter reports | 1 for 30 days | Tests whether a tighter report cap creates stronger upgrade intent. |
| C | Unlimited reports | 1 for 30 days | Tests whether report freedom plus monitor habit improves activation. |

The app records first-party conversion signals such as billing views, checkout clicks, exhausted credits and monitor-limit hits.

Stripe Payment Links are configured through environment variables:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_WEBHOOK_SECRET="whsec_..."
```

Stripe webhook endpoint:

```text
https://osintpro-48j4.onrender.com/api/stripe/webhook
```

Required Stripe event:

```text
checkout.session.completed
```

The free tier is for evaluation and product trust. Ongoing usage, monitoring and agency workflows are positioned for paid plans.

## Admin And Operations

The private admin panel is protected by `OSINTPRO_ADMIN_CODE`.

Operational capabilities:

- production status checks
- user and plan overview
- manual plan updates
- sanitized operational export
- SQLite snapshot creation and restore
- recent Stripe event review

The admin code is an environment secret and should not appear in GitHub, screenshots or public documentation.

## Monitoring

Saved domains can be rechecked manually in the app or through the protected cron endpoint:

```bash
curl -X POST "https://<host>/api/cron/monitors" \
  -H "Authorization: Bearer $OSINTPRO_CRON_SECRET"
```

Useful variables:

```text
OSINTPRO_CRON_SECRET
OSINTPRO_MONITOR_BATCH_LIMIT=20
OSINTPRO_API_KEY_RATE_LIMIT=30
OSINTPRO_REGISTRATION_IP_LIMIT=3
OSINTPRO_REGISTRATION_IP_ALLOWLIST="203.0.113.10,198.51.100.0/24"
OSINTPRO_FREE_TIER_VARIANT="A"
OSINTPRO_DB_PATH="/path/to/osintpro.sqlite3"
OSINTPRO_BACKUP_DIR="/path/to/backups"
OSINTPRO_BACKUP_RETENTION=30
OSINTPRO_ALERT_WEBHOOK_URL="https://example.com/webhook"
OSINTPRO_REPORT_BRAND="OSINTPRO"
```

`OSINTPRO_REGISTRATION_IP_ALLOWLIST` can exclude trusted connections from the free-account anti-abuse limit.
`OSINTPRO_REPORT_BRAND` changes the heading used in generated HTML/PDF reports for agency delivery.

## Free Persistence Strategy

Render Free does not include a persistent disk. OSINTPRO stays usable without paid infrastructure by combining SQLite with GitHub Actions artifacts.

This is acceptable for a zero-cost MVP, but it is not the target production architecture for paying customers. Once real paid usage starts, the first infrastructure upgrade should be persistent storage or managed PostgreSQL so Stripe billing state, user accounts, history and monitor data do not depend on artifact restores.

The scheduled workflow can:

- call `/api/cron/monitors`
- call `/api/cron/backup`
- download `/api/cron/backup/download`
- store a SQLite snapshot as a private GitHub Actions artifact

If the Render filesystem resets:

1. Open GitHub Actions.
2. Select the latest successful `OSINTPRO monitor cron` run.
3. Download the `osintpro-sqlite-backup-<run_id>` artifact.
4. Extract `osintpro.sqlite3`.
5. Open the private admin panel.
6. Upload the snapshot through `Restore SQLite snapshot`.

The restore flow validates the SQLite snapshot, creates a pre-restore backup and then replaces the current database.

## Wallet OSINT Scope

Wallet OSINT accepts public Bitcoin or Ethereum/EVM addresses and returns:

- public balance
- recent transactions
- counterparties
- direction and approximate flow
- explorer links
- heuristic findings such as high fan-in/fan-out, smart contract/account type and activity bursts

This feature is designed for authorized fraud reconstruction, scam wallet triage and compliance-style case mapping. It does not move funds, deanonymize private users, bypass mixers or provide evasion guidance.

## Web Audit Lab Scope

The Web Audit Lab translates Burp Suite-style concepts into a beginner-friendly authorized testing workflow:

- proxy, request, response, headers, cookies, CSP and HSTS explained in plain English
- safe terminal checks using `curl`, `openssl` and `dig`
- evidence checklist for headers, `security.txt`, `robots.txt` and `sitemap.xml`
- Burp feature map covering Target, Proxy, Repeater, Decoder, Comparer, Logger, Sequencer, Scanner, Intruder and Collaborator
- vulnerability classes explained safely: XSS, SQL injection, IDOR, authentication/session risk, SSRF, file upload risk, command injection and CSRF
- passive findings converted into client-ready next steps

It does not provide exploit payloads, automated fuzzing, brute force, credential attacks, callback exploitation or invasive crawling. It is designed for domains the user owns or is explicitly authorized to review.

## Repository Audit Lab Scope

Repository Audit Lab reviews an authorized local source folder without executing it:

- filters dependency directories, build output, binaries and oversized files in the browser
- checks eligible source text for secret exposure, unsafe execution, deserialization, TLS, CORS, SQL and frontend review patterns
- reports file, line, severity, confidence, applicability and remediation
- redacts secret-like evidence before returning or rendering it
- exports the result as JSON for developer follow-up

It does not install dependencies, run builds, execute uploaded code, generate exploits or claim that a pattern match proves exploitability. See the [Repository Audit Lab guide](docs/REPOSITORY_AUDIT_LAB.md).

## Network Traffic Lab Scope

The Network Traffic Lab translates Wireshark-style packet analysis into two simple, readable workflows:

- Website traffic mode: DNS query and answer story for the authorized domain
- Website traffic mode: TCP/TLS connection timeline, certificate issuer, subject and expiry
- Website traffic mode: HTTP response status, server hint and security headers
- Own-network mode: local runtime IP context when OSINTPRO is running on the user's own machine
- Own-network mode: Wireshark filters for ARP, DNS, TCP/443, mDNS and DHCP/BOOTP
- copy-friendly Wireshark display filters for authorized local captures
- safe terminal checks using `dig`, `curl` and `openssl`

It does not secretly sniff traffic, capture other users' packets, decode private sessions, expose cloud server network details or bypass encryption. Real packet capture should only be performed on devices and networks the operator owns or is explicitly authorized to inspect.

## GitHub Discovery Plan

Free ways to improve repository traffic:

- Keep the README in English with clear keywords: passive OSINT, domain intelligence, brand monitoring, crypto wallet OSINT, blockchain tracing, fraud investigation, network traffic analysis, Wireshark workflow, threat intelligence.
- Use GitHub topics that match real search intent.
- Keep the live demo URL in the repository homepage.
- Keep `docs/LOCAL_SETUP.md` and `docs/EXPLAIN_OSINTPRO.md` linked near the top.
- Maintain `docs/SHOWCASE.md` with copy/paste launch posts and sanitized workflows.
- Publish small example reports with sanitized public targets.
- Open roadmap issues for high-value features so GitHub has searchable project activity.
- Keep public roadmap issues active: `https://github.com/haizen1312/osintpro/issues`
- Share the live demo in relevant communities only with a passive/intelligence framing, not as an offensive scanner.

## Roadmap

See `ROADMAP.md` for the public product roadmap.

Near-term technical work:

1. Password reset remains intentionally gated until a trusted recovery channel is introduced.
2. Agency workspaces with client folders are implemented.
3. Free-to-Pro/Agency onboarding is built into the Billing page.
4. Server-side PDF generation is implemented at `/api/reports/<id>/pdf`.
5. Web Audit Lab CSV export and saved playbooks are implemented.
6. Wallet graph improvements now include manual tags, case notes, transaction timeline and counterparty hop expansion.
7. Entity graph filters, agency case summaries, report comparison and sanitized example reports are implemented.
8. PostgreSQL migration remains intentionally gated until paid usage justifies the cost.

## Safety Boundary

OSINTPRO is a passive intelligence and monitoring product. It should be used only for domains, brands, usernames, wallets and investigations where the user has authorization or a legitimate public-interest reason.
