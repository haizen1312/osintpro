# OSINTPRO Roadmap

OSINTPRO is moving toward a focused passive intelligence workspace for domains, brands, public identities and blockchain wallets.

## Product Thesis

The primary product is the client-ready investigation graph: passive evidence from domains, public profiles and wallets gets normalized into readable findings, relationships, notes, exports and monitoring.

Web Audit Lab, Repository Audit Lab, Network Traffic Lab, Social OSINT and Wallet OSINT are input modules for that workspace. They should strengthen the investigation graph instead of becoming disconnected products.

## Current Focus

- Keep the core app fast, readable and fully English.
- Improve account-level workspace organization.
- Expand passive wallet OSINT for fraud reconstruction.
- Strengthen exports and case-ready reporting.
- Expand beginner-friendly Web Audit Lab workflows without adding invasive scanning.
- Expand defensive repository review without executing uploaded code or generating exploits.
- Add beginner-friendly network traffic analysis without unauthorized packet capture.
- Add defensive online-game security review for studios without cheat, bypass or exploit guidance.
- Keep hosting costs at zero until paid usage justifies infrastructure spend.
- Keep infrastructure risk visible while the project stays on zero-cost hosting.

## Near-Term Milestones

### Intelligence Workspace

- Cleaner dashboard for choosing domain, social or wallet investigations.
- Web Audit Lab for guided passive web review, beginner commands and technical explanations.
- Network Traffic Lab for Wireshark-style website traffic and own-network interpretation.
- Entity graph with stronger filtering by domain, person, wallet and finding type.
- Entity graph export for external case tooling.
- Manual notes and tags for wallets, counterparties and suspicious infrastructure.
- Better case summaries for agencies and investigators.

Status: client folders, active folder routing, saved playbook organization,
case summaries, entity graph filters, JSON-LD/DOT/CSV graph export, a cleaner
command/evidence/labs/operations dashboard and dual-mode Network Traffic Lab
are implemented. Auth is now split across dedicated login, register, password
reset and security settings pages.

### Game Security Lab

- Defensive review workflow for studios building online PC games.
- Trust-boundary checklist for auth, inventory, economy, netcode, anti-cheat telemetry, backend APIs and build pipeline.
- Engineering-ticket output that avoids cheats, bypasses, packet tampering steps or exploit automation.

Status: Game Security Lab is implemented as a defensive engineering checklist
inside the app. It is intentionally educational and remediation-oriented, not
an offensive game-hacking module.

### Wallet OSINT

- Hop expansion for selected counterparties.
- Manual labels such as exchange, scam, victim, bridge, mixer, service or unknown.
- CSV export for wallet transactions and counterparties.
- Case timeline view for suspicious wallet flows.

Status: wallet CSV export, manual wallet tags, case notes, transaction timeline and counterparty hop expansion are implemented. Timeline depth can improve later with richer public-chain sources.

### Reporting

- Server-side PDF generation.
- Web Audit Lab export with evidence checklist and glossary.
- Sanitized example reports for public marketing.
- Agency-friendly report branding.
- Report comparison for monitored domains.

Status: server-side PDF export, report CSV, Web Audit Lab CSV/playbook export,
anonymous session export support, sanitized example reports, report comparison
and configurable report branding are implemented. PDF reports now use a
branded multipage A4 layout with executive summary, findings, evidence,
methodology and numbered confidentiality footers. Export endpoints have HTTP
regression tests.

### Repository Audit

- Static source-folder review with browser-side filtering.
- File and line references with redacted evidence.
- Applicability and confidence notes to reduce false positives.
- JSON export for developer remediation work.
- SARIF export for code scanning and security-review pipelines.
- Adjustable confidence threshold in the UI.
- `.gitignore` parsing to reduce generated-file and fixture noise.
- Dependency advisory matching for npm, pip, Cargo and Composer manifests.
- Future framework-aware route/controller rules.

Status: the defensive static-analysis MVP is implemented with JSON/SARIF
exports, confidence filtering, `.gitignore` support and persisted redacted
audit reports. It now includes offline dependency advisory matching for common
manifest files. It does not execute source code, install dependencies or retain
uploaded source bundles.

### Monetization

- Better Free-to-Pro onboarding.
- Agency workspaces with client folders.
- Billing status visibility after Stripe checkout.
- Paid plan value messaging inside the app.
- First-party conversion signals for checkout clicks, paywall hits and monitor-limit hits.

Status: Free-to-Pro/Agency onboarding, billing status messaging, agency client folder value and first-party conversion signals are implemented in the app.
Plan-level feature flags, account metrics and non-invasive upgrade nudges are
also implemented.

### API

- Keep `/api/meta` public for product metadata and safety boundaries.
- Design paid agency API keys only after persistent production storage is available.
- Add per-key usage metering, quotas, logs and deletion controls before selling API access.

Status: API preview documentation, public metadata endpoint and Agency/Admin API key MVP are implemented. Higher-volume API selling remains deferred until persistent storage and stronger metering are in place.
Public API status and GET domain analysis endpoints are implemented for API key
users, alongside the existing POST report endpoints.

### Notifications

- Account webhooks for monitor and report events.
- Optional SMTP email notification for monitor drift.
- Delivery logs for webhook/email attempts.

Status: Pro/Agency webhook management, monitor.changed delivery and optional
SMTP email notification are implemented. Email remains disabled until SMTP
environment variables and a recipient are configured. Password reset links use
one-time hashed tokens and send only when SMTP and an account recovery address
are available.

### Infrastructure

- Continue with SQLite and free Render/GitHub Actions backup artifacts while traffic is early.
- Add persistent disk or PostgreSQL when paid usage, real customer data or recurring monitor volume makes data durability more important than zero-cost hosting.
- Keep secrets in environment variables and out of GitHub.

Status: SQLite remains the default zero-cost database. PostgreSQL is
intentionally deferred because the project is currently constrained to no paid
infrastructure. A production readiness checklist is documented in
`docs/PRODUCTION_READINESS.md`, and the migration blueprint/config preview is
documented in `POSTGRES_MIGRATION.md`.

## Known Limitations

- PostgreSQL has a documented migration/configuration blueprint, but SQLite is
  still the only active runtime adapter until paid usage justifies migration.
- Conversion analytics are first-party event counts, not a full experiment
  dashboard.
- Standard-library trace currently covers about 59.48% of the monolithic
  backend with 43 tests. The graph/SARIF/export/security/admin/cron/growth/API
  and webhook paths are covered, but reaching 70% honestly requires more
  fixtures around monitoring, network edge cases and route handlers or a deeper
  backend extraction.

## Safety Boundary

OSINTPRO will remain a passive OSINT product. It will not add exploit execution, brute force, credential attacks, invasive scanning, wallet movement, mixing, obfuscation or evasion tooling.
Network analysis will remain limited to authorized traffic interpretation, passive evidence and beginner education.
Game security workflows will remain limited to authorized defensive review for studios and engineering teams, without cheat development, bypass guidance or exploit instructions.
