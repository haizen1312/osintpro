# OSINTPRO Roadmap

OSINTPRO is moving toward a focused passive intelligence workspace for domains, brands, public identities and blockchain wallets.

## Current Focus

- Keep the core app fast, readable and fully English.
- Improve account-level workspace organization.
- Expand passive wallet OSINT for fraud reconstruction.
- Strengthen exports and case-ready reporting.
- Expand beginner-friendly Web Audit Lab workflows without adding invasive scanning.
- Add beginner-friendly network traffic analysis without unauthorized packet capture.
- Keep hosting costs at zero until paid usage justifies infrastructure spend.

## Near-Term Milestones

### Intelligence Workspace

- Cleaner dashboard for choosing domain, social or wallet investigations.
- Web Audit Lab for guided passive web review, beginner commands and technical explanations.
- Network Traffic Lab for Wireshark-style DNS, TCP/TLS and HTTP interpretation.
- Entity graph with stronger filtering by domain, person, wallet and finding type.
- Manual notes and tags for wallets, counterparties and suspicious infrastructure.
- Better case summaries for agencies and investigators.

Status: client folders, active folder routing, saved playbook organization and Network Traffic Lab are implemented. Password reset remains gated until a trusted recovery channel exists.

### Wallet OSINT

- Hop expansion for selected counterparties.
- Manual labels such as exchange, scam, victim, bridge, mixer, service or unknown.
- CSV export for wallet transactions and counterparties.
- Case timeline view for suspicious wallet flows.

Status: wallet CSV export, manual wallet tags, case notes and counterparty hop expansion are implemented. Timeline depth can improve later with richer public-chain sources.

### Reporting

- Server-side PDF generation.
- Web Audit Lab export with evidence checklist and glossary.
- Sanitized example reports for public marketing.
- Agency-friendly report branding.
- Report comparison for monitored domains.

Status: server-side PDF export and Web Audit Lab CSV/playbook export are implemented. Report comparison and branded templates remain future polish.

### Monetization

- Better Free-to-Pro onboarding.
- Agency workspaces with client folders.
- Billing status visibility after Stripe checkout.
- Paid plan value messaging inside the app.

Status: Free-to-Pro/Agency onboarding, billing status messaging and agency client folder value are implemented in the app.

### Infrastructure

- Continue with SQLite and free Render/GitHub Actions backup artifacts while traffic is early.
- Add PostgreSQL only after revenue supports persistent managed hosting.
- Keep secrets in environment variables and out of GitHub.

Status: SQLite remains the default zero-cost database. PostgreSQL is intentionally deferred until paid usage justifies managed infrastructure.

## Safety Boundary

OSINTPRO will remain a passive OSINT product. It will not add exploit execution, brute force, credential attacks, invasive scanning, wallet movement, mixing, obfuscation or evasion tooling.
Network analysis will remain limited to authorized traffic interpretation, passive evidence and beginner education.
