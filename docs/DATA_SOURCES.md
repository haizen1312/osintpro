# Data Sources And Unit Costs

OSINTPRO currently uses passive public sources and direct observations. It avoids invasive scanning, exploit execution, credential attacks, private scraping and unauthorized packet capture.

## Current Sources

| Area | Source | Cost today | Notes |
| --- | --- | --- | --- |
| DNS records | Local resolver and `dig` when available | No paid API | A/AAAA, MX, NS, TXT, CAA, SOA, DS, DNSKEY, BIMI, DMARC, MTA-STS and TLS-RPT checks. |
| IP and hostname basics | Local DNS resolution | No paid API | Used for public posture and relationship mapping. |
| HTTPS and TLS | Direct public connection to the submitted host | No paid API | Certificate metadata and public response headers only. |
| Web exposure | Public HTTP paths on the submitted host | No paid API | `security.txt`, `robots.txt`, `sitemap.xml` and selected `.well-known` paths. |
| RDAP | `rdap.org` | No paid API | Public registration metadata where available. |
| Certificate Transparency | `crt.sh` JSON output | No paid API | Public CT names and subdomain evidence. |
| Social username checks | Public profile URLs | No paid API | Presence checks only. No login, private scraping or attribution guarantee. |
| Bitcoin wallet OSINT | Blockstream public API | No paid API | Public balance, recent transactions and explorer links. Subject to fair-use limits. |
| Ethereum/EVM wallet OSINT | Blockscout public API | No paid API | Public balance, account type and recent activity where available. Subject to fair-use limits. |
| Billing | Stripe Payment Links and webhooks | Stripe fees on payments | No custom card storage. OSINTPRO only receives signed checkout events. |

## Unit Economics

The current MVP has no paid data-provider cost per query. The practical limits are hosting, API rate limits, response latency and fair-use expectations from public services.

If usage grows, the upgrade order should be:

1. Add stronger caching and request queues.
2. Move persistence from free ephemeral storage to persistent disk or managed PostgreSQL.
3. Add provider-specific API keys only where they unlock reliability or better evidence.
4. Track cost per investigation by source family before increasing free-tier limits.

## Paid Provider Candidates

OSINTPRO does not currently require these providers, but they are candidates if revenue justifies deeper intelligence:

| Provider type | Why add it | Risk |
| --- | --- | --- |
| Whois/RDAP API | More reliable registration history | Recurring API cost per lookup. |
| Passive DNS API | Historical infrastructure links | Can become expensive at scale. |
| Threat intelligence API | Reputation and malware context | Must avoid overstating certainty. |
| Blockchain analytics API | Better labels and graph depth | Higher cost and stricter compliance expectations. |

## Safety Notes

OSINTPRO findings are evidence leads, not legal conclusions. Public usernames, domains and wallets should not be treated as belonging to the same actor unless the user adds verified case context.

Wallet OSINT must remain limited to public blockchain observation and case reconstruction. It must not provide laundering, mixing, obfuscation, evasion or fund movement guidance.
