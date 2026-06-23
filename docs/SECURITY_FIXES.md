# OSINTPRO Self-Audit Corrections

OSINTPRO uses its own passive domain report to review the live service. This
document separates confirmed application controls from signals that are
optional, contextual or impossible to configure on a provider-owned hostname.

## Fixed In The Application

- Security headers include HSTS, CSP, MIME sniffing protection, frame
  protection, a restrictive referrer policy, Permissions Policy, COOP and
  CORP.
- CSP also blocks plugins, workers and unexpected manifest sources.
- `robots.txt` excludes the admin page, APIs, data, backups and private paths.
- `sitemap.xml` lists only the landing page and intentionally public
  documentation.
- Public `robots.txt` and `sitemap.xml` files are no longer classified as a
  vulnerability. They remain useful indexing evidence.
- OpenID configuration, mobile association files and BIMI are shown as
  optional capabilities rather than failed security controls.
- SPF, DMARC, MTA-STS and TLS-RPT are findings only when OSINTPRO observes mail
  service or an email authentication policy.
- DNS parsing now accepts only answers matching the requested record type.
  Provider CNAME chains can no longer be mistaken for MX or TXT records.
- HTTPS collection uses `urllib` and records an explicit `not assessed` state
  on transport failure. A timeout can no longer become six false
  missing-header findings.
- PDF exports now include the interpretation rules so clients can distinguish
  evidence, hypotheses and non-applicable controls.

`X-XSS-Protection` is intentionally not enabled. Modern browsers deprecated
that header; Content Security Policy is the supported control.

## Provider-Owned Hostname Limitation

The live demo uses `osintpro-48j4.onrender.com`. Render owns the DNS zone for
`onrender.com`, so this project cannot publish TXT records at:

- `osintpro-48j4.onrender.com` for SPF
- `_dmarc.osintpro-48j4.onrender.com` for DMARC
- `_mta-sts.osintpro-48j4.onrender.com` for MTA-STS discovery
- `_smtp._tls.osintpro-48j4.onrender.com` for TLS-RPT
- `default._bimi.osintpro-48j4.onrender.com` for BIMI

OSINTPRO also does not currently send or receive product email. These controls
are therefore reported as not applicable for the demo, not as remediated DNS
records.

When a custom domain and a real mail provider are introduced, configure the
records from that provider's exact documentation. Do not publish a placeholder
SPF include or an MTA-STS MX host that does not exist.

## Certificate Transparency

Certificate Transparency is an asset discovery and monitoring source, not a
vulnerability. OSINTPRO already records CT names in reports and supports
domain monitoring. A future custom domain should also have an external CT
alert so certificate issuance is observed independently from the application.

## Indexing Is Not Access Control

`robots.txt` is guidance for cooperative crawlers. The backend protects static
and API paths with an explicit allowlist, authentication and account-scoped
queries. Sensitive paths must remain inaccessible even when a crawler ignores
`robots.txt`.

## Honest Retest Criteria

A successful self-audit should show:

- all expected browser security headers present;
- no SPF or DMARC high finding when no mail service is observed;
- public indexing files as contextual metadata;
- optional protocols labeled `N/A` or `Not declared`;
- no claim that passive evidence proves exploitability.

The June 23, 2026 backend retest returned 100/100, observed all six browser
security headers and produced no high-severity finding. CAA and DNSSEC remain
low-priority provider-DNS observations.

The goal remains accurate risk communication, not an artificial score.
