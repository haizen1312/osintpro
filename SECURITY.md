# Security Policy

OSINTPRO is designed for passive intelligence on domains, brands and public usernames.
It does not intentionally run exploit payloads, brute force, credential attacks or aggressive scanning.

## Reporting Security Issues

If you find a vulnerability in OSINTPRO, report it privately to the repository owner.
Do not publish exploit details before a fix is available.

Useful details:

- affected endpoint or page
- expected behavior
- actual behavior
- minimal reproduction steps
- screenshots or logs with secrets redacted

## Secret Handling

Never commit production values for:

- `OSINTPRO_ADMIN_CODE`
- `OSINTPRO_SECRET_KEY`
- `OSINTPRO_STRIPE_WEBHOOK_SECRET`
- Stripe live API keys
- GitHub tokens
- Render secrets

Use environment variables in production and `.env.example` as a safe template.

## Admin Surface

The owner/admin interface is protected by `OSINTPRO_ADMIN_CODE`.
Do not rely on hidden URLs as a security boundary.
Use a long random admin code in production and rotate it if exposed.

## Public OSINT Boundaries

Only analyze assets you own, manage, or are authorized to assess.
Findings are hypotheses based on public signals and should be manually verified before client remediation work.

Email authentication findings are contextual. SPF, DMARC, MTA-STS, TLS-RPT and
BIMI are not active failures when no mail service or brand email policy is
observed. Public `robots.txt` and `sitemap.xml` files are indexing metadata, not
vulnerabilities by themselves.

## Export Safety

- PDF and CSV exports are scoped to the signed browser session.
- Authenticated accounts can export only their own saved reports.
- Anonymous sessions retain only their latest report per type.
- Attachment filenames are normalized before being added to headers.
- Secret-like values are redacted before report rendering.
- Export errors remain JSON errors on the server and visible messages in the
  browser; do not silently navigate users to an error payload.
