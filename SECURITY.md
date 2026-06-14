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

## Public OSINT Boundaries

Only analyze assets you own, manage, or are authorized to assess.
Findings are hypotheses based on public signals and should be manually verified before client remediation work.
