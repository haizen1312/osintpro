# API Preview

OSINTPRO is not ready to sell a public API yet. The app already uses structured JSON endpoints internally, but external API keys should come after persistent production storage and real paid usage.

## Current Public Endpoint

```http
GET /api/meta
```

Returns product metadata, safety boundaries, available modules and plan limits.

## Candidate Paid API

The first paid API should be built for agencies that want OSINTPRO reports inside their own workflow.

Candidate endpoints:

```http
POST /api/v1/domain-reports
POST /api/v1/social-reports
POST /api/v1/wallet-reports
GET /api/v1/reports/{id}
GET /api/v1/reports/{id}.pdf
GET /api/v1/cases/{id}/graph
```

## API Safety Boundary

The API must keep the same boundaries as the web app:

- passive public-source intelligence only
- no exploit execution
- no brute force
- no credential attacks
- no invasive scanning
- no unauthorized packet capture
- no wallet movement, mixing, laundering, obfuscation or evasion guidance

## Before Launching API Keys

Required technical work:

- persistent database or managed PostgreSQL
- per-key rate limits
- per-key usage metering
- API usage logs in the admin panel
- plan-based quotas
- clear error contracts
- export and deletion controls for account data

## Pricing Direction

API access should not be included in Free.

Suggested packaging:

- Pro: no public API, web app only.
- Agency: limited API access for client workflows.
- Enterprise or custom: higher limits, dedicated support and custom retention.
