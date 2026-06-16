# API Preview

OSINTPRO is not ready to sell a public API yet. The app already uses structured JSON endpoints internally, but external API keys should come after persistent production storage and real paid usage.

## Current Public Endpoint

```http
GET /api/meta
```

Returns product metadata, safety boundaries, available modules and plan limits.

No authentication is required for this metadata endpoint.

## Current Internal App Endpoints

These endpoints power the web app today. They are not sold as a stable public API yet.

| Endpoint | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/health` | `GET` | none | Service health check. |
| `/api/meta` | `GET` | none | Public product metadata and safety boundary. |
| `/api/session` | `GET` | session cookie | Current user, reports, monitors, folders and pricing state. |
| `/api/analyze` | `POST` | session cookie | Passive domain intelligence report. |
| `/api/social/analyze` | `POST` | session cookie | Public username presence check. |
| `/api/wallet/analyze` | `POST` | session cookie | Public wallet OSINT report. |
| `/api/intel/workspace` | `GET` | session cookie | Entity graph, dossiers, case summaries and workspace stats. |
| `/api/reports/{id}/pdf` | `GET` | session cookie | Server-side PDF export for a report owned by the account. |
| `/api/monitors` | `GET/POST` | session cookie | List or create passive domain monitors. |
| `/api/billing/checkout` | `POST` | session cookie | Create a Stripe Payment Link redirect for Pro/Agency. |

## Current Auth Model

The app currently uses:

- nickname/password accounts
- PBKDF2 password hashes
- HTTP-only session cookies
- account-isolated report history
- server-side plan limits

Public API keys are intentionally not available yet. API keys should be added only after persistent production storage, usage metering and per-key quotas exist.

## Current Rate Limits

The app has simple IP/path rate limits for abuse control:

| Endpoint family | Current limit |
| --- | --- |
| login | 12 requests/minute |
| register | 10 requests/minute |
| password change | 8 requests/minute |
| domain/social/wallet analysis | 30 requests/minute each |
| event telemetry | 60 requests/minute |
| monitor run | 12 requests/minute |

These limits are not a final API pricing model. Paid API access should use per-key metering and plan quotas.

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

Potential pricing metric:

- per included investigation per month
- overage per domain/social/wallet report
- separate monitor quota
- export/download quota for PDFs and CSVs
