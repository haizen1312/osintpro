# API Preview

OSINTPRO now includes an MVP API-key workflow for Agency/Admin accounts. It is a controlled integration surface for passive report automation, not a high-volume public API product yet.

## Public Metadata

```http
GET /api/meta
```

Returns product metadata, safety boundaries, modules and plan limits. No authentication is required.

## API Key Access

Agency/Admin users can create API keys from the app's `API Preview` section.

Security model:

- API keys start with `opk_`.
- The full key is shown only once.
- Only an HMAC hash and short prefix are stored.
- Keys can be revoked from the app.
- API access is blocked for Free and Pro accounts.

Use:

```http
Authorization: Bearer opk_your_key_here
```

## Live API Endpoints

These endpoints are available with an Agency/Admin API key.

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/v1/status` | `GET` | Return plan, per-minute key limit and available API endpoints. |
| `/api/v1/domains/analyze?domain=example.com` | `GET` | Run passive domain intelligence and store the report. |
| `/api/v1/domain-reports` | `POST` | Run passive domain intelligence and store the report. |
| `/api/v1/social-reports` | `POST` | Run a public username presence check and store the report. |
| `/api/v1/wallet-reports` | `POST` | Run public wallet OSINT and store the report. |
| `/api/v1/reports/{id}` | `GET` | Fetch JSON for a report owned by the API key account. |

Examples:

```bash
curl "https://osintpro-48j4.onrender.com/api/v1/status" \
  -H "Authorization: Bearer $OSINTPRO_API_KEY"
```

```bash
curl "https://osintpro-48j4.onrender.com/api/v1/domains/analyze?domain=example.com" \
  -H "Authorization: Bearer $OSINTPRO_API_KEY"
```

```bash
curl -X POST "https://osintpro-48j4.onrender.com/api/v1/domain-reports" \
  -H "Authorization: Bearer $OSINTPRO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

```bash
curl -X POST "https://osintpro-48j4.onrender.com/api/v1/social-reports" \
  -H "Authorization: Bearer $OSINTPRO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"example"}'
```

```bash
curl -X POST "https://osintpro-48j4.onrender.com/api/v1/wallet-reports" \
  -H "Authorization: Bearer $OSINTPRO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"address":"0x0000000000000000000000000000000000000000"}'
```

## Internal App Endpoints

These endpoints power the web app and remain session-cookie based.

| Endpoint | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/health` | `GET` | none | Service health check. |
| `/api/session` | `GET` | session cookie | Current user, reports, monitors, folders and pricing state. |
| `/api/analyze` | `POST` | session cookie | Passive domain intelligence report. |
| `/api/social/analyze` | `POST` | session cookie | Public username presence check. |
| `/api/wallet/analyze` | `POST` | session cookie | Public wallet OSINT report. |
| `/api/intel/workspace` | `GET` | session cookie | Entity graph, dossiers, case summaries and workspace stats. |
| `/api/graphs/current/export?format=jsonld` | `GET` | session cookie | Export the account graph as JSON-LD. |
| `/api/graphs/current/export?format=dot` | `GET` | session cookie | Export the account graph as Graphviz DOT. |
| `/api/graphs/current/export?format=csv` | `GET` | session cookie | Export the account graph as a CSV edge list. |
| `/api/reports/{id}/pdf` | `GET` | session cookie | Server-side PDF export for a report owned by the account. |
| `/api/reports/{id}/findings.csv` | `GET` | session cookie | Owner-ready findings CSV with abuse context, business impact and owner action. |
| `/api/reports/{id}/sarif` | `GET` | session cookie | SARIF export for a saved Repository Audit Lab report. |
| `/api/reports/{id}/repository.json` | `GET` | session cookie | Redacted JSON export for a saved Repository Audit Lab report. |
| `/api/api-keys` | `GET/POST` | Agency/Admin session | List or create API keys. |
| `/api/webhooks` | `GET/POST` | Pro/Agency session | List or create monitor/event webhooks. |
| `/api/webhooks/{id}` | `DELETE` | Pro/Agency session | Disable a webhook. |
| `/api/notifications/test` | `POST` | Pro/Agency session | Send a safe test notification to configured webhooks/email. |

## Current Auth Model

The web app currently uses:

- nickname/password accounts
- PBKDF2 password hashes
- HTTP-only session cookies
- account-isolated report history
- server-side plan limits

The API-key flow is intended for Agency/Admin workflow automation. High-volume API selling should wait for persistent production storage, stronger metering and per-key quotas.

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
| API key calls | 30 requests/minute per key by default |

`OSINTPRO_API_KEY_RATE_LIMIT` can tune API key calls per minute.

These limits are not a final API pricing model. Higher-volume paid API access should use stronger per-key metering and plan quotas.

## Webhooks And Notifications

Pro/Agency accounts can register HTTPS webhooks for these events:

- `monitor.changed`
- `monitor.checked`
- `report.generated`

Create a webhook:

```bash
curl -X POST "https://osintpro-48j4.onrender.com/api/webhooks" \
  -H "Content-Type: application/json" \
  -b "osintpro_session=..." \
  -d '{"event_type":"monitor.changed","url":"https://example.com/osintpro"}'
```

Webhook safety rules:

- HTTPS only.
- Localhost and private IP targets are rejected.
- Payloads are redacted before delivery.
- Delivery attempts are logged as notification events.

Email notification is optional and only activates when SMTP environment
variables are configured:

```text
OSINTPRO_SMTP_HOST
OSINTPRO_SMTP_PORT
OSINTPRO_SMTP_USER
OSINTPRO_SMTP_PASSWORD
OSINTPRO_SMTP_FROM
OSINTPRO_NOTIFICATION_EMAIL_TO
```

## Next API Work

Next endpoints to consider:

- `GET /api/v1/reports/{id}.pdf`
- `GET /api/v1/cases/{id}/graph`
- `GET /api/v1/usage`
- `DELETE /api/v1/reports/{id}`

## API Safety Boundary

The API must keep the same boundaries as the web app:

- passive public-source intelligence only
- no exploit execution
- no brute force
- no credential attacks
- no invasive scanning
- no unauthorized packet capture
- no wallet movement, mixing, laundering, obfuscation or evasion guidance

## Before Selling Higher-Volume API Access

Required technical work:

- persistent database or managed PostgreSQL
- stronger per-key usage metering
- API usage logs in the admin panel
- plan-based quotas
- clear error contracts
- export and deletion controls for account data

## Pricing Direction

API access is not included in Free or Pro.

Suggested packaging:

- Pro: web app only.
- Agency: controlled API access for client workflows.
- Enterprise or custom: higher limits, dedicated support and custom retention.

Potential pricing metric:

- per included investigation per month
- overage per domain/social/wallet report
- separate monitor quota
- export/download quota for PDFs and CSVs
