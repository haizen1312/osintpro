# Local Setup

This guide explains how to run OSINTPRO on your own machine for development, demos or authorized local testing.

## Requirements

- Python 3.10 or newer
- A terminal
- A browser
- Optional: `dig`, `curl` and `openssl` for richer local checks

OSINTPRO does not require Node, Docker or a paid database for local development.

## Fast Start

From the repository folder:

```bash
python3 server.py
```

Open:

```text
http://127.0.0.1:8765
```

The app creates a local SQLite database automatically in:

```text
data/osintpro.sqlite3
```

## Create Your Account

1. Open the app.
2. Go to `Account`.
3. Register with a nickname and password.
4. Run a domain, social or wallet investigation.

Accounts are local to your SQLite database. The local database is not shared with the live hosted demo.

## Optional Environment File

Copy the example file:

```bash
cp .env.example .env
```

Then set values only for what you need. For local testing, the app works without Stripe.

Useful local variables:

```text
OSINTPRO_ADMIN_CODE="change-me"
OSINTPRO_SECRET_KEY="generate-a-long-random-secret"
OSINTPRO_FREE_TIER_VARIANT="A"
OSINTPRO_API_KEY_RATE_LIMIT="30"
OSINTPRO_DB_PATH="./data/osintpro.sqlite3"
OSINTPRO_BACKUP_DIR="./data/backups"
OSINTPRO_REPORT_BRAND="OSINTPRO"
```

Free tier variants:

- `A`: 5 starter reports and 1 monitor for a 30-day trial.
- `B`: 3 starter reports and 1 monitor for a 30-day trial.
- `C`: unlimited reports and 1 monitor for a 30-day trial.

Use variants only for deliberate conversion tests. Keep the admin funnel open while testing so checkout clicks, exhausted credits and monitor-limit hits can be compared.

## Admin Access

Set `OSINTPRO_ADMIN_CODE`, restart the server, then open:

```text
http://127.0.0.1:8765/admin.html
```

Use the private admin code to unlock owner-only controls.

Do not commit the admin code, screenshots of secrets or local database files.

## Stripe Is Optional Locally

Stripe Payment Links are only needed if you want to test checkout.

```text
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_WEBHOOK_SECRET="whsec_..."
```

Without these variables, the billing page still loads and explains which setup is missing.

## Local Safety Boundary

Use OSINTPRO only for:

- domains you own or are authorized to review
- public usernames with a legitimate security, brand or fraud-analysis reason
- public wallet addresses for compliance-style or fraud reconstruction work
- your own local network when using the Network Lab own-network mode

Do not use it for harassment, stalking, credential attacks, brute force, exploit execution, unauthorized scanning, packet capture without permission or wallet evasion.

## Troubleshooting

If the app does not open:

1. Check the terminal for errors.
2. Make sure the server says `OSINTPRO running at http://127.0.0.1:8765`.
3. Try another port:

```bash
python3 server.py --port 8787
```

4. Open:

```text
http://127.0.0.1:8787
```

If DNS data is limited, install or enable `dig` on your system. The app still works without it, but DNS records may be less complete.
