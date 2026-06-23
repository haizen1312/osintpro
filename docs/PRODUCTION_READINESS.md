# Production Readiness

OSINTPRO currently supports a zero-cost MVP path with SQLite and GitHub Actions backup artifacts. That is useful for early validation, but paid customer usage requires stronger durability.

## Current Zero-Cost Setup

- Render web service
- SQLite database
- protected backup endpoint
- GitHub Actions artifact backups
- admin restore flow

This is acceptable for demos, early users and no-budget validation.

## Upgrade Trigger

Move to persistent storage when any of these become true:

- first real paying customer
- recurring monitoring used by external users
- meaningful signup volume
- API keys used by an agency workflow
- data loss would damage trust

## Option A: Render Persistent Disk

Best first paid step when keeping the app simple.

Checklist:

1. Add a Render persistent disk.
2. Set `OSINTPRO_DB_PATH` to the mounted disk path.
3. Set `OSINTPRO_BACKUP_DIR` to the mounted disk backup folder.
4. Deploy.
5. Create a manual admin backup.
6. Restore the latest SQLite artifact if needed.
7. Confirm `/api/health`, login, reports, monitors and Stripe webhook.

## Option B: Managed PostgreSQL

Best later step when usage grows.

Detailed blueprint: [`POSTGRES_MIGRATION.md`](../POSTGRES_MIGRATION.md).

Checklist:

1. Add a PostgreSQL database.
2. Add a migration layer.
3. Write a one-time SQLite-to-Postgres migration.
4. Run migration on a staging copy first.
5. Verify users, reports, monitors, folders, wallet notes, API keys and Stripe events.
6. Keep SQLite backup artifact for rollback.

## Backup Strategy

Minimum:

- daily protected cron backup
- manual backup before migrations
- restore test after schema changes
- 30-day artifact retention while on free infrastructure

Before paid launch:

- persistent disk or managed database
- documented restore drill
- admin export check
- alert webhook for cron failures

## Environment Checklist

Required for production:

```text
OSINTPRO_ADMIN_CODE
OSINTPRO_SECRET_KEY
OSINTPRO_CRON_SECRET
OSINTPRO_STRIPE_PRO_URL
OSINTPRO_STRIPE_AGENCY_URL
OSINTPRO_STRIPE_WEBHOOK_SECRET
```

Recommended:

```text
OSINTPRO_DB_PATH
OSINTPRO_BACKUP_DIR
OSINTPRO_ALERT_WEBHOOK_URL
OSINTPRO_REPORT_BRAND
OSINTPRO_API_KEY_RATE_LIMIT
OSINTPRO_FREE_TIER_VARIANT
```

## Rollback Plan

1. Create a backup before changing storage.
2. Keep the previous deployment available.
3. Restore the latest verified SQLite snapshot if migration fails.
4. Disable public checkout links if billing state cannot be trusted.
5. Re-enable checkout after account and plan state are verified.
