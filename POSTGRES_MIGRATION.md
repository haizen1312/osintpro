# PostgreSQL Migration Blueprint

OSINTPRO currently runs on SQLite because the project is intentionally staying
zero-cost until paid usage justifies infrastructure spend. PostgreSQL is the
target production database once real customer data, recurring monitors or paid
conversions make durability more important than free hosting.

## Current State

- Active adapter: SQLite
- Default file: `data/osintpro.sqlite3`
- Optional persistent file: `OSINTPRO_DB_PATH`
- Backup strategy: cron/admin SQLite snapshots
- Runtime dependencies: Python standard library only

## Planned Target

- Database: Render Managed PostgreSQL or another managed PostgreSQL provider
- Connections: small pool, default target size `5`
- Backups: provider-managed daily backups plus periodic logical exports
- Rollback: keep the last SQLite snapshot until PostgreSQL has been stable for
  at least 48 hours

## Configuration Preview

These variables are documented now but should not be enabled on the live free
deployment until the SQL migration is implemented and tested.

```bash
OSINTPRO_DB_TYPE=sqlite

# Future PostgreSQL migration settings:
OSINTPRO_POSTGRES_HOST="..."
OSINTPRO_POSTGRES_DB="osintpro"
OSINTPRO_POSTGRES_USER="..."
OSINTPRO_POSTGRES_PASSWORD="..."
OSINTPRO_POSTGRES_POOL_SIZE="5"
```

If `OSINTPRO_DB_TYPE=postgresql` is set before migration, OSINTPRO fails closed
with an explicit runtime error instead of silently writing partial data to an
unmigrated backend.

## Schema Mapping

SQLite text primary keys map cleanly to PostgreSQL `uuid` or `text` columns.
The first migration should keep existing UUID strings as `text` to reduce
change risk, then convert later only if there is a real query or indexing need.

```sql
CREATE TABLE users (
    id text PRIMARY KEY,
    email text UNIQUE,
    nickname text UNIQUE,
    password_hash text,
    plan text NOT NULL DEFAULT 'Free',
    credits integer NOT NULL DEFAULT 10,
    signup_fingerprint text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE reports (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    domain text NOT NULL,
    score integer NOT NULL,
    summary text NOT NULL,
    generated_at timestamptz NOT NULL,
    payload_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    folder_id text
);

CREATE TABLE repository_reports (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    repository text NOT NULL,
    score integer NOT NULL,
    findings_json jsonb NOT NULL,
    payload_json jsonb NOT NULL,
    generated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);
```

The remaining tables follow the same mapping:

- `social_reports.payload_json` -> `jsonb`
- `wallet_reports.payload_json` -> `jsonb`
- `wallet_annotations.tags_json` -> `jsonb`
- `web_audit_playbooks.payload_json` -> `jsonb`
- `conversion_events.metadata_json` -> `jsonb`
- `api_keys.scopes_json` -> `jsonb`

## Migration Steps

1. Create a managed PostgreSQL instance.
2. Freeze writes briefly or put the app in maintenance mode.
3. Create a final SQLite backup from the admin panel.
4. Export SQLite tables to newline-delimited JSON or CSV.
5. Create PostgreSQL schema and indexes.
6. Import users first, then folders, reports, monitors, annotations and events.
7. Run integrity checks:
   - user count matches
   - report counts match by table
   - sample login works
   - sample PDF/CSV/SARIF/graph exports work
8. Deploy with `OSINTPRO_DB_TYPE=postgresql`.
9. Monitor errors and conversion events for 24-48 hours.
10. Keep the SQLite snapshot as rollback until confidence is high.

## Rollback

If PostgreSQL writes fail during the cutover:

1. Set `OSINTPRO_DB_TYPE=sqlite`.
2. Restore the final SQLite snapshot through the admin panel.
3. Restart the service.
4. Investigate the failed SQL path offline before another migration attempt.

## Cost Trigger

Do not migrate only because the blueprint exists. Migrate when one of these is
true:

- at least one paying customer depends on retained data
- monitor history becomes commercially valuable
- backup restores are happening often enough to waste time
- API usage needs reliable metering

One Pro subscriber at 19 EUR/month roughly covers a small managed database.
