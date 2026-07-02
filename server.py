from __future__ import annotations

import datetime as dt
import csv
import fnmatch
import hashlib
import hmac
import io
import html
import json
import os
import re
import secrets
import socket
import ssl
import sqlite3
import subprocess
import threading
import time
import uuid
import ipaddress
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("OSINTPRO_DATA_DIR", str(ROOT / "data"))).expanduser()
DB_PATH = Path(os.getenv("OSINTPRO_DB_PATH", str(DATA_DIR / "osintpro.sqlite3"))).expanduser()
BACKUP_DIR = Path(os.getenv("OSINTPRO_BACKUP_DIR", str(DATA_DIR / "backups"))).expanduser()
SECRET_PATH = DATA_DIR / ".osintpro_secret"
SESSION_COOKIE = "osintpro_session"
DB_TYPE = os.getenv("OSINTPRO_DB_TYPE", "sqlite").strip().lower() or "sqlite"
FREE_TIER_VARIANTS = {
    "A": {
        "credits": 5,
        "monitors": 1,
        "monitor_trial_days": 30,
        "description": "5 starter reports and 1 monitor for a 30-day trial.",
    },
    "B": {
        "credits": 3,
        "monitors": 1,
        "monitor_trial_days": 30,
        "description": "3 starter reports and 1 monitor for a 30-day trial.",
    },
    "C": {
        "credits": None,
        "monitors": 1,
        "monitor_trial_days": 30,
        "description": "Unlimited reports and 1 monitor for a 30-day trial.",
    },
}


def configured_free_tier() -> str:
    value = os.getenv("OSINTPRO_FREE_TIER_VARIANT", "A").strip().upper()
    return value if value in FREE_TIER_VARIANTS else "A"


FREE_TIER_VARIANT = configured_free_tier()
FREE_PLAN_LIMITS = FREE_TIER_VARIANTS[FREE_TIER_VARIANT]
FREE_CREDITS = -1 if FREE_PLAN_LIMITS["credits"] is None else int(FREE_PLAN_LIMITS["credits"])
PLAN_LIMITS = {
    "Free": FREE_PLAN_LIMITS,
    "Pro": {"credits": None, "monitors": 5},
    "Agency": {"credits": None, "monitors": 25},
    "Admin": {"credits": None, "monitors": 9999},
}
PAID_PLANS = {"Pro", "Agency", "Admin"}
FEATURE_FLAGS = {
    "domain_intel": "Free",
    "social_osint": "Free",
    "repository_audit": "Free",
    "repo_audit_json": "Free",
    "confidence_slider": "Free",
    "entity_graph_export": "Free",
    "web_audit_lab": "Free",
    "network_traffic_lab": "Free",
    "repo_audit_sarif": "Pro",
    "dependency_advisory": "Pro",
    "wallet_graph": "Pro",
    "monitoring": "Pro",
    "webhooks": "Pro",
    "email_notifications": "Pro",
    "api_access": "Agency",
    "team_collaboration": "Agency",
}
WEBHOOK_EVENTS = {
    "monitor.changed",
    "monitor.checked",
    "report.generated",
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,32}$")
BTC_ADDRESS_RE = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,90}$", re.IGNORECASE)
EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
UUID_RE = re.compile(r"^[a-f0-9-]{36}$")
API_KEY_RE = re.compile(r"^opk_[A-Za-z0-9_-]{32,96}$")
EVENT_NAME_RE = re.compile(r"^[a-z0-9_:-]{2,48}$")
EVENT_SOURCE_RE = re.compile(r"^[a-z0-9_:-]{0,48}$")
SECRET_KEY_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|authorization|bearer)\b"
)
SECRET_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*)[^\s,;\"'<>]+"),
    re.compile(r"(?i)(\bauthorization\s*[:=]\s*(?:bearer|basic)\s+)[a-z0-9._~+/=-]+"),
    re.compile(r"\b(?:sk|pk|rk|whsec|ghp|github_pat|xox[baprs])[_-][-A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9_=-]{24,}\.[A-Za-z0-9_=-]{12,}\.[A-Za-z0-9_=-]{12,}\b"),
]
REDACTED = "[redacted]"
RATE_LIMIT_WINDOW = 60
RATE_LIMITS = {
    "/api/admin/login": 8,
    "/api/auth/login": 12,
    "/api/auth/password": 8,
    "/api/auth/register": 10,
    "/api/events": 60,
    "/api/analyze": 30,
    "/api/social/analyze": 30,
    "/api/wallet/analyze": 30,
    "/api/repository/audit": 12,
    "/api/monitors/run": 12,
}
RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}
API_RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}
RATE_LOCK = threading.Lock()
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
HTTP_TIMEOUT = 5
HTTP_LIMIT = 350000
MAX_BODY_BYTES = 16384
MAX_WEBHOOK_BYTES = 262144
MAX_RESTORE_BYTES = 25 * 1024 * 1024
MAX_REPO_AUDIT_BYTES = 2 * 1024 * 1024
MAX_REPO_AUDIT_FILES = 180
MAX_REPO_FILE_BYTES = 180000
REPO_CONFIDENCE_SCORES = {"high": 0.95, "medium": 0.7, "low": 0.45}
DEPENDENCY_ADVISORIES = {
    "npm": {
        "lodash": {"fixed": "4.17.21", "severity": "high", "advisory": "Prototype pollution and command injection advisories affect older lodash releases."},
        "js-yaml": {"fixed": "3.13.1", "severity": "high", "advisory": "Older js-yaml releases include unsafe object parsing advisories."},
        "serialize-javascript": {"fixed": "3.1.0", "severity": "high", "advisory": "Older serialize-javascript versions can enable unsafe code injection patterns."},
        "handlebars": {"fixed": "4.7.7", "severity": "high", "advisory": "Older handlebars releases include template injection and prototype pollution advisories."},
        "moment": {"fixed": "2.29.4", "severity": "medium", "advisory": "Older moment releases include parsing and ReDoS advisories."},
        "minimist": {"fixed": "1.2.6", "severity": "medium", "advisory": "Older minimist releases include prototype pollution advisories."},
    },
    "pip": {
        "django": {"fixed": "3.2.20", "severity": "high", "advisory": "Older Django branches include multiple web security advisories."},
        "flask": {"fixed": "2.2.5", "severity": "medium", "advisory": "Older Flask releases lack later security fixes and hardening."},
        "jinja2": {"fixed": "3.1.3", "severity": "medium", "advisory": "Older Jinja2 releases include sandbox and template security advisories."},
        "pillow": {"fixed": "8.3.2", "severity": "high", "advisory": "Older Pillow releases include image parsing memory-safety advisories."},
        "pyyaml": {"fixed": "5.4.0", "severity": "high", "advisory": "Older PyYAML releases are commonly associated with unsafe load patterns."},
        "requests": {"fixed": "2.31.0", "severity": "medium", "advisory": "Older Requests releases miss transport and parsing security fixes."},
    },
    "cargo": {
        "tokio": {"fixed": "1.0.0", "severity": "medium", "advisory": "Pre-1.0 async runtime versions should be reviewed before production use."},
        "hyper": {"fixed": "0.14.0", "severity": "medium", "advisory": "Older hyper branches have HTTP parsing and ecosystem advisories."},
        "time": {"fixed": "0.2.23", "severity": "high", "advisory": "Older time releases include known unsoundness advisories."},
    },
    "composer": {
        "guzzlehttp/guzzle": {"fixed": "6.5.8", "severity": "high", "advisory": "Older Guzzle releases include SSRF and header handling advisories."},
        "symfony/http-foundation": {"fixed": "5.4.46", "severity": "medium", "advisory": "Older Symfony HTTP Foundation releases include request parsing advisories."},
        "laravel/framework": {"fixed": "8.83.27", "severity": "high", "advisory": "Older Laravel framework branches include multiple security advisories."},
    },
}
DEFAULT_REPO_IGNORE_PATTERNS = [
    ".git/**",
    "node_modules/**",
    "vendor/**",
    "dist/**",
    "build/**",
    "coverage/**",
    ".next/**",
    ".nuxt/**",
    ".venv/**",
    "venv/**",
    "__pycache__/**",
    "target/**",
    "bin/**",
    "obj/**",
    "*.pyc",
    ".DS_Store",
]
DEFAULT_MONITOR_BATCH_LIMIT = 20
DEFAULT_API_KEY_RATE_LIMIT = 30
DEFAULT_REGISTRATION_IP_LIMIT = 3
DEFAULT_BACKUP_RETENTION = 14
PUBLIC_STATIC_PATHS = {
    "/",
    "/index.html",
    "/app.js",
    "/auth.js",
    "/styles.css",
    "/admin.html",
    "/admin/metrics",
    "/admin.js",
    "/favicon.ico",
    "/favicon.svg",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/README.md",
    "/ARCHITECTURE.md",
    "/PERFORMANCE.md",
    "/POSTGRES_MIGRATION.md",
    "/ROADMAP.md",
    "/docs/API_PREVIEW.md",
    "/docs/AI_DEVELOPMENT_GUIDE.md",
    "/docs/DATA_SOURCES.md",
    "/docs/DISTRIBUTION.md",
    "/docs/EXAMPLE_REPORTS.md",
    "/docs/EXPLAIN_OSINTPRO.md",
    "/docs/GITHUB_GROWTH.md",
    "/docs/LOCAL_SETUP.md",
    "/docs/OUTREACH_PLAYBOOK.md",
    "/docs/PRODUCTION_READINESS.md",
    "/docs/PRODUCT_HUNT_LAUNCH.md",
    "/docs/REPOSITORY_AUDIT_LAB.md",
    "/docs/SHOWCASE.md",
    "/docs/SECURITY_FIXES.md",
    "/docs/WEB_AUDIT_LAB.md",
}
CHECKOUT_REFERENCE_RE = re.compile(r"^osintpro_([a-f0-9-]{36})_(pro|agency)$")
BACKUP_NAME_RE = re.compile(r"^osintpro-[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+-[a-f0-9]{6}\.sqlite3$")
PLAN_RANK = {"Free": 0, "Pro": 1, "Agency": 2, "Admin": 3}
SOCIAL_PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{username}"},
    {"name": "GitLab", "url": "https://gitlab.com/{username}"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{username}"},
    {"name": "X", "url": "https://x.com/{username}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{username}"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{username}"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{username}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{username}/"},
    {"name": "Medium", "url": "https://medium.com/@{username}"},
    {"name": "Keybase", "url": "https://keybase.io/{username}"},
    {"name": "Telegram", "url": "https://t.me/{username}"},
]
TAKEOVER_CNAME_HINTS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud App",
    "cloudfront.net": "AWS CloudFront",
    "s3.amazonaws.com": "AWS S3",
    "netlify.app": "Netlify",
    "pages.dev": "Cloudflare Pages",
    "vercel-dns.com": "Vercel",
    "readme.io": "ReadMe",
    "helpscoutdocs.com": "Help Scout Docs",
    "zendesk.com": "Zendesk",
}
ADVANCED_WELL_KNOWN_PATHS = {
    "change_password": "/.well-known/change-password",
    "openid_configuration": "/.well-known/openid-configuration",
    "assetlinks": "/.well-known/assetlinks.json",
    "apple_app_site_association": "/apple-app-site-association",
}


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def server_secret() -> str:
    env_secret = os.getenv("OSINTPRO_SECRET_KEY")
    if env_secret:
        return env_secret
    DATA_DIR.mkdir(exist_ok=True)
    if SECRET_PATH.exists():
        return SECRET_PATH.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    SECRET_PATH.write_text(secret, encoding="utf-8")
    try:
        SECRET_PATH.chmod(0o600)
    except OSError:
        pass
    return secret


def sign_value(value: str) -> str:
    signature = hmac.new(server_secret().encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{signature}"


def verify_signed_value(value: str) -> str | None:
    raw, separator, signature = value.partition(".")
    if not separator or not UUID_RE.match(raw):
        return None
    expected = hmac.new(server_secret().encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature, expected):
        return raw
    return None


def stable_fingerprint(value: str) -> str:
    normalized = value.strip().lower()
    return hmac.new(server_secret().encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_VALUE_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
        else:
            redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact_dns_txt(value: str) -> str:
    redacted = redact_text(value)
    lower = redacted.lower()
    if lower.strip('"').startswith("ms="):
        quote = '"' if redacted.strip().startswith('"') else ""
        return f"{quote}MS={REDACTED}{quote}"
    token_markers = (
        "verification",
        "verify",
        "token",
        "tailscale",
        "keybase-site-verification",
        "google-site-verification",
        "facebook-domain-verification",
        "atlassian-domain-verification",
        "apple-domain-verification",
        "airtable-verification",
    )
    if any(marker in lower for marker in token_markers):
        masked = re.sub(r"([=:]\s*)[^\"'\s;]+", rf"\1{REDACTED}", redacted, count=1)
        if masked != redacted:
            return masked
        quote = '"' if redacted.strip().startswith('"') else ""
        marker = next(item for item in token_markers if item in lower)
        return f"{quote}{marker}={REDACTED}{quote}"
    return redacted


def redact_data(value: object, key: str = "") -> object:
    if SECRET_KEY_RE.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item, key) for item in value]
    if isinstance(value, dict):
        return {str(item_key): redact_data(item_value, str(item_key)) for item_key, item_value in value.items()}
    return value


def csv_cell(value: object) -> str:
    text = redact_text(str(value))
    if text.startswith(("=", "+", "-", "@")):
        text = "'" + text
    return f'"{text.replace(chr(34), chr(34) + chr(34))}"'


def safe_download_filename(value: object, fallback: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip()).strip(".-")
    return (name[:120] or fallback).lower()


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    """Open one transaction-scoped database connection and always close it.

    SQLite remains the active zero-cost backend. PostgreSQL settings are read
    for production planning, but the runtime intentionally fails closed if a
    deployment flips the provider before the SQL migration has been executed.
    """
    if DB_TYPE != "sqlite":
        raise RuntimeError(
            "OSINTPRO_DB_TYPE=postgresql is documented for migration planning, "
            "but this deployment has not been migrated from SQLite yet."
        )
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                nickname TEXT UNIQUE,
                password_hash TEXT,
                plan TEXT NOT NULL DEFAULT 'Free',
                credits INTEGER NOT NULL DEFAULT 10,
                signup_fingerprint TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS monitors (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                last_score INTEGER,
                last_summary TEXT,
                last_checked_at TEXT,
                last_changed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, domain),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS social_reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS wallet_reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                chain TEXT NOT NULL,
                address TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS stripe_events (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                plan TEXT,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS client_folders (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, name),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS wallet_annotations (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                chain TEXT NOT NULL,
                address TEXT NOT NULL,
                tags_json TEXT NOT NULL DEFAULT '[]',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, chain, address),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS web_audit_playbooks (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                report_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                title TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS conversion_events (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                event TEXT NOT NULL,
                plan TEXT,
                source TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                scopes_json TEXT NOT NULL DEFAULT '["reports:write","reports:read"]',
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS repository_reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                repository TEXT NOT NULL,
                score INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                url TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, event_type, url),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS notification_events (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                event_type TEXT NOT NULL,
                channel TEXT NOT NULL,
                status TEXT NOT NULL,
                target TEXT,
                message TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS password_resets (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        ensure_column(connection, "users", "email", "TEXT")
        ensure_column(connection, "users", "nickname", "TEXT")
        ensure_column(connection, "users", "password_hash", "TEXT")
        ensure_column(connection, "users", "signup_fingerprint", "TEXT")
        ensure_column(connection, "reports", "folder_id", "TEXT")
        ensure_column(connection, "social_reports", "folder_id", "TEXT")
        ensure_column(connection, "wallet_reports", "folder_id", "TEXT")
        ensure_column(connection, "monitors", "folder_id", "TEXT")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname ON users(nickname)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_users_signup_fingerprint ON users(signup_fingerprint)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_reports_folder ON reports(user_id, folder_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_social_reports_folder ON social_reports(user_id, folder_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_wallet_reports_folder ON wallet_reports(user_id, folder_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_monitors_folder ON monitors(user_id, folder_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_conversion_events_event ON conversion_events(event, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_conversion_events_user ON conversion_events(user_id, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id, revoked_at, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_repository_reports_user ON repository_reports(user_id, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id, event_type, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_notification_events_user ON notification_events(user_id, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id, created_at)")


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def row_to_user(row: sqlite3.Row) -> dict[str, object]:
    limits = PLAN_LIMITS.get(row["plan"], PLAN_LIMITS["Free"])
    credit_limit = limits.get("credits")
    return {
        "nickname": row["nickname"],
        "authenticated": bool(row["nickname"]),
        "plan": row["plan"],
        "credits": None if credit_limit is None and row["plan"] == "Free" else row["credits"],
        "free_credits": credit_limit if row["plan"] == "Free" else None,
        "monitor_limit": limits["monitors"],
        "monitor_trial_days": limits.get("monitor_trial_days"),
        "free_tier_variant": FREE_TIER_VARIANT,
    }


def plan_allows(plan: object, required_plan: object) -> bool:
    """Return whether a plan satisfies a product gate.

    Feature flags are intentionally plan-rank based so future AI/developers can
    add gated capabilities without scattering billing logic across handlers.
    """
    return PLAN_RANK.get(str(plan or "Free"), 0) >= PLAN_RANK.get(str(required_plan or "Free"), 0)


def feature_allowed(plan: object, feature: str) -> bool:
    return plan_allows(plan, FEATURE_FLAGS.get(feature, "Free"))


def public_feature_flags(plan: object) -> dict[str, dict[str, object]]:
    current_plan = str(plan or "Free")
    return {
        key: {
            "required_plan": required,
            "allowed": feature_allowed(current_plan, key),
        }
        for key, required in FEATURE_FLAGS.items()
    }


def internal_user(row: sqlite3.Row) -> dict[str, object]:
    user = row_to_user(row)
    user["_id"] = row["id"]
    return user


def public_user(user: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in user.items() if not key.startswith("_")}


def clean_event_name(value: object) -> str:
    event = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not EVENT_NAME_RE.match(event):
        raise ValueError("Invalid event name.")
    return event


def clean_event_source(value: object) -> str:
    source = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not EVENT_SOURCE_RE.match(source):
        raise ValueError("Invalid event source.")
    return source


def clean_event_plan(value: object) -> str | None:
    if value is None or value == "":
        return None
    plan = str(value).strip().capitalize()
    if plan not in PLAN_LIMITS:
        raise ValueError("Invalid event plan.")
    return plan


def clean_event_metadata(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    allowed: dict[str, object] = {}
    for key, raw in value.items():
        name = str(key or "").strip().lower().replace("-", "_").replace(" ", "_")
        if not EVENT_SOURCE_RE.match(name) or not name:
            continue
        if isinstance(raw, bool):
            allowed[name] = raw
        elif isinstance(raw, (int, float)):
            allowed[name] = raw
        else:
            text = str(raw or "").strip()
            if text:
                allowed[name] = text[:80]
        if len(allowed) >= 8:
            break
    return redact_data(allowed)


def record_conversion_event(
    connection: sqlite3.Connection,
    user_id: str | None,
    event: str,
    plan: str | None = None,
    source: str | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO conversion_events (id, user_id, event, plan, source, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            user_id,
            clean_event_name(event),
            clean_event_plan(plan),
            clean_event_source(source) if source else None,
            json.dumps(clean_event_metadata(metadata or {})),
            utc_now(),
        ),
    )


def is_admin_user(user: dict[str, object]) -> bool:
    return user.get("plan") == "Admin"


def checkout_reference(user_id: str, plan: str) -> str:
    return f"osintpro_{user_id}_{plan.lower()}"


def parse_checkout_reference(value: object) -> tuple[str, str] | None:
    match = CHECKOUT_REFERENCE_RE.match(str(value or ""))
    if not match:
        return None
    user_id, plan = match.groups()
    return user_id, plan.capitalize()


def add_checkout_reference(url: str, user_id: str, plan: str) -> str:
    parsed = urlparse(url)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != "client_reference_id"]
    query.append(("client_reference_id", checkout_reference(user_id, plan)))
    return urlunparse(parsed._replace(query=urlencode(query)))


def stripe_webhook_secret() -> str:
    return os.getenv("OSINTPRO_STRIPE_WEBHOOK_SECRET", "")


def verify_stripe_signature(payload: bytes, header: str) -> bool:
    secret = stripe_webhook_secret()
    if not secret or not header:
        return False
    parts: dict[str, list[str]] = {}
    for item in header.split(","):
        key, separator, value = item.partition("=")
        if separator:
            parts.setdefault(key.strip(), []).append(value.strip())
    timestamps = parts.get("t", [])
    signatures = parts.get("v1", [])
    if not timestamps or not signatures:
        return False
    try:
        timestamp = int(timestamps[0])
    except ValueError:
        return False
    if abs(time.time() - timestamp) > 300:
        return False
    signed_payload = f"{timestamp}.".encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, signature) for signature in signatures)


def apply_stripe_event(event: dict[str, object]) -> dict[str, object]:
    event_id = str(event.get("id", ""))
    event_type = str(event.get("type", ""))
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    session = data.get("object") if isinstance(data, dict) and isinstance(data.get("object"), dict) else {}
    now = utc_now()
    if not event_id:
        raise ValueError("Stripe event missing id.")
    if event_type != "checkout.session.completed":
        with db() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO stripe_events (id, type, status, created_at) VALUES (?, ?, 'ignored', ?)",
                (event_id, event_type, now),
            )
        return {"ok": True, "status": "ignored"}
    if session.get("status") != "complete":
        with db() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO stripe_events (id, type, status, created_at) VALUES (?, ?, 'incomplete', ?)",
                (event_id, event_type, now),
            )
        return {"ok": True, "status": "incomplete"}
    reference = parse_checkout_reference(session.get("client_reference_id"))
    if not reference:
        with db() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO stripe_events (id, type, status, created_at) VALUES (?, ?, 'missing_reference', ?)",
                (event_id, event_type, now),
            )
        return {"ok": True, "status": "missing_reference"}
    user_id, plan = reference
    with db() as connection:
        duplicate = connection.execute("SELECT id FROM stripe_events WHERE id = ?", (event_id,)).fetchone()
        if duplicate:
            return {"ok": True, "status": "duplicate"}
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            connection.execute(
                "INSERT INTO stripe_events (id, user_id, plan, type, status, created_at) VALUES (?, ?, ?, ?, 'user_not_found', ?)",
                (event_id, user_id, plan, event_type, now),
            )
            return {"ok": True, "status": "user_not_found"}
        current_plan = row["plan"]
        next_plan = plan if PLAN_RANK.get(plan, 0) > PLAN_RANK.get(current_plan, 0) else current_plan
        connection.execute(
            "UPDATE users SET plan = ?, updated_at = ? WHERE id = ?",
            (next_plan, now, user_id),
        )
        connection.execute(
            "INSERT INTO stripe_events (id, user_id, plan, type, status, created_at) VALUES (?, ?, ?, ?, 'activated', ?)",
            (event_id, user_id, plan, event_type, now),
        )
    return {"ok": True, "status": "activated", "plan": next_plan}


def admin_code() -> str:
    return os.getenv("OSINTPRO_ADMIN_CODE", "")


def cron_secret() -> str:
    return os.getenv("OSINTPRO_CRON_SECRET", "")


def report_brand() -> str:
    return redact_text(os.getenv("OSINTPRO_REPORT_BRAND", "OSINTPRO")).strip()[:64] or "OSINTPRO"


def report_analyst() -> str:
    value = os.getenv("OSINTPRO_REPORT_ANALYST", "OSINTPRO Analyst")
    return redact_text(value).strip()[:96] or "OSINTPRO Analyst"


def report_contact() -> str:
    return redact_text(os.getenv("OSINTPRO_REPORT_CONTACT", "")).strip()[:160]


def monitor_batch_limit() -> int:
    try:
        return max(1, min(100, int(os.getenv("OSINTPRO_MONITOR_BATCH_LIMIT", str(DEFAULT_MONITOR_BATCH_LIMIT)))))
    except ValueError:
        return DEFAULT_MONITOR_BATCH_LIMIT


def registration_ip_limit() -> int:
    try:
        return max(0, min(50, int(os.getenv("OSINTPRO_REGISTRATION_IP_LIMIT", str(DEFAULT_REGISTRATION_IP_LIMIT)))))
    except ValueError:
        return DEFAULT_REGISTRATION_IP_LIMIT


def backup_retention() -> int:
    try:
        return max(1, min(90, int(os.getenv("OSINTPRO_BACKUP_RETENTION", str(DEFAULT_BACKUP_RETENTION)))))
    except ValueError:
        return DEFAULT_BACKUP_RETENTION


def api_key_rate_limit() -> int:
    try:
        return max(1, min(300, int(os.getenv("OSINTPRO_API_KEY_RATE_LIMIT", str(DEFAULT_API_KEY_RATE_LIMIT)))))
    except ValueError:
        return DEFAULT_API_KEY_RATE_LIMIT


def registration_allowlist() -> list[str]:
    raw = os.getenv("OSINTPRO_REGISTRATION_IP_ALLOWLIST", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_iso_datetime(value: object) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value or ""))
    except ValueError:
        return dt.datetime.now(dt.UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def user_growth_metrics(user_id: str) -> dict[str, object]:
    with db() as connection:
        user = connection.execute(
            "SELECT plan, credits, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            raise ValueError("User not found.")
        resource_counts = {
            "domains": connection.execute("SELECT COUNT(*) AS count FROM reports WHERE user_id = ?", (user_id,)).fetchone()["count"],
            "repos": connection.execute("SELECT COUNT(*) AS count FROM repository_reports WHERE user_id = ?", (user_id,)).fetchone()["count"],
            "social": connection.execute("SELECT COUNT(*) AS count FROM social_reports WHERE user_id = ?", (user_id,)).fetchone()["count"],
            "wallets": connection.execute("SELECT COUNT(*) AS count FROM wallet_reports WHERE user_id = ?", (user_id,)).fetchone()["count"],
            "monitors": connection.execute("SELECT COUNT(*) AS count FROM monitors WHERE user_id = ?", (user_id,)).fetchone()["count"],
        }
        since = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).replace(microsecond=0).isoformat()
        recent_events = [
            dict(row)
            for row in connection.execute(
                """
                SELECT event, plan, source, created_at
                FROM conversion_events
                WHERE user_id = ? AND created_at >= ?
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (user_id, since),
            ).fetchall()
        ]
    plan = str(user["plan"])
    created = parse_iso_datetime(user["created_at"])
    upsell: list[dict[str, object]] = []
    if plan == "Free":
        total_reports = (
            resource_counts["domains"]
            + resource_counts["repos"]
            + resource_counts["social"]
            + resource_counts["wallets"]
        )
        if total_reports >= 3:
            upsell.append({
                "feature": "unlimited_reports",
                "plan": "Pro",
                "message": "Pro removes report limits and keeps investigations flowing.",
            })
        if resource_counts["monitors"] >= 1:
            upsell.append({
                "feature": "monitoring",
                "plan": "Pro",
                "message": "Monitoring is the sticky Pro workflow for drift alerts.",
            })
    return {
        "user_plan": plan,
        "account_age_days": max(0, (dt.datetime.now(dt.UTC) - created).days),
        "resource_counts": resource_counts,
        "feature_usage": {
            "domain_analysis": resource_counts["domains"],
            "repo_audit": resource_counts["repos"],
            "social_osint": resource_counts["social"],
            "wallet_trace": resource_counts["wallets"],
            "monitoring_active": resource_counts["monitors"],
        },
        "recent_conversion_events": recent_events,
        "upsell": upsell[:2],
    }


def admin_growth_metrics() -> dict[str, object]:
    since = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).replace(microsecond=0).isoformat()
    with db() as connection:
        plan_counts = {
            row["plan"]: row["count"]
            for row in connection.execute(
                """
                SELECT plan, COUNT(*) AS count
                FROM users
                WHERE nickname IS NOT NULL
                GROUP BY plan
                """
            ).fetchall()
        }
        total_users = sum(plan_counts.values())
        reports = {
            "domain_reports": connection.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"],
            "repository_audits": connection.execute("SELECT COUNT(*) AS count FROM repository_reports").fetchone()["count"],
            "social_reports": connection.execute("SELECT COUNT(*) AS count FROM social_reports").fetchone()["count"],
            "wallet_reports": connection.execute("SELECT COUNT(*) AS count FROM wallet_reports").fetchone()["count"],
            "monitors": connection.execute("SELECT COUNT(*) AS count FROM monitors").fetchone()["count"],
        }
        stripe_conversions = connection.execute(
            "SELECT COUNT(*) AS count FROM stripe_events WHERE status = 'activated'"
        ).fetchone()["count"]
        new_users_30d = connection.execute(
            "SELECT COUNT(*) AS count FROM users WHERE nickname IS NOT NULL AND created_at >= ?",
            (since,),
        ).fetchone()["count"]
        funnel = [
            dict(row)
            for row in connection.execute(
                """
                SELECT event, COALESCE(plan, '-') AS plan, COALESCE(source, '-') AS source, COUNT(*) AS count
                FROM conversion_events
                WHERE created_at >= ?
                GROUP BY event, plan, source
                ORDER BY count DESC, event ASC
                LIMIT 30
                """,
                (since,),
            ).fetchall()
        ]
    pro_users = int(plan_counts.get("Pro", 0))
    agency_users = int(plan_counts.get("Agency", 0))
    total_mrr = pro_users * 19 + agency_users * 79
    conversion_rate = round((stripe_conversions / total_users) * 100, 2) if total_users else 0
    return {
        "total_users": total_users,
        "plans": {
            "free": int(plan_counts.get("Free", 0)),
            "pro": pro_users,
            "agency": agency_users,
            "admin": int(plan_counts.get("Admin", 0)),
        },
        "conversion_rate_percent": conversion_rate,
        "stripe_conversions": stripe_conversions,
        "new_users_30d": new_users_30d,
        "accounts_created_30d": new_users_30d,
        "reports": reports,
        "total_reports": sum(reports.values()),
        "mrr_estimate_eur": total_mrr,
        "pro_mrr_estimate": pro_users * 19,
        "agency_mrr_estimate": agency_users * 79,
        "funnel_30d": funnel,
    }


def ip_allowed(ip_value: str, allowlist: list[str]) -> bool:
    if not ip_value:
        return False
    for item in allowlist:
        try:
            if "/" in item and ipaddress.ip_address(ip_value) in ipaddress.ip_network(item, strict=False):
                return True
            if ip_value == item:
                return True
        except ValueError:
            if ip_value == item:
                return True
    return False


def cron_authorized(headers: object) -> bool:
    secret = cron_secret()
    if not secret:
        return False
    bearer = str(headers.get("Authorization", ""))
    token = str(headers.get("X-OSINTPRO-CRON", ""))
    expected = f"Bearer {secret}"
    return hmac.compare_digest(bearer, expected) or hmac.compare_digest(token, secret)


def alert_webhook_url() -> str:
    return os.getenv("OSINTPRO_ALERT_WEBHOOK_URL", "")


def smtp_settings() -> dict[str, str]:
    return {
        "host": os.getenv("OSINTPRO_SMTP_HOST", ""),
        "port": os.getenv("OSINTPRO_SMTP_PORT", "587"),
        "user": os.getenv("OSINTPRO_SMTP_USER", ""),
        "password": os.getenv("OSINTPRO_SMTP_PASSWORD", ""),
        "sender": os.getenv("OSINTPRO_SMTP_FROM", os.getenv("OSINTPRO_SMTP_USER", "")),
        "recipient": os.getenv("OSINTPRO_NOTIFICATION_EMAIL_TO", ""),
    }


def clean_webhook_event(value: object) -> str:
    event = str(value or "").strip().lower()
    if event not in WEBHOOK_EVENTS:
        raise ValueError("Unsupported webhook event.")
    return event


def clean_webhook_url(value: object) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Webhook URL must be HTTPS.")
    host = parsed.hostname or ""
    if host in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Webhook URL cannot target local addresses.")
    try:
        if ipaddress.ip_address(host).is_private:
            raise ValueError("Webhook URL cannot target private IP addresses.")
    except ValueError as exc:
        if "Webhook URL" in str(exc):
            raise
    if len(url) > 512:
        raise ValueError("Webhook URL is too long.")
    return url


def notification_log(
    connection: sqlite3.Connection,
    user_id: str | None,
    event_type: str,
    channel: str,
    status: str,
    target: str | None = None,
    message: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO notification_events
            (id, user_id, event_type, channel, status, target, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            user_id,
            event_type,
            channel,
            status,
            target,
            redact_text(message or "")[:240],
            utc_now(),
        ),
    )


def webhook_rows(connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT id, event_type, url, active, created_at, updated_at
        FROM webhooks
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user_id,),
    ).fetchall()


def public_webhook(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "event_type": row["event_type"],
        "url": row["url"],
        "active": bool(row["active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def deliver_webhook(url: str, event_type: str, payload: dict[str, object]) -> tuple[bool, str]:
    body = json.dumps(redact_data({
        "event": event_type,
        "sent_at": utc_now(),
        "payload": payload,
    })).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "OSINTPRO-webhook/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read(2048)
            return 200 <= response.status < 300, f"HTTP {response.status}"
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return False, exc.__class__.__name__


def deliver_user_webhooks(
    connection: sqlite3.Connection,
    user_id: str,
    event_type: str,
    payload: dict[str, object],
) -> dict[str, int]:
    sent = 0
    failed = 0
    rows = connection.execute(
        """
        SELECT id, url
        FROM webhooks
        WHERE user_id = ? AND event_type = ? AND active = 1
        ORDER BY created_at ASC
        LIMIT 10
        """,
        (user_id, event_type),
    ).fetchall()
    for row in rows:
        ok, message = deliver_webhook(row["url"], event_type, payload)
        sent += 1 if ok else 0
        failed += 0 if ok else 1
        notification_log(
            connection,
            user_id,
            event_type,
            "webhook",
            "sent" if ok else "failed",
            row["url"],
            message,
        )
    return {"webhooks_sent": sent, "webhooks_failed": failed}


def monitor_email_body(domain: str, payload: dict[str, object]) -> str:
    return (
        f"OSINTPRO monitor alert for {domain}\n\n"
        f"Event: monitor.changed\n"
        f"Previous score: {payload.get('previous_score')}\n"
        f"New score: {payload.get('score')}\n"
        f"Summary: {payload.get('summary')}\n\n"
        "Open OSINTPRO to review the full report and update the client case."
    )


def send_monitor_email(domain: str, payload: dict[str, object], recipient: str | None = None) -> tuple[bool, str]:
    settings = smtp_settings()
    to_address = recipient or settings["recipient"]
    required = [settings["host"], settings["user"], settings["password"], settings["sender"], to_address]
    if not all(required):
        return False, "SMTP not configured."
    try:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = f"OSINTPRO monitor changed: {domain}"
        message["From"] = settings["sender"]
        message["To"] = to_address
        message.set_content(monitor_email_body(domain, payload))
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=8) as smtp:
            smtp.starttls()
            smtp.login(settings["user"], settings["password"])
            smtp.send_message(message)
        return True, "sent"
    except (OSError, ValueError, TimeoutError) as exc:
        return False, exc.__class__.__name__


def postgres_settings() -> dict[str, object]:
    """Expose only non-secret PostgreSQL migration settings for ops checks."""
    host = os.getenv("OSINTPRO_POSTGRES_HOST", "")
    database = os.getenv("OSINTPRO_POSTGRES_DB", "osintpro")
    user = os.getenv("OSINTPRO_POSTGRES_USER", "")
    try:
        pool_size = max(1, min(50, int(os.getenv("OSINTPRO_POSTGRES_POOL_SIZE", "5"))))
    except ValueError:
        pool_size = 5
    return {
        "host_configured": bool(host),
        "database": database,
        "user_configured": bool(user),
        "password_configured": bool(os.getenv("OSINTPRO_POSTGRES_PASSWORD", "")),
        "pool_size": pool_size,
    }


def database_status() -> dict[str, object]:
    configured_path = bool(os.getenv("OSINTPRO_DB_PATH"))
    default_path = DATA_DIR / "osintpro.sqlite3"
    on_default_local_path = DB_PATH.resolve() == default_path.resolve()
    backup_count = len(list_backups())
    latest = latest_backup()
    return {
        "type": DB_TYPE,
        "active_adapter": "sqlite" if DB_TYPE == "sqlite" else "migration_blueprint_only",
        "configured_path": configured_path,
        "persistent_hint": configured_path and not on_default_local_path,
        "location": "custom" if configured_path else "default",
        "backup_count": backup_count,
        "latest_backup": latest["created_at"] if latest else None,
        "postgres": postgres_settings(),
    }


def list_backups(include_internal: bool = False) -> list[dict[str, object]]:
    if not BACKUP_DIR.exists():
        return []
    backups = []
    for path in BACKUP_DIR.glob("*.sqlite3"):
        if not BACKUP_NAME_RE.match(path.name):
            continue
        stat = path.stat()
        backups.append({
            "name": path.name,
            "size": stat.st_size,
            "created_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.UTC).replace(microsecond=0).isoformat(),
            "mtime": stat.st_mtime,
        })
    sorted_backups = sorted(backups, key=lambda item: (float(item["mtime"]), str(item["name"])), reverse=True)
    if include_internal:
        return sorted_backups
    return [{key: value for key, value in item.items() if key != "mtime"} for item in sorted_backups]


def latest_backup() -> dict[str, object] | None:
    backups = list_backups()
    return backups[0] if backups else None


def backup_path(name: str) -> Path:
    if not BACKUP_NAME_RE.match(name):
        raise ValueError("Invalid backup.")
    path = (BACKUP_DIR / name).resolve()
    if BACKUP_DIR.resolve() not in path.parents:
        raise ValueError("Invalid backup.")
    return path


def prune_backups(protected_name: str = "") -> None:
    retained = 0
    for item in list_backups(include_internal=True):
        if item["name"] == protected_name:
            retained += 1
            continue
        if retained < backup_retention():
            retained += 1
            continue
        try:
            backup_path(str(item["name"])).unlink()
        except OSError:
            pass


def create_sqlite_backup(reason: str = "manual") -> dict[str, object]:
    if not DB_PATH.exists():
        raise ValueError("Database has not been created yet.")
    safe_reason = re.sub(r"[^a-z0-9-]+", "-", reason.lower()).strip("-")[:32] or "manual"
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = secrets.token_hex(3)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    destination = BACKUP_DIR / f"osintpro-{timestamp}-{safe_reason}-{suffix}.sqlite3"
    source = sqlite3.connect(DB_PATH)
    try:
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    stat = destination.stat()
    prune_backups(destination.name)
    return {
        "name": destination.name,
        "size": stat.st_size,
        "created_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.UTC).replace(microsecond=0).isoformat(),
        "retention": backup_retention(),
    }


def validate_sqlite_database(path: Path) -> dict[str, object]:
    required_tables = {"users", "reports", "social_reports", "monitors", "stripe_events"}
    try:
        connection = sqlite3.connect(path)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise ValueError("Snapshot SQLite non integro.")
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            missing = sorted(required_tables - tables)
            if missing:
                raise ValueError("Snapshot non compatibile con OSINTPRO.")
            user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            report_count = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            social_count = connection.execute("SELECT COUNT(*) FROM social_reports").fetchone()[0]
            monitor_count = connection.execute("SELECT COUNT(*) FROM monitors").fetchone()[0]
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        raise ValueError("Invalid SQLite file.") from exc
    return {
        "users": user_count,
        "reports": report_count,
        "social_reports": social_count,
        "monitors": monitor_count,
    }


def restore_sqlite_backup(payload: bytes) -> dict[str, object]:
    if len(payload) > MAX_RESTORE_BYTES:
        raise ValueError("Backup is too large.")
    if not payload.startswith(b"SQLite format 3\x00"):
        raise ValueError("Invalid SQLite backup file.")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    temp_path = BACKUP_DIR / f"restore-{secrets.token_hex(8)}.sqlite3"
    temp_path.write_bytes(payload)
    try:
        restored_counts = validate_sqlite_database(temp_path)
        previous_backup = create_sqlite_backup("pre-restore") if DB_PATH.exists() else None
        for suffix in ("-wal", "-shm"):
            try:
                Path(str(DB_PATH) + suffix).unlink()
            except OSError:
                pass
        os.replace(temp_path, DB_PATH)
        init_db()
        return {
            "ok": True,
            "restored": restored_counts,
            "pre_restore_backup": previous_backup,
            "admin": None,
        }
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def send_alert(event: str, payload: dict[str, object]) -> None:
    url = alert_webhook_url()
    if not url:
        return
    body = json.dumps(redact_data({"event": event, "sent_at": utc_now(), **payload})).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "OSINTPRO-monitor-alert/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            response.read(1024)
    except (OSError, urllib.error.URLError, TimeoutError):
        pass


def is_paid_plan(plan: str) -> bool:
    return plan in PAID_PLANS


def can_use_api(plan: str) -> bool:
    return plan in {"Agency", "Admin"}


def clean_api_key_name(value: object) -> str:
    name = re.sub(r"\s+", " ", str(value or "").strip())
    if not name:
        name = "Agency API key"
    if len(name) > 64:
        raise ValueError("API key name is too long.")
    if SECRET_KEY_RE.search(name):
        raise ValueError("API key name cannot contain secret-like words.")
    return name


def generate_api_key() -> str:
    return "opk_" + secrets.token_urlsafe(36)


def hash_api_key(token: str) -> str:
    return hmac.new(server_secret().encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def api_key_prefix(token: str) -> str:
    return token[:12]


def public_api_key(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "name": row["name"],
        "prefix": row["prefix"],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "revoked_at": row["revoked_at"],
    }


def report_credit_limit(plan: str) -> int | None:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["Free"]).get("credits")


def has_report_access(row: sqlite3.Row) -> bool:
    if is_paid_plan(row["plan"]):
        return True
    limit = report_credit_limit(row["plan"])
    return limit is None or int(row["credits"]) > 0


def should_decrement_report_credit(row: sqlite3.Row) -> bool:
    return not is_paid_plan(row["plan"]) and report_credit_limit(row["plan"]) is not None


def clean_repo_path(value: object) -> str:
    path = str(value or "").replace("\\", "/").strip().lstrip("/")
    if not path or len(path) > 240:
        raise ValueError("Invalid repository path.")
    parts = [part for part in path.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        raise ValueError("Invalid repository path.")
    return "/".join(parts)


def repo_line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def repo_evidence(line: str) -> str:
    return redact_text(line.strip())[:220]


def repo_rule_id(category: str, title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", f"{category}-{title}".lower()).strip("-")
    return f"OSINTPRO-{slug[:80] or 'repository-finding'}"


def repo_finding(
    *,
    severity: str,
    confidence: str,
    category: str,
    title: str,
    path: str,
    line: int,
    evidence: str,
    why: str,
    remediation: str,
    applicability: str = "Applies when this code path is reachable in production.",
) -> dict[str, object]:
    abuse_context = repository_abuse_context(category, title)
    return {
        "rule_id": repo_rule_id(category, title),
        "severity": severity,
        "confidence": confidence,
        "confidence_score": REPO_CONFIDENCE_SCORES.get(confidence, 0.5),
        "category": category,
        "title": title,
        "path": path,
        "line": line,
        "evidence": repo_evidence(evidence),
        "why": why,
        "abuse_path": abuse_context["abuse_path"],
        "business_impact": abuse_context["business_impact"],
        "owner_action": abuse_context["owner_action"],
        "remediation": remediation,
        "applicability": applicability,
    }


def repository_abuse_context(category: str, title: str) -> dict[str, str]:
    """Explain realistic defensive impact without giving exploitation steps."""
    key = f"{category} {title}".lower()
    if "secret" in key or "credential" in key or "aws" in key or "private key" in key:
        return {
            "abuse_path": "An attacker who obtains the repository or build artifact could try the exposed credential against the issuing service, then pivot into data, billing or deployment systems if the key is still valid.",
            "business_impact": "Cloud cost spikes, customer data exposure, supply-chain compromise or unauthorized production changes.",
            "owner_action": "Treat the value as exposed: revoke it, rotate dependent secrets, inspect provider logs and replace long-lived keys with scoped workload identities.",
        }
    if "command" in key or "execution" in key or "deserialization" in key:
        return {
            "abuse_path": "If external input can reach this code path, an attacker may try to turn data into server-side execution or unsafe object loading.",
            "business_impact": "Service takeover, data theft, ransomware staging or lateral movement from the affected runtime.",
            "owner_action": "Remove dynamic execution, enforce strict allowlists, isolate the runtime and add tests that prove untrusted input stays data-only.",
        }
    if "database" in key or "sql" in key:
        return {
            "abuse_path": "If user-controlled values influence the query shape, an attacker may attempt to read or alter records outside the intended object scope.",
            "business_impact": "Customer data leakage, account takeover support paths, billing manipulation or audit-log tampering.",
            "owner_action": "Use parameterized queries, object-level authorization and query logging around sensitive tables.",
        }
    if "browser" in key or "cors" in key or "innerhtml" in key:
        return {
            "abuse_path": "A malicious site or crafted content could try to make a trusted browser read data or execute script in a context the user already trusts.",
            "business_impact": "Session abuse, data exposure, fraudulent actions or loss of customer trust after visible account compromise.",
            "owner_action": "Constrain trusted origins, sanitize rendered HTML and add browser security headers with regression tests.",
        }
    if "transport" in key or "tls" in key:
        return {
            "abuse_path": "On an untrusted network, a machine-in-the-middle position could make the application trust an impostor endpoint.",
            "business_impact": "Credential interception, poisoned API responses or silent data exposure in internal tooling.",
            "owner_action": "Restore certificate validation, pin only where operationally justified and monitor for disabled verification in CI.",
        }
    return {
        "abuse_path": "A real attacker would first confirm whether this code path is reachable, then look for trust-boundary mistakes around the affected data.",
        "business_impact": "Operational risk depends on reachability, privilege and data sensitivity.",
        "owner_action": "Confirm applicability with the owning engineer, add a regression test and document the accepted risk or fix.",
    }


def dependency_version_tuple(version: object) -> tuple[int, ...]:
    value = str(version or "").strip()
    value = re.sub(r"^[~^<>=! ]+", "", value)
    value = value.split("||")[0].split(",")[0].strip()
    match = re.search(r"(\d+(?:\.\d+){0,4})", value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def dependency_is_older(current: object, fixed: object) -> bool:
    current_tuple = dependency_version_tuple(current)
    fixed_tuple = dependency_version_tuple(fixed)
    if not current_tuple or not fixed_tuple:
        return False
    size = max(len(current_tuple), len(fixed_tuple))
    return current_tuple + (0,) * (size - len(current_tuple)) < fixed_tuple + (0,) * (size - len(fixed_tuple))


def parse_package_json_dependencies(content: str) -> dict[str, str]:
    payload = json.loads(content)
    if not isinstance(payload, dict):
        return {}
    dependencies: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = payload.get(section)
        if isinstance(values, dict):
            dependencies.update({str(name).lower(): str(version) for name, version in values.items()})
    return dependencies


def parse_requirements_dependencies(content: str) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(("-r ", "--")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([^#;\s]+)?", line)
        if match:
            dependencies[match.group(1).lower().replace("_", "-")] = match.group(2) or ""
    return dependencies


def parse_cargo_dependencies(content: str) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    in_dependencies = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_dependencies = stripped in {"[dependencies]", "[dev-dependencies]"}
            continue
        if not in_dependencies or not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, raw_value = stripped.split("=", 1)
        version_match = re.search(r'"([^"]+)"', raw_value)
        if version_match:
            dependencies[name.strip().strip('"').lower()] = version_match.group(1)
    return dependencies


def parse_composer_dependencies(content: str) -> dict[str, str]:
    payload = json.loads(content)
    if not isinstance(payload, dict):
        return {}
    dependencies: dict[str, str] = {}
    for section in ("require", "require-dev"):
        values = payload.get(section)
        if isinstance(values, dict):
            dependencies.update({str(name).lower(): str(version) for name, version in values.items()})
    return dependencies


def dependency_advisories_for_files(files: list[tuple[str, str]]) -> list[dict[str, object]]:
    """Return offline dependency review leads from uploaded manifest files.

    This intentionally does not call package registries or install dependencies;
    it is a passive, explainable advisory layer for the Repository Audit Lab.
    """
    parsers = {
        "package.json": ("npm", parse_package_json_dependencies),
        "requirements.txt": ("pip", parse_requirements_dependencies),
        "cargo.toml": ("cargo", parse_cargo_dependencies),
        "composer.json": ("composer", parse_composer_dependencies),
    }
    findings: list[dict[str, object]] = []
    for path, content in files:
        name = Path(path).name.lower()
        if name not in parsers:
            continue
        ecosystem, parser = parsers[name]
        try:
            dependencies = parser(content)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        for package, current in dependencies.items():
            advisory = DEPENDENCY_ADVISORIES.get(ecosystem, {}).get(package.lower())
            if not advisory:
                continue
            fixed = str(advisory["fixed"])
            if not dependency_is_older(current, fixed):
                continue
            findings.append({
                "ecosystem": ecosystem,
                "package": package,
                "current": str(current),
                "fixed_version": fixed,
                "severity": advisory["severity"],
                "advisory": advisory["advisory"],
                "path": path,
                "abuse_path": "An attacker may target known vulnerable package versions when the dependency is reachable through public routes, parsing code or build tooling.",
                "business_impact": "Impact depends on the advisory class, but common outcomes include data exposure, account abuse, build compromise or denial of service.",
                "owner_action": "Confirm whether the package is loaded in production, upgrade to the fixed version and redeploy from a clean lockfile.",
                "remediation": f"Upgrade {package} to >= {fixed} and regenerate the lockfile.",
            })
    return findings[:60]


def parse_gitignore_text(content: str, base_dir: str = "") -> list[str]:
    """Parse the subset of .gitignore syntax useful for bounded static review.

    Negated patterns are intentionally ignored. OSINTPRO uses this only to
    reduce false positives and avoid reviewing dependency/generated files; it
    does not need to perfectly emulate Git's matcher.
    """
    patterns: list[str] = []
    clean_base = base_dir.strip("/")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        line = line.lstrip("/")
        if line.endswith("/"):
            line = f"{line}**"
        if clean_base and "/" not in line:
            patterns.append(f"{clean_base}/**/{line}")
        if clean_base and not line.startswith(clean_base + "/"):
            patterns.append(f"{clean_base}/{line}")
        patterns.append(line)
    return patterns


def repo_ignore_patterns(files: list[tuple[str, str]]) -> list[str]:
    patterns = list(DEFAULT_REPO_IGNORE_PATTERNS)
    for path, content in files:
        if Path(path).name == ".gitignore":
            parent = str(Path(path).parent).replace(".", "").strip("/")
            patterns.extend(parse_gitignore_text(content, parent))
    return patterns


def should_ignore_repo_path(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/").strip("/")
    parts = normalized.split("/")
    for pattern in patterns:
        clean = pattern.replace("\\", "/").strip("/")
        if not clean:
            continue
        if clean.endswith("/**") and normalized.startswith(clean[:-3].rstrip("/") + "/"):
            return True
        if "/" not in clean and any(fnmatch.fnmatch(part, clean) for part in parts):
            return True
        if fnmatch.fnmatch(normalized, clean):
            return True
        if fnmatch.fnmatch(normalized, f"**/{clean}"):
            return True
    return False


REPO_AUDIT_RULES = [
    {
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "severity": "critical",
        "confidence": "high",
        "category": "Secrets",
        "title": "Private key material committed",
        "why": "A private key inside source control can grant direct access to systems or signed identities.",
        "remediation": "Revoke and rotate the key, remove it from Git history and load the replacement from a secret manager.",
        "applicability": "Always applicable unless this is an intentionally fake fixture with no real key material.",
    },
    {
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "critical",
        "confidence": "high",
        "category": "Secrets",
        "title": "Possible AWS access key",
        "why": "AWS access keys can authorize cloud API actions and create direct financial and data exposure.",
        "remediation": "Disable the credential, inspect CloudTrail, rotate it and use workload identities or environment secrets.",
        "applicability": "Confirm in the AWS account. Example values should still be replaced with clearly invalid placeholders.",
    },
    {
        "pattern": re.compile(r"\b(?:sk_live|rk_live|ghp_|github_pat_|xox[baprs]-)[-A-Za-z0-9_]{12,}\b"),
        "severity": "critical",
        "confidence": "high",
        "category": "Secrets",
        "title": "Live service credential pattern",
        "why": "The value resembles a production credential for a third-party service.",
        "remediation": "Revoke it immediately, inspect provider logs and replace it with an environment variable.",
        "applicability": "Confirm with the issuing provider; the displayed evidence is redacted by OSINTPRO.",
    },
    {
        "pattern": re.compile(r"(?m)^\s*(?:SECRET_KEY|API_KEY|ACCESS_TOKEN|PASSWORD)\s*=\s*[\"'][^\"'\n]{8,}[\"']"),
        "severity": "high",
        "confidence": "medium",
        "category": "Secrets",
        "title": "Hard-coded secret-like value",
        "why": "Long-lived credentials in code are copied into builds, logs and repository history.",
        "remediation": "Move the value to an environment variable or secret manager and rotate it if it was real.",
        "applicability": "Review whether the value is a real credential or an explicitly fake development placeholder.",
    },
    {
        "pattern": re.compile(r"\b(?:subprocess\.(?:run|Popen|call)|os\.system)\s*\([^\n]*(?:shell\s*=\s*True|request\.|input\(|argv|params|query)", re.IGNORECASE),
        "severity": "critical",
        "confidence": "medium",
        "category": "Command execution",
        "title": "User-influenced shell execution",
        "why": "Combining external input with a shell can allow command injection.",
        "remediation": "Avoid shell=True, pass a fixed argument array and validate every variable against a strict allowlist.",
    },
    {
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "severity": "high",
        "confidence": "medium",
        "category": "Code execution",
        "title": "Dynamic code execution",
        "why": "eval/exec can turn untrusted or partially controlled strings into executable code.",
        "remediation": "Replace dynamic execution with a parser, explicit dispatch table or structured data format.",
        "applicability": "Priority is high only when the evaluated value can be influenced outside the trusted codebase.",
    },
    {
        "pattern": re.compile(r"\bpickle\.loads?\s*\("),
        "severity": "high",
        "confidence": "high",
        "category": "Deserialization",
        "title": "Unsafe pickle deserialization",
        "why": "Python pickle can execute code while loading crafted data.",
        "remediation": "Use JSON or another non-executable format and never unpickle untrusted input.",
        "applicability": "Applies when the serialized input is not fully controlled and authenticated.",
    },
    {
        "pattern": re.compile(r"\byaml\.load\s*\([^,\n\)]*\)"),
        "severity": "high",
        "confidence": "medium",
        "category": "Deserialization",
        "title": "YAML load without an explicit safe loader",
        "why": "Unsafe YAML loaders may instantiate attacker-controlled objects.",
        "remediation": "Use yaml.safe_load or explicitly pass SafeLoader.",
    },
    {
        "pattern": re.compile(r"(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False)"),
        "severity": "high",
        "confidence": "high",
        "category": "Transport security",
        "title": "TLS certificate verification disabled",
        "why": "Disabling certificate or hostname validation allows machine-in-the-middle interception.",
        "remediation": "Restore certificate verification and configure a trusted CA bundle for private services.",
        "applicability": "Test-only code should be isolated and impossible to enable in production.",
    },
    {
        "pattern": re.compile(r"(?:Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']\*|origins?\s*=\s*[\"']\*[\"'])", re.IGNORECASE),
        "severity": "medium",
        "confidence": "medium",
        "category": "Browser security",
        "title": "Broad cross-origin access",
        "why": "A wildcard CORS policy can expose browser-readable data to unrelated origins.",
        "remediation": "Allow only the exact trusted origins and avoid wildcard credentials combinations.",
        "applicability": "Public, intentionally unauthenticated APIs may accept wildcard origins after data exposure review.",
    },
    {
        "pattern": re.compile(r"\bDEBUG\s*=\s*True\b|app\.run\([^\n]*debug\s*=\s*True", re.IGNORECASE),
        "severity": "medium",
        "confidence": "high",
        "category": "Configuration",
        "title": "Debug mode enabled",
        "why": "Production debug modes can expose stack traces, source code or interactive debuggers.",
        "remediation": "Use environment-specific configuration and force debug off in production.",
        "applicability": "Ignore only for isolated local configuration that cannot be deployed.",
    },
    {
        "pattern": re.compile(r"\.execute\s*\(\s*f[\"']|\.execute\s*\([^\n]*\+\s*(?:request|input|params|query)", re.IGNORECASE),
        "severity": "high",
        "confidence": "medium",
        "category": "Database",
        "title": "SQL built with string interpolation",
        "why": "Dynamic SQL construction can create SQL injection when values are externally influenced.",
        "remediation": "Use parameterized queries and allowlist any dynamic table or column identifiers.",
    },
    {
        "pattern": re.compile(r"\.innerHTML\s*=\s*(?![\"'`]\s*[\"'`])"),
        "severity": "low",
        "confidence": "low",
        "category": "Frontend",
        "title": "Dynamic innerHTML assignment",
        "why": "Writing non-constant HTML can create DOM XSS if the value contains untrusted data.",
        "remediation": "Prefer textContent or construct DOM nodes; otherwise sanitize with a proven HTML sanitizer.",
        "applicability": "Review the full data flow. This is not a vulnerability when every interpolated value is safely escaped.",
    },
]


def analyze_repository(raw_files: object, repository_name: object = "") -> dict[str, object]:
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("Select a repository folder with readable text files.")
    if len(raw_files) > MAX_REPO_AUDIT_FILES:
        raise ValueError(f"Repository audit accepts at most {MAX_REPO_AUDIT_FILES} text files per run.")

    received_files: list[tuple[str, str]] = []
    for item in raw_files:
        if not isinstance(item, dict):
            raise ValueError("Invalid repository file payload.")
        content = item.get("content")
        if not isinstance(content, str):
            raise ValueError("Repository files must contain text.")
        received_files.append((clean_repo_path(item.get("path")), content))

    ignore_patterns = repo_ignore_patterns(received_files)
    files: list[tuple[str, str]] = []
    total_bytes = 0
    ignored_files = 0
    for path, content in received_files:
        if Path(path).name != ".gitignore" and should_ignore_repo_path(path, ignore_patterns):
            ignored_files += 1
            continue
        size = len(content.encode("utf-8"))
        if size > MAX_REPO_FILE_BYTES:
            ignored_files += 1
            continue
        total_bytes += size
        if total_bytes > MAX_REPO_AUDIT_BYTES:
            raise ValueError("Repository text exceeds the 2 MB audit limit.")
        files.append((path, content))

    if not files:
        raise ValueError("No readable source files were included.")

    findings: list[dict[str, object]] = []
    languages: set[str] = set()
    manifests: set[str] = set()
    signals = {
        "email": False,
        "authentication": False,
        "payments": False,
        "database": False,
        "frontend": False,
        "container": False,
        "ci": False,
    }
    extension_languages = {
        ".py": "Python",
        ".js": "JavaScript",
        ".mjs": "JavaScript",
        ".cjs": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript/React",
        ".jsx": "JavaScript/React",
        ".php": "PHP",
        ".rb": "Ruby",
        ".go": "Go",
        ".rs": "Rust",
        ".java": "Java",
        ".cs": "C#",
        ".html": "HTML",
        ".css": "CSS",
        ".sql": "SQL",
        ".yml": "YAML",
        ".yaml": "YAML",
    }
    manifest_names = {
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "cargo.toml",
        "composer.json",
        "gemfile",
        "dockerfile",
    }

    for path, content in files:
        suffix = Path(path).suffix.lower()
        if suffix in extension_languages:
            languages.add(extension_languages[suffix])
        name = Path(path).name.lower()
        if name in manifest_names:
            manifests.add(name)
        lower_blob = content.lower()
        signals["email"] = signals["email"] or any(token in lower_blob for token in ("smtp", "sendgrid", "mailgun", "postmark", "nodemailer", "send_mail"))
        signals["authentication"] = signals["authentication"] or any(token in lower_blob for token in ("login", "password_hash", "bcrypt", "session", "jwt"))
        signals["payments"] = signals["payments"] or any(token in lower_blob for token in ("stripe", "paypal", "checkout.session"))
        signals["database"] = signals["database"] or any(token in lower_blob for token in ("sqlite", "postgres", "mysql", "mongodb", ".execute("))
        signals["frontend"] = signals["frontend"] or suffix in {".js", ".ts", ".tsx", ".jsx", ".html"}
        signals["container"] = signals["container"] or name in {"dockerfile", "docker-compose.yml", "compose.yml"}
        signals["ci"] = signals["ci"] or path.startswith(".github/workflows/")

        for rule in REPO_AUDIT_RULES:
            for match in rule["pattern"].finditer(content):
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.end())
                if line_end < 0:
                    line_end = len(content)
                line_text = content[line_start:line_end]
                if any(placeholder in line_text.lower() for placeholder in ("example", "dummy", "changeme", "your_", "<secret", "redacted")):
                    continue
                findings.append(repo_finding(
                    severity=str(rule["severity"]),
                    confidence=str(rule["confidence"]),
                    category=str(rule["category"]),
                    title=str(rule["title"]),
                    path=path,
                    line=repo_line_number(content, match.start()),
                    evidence=line_text,
                    why=str(rule["why"]),
                    remediation=str(rule["remediation"]),
                    applicability=str(rule.get("applicability", "Applies when this code path is reachable in production.")),
                ))
                if len(findings) >= 120:
                    break
            if len(findings) >= 120:
                break
        if len(findings) >= 120:
            break

    paths = {path.lower() for path, _ in files}
    if ".env" in paths or any(path.endswith("/.env") for path in paths):
        findings.append(repo_finding(
            severity="high",
            confidence="high",
            category="Secrets",
            title="Environment file included in repository",
            path=".env",
            line=1,
            evidence=".env",
            why="Environment files commonly contain credentials and deployment configuration.",
            remediation="Remove it from version control, rotate exposed values and commit only a sanitized .env.example.",
            applicability="Applies unless the file is a guaranteed secret-free fixture.",
        ))

    if "package.json" in manifests and not manifests.intersection({"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}):
        findings.append(repo_finding(
            severity="low",
            confidence="high",
            category="Dependencies",
            title="JavaScript dependency lockfile not included",
            path="package.json",
            line=1,
            evidence="package.json without a detected lockfile",
            why="Unpinned dependency resolution makes builds less reproducible and can introduce unexpected versions.",
            remediation="Commit the lockfile generated by the package manager used in CI and production.",
            applicability="Applies to deployable applications; reusable libraries may intentionally support broader dependency ranges.",
        ))

    dependency_advisories = dependency_advisories_for_files(files)
    for advisory in dependency_advisories:
        package = str(advisory["package"])
        fixed_version = str(advisory["fixed_version"])
        ecosystem = str(advisory["ecosystem"]).upper()
        findings.append(repo_finding(
            severity=str(advisory["severity"]),
            confidence="high",
            category="Dependencies",
            title=f"Known vulnerable {ecosystem} dependency: {package}",
            path=str(advisory["path"]),
            line=1,
            evidence=f"{package} {advisory['current']}",
            why=str(advisory["advisory"]),
            remediation=str(advisory["remediation"]),
            applicability=f"Applies when {package} is installed in production or CI. Upgrade to >= {fixed_version} and rerun tests.",
        ))

    raw_findings = findings
    title_occurrences: dict[str, int] = {}
    displayed_by_title: dict[str, int] = {}
    findings = []
    for item in raw_findings:
        title = str(item["title"])
        title_occurrences[title] = title_occurrences.get(title, 0) + 1
        if displayed_by_title.get(title, 0) >= 8:
            continue
        findings.append(item)
        displayed_by_title[title] = displayed_by_title.get(title, 0) + 1

    severity_weight = {"critical": 25, "high": 14, "medium": 7, "low": 2, "info": 0}
    confidence_weight = {"high": 1.0, "medium": 0.65, "low": 0.2}
    family_caps = {"critical": 35, "high": 25, "medium": 12, "low": 4, "info": 0}
    penalty_by_title: dict[str, float] = {}
    for item in raw_findings:
        severity = str(item["severity"])
        title = str(item["title"])
        penalty = severity_weight.get(severity, 0) * confidence_weight.get(str(item["confidence"]), 0.5)
        penalty_by_title[title] = min(family_caps.get(severity, 10), penalty_by_title.get(title, 0) + penalty)
    score = max(0, 100 - round(sum(penalty_by_title.values())))
    counts = {level: sum(1 for item in raw_findings if item["severity"] == level) for level in ("critical", "high", "medium", "low")}
    suppressed_findings = len(raw_findings) - len(findings)
    repo_name = re.sub(r"[^a-zA-Z0-9._ -]", "", str(repository_name or "").strip())[:80] or "Uploaded repository"
    return redact_data({
        "id": str(uuid.uuid4()),
        "repository": repo_name,
        "generated_at": utc_now(),
        "score": score,
        "files_scanned": len(files),
        "bytes_scanned": total_bytes,
        "ignored_files": ignored_files,
        "ignore_patterns": ignore_patterns[:60],
        "languages": sorted(languages),
        "manifests": sorted(manifests),
        "context": signals,
        "counts": counts,
        "findings": findings,
        "dependency_advisories": dependency_advisories,
        "total_findings": len(raw_findings),
        "suppressed_findings": suppressed_findings,
        "finding_families": title_occurrences,
        "limitations": [
            "Static review only: OSINTPRO does not execute uploaded code, install dependencies or run build scripts.",
            "A finding is a review lead, not proof of exploitability. Confirm reachability, trust boundaries and deployment configuration.",
            "Files larger than 180 KB, binaries and ignored dependency/build folders are skipped.",
        ],
    })


def normalize_nickname(raw: str) -> str:
    value = raw.strip().lstrip("@").lower()
    if not USERNAME_RE.match(value):
        raise ValueError("Invalid nickname: use 2-32 characters with letters, numbers, dot, underscore or dash.")
    return value


def password_hash(password: str, salt: str | None = None) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 180000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        scheme, salt, expected = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        candidate = password_hash(password, salt).split("$", 2)[2]
    except ValueError:
        return False
    return hmac.compare_digest(candidate, expected)


def hash_reset_token(token: str) -> str:
    """Store reset tokens as keyed digests so database leaks do not expose links."""
    return hmac.new(server_secret().encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def public_base_url() -> str:
    return os.getenv("OSINTPRO_PUBLIC_URL", "https://osintpro-48j4.onrender.com").rstrip("/")


def reset_password_url(token: str) -> str:
    return f"{public_base_url()}/reset-password/{quote(token)}"


def send_password_reset_email(email: str, token: str) -> tuple[bool, str]:
    settings = smtp_settings()
    required = [settings["host"], settings["user"], settings["password"], settings["sender"], email]
    if not all(required):
        return False, "SMTP not configured."
    try:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = "OSINTPRO - Reset your password"
        message["From"] = settings["sender"]
        message["To"] = email
        message.set_content(
            "Password reset requested for your OSINTPRO account.\n\n"
            f"Reset your password here. The link expires in 1 hour:\n{reset_password_url(token)}\n\n"
            "If you did not request this, ignore this email."
        )
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=8) as smtp:
            smtp.starttls()
            smtp.login(settings["user"], settings["password"])
            smtp.send_message(message)
        return True, "sent"
    except (OSError, ValueError, TimeoutError) as exc:
        return False, exc.__class__.__name__


def reset_row_for_token(connection: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    token_hash = hash_reset_token(token)
    row = connection.execute(
        """
        SELECT user_id, expires_at, used_at
        FROM password_resets
        WHERE token_hash = ?
        """,
        (token_hash,),
    ).fetchone()
    if not row or row["used_at"]:
        return None
    try:
        expires_at = dt.datetime.fromisoformat(str(row["expires_at"]))
    except ValueError:
        return None
    now = dt.datetime.now(dt.UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=dt.UTC)
    return row if expires_at >= now else None


def clean_domain(raw: str) -> str:
    value = raw.strip().lower()
    if "://" in value:
        value = urlparse(value).netloc
    value = value.split("/")[0].split(":")[0].strip(".")
    if value.startswith("www."):
        value = value[4:]
    if not DOMAIN_RE.match(value):
        raise ValueError("Enter a valid domain, for example openai.com")
    return value


def clean_username(raw: str) -> str:
    value = raw.strip().lstrip("@")
    if not USERNAME_RE.match(value):
        raise ValueError("Enter a valid username: 2-32 characters, letters, numbers, dot, underscore or dash.")
    return value


def clean_folder_name(raw: str) -> str:
    value = re.sub(r"\s+", " ", raw.strip())
    if not 2 <= len(value) <= 64:
        raise ValueError("Folder name must be 2-64 characters.")
    if re.search(r"[<>]", value):
        raise ValueError("Folder name contains unsupported characters.")
    return value


def clean_folder_id(raw: object) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if not UUID_RE.match(value):
        raise ValueError("Invalid client folder.")
    return value


def clean_tags(raw: object) -> list[str]:
    if isinstance(raw, str):
        items = raw.split(",")
    elif isinstance(raw, list):
        items = [str(item) for item in raw]
    else:
        items = []
    tags = []
    for item in items:
        tag = re.sub(r"[^a-zA-Z0-9 _.-]+", "", item).strip().lower()
        tag = re.sub(r"\s+", "-", tag)[:28]
        if tag and tag not in tags:
            tags.append(tag)
    return tags[:12]


def clean_case_note(raw: object) -> str:
    return redact_text(str(raw or "").strip())[:1600]


def clean_wallet_address(raw: str) -> tuple[str, str]:
    value = raw.strip()
    if EVM_ADDRESS_RE.match(value):
        return "ethereum", value
    if BTC_ADDRESS_RE.match(value):
        return "bitcoin", value
    raise ValueError("Enter a valid Bitcoin or Ethereum/EVM wallet address.")


def btc_to_unit(value: int | float | None) -> float:
    return round(float(value or 0) / 100_000_000, 8)


def wei_to_eth(value: str | int | float | None) -> float:
    try:
        return round(float(value or 0) / 10**18, 8)
    except (TypeError, ValueError):
        return 0.0


def compact_address(value: str | None) -> str:
    if not value:
        return "unknown"
    return value if len(value) <= 18 else f"{value[:8]}...{value[-6:]}"


def wallet_explorer_url(chain: str, address: str) -> str:
    if chain == "bitcoin":
        return f"https://blockstream.info/address/{quote(address)}"
    return f"https://eth.blockscout.com/address/{quote(address)}"


def wallet_tx_url(chain: str, txid: str) -> str:
    if chain == "bitcoin":
        return f"https://blockstream.info/tx/{quote(txid)}"
    return f"https://eth.blockscout.com/tx/{quote(txid)}"


def local_network_snapshot() -> dict[str, object]:
    hostname = socket.gethostname()
    addresses = []
    seen = set()
    try:
        candidates = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except socket.gaierror:
        candidates = []
    for item in candidates:
        ip_value = item[4][0]
        if ip_value not in seen:
            seen.add(ip_value)
            addresses.append({
                "ip": ip_value,
                "type": "private" if ipaddress.ip_address(ip_value).is_private else "public",
                "loopback": ipaddress.ip_address(ip_value).is_loopback,
            })
    if "127.0.0.1" not in seen:
        addresses.append({"ip": "127.0.0.1", "type": "loopback", "loopback": True})

    resolver_hosts = []
    resolv_conf = Path("/etc/resolv.conf")
    if resolv_conf.exists():
        try:
            for line in resolv_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("nameserver "):
                    resolver_hosts.append(line.split()[1])
        except OSError:
            pass

    return redact_data({
        "hostname": hostname,
        "addresses": addresses[:12],
        "resolvers": resolver_hosts[:6],
        "capture_filters": [
            {"filter": "arp or icmp", "use": "See local discovery and ping traffic on your own network."},
            {"filter": "dns", "use": "See name lookups made by your device."},
            {"filter": "tcp.port == 443", "use": "Focus on HTTPS connection metadata."},
            {"filter": "mdns or udp.port == 5353", "use": "Review local multicast device discovery."},
            {"filter": "dhcp or bootp", "use": "Review address assignment traffic when reconnecting to your network."},
        ],
        "timeline": [
            {"protocol": "ARP", "summary": "Device asks who owns a local IP address.", "plain": "This is normal local discovery."},
            {"protocol": "DNS", "summary": "Device asks a resolver for a domain name.", "plain": "Useful for seeing which public services a device contacts."},
            {"protocol": "TCP", "summary": "Device opens a connection to a remote IP and port.", "plain": "Shows metadata such as endpoints and ports, not encrypted page content."},
            {"protocol": "TLS", "summary": "Device negotiates an encrypted HTTPS session.", "plain": "Certificate and SNI metadata may be visible; passwords and page bodies remain encrypted."},
            {"protocol": "mDNS", "summary": "Local devices announce names and services.", "plain": "Useful for understanding printers, TVs and other devices on your own LAN."},
        ],
    })


def wallet_counterparty_score(counterparties: list[dict[str, object]]) -> list[dict[str, object]]:
    ranked: dict[str, dict[str, object]] = {}
    for item in counterparties:
        address = str(item.get("address") or "")
        if not address:
            continue
        current = ranked.setdefault(address, {
            "address": address,
            "direction": set(),
            "tx_count": 0,
            "total_value": 0.0,
            "labels": set(),
        })
        current["tx_count"] = int(current["tx_count"]) + 1
        current["total_value"] = round(float(current["total_value"]) + float(item.get("value") or 0), 8)
        current["direction"].add(str(item.get("direction") or "unknown"))
        if item.get("label"):
            current["labels"].add(str(item.get("label")))

    results = []
    for item in ranked.values():
        results.append({
            "address": item["address"],
            "short": compact_address(str(item["address"])),
            "direction": "/".join(sorted(item["direction"])),
            "tx_count": item["tx_count"],
            "total_value": item["total_value"],
            "labels": sorted(item["labels"]),
        })
    results.sort(key=lambda row: (int(row["tx_count"]), float(row["total_value"])), reverse=True)
    return results[:24]


def wallet_findings(chain: str, address_info: dict[str, object], transactions: list[dict[str, object]], counterparties: list[dict[str, object]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    tx_count = int(address_info.get("tx_count") or 0)
    balance = float(address_info.get("balance") or 0)
    high_fan_tx = [tx for tx in transactions if int(tx.get("input_count") or 0) >= 8 or int(tx.get("output_count") or 0) >= 8]
    unique_counterparties = len({item.get("address") for item in counterparties if item.get("address")})
    has_contract = bool(address_info.get("is_contract"))
    tags = " ".join(address_info.get("tags") or []).lower()
    mixer_terms = {"mixer", "tornado", "privacy", "coinjoin", "wasabi", "samourai", "chipmixer"}
    exchange_terms = {"exchange", "binance", "coinbase", "kraken", "okx", "bybit", "kucoin"}

    if tx_count >= 1000:
        findings.append({
            "level": "high",
            "title": "Very high-activity wallet",
            "detail": "The number of public transactions is very high: useful for cluster analysis, exchange deposit review or fraud reconstruction.",
        })
    elif tx_count >= 100:
        findings.append({
            "level": "medium",
            "title": "High-activity wallet",
            "detail": "Transaction volume suggests an operational node or frequently used wallet.",
        })

    if unique_counterparties >= 20:
        findings.append({
            "level": "medium",
            "title": "Many counterparties observed",
            "detail": "The wallet interacts with many entities in the recent window; expand the graph to additional hops.",
        })

    if high_fan_tx:
        findings.append({
            "level": "medium",
            "title": "Fan-in/fan-out pattern",
            "detail": "Some transactions have many inputs/outputs: possible consolidation, distribution or obfuscation to verify manually.",
        })

    if any(term in tags for term in mixer_terms):
        findings.append({
            "level": "high",
            "title": "Public tag compatible with mixer/privacy service",
            "detail": "Public sources associate privacy/mixer tags: use as an OSINT indicator, not definitive attribution.",
        })

    if any(term in tags for term in exchange_terms):
        findings.append({
            "level": "info",
            "title": "Possible exchange/service wallet",
            "detail": "Public tags suggest a centralized service or exchange; useful for compliance requests or preservation letters.",
        })

    if has_contract:
        findings.append({
            "level": "info",
            "title": "Contract or smart account address",
            "detail": "The EVM address appears to be a contract/smart account: review methods, token transfers and explorer interactions.",
        })

    if balance > 0:
        findings.append({
            "level": "info",
            "title": "Observable balance",
            "detail": f"Estimated public balance: {balance} {chain.upper() if chain == 'bitcoin' else 'ETH'}.",
        })

    if not findings:
        findings.append({
            "level": "low",
            "title": "No priority pattern in the recent window",
            "detail": "Public sources do not show strong signals; expand the time window or additional chains if needed.",
        })
    return findings[:8]


def wallet_risk_score(findings: list[dict[str, str]], tx_count: int, counterparties: int) -> int:
    score = min(45, tx_count // 20) + min(25, counterparties * 2)
    for finding in findings:
        if finding.get("level") == "high":
            score += 25
        elif finding.get("level") == "medium":
            score += 12
        elif finding.get("level") == "info":
            score += 4
    return max(1, min(100, score))


def analyze_bitcoin_wallet(address: str) -> dict[str, object]:
    overview = json_get(f"https://blockstream.info/api/address/{quote(address)}")
    txs = json_get(f"https://blockstream.info/api/address/{quote(address)}/txs")
    if not isinstance(overview, dict):
        raise ValueError("Bitcoin data is not available from the public source.")
    if not isinstance(txs, list):
        txs = []

    chain_stats = overview.get("chain_stats") or {}
    mempool_stats = overview.get("mempool_stats") or {}
    funded = int(chain_stats.get("funded_txo_sum") or 0) + int(mempool_stats.get("funded_txo_sum") or 0)
    spent = int(chain_stats.get("spent_txo_sum") or 0) + int(mempool_stats.get("spent_txo_sum") or 0)
    tx_count = int(chain_stats.get("tx_count") or 0) + int(mempool_stats.get("tx_count") or 0)
    balance = btc_to_unit(funded - spent)
    total_received = btc_to_unit(funded)
    total_sent = btc_to_unit(spent)
    transactions: list[dict[str, object]] = []
    counterparties: list[dict[str, object]] = []

    for tx in txs[:12]:
        vin = tx.get("vin") or []
        vout = tx.get("vout") or []
        incoming = sum(int(out.get("value") or 0) for out in vout if out.get("scriptpubkey_address") == address)
        outgoing = sum(int(inp.get("prevout", {}).get("value") or 0) for inp in vin if inp.get("prevout", {}).get("scriptpubkey_address") == address)
        direction = "incoming" if incoming >= outgoing else "outgoing"
        net = btc_to_unit(incoming - outgoing)
        txid = str(tx.get("txid") or "")
        transactions.append({
            "hash": txid,
            "short": compact_address(txid),
            "direction": direction,
            "value": abs(net),
            "net": net,
            "fee": btc_to_unit(tx.get("fee") or 0),
            "timestamp": dt.datetime.fromtimestamp(int((tx.get("status") or {}).get("block_time") or 0), tz=dt.UTC).isoformat() if (tx.get("status") or {}).get("block_time") else None,
            "input_count": len(vin),
            "output_count": len(vout),
            "url": wallet_tx_url("bitcoin", txid),
        })
        for inp in vin:
            prev = inp.get("prevout") or {}
            other = prev.get("scriptpubkey_address")
            if other and other != address:
                counterparties.append({"address": other, "direction": "from", "value": btc_to_unit(prev.get("value") or 0)})
        for out in vout:
            other = out.get("scriptpubkey_address")
            if other and other != address:
                counterparties.append({"address": other, "direction": "to", "value": btc_to_unit(out.get("value") or 0)})

    cp_ranked = wallet_counterparty_score(counterparties)
    info = {
        "chain": "bitcoin",
        "address": address,
        "balance": balance,
        "total_received": total_received,
        "total_sent": total_sent,
        "tx_count": tx_count,
        "tags": [],
        "is_contract": False,
    }
    findings = wallet_findings("bitcoin", info, transactions, counterparties)
    risk = wallet_risk_score(findings, tx_count, len(cp_ranked))
    return {
        "id": str(uuid.uuid4()),
        "chain": "bitcoin",
        "address": address,
        "asset": "BTC",
        "generated_at": utc_now(),
        "summary": f"Bitcoin wallet with {tx_count} public transactions and estimated balance {balance} BTC.",
        "risk_score": risk,
        "explorer_url": wallet_explorer_url("bitcoin", address),
        "balance": balance,
        "total_received": total_received,
        "total_sent": total_sent,
        "tx_count": tx_count,
        "counterparties": cp_ranked,
        "transactions": transactions,
        "findings": findings,
        "reconstruction_notes": [
            "Expand counterparties with the highest transaction count or value first.",
            "Manually tag exchanges, mixers, victim wallets and hot wallets when identified.",
            "Fan-in/fan-out and repeated splits are indicators to verify with external context.",
        ],
    }


def analyze_ethereum_wallet(address: str) -> dict[str, object]:
    overview = json_get(f"https://eth.blockscout.com/api/v2/addresses/{quote(address)}")
    tx_payload = json_get(
        "https://eth.blockscout.com/api?"
        + urlencode({
            "module": "account",
            "action": "txlist",
            "address": address,
            "page": "1",
            "offset": "12",
            "sort": "desc",
        })
    )
    if not isinstance(overview, dict):
        raise ValueError("Ethereum data is not available from the public source.")
    tx_items = tx_payload.get("result") if isinstance(tx_payload, dict) else []
    if not isinstance(tx_items, list):
        tx_items = []

    balance = wei_to_eth(overview.get("coin_balance"))
    tags = []
    metadata = overview.get("metadata") or {}
    for tag in metadata.get("tags") or []:
        if isinstance(tag, dict) and tag.get("name"):
            tags.append(str(tag["name"]))
    for tag in overview.get("public_tags") or []:
        if isinstance(tag, dict) and tag.get("label"):
            tags.append(str(tag["label"]))
        elif isinstance(tag, str):
            tags.append(tag)
    ens = overview.get("ens_domain_name")
    if ens:
        tags.append(str(ens))

    transactions: list[dict[str, object]] = []
    counterparties: list[dict[str, object]] = []
    normalized = address.lower()
    for tx in tx_items[:12]:
        from_raw = str(tx.get("from") or "")
        to_raw = str(tx.get("to") or "")
        from_address = from_raw.lower()
        to_address = to_raw.lower()
        direction = "incoming" if to_address == normalized else "outgoing" if from_address == normalized else "related"
        value = wei_to_eth(tx.get("value"))
        tx_hash = str(tx.get("hash") or "")
        timestamp = None
        if tx.get("timeStamp"):
            try:
                timestamp = dt.datetime.fromtimestamp(int(tx["timeStamp"]), tz=dt.UTC).isoformat()
            except (TypeError, ValueError):
                timestamp = None
        transactions.append({
            "hash": tx_hash,
            "short": compact_address(tx_hash),
            "direction": direction,
            "value": value,
            "net": value if direction == "incoming" else -value if direction == "outgoing" else 0,
            "fee": wei_to_eth(int(tx.get("gasUsed") or 0) * int(tx.get("gasPrice") or 0)),
            "timestamp": timestamp,
            "input_count": 1,
            "output_count": 1,
            "url": wallet_tx_url("ethereum", tx_hash),
            "method": tx.get("methodId"),
            "status": "error" if str(tx.get("isError")) == "1" else "ok",
        })
        if direction == "incoming" and from_address:
            counterparties.append({
                "address": from_raw,
                "direction": "from",
                "value": value,
            })
        elif direction == "outgoing" and to_address:
            counterparties.append({
                "address": to_raw,
                "direction": "to",
                "value": value,
            })

    cp_ranked = wallet_counterparty_score(counterparties)
    tx_count = len(tx_items)
    info = {
        "chain": "ethereum",
        "address": address,
        "balance": balance,
        "tx_count": tx_count,
        "tags": tags,
        "is_contract": bool(overview.get("is_contract")),
    }
    findings = wallet_findings("ethereum", info, transactions, counterparties)
    risk = wallet_risk_score(findings, tx_count, len(cp_ranked))
    return {
        "id": str(uuid.uuid4()),
        "chain": "ethereum",
        "address": address,
        "asset": "ETH",
        "generated_at": utc_now(),
        "summary": f"Ethereum/EVM wallet with estimated balance {balance} ETH and {len(transactions)} recent transactions collected.",
        "risk_score": risk,
        "explorer_url": wallet_explorer_url("ethereum", address),
        "balance": balance,
        "total_received": None,
        "total_sent": None,
        "tx_count": tx_count,
        "ens": ens,
        "is_contract": bool(overview.get("is_contract")),
        "reputation": overview.get("reputation"),
        "tags": sorted(set(tags))[:12],
        "counterparties": cp_ranked,
        "transactions": transactions,
        "findings": findings,
        "reconstruction_notes": [
            "Check token transfers and internal transactions in the explorer when direct ETH value is low.",
            "If contracts/smart accounts appear, verify method and destination before attribution.",
            "Public tags and ENS are OSINT indicators, not definitive identity proof.",
        ],
    }


def analyze_wallet(raw_address: str) -> dict[str, object]:
    chain, address = clean_wallet_address(raw_address)
    report = analyze_bitcoin_wallet(address) if chain == "bitcoin" else analyze_ethereum_wallet(address)
    return redact_data(report)


def profile_probe(platform: dict[str, str], username: str) -> dict[str, object]:
    url = platform["url"].format(username=quote(username))
    request = urllib.request.Request(url, headers={"User-Agent": "OSINTPRO-social-passive/1.0"})
    status: int | None = None
    final_url = url
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            status = response.status
            final_url = response.geturl()
            sample = response.read(1800).decode("utf-8", errors="replace").lower()
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl()
        sample = ""
    except (OSError, urllib.error.URLError, TimeoutError):
        sample = ""

    if status in {200, 301, 302}:
        present = True
        confidence = "medium"
        if username.lower() in sample or f"@{username.lower()}" in sample:
            confidence = "high"
    elif status in {401, 403, 429}:
        present = None
        confidence = "low"
    else:
        present = False
        confidence = "medium" if status == 404 else "low"

    return {
        "platform": platform["name"],
        "url": url,
        "final_url": final_url,
        "status": status,
        "present": present,
        "confidence": confidence,
    }


def social_findings(username: str, profiles: list[dict[str, object]]) -> list[dict[str, str]]:
    found = [item for item in profiles if item["present"] is True]
    uncertain = [item for item in profiles if item["present"] is None]
    findings: list[dict[str, str]] = []
    if len(found) >= 5:
        findings.append({
            "level": "medium",
            "title": "Username reused across many platforms",
            "detail": "Reuse enables identity correlation, social graph mapping and brand impersonation checks.",
        })
    if len(found) == 0 and uncertain:
        findings.append({
            "level": "low",
            "title": "Uncertain results",
            "detail": "Some platforms limit public requests; manual verification is required.",
        })
    if any(item["platform"] in {"GitHub", "GitLab", "Keybase"} and item["present"] is True for item in profiles):
        findings.append({
            "level": "info",
            "title": "Observable developer footprint",
            "detail": "Public technical profiles can support attribution, supply-chain review and exposure review.",
        })
    if any(item["platform"] in {"Telegram", "X", "Instagram", "TikTok"} and item["present"] is True for item in profiles):
        findings.append({
            "level": "info",
            "title": "Potentially monetizable social handle",
            "detail": "Useful for brand monitoring, creator due diligence or anti-impersonation packages.",
        })
    return findings[:8]


def analyze_username(raw_username: str) -> dict[str, object]:
    username = clean_username(raw_username)
    profiles: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(profile_probe, platform, username) for platform in SOCIAL_PLATFORMS]
        for future in as_completed(futures):
            profiles.append(future.result())
    profiles.sort(key=lambda item: (item["present"] is not True, item["platform"]))

    found = [item for item in profiles if item["present"] is True]
    uncertain = [item for item in profiles if item["present"] is None]
    score = min(100, len(found) * 12 + len(uncertain) * 4)
    summary = f"Found {len(found)} likely profiles and {len(uncertain)} uncertain results for @{username}."
    findings = social_findings(username, profiles)
    recommendations = [
        "Manually verify high-confidence profiles before contacting or attributing.",
        "Monitor platforms where the username is available if it belongs to a brand.",
        "For creators/brands, reserve critical handles on major platforms.",
    ]
    return {
        "id": str(uuid.uuid4()),
        "username": username,
        "generated_at": utc_now(),
        "summary": summary,
        "score": score,
        "profiles": profiles,
        "findings": findings,
        "recommendations": recommendations,
        "red_team_paths": [
            {
                "name": "Handle correlation",
                "objective": "Correlate public presence for authorized attribution.",
                "signal": f"{len(found)} likely profiles.",
            },
            {
                "name": "Impersonation gap",
                "objective": "Identify platforms where a brand should reserve the username.",
                "signal": f"{len([item for item in profiles if item['present'] is False])} handles not observed.",
            },
        ],
        "purple_team_controls": [
            {
                "control": "Username watchlist",
                "why": "New profiles with similar handles can indicate impersonation.",
                "cadence": "weekly",
            },
            {
                "control": "Brand handle coverage",
                "why": "Reduces fake-account opportunities on high-visibility platforms.",
                "cadence": "monthly",
            },
        ],
    }


def parse_dig_answers(output: str, record_type: str) -> list[str]:
    """Return only RDATA values matching the requested DNS record type."""
    expected = record_type.upper()
    records: set[str] = set()
    for raw_line in output.splitlines():
        parts = raw_line.split(None, 4)
        if len(parts) != 5 or parts[3].upper() != expected:
            continue
        records.add(parts[4].strip().rstrip(".").strip())
    return sorted(records)


def dig(domain: str, record_type: str) -> list[str]:
    try:
        result = subprocess.run(
            ["dig", "+noall", "+answer", domain, record_type],
            capture_output=True,
            check=False,
            text=True,
            timeout=4,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return parse_dig_answers(result.stdout, record_type)


def json_get(url: str) -> object | None:
    request = urllib.request.Request(url, headers={"User-Agent": "OSINTPRO-passive-intel/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return json.loads(response.read(HTTP_LIMIT).decode("utf-8", errors="replace"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def text_probe(domain: str, path: str) -> dict[str, object]:
    status: int | None = None
    body = ""
    headers: dict[str, str] = {}
    error_message = ""
    request = urllib.request.Request(
        f"https://{domain}{path}",
        headers={"User-Agent": "OSINTPRO-passive-intel/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(HTTP_LIMIT).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
        body = error.read(HTTP_LIMIT).decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        error_message = type(error).__name__
    return {
        "path": path,
        "available": status is not None,
        "present": status is not None and 200 <= status < 400,
        "status": status,
        "content_type": headers.get("content-type"),
        "sample": redact_text(body[:700]),
        "error": error_message,
    }


def parse_cert_expiry(value: str | None) -> dict[str, object]:
    if not value:
        return {"expires_at": None, "days_remaining": None}
    try:
        expires_at = parsedate_to_datetime(value)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=dt.UTC)
        days = (expires_at - dt.datetime.now(dt.UTC)).days
        return {"expires_at": expires_at.isoformat(), "days_remaining": days}
    except (TypeError, ValueError, OverflowError):
        return {"expires_at": value, "days_remaining": None}


def resolve_addresses(domain: str) -> list[str]:
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP):
            addresses.add(info[4][0])
    except socket.gaierror:
        pass
    return sorted(addresses)


def certificate_info(domain: str) -> dict[str, str | None]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return {"subject": None, "issuer": None, "expires": None}

    subject = " / ".join("=".join(item) for group in cert.get("subject", []) for item in group)
    issuer = " / ".join("=".join(item) for group in cert.get("issuer", []) for item in group)
    return {
        "subject": subject or None,
        "issuer": issuer or None,
        "expires": cert.get("notAfter"),
    }


def https_headers(domain: str) -> dict[str, object]:
    headers: dict[str, str] = {}
    status: int | None = None
    server: str | None = None
    error_message = ""
    request = urllib.request.Request(
        f"https://{domain}/",
        headers={"User-Agent": "OSINTPRO-passive-intel/1.0"},
        method="HEAD",
    )

    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        error_message = type(error).__name__
    if headers:
        server = headers.get("server")

    assessed = status is not None
    checks = []
    for name in SECURITY_HEADERS:
        value = headers.get(name)
        checks.append({
            "name": name,
            "assessed": assessed,
            "present": bool(value),
            "value": redact_text(value) if value else value,
            "reason": (
                "Header not found in the HTTPS response"
                if assessed and not value
                else "HTTPS response unavailable; header not assessed"
                if not assessed
                else ""
            ),
        })

    return {
        "available": assessed,
        "status": status,
        "server": redact_text(server) if server else server,
        "error": error_message,
        "security_headers": checks,
    }


def rdap_info(domain: str) -> dict[str, object]:
    data = json_get(f"https://rdap.org/domain/{quote(domain)}")
    if not isinstance(data, dict):
        return {"available": False, "registrar": None, "created": None, "expires": None, "updated": None}

    events = {}
    for event in data.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            events[action] = date

    registrar = None
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item and item[0] == "fn":
                    registrar = item[3]
                    break

    return {
        "available": True,
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed") or events.get("last update of RDAP database"),
    }


def certificate_transparency(domain: str) -> dict[str, object]:
    data = json_get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json")
    if not isinstance(data, list):
        return {"available": False, "subdomains": [], "issuers": []}

    subdomains: set[str] = set()
    issuers: set[str] = set()
    for item in data[:150]:
        if not isinstance(item, dict):
            continue
        issuer = item.get("issuer_name")
        if issuer:
            issuers.add(str(issuer))
        names = str(item.get("name_value") or item.get("common_name") or "").splitlines()
        for name in names:
            clean = name.lower().replace("*.", "").strip().strip(".")
            if clean.endswith(domain) and DOMAIN_RE.match(clean):
                subdomains.add(clean)

    return {
        "available": True,
        "subdomains": sorted(subdomains)[:35],
        "issuers": sorted(issuers)[:8],
    }


def email_posture(domain: str, mx: list[str], txt: list[str]) -> dict[str, object]:
    dmarc = dig(f"_dmarc.{domain}", "TXT")
    mta_sts = dig(f"_mta-sts.{domain}", "TXT")
    tls_rpt = dig(f"_smtp._tls.{domain}", "TXT")
    txt_blob = " ".join(txt).lower()
    dmarc_blob = " ".join(dmarc).lower()
    flags = {
        "mx_present": bool(mx),
        "spf_present": "v=spf1" in txt_blob,
        "dmarc_present": "v=dmarc1" in dmarc_blob,
        "dmarc_reject": "p=reject" in dmarc_blob,
        "dmarc_quarantine": "p=quarantine" in dmarc_blob,
        "mta_sts_present": bool(mta_sts),
        "tls_rpt_present": bool(tls_rpt),
    }
    applicable = bool(flags["mx_present"] or flags["spf_present"] or flags["dmarc_present"])
    mode = (
        "mail_service_observed"
        if flags["mx_present"]
        else "outbound_or_brand_policy_observed"
        if applicable
        else "no_mail_use_observed"
    )
    raw_score = sum([
        20 if flags["mx_present"] else 0,
        20 if flags["spf_present"] else 0,
        20 if flags["dmarc_present"] else 0,
        15 if flags["dmarc_reject"] or flags["dmarc_quarantine"] else 0,
        15 if flags["mta_sts_present"] else 0,
        10 if flags["tls_rpt_present"] else 0,
    ])
    return {
        "score": min(100, raw_score) if applicable else None,
        "applicable": applicable,
        "mode": mode,
        "scope_note": (
            "Mail service or email authentication records were observed."
            if applicable
            else "No MX, SPF or DMARC signal was observed. Email controls are treated as optional brand-protection guidance, not an active mail-system failure."
        ),
        "flags": flags,
        "dmarc": dmarc,
        "mta_sts": mta_sts,
        "tls_rpt": tls_rpt,
    }


def web_presence(domain: str) -> dict[str, object]:
    return {
        "security_txt": text_probe(domain, "/.well-known/security.txt"),
        "robots_txt": text_probe(domain, "/robots.txt"),
        "sitemap_xml": text_probe(domain, "/sitemap.xml"),
        "mta_sts_policy": text_probe(f"mta-sts.{domain}", "/.well-known/mta-sts.txt"),
        "indexing_note": (
            "robots.txt and sitemap.xml are expected public indexing metadata. "
            "Their presence is not a vulnerability unless sensitive paths are disclosed."
        ),
    }


def dnssec_posture(domain: str) -> dict[str, object]:
    ds = dig(domain, "DS")
    dnskey = dig(domain, "DNSKEY")
    return {
        "ds": ds,
        "dnskey": dnskey[:6],
        "enabled": bool(ds or dnskey),
        "score": 100 if ds else 60 if dnskey else 0,
    }


def bimi_posture(domain: str) -> dict[str, object]:
    records = [redact_dns_txt(item) for item in dig(f"default._bimi.{domain}", "TXT")]
    joined = " ".join(records).lower()
    return {
        "records": records,
        "present": "v=bimi1" in joined,
        "has_vmc_hint": "a=" in joined or "vmc" in joined,
    }


def well_known_posture(domain: str) -> dict[str, object]:
    return {name: text_probe(domain, path) for name, path in ADVANCED_WELL_KNOWN_PATHS.items()}


def cname_takeover_hints(subdomains: list[str]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    for subdomain in subdomains[:18]:
        for cname in dig(subdomain, "CNAME")[:3]:
            lower = cname.lower().rstrip(".")
            provider = next((name for suffix, name in TAKEOVER_CNAME_HINTS.items() if suffix in lower), None)
            if provider:
                hints.append({
                    "subdomain": subdomain,
                    "cname": lower,
                    "provider": provider,
                    "note": "CNAME points to a managed platform: verify ownership and resource state in an authorized way.",
                })
                break
    return hints[:10]


def advanced_passive_intel(domain: str, ct: dict[str, object]) -> dict[str, object]:
    subdomains = [str(item) for item in ct.get("subdomains", [])] if isinstance(ct, dict) else []
    dnssec = dnssec_posture(domain)
    bimi = bimi_posture(domain)
    well_known = well_known_posture(domain)
    takeover = cname_takeover_hints(subdomains)
    return {
        "dnssec": dnssec,
        "bimi": bimi,
        "well_known": well_known,
        "takeover_hints": takeover,
        "signals": {
            "dnssec_enabled": dnssec["enabled"],
            "bimi_present": bimi["present"],
            "well_known_count": sum(1 for item in well_known.values() if item.get("present")),
            "takeover_hint_count": len(takeover),
        },
    }


def technology_fingerprint(headers: dict[str, object], web: dict[str, object]) -> list[str]:
    tech: set[str] = set()
    server = str(headers.get("server") or "").lower()
    if "cloudflare" in server:
        tech.add("Cloudflare edge")
    if "nginx" in server:
        tech.add("nginx")
    if "apache" in server:
        tech.add("Apache")
    if "vercel" in server:
        tech.add("Vercel")
    if "cloudfront" in server:
        tech.add("AWS CloudFront")
    if web.get("security_txt", {}).get("present"):
        tech.add("security.txt disclosure")
    if web.get("sitemap_xml", {}).get("present"):
        tech.add("XML sitemap")
    return sorted(tech)


def public_finding(
    level: str,
    title: str,
    detail: str,
    abuse_path: str,
    business_impact: str,
    owner_action: str,
    evidence_to_collect: str,
    root_cause: str = "general",
) -> dict[str, str]:
    """Create a defensive finding with realistic owner-oriented risk context."""
    return {
        "level": level,
        "title": title,
        "detail": detail,
        "abuse_path": abuse_path,
        "business_impact": business_impact,
        "owner_action": owner_action,
        "evidence_to_collect": evidence_to_collect,
        "type": root_cause,
        "root_cause": root_cause,
    }


def hypothesis(
    severity: str,
    confidence: str,
    title: str,
    evidence: str,
    next_step: str,
    attacker_path: str,
    likely_impact: str,
    defensive_priority: str,
) -> dict[str, str]:
    """Explain potential abuse without payloads, bypasses or attack procedure."""
    return {
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "evidence": evidence,
        "next_step": next_step,
        "attacker_path": attacker_path,
        "likely_impact": likely_impact,
        "defensive_priority": defensive_priority,
    }


def risk_findings(report: dict[str, object]) -> list[dict[str, str]]:
    dns = report.get("dns", {})
    https = report.get("https", {})
    email = report.get("email_security", {})
    web = report.get("web_presence", {})
    advanced = report.get("advanced_intel", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    days = cert.get("days_remaining")
    headers = https.get("security_headers", []) if isinstance(https, dict) else []
    https_available = bool(
        https.get("available", https.get("status") is not None or bool(headers))
    )
    findings: list[dict[str, str]] = []

    for item in headers if https_available else []:
        if not item.get("present"):
            findings.append(public_finding(
                "medium",
                f"Missing header: {item['name']}",
                "Reduces the publicly observable browser-side security posture.",
                "A real attacker would combine missing browser controls with an application bug, malicious embed or unsafe third-party content to increase account or data exposure.",
                "Customer sessions, forms, admin panels or embedded flows may become easier to abuse if a separate application flaw exists.",
                "Add the missing header with a staged rollout and regression tests for critical pages.",
                "Collect affected response paths, current header values, CSP/HSTS rollout status and iframe/script dependencies.",
                f"security_header:{item['name']}",
            ))
    flags = email.get("flags", {})
    email_applicable = bool(email.get("applicable"))
    if email_applicable and flags.get("mx_present") and not flags.get("spf_present"):
        findings.append(public_finding(
            "high",
            "SPF missing",
            "The domain does not publish an SPF policy in the main TXT records.",
            "An attacker can send mail that appears aligned with the brand, then rely on weak receiving-side checks to reach customers or employees.",
            "Invoice fraud, support impersonation, credential harvesting and brand-trust damage.",
            "Publish SPF for authorized senders, remove obsolete senders and pair it with DMARC reporting.",
            "Collect legitimate mail vendors, bounce domains, helpdesk workflows and recent spoofing complaints.",
            "spf",
        ))
    if email_applicable and not flags.get("dmarc_present"):
        findings.append(public_finding(
            "high",
            "DMARC missing",
            "No public anti-impersonation policy was found on _dmarc.",
            "An attacker can imitate the domain in phishing campaigns while the company has no public policy telling receivers how to handle failed authentication.",
            "Higher chance of executive impersonation, customer scams and vendor-payment fraud.",
            "Start with DMARC p=none plus reports, validate legitimate flows and move toward quarantine/reject.",
            "Collect aggregate reports, mail sources, third-party sender inventory and finance/support spoofing scenarios.",
            "dmarc",
        ))
    if isinstance(days, int) and days < 30:
        findings.append(public_finding(
            "high",
            "TLS expiring soon",
            f"The certificate expires in {days} days.",
            "Attackers do not need to break TLS: an outage window can push users toward insecure workarounds, fake support links or rushed emergency changes.",
            "Service outage, failed checkout/login flows and increased phishing success during incident confusion.",
            "Verify automated renewal, alert owners and rehearse renewal failure recovery.",
            "Collect certificate owner, renewal automation logs, alert routing and dependency inventory.",
            "tls_expiry",
        ))
    security_txt = web.get("security_txt", {})
    if security_txt.get("available") and not security_txt.get("present"):
        findings.append(public_finding(
            "low",
            "security.txt missing",
            "No standard public security disclosure channel was found.",
            "A researcher or customer who finds a weakness may struggle to report it, increasing the chance of public disclosure before triage.",
            "Slower vulnerability intake, missed reports and reputational damage from unmanaged disclosure.",
            "Publish security.txt with contact, policy and expiry fields routed to the right owner.",
            "Collect current security contact, intake SLA, disclosure policy and escalation owner.",
            "security_txt",
        ))
    if not dns.get("caa"):
        findings.append(public_finding(
            "low",
            "CAA missing",
            "The domain does not publicly restrict which CAs can issue certificates.",
            "If a certificate authority or validation process is abused, there is no DNS-level policy limiting who may issue for the domain.",
            "Weaker certificate governance and harder incident scoping after suspicious certificate issuance.",
            "Add CAA records for approved CAs and document who can change certificate policy.",
            "Collect current CAs, wildcard usage, ACME providers and certificate issuance history.",
            "caa",
        ))
    signals = advanced.get("signals", {}) if isinstance(advanced, dict) else {}
    if not signals.get("dnssec_enabled"):
        findings.append(public_finding(
            "low",
            "DNSSEC not observed",
            "No public DS/DNSKEY records were found from the local resolver.",
            "In some DNS attack or misrouting scenarios, unsigned zones provide less cryptographic assurance for resolver responses.",
            "Lower DNS integrity assurance for mail, web and certificate validation records.",
            "Evaluate DNSSEC support with the registrar and DNS provider before enabling.",
            "Collect registrar support, DNS provider support, rollback plan and operational ownership.",
            "dnssec",
        ))
    if advanced.get("takeover_hints"):
        findings.append(public_finding(
            "high",
            "CNAME to managed providers",
            "Some subdomains point to SaaS/cloud platforms: verify ownership to prevent takeover.",
            "An attacker may look for abandoned cloud/SaaS resources referenced by DNS and try to claim the unowned resource behind the hostname.",
            "Brand impersonation under a trusted subdomain, phishing pages, cookie exposure or customer-data capture depending on host use.",
            "Verify every managed-provider CNAME is claimed by an active account and remove stale DNS records.",
            "Collect DNS owner, cloud/SaaS account owner, last deployment date and proof of resource ownership.",
            "subdomain_takeover",
        ))
    return findings[:10]


def vulnerability_hypotheses(report: dict[str, object]) -> list[dict[str, str]]:
    https = report.get("https", {})
    email = report.get("email_security", {})
    web = report.get("web_presence", {})
    dns = report.get("dns", {})
    advanced = report.get("advanced_intel", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    headers = {item.get("name"): item for item in https.get("security_headers", [])} if isinstance(https, dict) else {}
    flags = email.get("flags", {})
    https_available = bool(
        https.get("available", https.get("status") is not None or bool(headers))
    )
    vulns: list[dict[str, str]] = []

    if https_available and not headers.get("content-security-policy", {}).get("present"):
        vulns.append(hypothesis(
            "medium",
            "high",
            "Potentially broader XSS surface",
            "Content-Security-Policy was not observed on the main HTTPS response.",
            "Validate with authorized application testing and define a CSP for scripts, frames and connect-src.",
            "If an input-handling bug exists, the absence of CSP gives an attacker more room to make malicious browser code run and communicate outward.",
            "Session abuse, account actions performed in a trusted browser, sensitive page content exposure or reputational damage.",
            "Deploy a report-only CSP first, fix violations, then enforce for authenticated and payment/admin surfaces.",
        ))
    if https_available and not headers.get("strict-transport-security", {}).get("present"):
        vulns.append(hypothesis(
            "medium",
            "high",
            "Downgrade/SSL stripping not mitigated by HSTS",
            "Strict-Transport-Security was not observed.",
            "Enable HSTS with an appropriate max-age after full HTTPS validation.",
            "On first contact or after a stale bookmark, a network-positioned attacker may try to keep the user on an insecure path or confusing redirect chain.",
            "Credential exposure risk on hostile networks and lower trust in login or checkout flows.",
            "Force HTTPS everywhere, validate subdomains, then enable long-lived HSTS and preload only after rollout confidence.",
        ))
    if (
        https_available
        and not headers.get("x-frame-options", {}).get("present")
        and not headers.get("content-security-policy", {}).get("present")
    ):
        vulns.append(hypothesis(
            "medium",
            "medium",
            "Clickjacking to verify",
            "X-Frame-Options and CSP frame-ancestors are missing.",
            "Test iframe embedding in an authorized environment and block untrusted frames.",
            "A malicious page may visually wrap or overlay the real site and trick a logged-in user into unintended clicks.",
            "Unwanted account changes, support actions or workflow approvals if sensitive pages are frameable.",
            "Block untrusted framing and review high-risk authenticated actions for confirmation and CSRF protection.",
        ))
    if email.get("applicable") and not flags.get("dmarc_present"):
        vulns.append(hypothesis(
            "high",
            "high",
            "Email brand spoofing more likely",
            "DMARC record not found on _dmarc.",
            "Publish DMARC at least with p=none and reporting, then move toward quarantine/reject.",
            "An attacker can impersonate executives, billing, support or vendor contacts while receivers lack a clear policy for failed authentication.",
            "Payment fraud, credential theft, malware delivery and loss of customer trust.",
            "Inventory senders, enable reporting, fix alignment, then enforce quarantine/reject with finance/support awareness.",
        ))
    if email.get("applicable") and flags.get("dmarc_present") and not (flags.get("dmarc_reject") or flags.get("dmarc_quarantine")):
        vulns.append(hypothesis(
            "medium",
            "high",
            "DMARC present but not enforced",
            "DMARC was found, but no observable quarantine/reject policy is active.",
            "Analyze aggregate reports and plan gradual enforcement.",
            "Attackers may still benefit from brand spoofing because failed messages are monitored but not strongly rejected.",
            "Continued phishing exposure despite partial email-security investment.",
            "Use DMARC reports to close legitimate gaps, then move to quarantine and reject with change management.",
        ))
    if advanced.get("takeover_hints"):
        vulns.append(hypothesis(
            "high",
            "medium",
            "Potential subdomain takeover to verify",
            "Public CNAMEs to managed providers were observed in Certificate Transparency subdomains.",
            "Verify ownership of cloud/SaaS resources before any technical testing.",
            "An attacker may search for unclaimed provider resources referenced by DNS and attempt to bind the trusted subdomain to content they control.",
            "Trusted-domain phishing, brand abuse, session/cookie exposure depending on scope and customer deception.",
            "Confirm ownership in the provider console, remove stale CNAMEs and monitor CT/DNS drift.",
        ))
    days = cert.get("days_remaining")
    if isinstance(days, int) and days < 45:
        vulns.append(hypothesis(
            "medium" if days >= 15 else "high",
            "high",
            "Operational risk on TLS certificate",
            f"Certificate expires in {days} days.",
            "Verify automatic renewal and alerting before the critical window.",
            "Attackers can exploit user confusion during outages by pushing fake support, fake payment or fake login paths.",
            "Lost revenue, failed login/checkout, support load and increased phishing susceptibility during incident response.",
            "Test renewal automation, alert escalation and emergency certificate replacement before the final week.",
        ))
    return vulns[:8]


def red_team_paths(report: dict[str, object]) -> list[dict[str, str]]:
    ct = report.get("certificate_transparency", {})
    email = report.get("email_security", {})
    web = report.get("web_presence", {})
    tech = report.get("technology", [])
    advanced = report.get("advanced_intel", {})
    flags = email.get("flags", {})
    paths: list[dict[str, str]] = []

    if ct.get("subdomains"):
        paths.append({
            "name": "CT pivot",
            "objective": "Expand asset inventory from names in public certificates.",
            "signal": f"{len(ct.get('subdomains', []))} names observable in Certificate Transparency.",
        })
    if email.get("applicable") and not flags.get("dmarc_reject"):
        paths.append({
            "name": "Brand impersonation drill",
            "objective": "Measure exposure to authorized spoofing and phishing simulation.",
            "signal": "DMARC is not enforced with reject.",
        })
    if web.get("robots_txt", {}).get("present") or web.get("sitemap_xml", {}).get("present"):
        paths.append({
            "name": "Content discovery",
            "objective": "Review publicly indexed or declared paths.",
            "signal": "robots.txt/sitemap.xml available.",
        })
    if tech:
        paths.append({
            "name": "Stack fingerprint",
            "objective": "Correlate observed technology with hardening and patch policy.",
            "signal": ", ".join(tech[:4]),
        })
    if advanced.get("takeover_hints"):
        paths.append({
            "name": "Subdomain ownership review",
            "objective": "Verify cloud/SaaS assets referenced by public CNAMEs.",
            "signal": f"{len(advanced.get('takeover_hints', []))} CNAMEs to review.",
        })
    if not paths:
        paths.append({
            "name": "Baseline validation",
            "objective": "Establish a baseline and monitor DNS, TLS and header drift.",
            "signal": "Public surface is limited in passive sources.",
        })
    return paths[:5]


def purple_team_controls(report: dict[str, object]) -> list[dict[str, str]]:
    email = report.get("email_security", {})
    controls = [
        {
            "control": "DNS drift detection",
            "why": "New MX, NS, CAA or TXT records can indicate infrastructure changes or operational takeover risk.",
            "cadence": "daily",
        },
        {
            "control": "Certificate Transparency watch",
            "why": "New certificates can reveal subdomains, shadow IT or unexpected issuance.",
            "cadence": "daily",
        },
        {
            "control": "Web header baseline",
            "why": "CSP, HSTS, frame and MIME headers often regress during application deployments.",
            "cadence": "per release",
        },
        {
            "control": "Subdomain ownership register",
            "why": "CNAMEs to external providers should be mapped to owners and contracts to prevent takeover.",
            "cadence": "monthly",
        },
    ]
    if email.get("applicable"):
        controls.insert(2, {
            "control": "Email authentication guardrail",
            "why": "SPF/DMARC/MTA-STS reduce brand abuse for the observed mail or brand-protection scope.",
            "cadence": "weekly",
        })
    return controls


def score_report(
    addresses: list[str],
    cert: dict[str, object],
    headers: list[dict[str, object]],
    email: dict[str, object],
    web: dict[str, object],
) -> int:
    score = 35
    if addresses:
        score += 15
    if cert.get("expires"):
        score += 20
    assessed_headers = [item for item in headers if item.get("assessed", True)]
    if assessed_headers:
        score += sum(5 for item in assessed_headers if item["present"])
    else:
        score += 15
    if email.get("applicable"):
        score += min(15, int(email.get("score") or 0) // 8)
    else:
        score += 10
    if web.get("security_txt", {}).get("present"):
        score += 3
    if web.get("sitemap_xml", {}).get("present"):
        score += 2
    return max(0, min(100, score))


def recommendations(report: dict[str, object]) -> list[str]:
    dns = report.get("dns", {})
    https = report.get("https", {})
    email = report.get("email_security", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    headers = https.get("security_headers", []) if isinstance(https, dict) else []
    items: list[str] = []

    email_applicable = bool(email.get("applicable"))
    if not dns.get("mx") and email_applicable:
        items.append("Configure or verify MX records if the domain is expected to receive email.")
    txt_values = " ".join(dns.get("txt", [])) if isinstance(dns, dict) else ""
    if email_applicable and email.get("flags", {}).get("mx_present") and "v=spf1" not in txt_values.lower():
        items.append("Add an SPF record to reduce spoofing and email deliverability issues.")
    if email_applicable and not email.get("flags", {}).get("dmarc_present"):
        items.append("Evaluate a DMARC record to protect the brand from email impersonation.")
    if not cert.get("expires"):
        items.append("Verify the TLS certificate: OSINTPRO did not read a valid HTTPS expiry date.")
    missing = [
        item["name"]
        for item in headers
        if item.get("assessed", True) and not item.get("present")
    ]
    if missing:
        items.append(f"Add or review missing security headers: {', '.join(missing[:4])}.")
    if not items:
        items.append("Keep monitoring enabled: the observed public profile is good.")
    return items[:5]


def analyze(raw_target: str) -> dict[str, object]:
    domain = clean_domain(raw_target)
    addresses = resolve_addresses(domain)
    a = dig(domain, "A")
    aaaa = dig(domain, "AAAA")
    mx = dig(domain, "MX")
    ns = dig(domain, "NS")
    txt = [redact_dns_txt(item) for item in dig(domain, "TXT")[:8]]
    caa = dig(domain, "CAA")
    soa = dig(domain, "SOA")
    cert = certificate_info(domain)
    cert.update(parse_cert_expiry(cert.get("expires")))
    https = https_headers(domain)
    email = email_posture(domain, mx, txt)
    web = web_presence(domain)
    rdap = rdap_info(domain)
    ct = certificate_transparency(domain)
    advanced = advanced_passive_intel(domain, ct)
    tech = technology_fingerprint(https, web)
    score = score_report(addresses, cert, https["security_headers"], email, web)

    missing_headers = [
        item["name"]
        for item in https["security_headers"]
        if item.get("assessed", True) and not item["present"]
    ]
    if not addresses:
        summary = "The domain does not resolve IP addresses from the local backend."
    elif not https.get("available"):
        summary = "Domain is reachable, but the HTTPS header assessment was unavailable."
    elif email.get("applicable") and int(email.get("score") or 0) < 45:
        summary = "Domain is reachable, but the public email posture needs attention."
    elif missing_headers:
        summary = f"Domain is reachable. Missing {len(missing_headers)} observable security headers."
    else:
        summary = "Domain is reachable with the main security headers present."

    report = {
        "id": str(uuid.uuid4()),
        "domain": domain,
        "generated_at": utc_now(),
        "summary": summary,
        "score": score,
        "dns": {
            "addresses": addresses,
            "a": a,
            "aaaa": aaaa,
            "mx": mx,
            "ns": ns,
            "txt": txt,
            "caa": caa,
            "soa": soa,
        },
        "https": {
            **https,
            "certificate": cert,
        },
        "email_security": email,
        "web_presence": web,
        "rdap": rdap,
        "certificate_transparency": ct,
        "advanced_intel": advanced,
        "technology": tech,
    }
    report = redact_data(report)
    report["findings"] = risk_findings(report)
    report["recommendations"] = recommendations(report)
    report["vulnerability_hypotheses"] = vulnerability_hypotheses(report)
    report["red_team_paths"] = red_team_paths(report)
    report["purple_team_controls"] = purple_team_controls(report)
    return report


def folder_exists(connection: sqlite3.Connection, user_id: str, folder_id: str | None) -> bool:
    if not folder_id:
        return True
    row = connection.execute(
        "SELECT id FROM client_folders WHERE user_id = ? AND id = ?",
        (user_id, folder_id),
    ).fetchone()
    return bool(row)


def store_report(
    connection: sqlite3.Connection,
    user_id: str,
    report: dict[str, object],
    folder_id: str | None = None,
) -> None:
    report = redact_data(report)
    connection.execute(
        """
        INSERT INTO reports (id, user_id, domain, score, summary, generated_at, payload_json, created_at, folder_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report["id"],
            user_id,
            report["domain"],
            report["score"],
            report["summary"],
            report["generated_at"],
            json.dumps(report),
            utc_now(),
            folder_id,
        ),
    )


def store_social_report(
    connection: sqlite3.Connection,
    user_id: str,
    report: dict[str, object],
    folder_id: str | None = None,
) -> None:
    report = redact_data(report)
    connection.execute(
        """
        INSERT INTO social_reports (id, user_id, username, score, summary, generated_at, payload_json, created_at, folder_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report["id"],
            user_id,
            report["username"],
            report["score"],
            report["summary"],
            report["generated_at"],
            json.dumps(report),
            utc_now(),
            folder_id,
        ),
    )


def store_wallet_report(
    connection: sqlite3.Connection,
    user_id: str,
    report: dict[str, object],
    folder_id: str | None = None,
) -> None:
    report = redact_data(report)
    connection.execute(
        """
        INSERT INTO wallet_reports (id, user_id, chain, address, risk_score, summary, generated_at, payload_json, created_at, folder_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report["id"],
            user_id,
            report["chain"],
            report["address"],
            report["risk_score"],
            report["summary"],
            report["generated_at"],
            json.dumps(report),
            utc_now(),
            folder_id,
        ),
    )


def store_repository_report(
    connection: sqlite3.Connection,
    user_id: str,
    audit: dict[str, object],
) -> None:
    """Persist only the redacted repository audit, never the uploaded source."""
    audit = redact_data(audit)
    connection.execute(
        """
        INSERT INTO repository_reports
            (id, user_id, repository, score, findings_json, payload_json, generated_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit["id"],
            user_id,
            audit["repository"],
            audit["score"],
            json.dumps(audit.get("findings", [])),
            json.dumps(audit),
            audit["generated_at"],
            utc_now(),
        ),
    )


def prepare_session_report_storage(
    connection: sqlite3.Connection,
    user: dict[str, object],
    table: str,
) -> None:
    """Bound anonymous storage while keeping authenticated history intact."""
    if user.get("authenticated"):
        return
    if table not in {"reports", "social_reports", "wallet_reports", "repository_reports"}:
        raise ValueError("Invalid report storage table.")
    connection.execute(f"DELETE FROM {table} WHERE user_id = ?", (user["_id"],))


def run_monitor_rows(connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> dict[str, object]:
    checked = 0
    changed_count = 0
    failed = 0
    results: list[dict[str, object]] = []
    for monitor in rows:
        now = utc_now()
        try:
            report = analyze(monitor["domain"])
            changed = monitor["last_score"] is not None and int(monitor["last_score"]) != int(report["score"])
            store_report(connection, str(monitor["user_id"]), report)
            connection.execute(
                """
                UPDATE monitors
                SET status = ?, last_score = ?, last_summary = ?, last_checked_at = ?,
                    last_changed_at = CASE WHEN ? THEN ? ELSE last_changed_at END,
                    updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    "changed" if changed else "healthy",
                    report["score"],
                    report["summary"],
                    now,
                    1 if changed else 0,
                    now,
                    now,
                    monitor["id"],
                    monitor["user_id"],
                ),
            )
            checked += 1
            changed_count += 1 if changed else 0
            results.append({
                "domain": monitor["domain"],
                "status": "changed" if changed else "healthy",
                "score": report["score"],
            })
            if changed:
                payload = {
                    "domain": monitor["domain"],
                    "user_id": monitor["user_id"],
                    "previous_score": monitor["last_score"],
                    "score": report["score"],
                    "summary": report["summary"],
                }
                send_alert("monitor.changed", payload)
                deliver_user_webhooks(connection, str(monitor["user_id"]), "monitor.changed", payload)
                email_ok, email_message = send_monitor_email(str(monitor["domain"]), payload)
                notification_log(
                    connection,
                    str(monitor["user_id"]),
                    "monitor.changed",
                    "email",
                    "sent" if email_ok else "skipped",
                    smtp_settings().get("recipient") or None,
                    email_message,
                )
        except Exception:
            failed += 1
            connection.execute(
                """
                UPDATE monitors
                SET status = 'error', last_checked_at = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (now, now, monitor["id"], monitor["user_id"]),
            )
            results.append({"domain": monitor["domain"], "status": "error"})
            send_alert("monitor.error", {
                "domain": monitor["domain"],
                "user_id": monitor["user_id"],
            })
    return {
        "checked": checked,
        "changed": changed_count,
        "failed": failed,
        "results": results,
    }


def report_document(report: dict[str, object]) -> str:
    brand = report_brand()
    analyst = report_analyst()
    contact = report_contact()
    dns = report.get("dns", {})
    https = report.get("https", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    headers = https.get("security_headers", []) if isinstance(https, dict) else []
    email = report.get("email_security", {})
    rdap = report.get("rdap", {})
    ct = report.get("certificate_transparency", {})
    advanced = report.get("advanced_intel", {})
    web = report.get("web_presence", {})
    findings = report.get("findings", [])
    vulns = report.get("vulnerability_hypotheses", [])
    red_paths = report.get("red_team_paths", [])
    purple_controls = report.get("purple_team_controls", [])
    contact_label = f" | {html.escape(contact)}" if contact else ""

    def lines(values: list[str]) -> str:
        if not values:
            return "<span class='muted'>no data</span>"
        return "".join(f"<li>{html.escape(str(value))}</li>" for value in values)

    checks = "".join(
        f"<tr><td>{html.escape(item['name'])}</td><td>{'Not assessed' if item.get('assessed') is False else 'OK' if item.get('present') else 'Missing'}</td><td>{html.escape(str(item.get('value') or item.get('reason') or ''))}</td></tr>"
        for item in headers
    )
    recs = "".join(f"<li>{html.escape(item)}</li>" for item in recommendations(report))
    finding_rows = "".join(
        f"<tr><td>{html.escape(item.get('level', ''))}</td><td>{html.escape(item.get('title', ''))}</td><td>{html.escape(item.get('detail', ''))}</td></tr>"
        for item in findings
    )
    subdomain_rows = "".join(f"<li>{html.escape(item)}</li>" for item in ct.get("subdomains", [])[:25])
    dnssec = advanced.get("dnssec", {}) if isinstance(advanced, dict) else {}
    bimi = advanced.get("bimi", {}) if isinstance(advanced, dict) else {}
    well_known = advanced.get("well_known", {}) if isinstance(advanced, dict) else {}
    takeover_hints = advanced.get("takeover_hints", []) if isinstance(advanced, dict) else []
    well_known_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{'Observed' if value.get('present') else 'Not declared'}</td><td>{html.escape(str(value.get('status') or 'n/a'))}</td></tr>"
        for name, value in well_known.items()
    )
    takeover_rows = "".join(
        f"<tr><td>{html.escape(item.get('subdomain', ''))}</td><td>{html.escape(item.get('provider', ''))}</td><td>{html.escape(item.get('cname', ''))}</td></tr>"
        for item in takeover_hints
    )
    vuln_rows = "".join(
        f"<tr><td>{html.escape(item.get('severity', ''))}</td><td>{html.escape(item.get('title', ''))}</td><td>{html.escape(item.get('evidence', ''))}</td><td>{html.escape(item.get('next_step', ''))}</td></tr>"
        for item in vulns
    )
    red_rows = "".join(
        f"<tr><td>{html.escape(item.get('name', ''))}</td><td>{html.escape(item.get('objective', ''))}</td><td>{html.escape(item.get('signal', ''))}</td></tr>"
        for item in red_paths
    )
    purple_rows = "".join(
        f"<tr><td>{html.escape(item.get('control', ''))}</td><td>{html.escape(item.get('why', ''))}</td><td>{html.escape(item.get('cadence', ''))}</td></tr>"
        for item in purple_controls
    )
    email_score_label = f"{int(email.get('score') or 0)}/100" if email.get("applicable") else "Not applicable"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(brand)} report - {html.escape(str(report.get("domain", "")))}</title>
  <style>
    @page {{ size: A4; margin: 20mm; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 20mm; color: #17201b; background: #fff; font: 11pt/1.5 "Segoe UI", Arial, sans-serif; }}
    header {{ display: flex; justify-content: space-between; gap: 24px; border-bottom: 2px solid #17201b; margin-bottom: 28px; padding-bottom: 18px; }}
    h1 {{ margin: 0 0 8px; font-size: 30pt; line-height: 1.1; overflow-wrap: anywhere; }}
    h2 {{ margin: 28px 0 12px; font-size: 17pt; }}
    h3 {{ margin: 18px 0 8px; font-size: 12pt; }}
    .meta, .muted {{ color: #667069; }}
    .score {{ min-width: 112px; align-self: flex-start; border: 1px solid #d7ded8; border-radius: 8px; padding: 14px 18px; background: #f4f8f6; text-align: center; }}
    .score strong {{ display: block; font-size: 30pt; color: #0f6b57; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
    section, .box, tr {{ break-inside: avoid; page-break-inside: avoid; }}
    .box {{ border: 1px solid #d7ded8; border-radius: 8px; padding: 16px; background: #fbfcfb; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #17201b; color: #fff; }}
    td, th {{ border: 1px solid #dfe5e1; padding: 8px; text-align: left; vertical-align: top; }}
    tbody tr:nth-child(even) {{ background: #f4f8f6; }}
    code, li {{ overflow-wrap: anywhere; }}
    .report-footer {{ margin-top: 36px; padding-top: 12px; border-top: 1px solid #d7ded8; color: #667069; font-size: 9pt; }}
    @media print {{
      body {{ padding: 0; }}
      .report-footer {{ position: running(report-footer); }}
    }}
    @media (max-width: 720px) {{
      body {{ padding: 20px; }}
      header, .grid {{ display: block; }}
      .score {{ margin: 16px 0; }}
      .box {{ margin-bottom: 12px; }}
      table {{ font-size: 9pt; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <p class="meta">{html.escape(brand)} passive domain intelligence</p>
      <h1>{html.escape(str(report.get("domain", "")))}</h1>
      <p>{html.escape(str(report.get("summary", "")))}</p>
      <p class="meta">Generated: {html.escape(str(report.get("generated_at", "")))}<br>Analyst: {html.escape(analyst)}</p>
    </div>
    <div class="score"><span>Score</span><strong>{int(report.get("score", 0))}</strong></div>
  </header>
  <main>
    <section>
      <h2>Recommendations</h2>
      <div class="box"><ol>{recs}</ol></div>
    </section>
    <section class="grid">
      <div class="box"><h2>IP</h2><ul>{lines(dns.get("addresses", []))}</ul></div>
      <div class="box"><h2>MX</h2><ul>{lines(dns.get("mx", []))}</ul></div>
      <div class="box"><h2>Nameserver</h2><ul>{lines(dns.get("ns", []))}</ul></div>
      <div class="box"><h2>TLS certificate</h2><p>{html.escape(str(cert.get("subject") or "not available"))}</p><p class="meta">Expires: {html.escape(str(cert.get("expires") or "not available"))}</p></div>
    </section>
    <section class="grid">
      <div class="box"><h2>Email security</h2><p>Score: {email_score_label}</p><p>{html.escape(str(email.get("scope_note") or ""))}</p><ul>{lines(email.get("dmarc", []) + email.get("mta_sts", []) + email.get("tls_rpt", []))}</ul></div>
      <div class="box"><h2>RDAP</h2><p>Registrar: {html.escape(str(rdap.get("registrar") or "not available"))}</p><p class="meta">Created: {html.escape(str(rdap.get("created") or "n/a"))}<br>Expires: {html.escape(str(rdap.get("expires") or "n/a"))}</p></div>
      <div class="box"><h2>Well-known</h2><p>security.txt: {web.get("security_txt", {}).get("status") or "n/a"}<br>robots.txt: {web.get("robots_txt", {}).get("status") or "n/a"}<br>sitemap.xml: {web.get("sitemap_xml", {}).get("status") or "n/a"}</p></div>
      <div class="box"><h2>Certificate Transparency</h2><ul>{subdomain_rows or "<li>no names found</li>"}</ul></div>
    </section>
    <section>
      <h2>Advanced passive OSINT</h2>
      <div class="box">
        <p>DNSSEC: {'OK' if dnssec.get('enabled') else 'not observed'} | BIMI: {('OK' if bimi.get('present') else 'not observed') if email.get('applicable') else 'not applicable'}</p>
        <table><thead><tr><th>Well-known</th><th>Status</th><th>HTTP</th></tr></thead><tbody>{well_known_rows or "<tr><td colspan='3'>no data</td></tr>"}</tbody></table>
        <h3>CNAME takeover review</h3>
        <table><thead><tr><th>Subdomain</th><th>Provider</th><th>CNAME</th></tr></thead><tbody>{takeover_rows or "<tr><td colspan='3'>no priority hints</td></tr>"}</tbody></table>
      </div>
    </section>
    <section>
      <h2>Findings</h2>
      <table><thead><tr><th>Level</th><th>Finding</th><th>Detail</th></tr></thead><tbody>{finding_rows or "<tr><td>ok</td><td>No priority findings</td><td></td></tr>"}</tbody></table>
    </section>
    <section>
      <h2>Red/Purple Team</h2>
      <table><thead><tr><th>Severity</th><th>Hypothesis</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>{vuln_rows or "<tr><td>ok</td><td>No priority hypotheses</td><td></td><td></td></tr>"}</tbody></table>
      <h2>Red team paths</h2>
      <table><thead><tr><th>Path</th><th>Objective</th><th>Signal</th></tr></thead><tbody>{red_rows}</tbody></table>
      <h2>Purple team controls</h2>
      <table><thead><tr><th>Control</th><th>Reason</th><th>Cadence</th></tr></thead><tbody>{purple_rows}</tbody></table>
    </section>
    <section>
      <h2>Security header</h2>
      <table><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>{checks}</tbody></table>
    </section>
    <section>
      <h2>Appendix: methodology</h2>
      <div class="box">
        <p>OSINTPRO uses passive public DNS, HTTPS, certificate and well-known resources. It does not execute exploit payloads, brute force credentials or modify the target.</p>
        <p>Missing email controls are findings only when mail service or an email policy is observed. Public robots.txt and sitemap.xml files are expected indexing metadata, not vulnerabilities by themselves.</p>
      </div>
    </section>
  </main>
  <footer class="report-footer">Confidential client report{contact_label} | Passive evidence requires authorized validation.</footer>
</body>
</html>"""


def pdf_escape(value: str) -> str:
    clean = redact_text(value).replace("\r", " ").replace("\n", " ")
    clean = clean.encode("latin-1", "replace").decode("latin-1")
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


PDF_PAGE_WIDTH = 595
PDF_PAGE_HEIGHT = 842
PDF_MARGIN = 57
PDF_INK = (0.10, 0.13, 0.11)
PDF_MUTED = (0.35, 0.40, 0.37)
PDF_GREEN = (0.06, 0.42, 0.34)
PDF_CYAN = (0.10, 0.53, 0.66)
PDF_LINE = (0.84, 0.87, 0.85)
PDF_PANEL = (0.96, 0.98, 0.97)
PDF_HIGH = (0.78, 0.16, 0.20)
PDF_MEDIUM = (0.88, 0.43, 0.10)
PDF_LOW = (0.12, 0.42, 0.70)


def pdf_rgb(color: tuple[float, float, float]) -> str:
    """Return a compact PDF RGB color command fragment."""
    return " ".join(f"{channel:.3f}" for channel in color)


def pdf_wrap(value: object, max_chars: int) -> list[str]:
    """Wrap redacted text without requiring an external PDF dependency."""
    text = re.sub(r"\s+", " ", redact_text(str(value or ""))).strip()
    if not text:
        return [""]
    words = text.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        if len(word) > max_chars:
            if current:
                lines.append(current)
                current = ""
            lines.extend(word[index:index + max_chars] for index in range(0, len(word), max_chars))
            continue
        candidate = f"{current} {word}".strip()
        if len(candidate) <= max_chars:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


class PdfReportBuilder:
    """Small deterministic PDF canvas for dependency-free client reports."""

    def __init__(self, report: dict[str, object]):
        self.report = report
        self.brand = report_brand()
        self.domain = str(report.get("domain") or "target")
        self.pages: list[list[str]] = []
        self.y = PDF_PAGE_HEIGHT - PDF_MARGIN

    @property
    def page(self) -> list[str]:
        return self.pages[-1]

    def text(
        self,
        value: object,
        x: float,
        y: float,
        size: float = 10,
        bold: bool = False,
        color: tuple[float, float, float] = PDF_INK,
    ) -> None:
        font = "F2" if bold else "F1"
        self.page.append(
            f"BT /{font} {size:.1f} Tf {pdf_rgb(color)} rg "
            f"1 0 0 1 {x:.1f} {y:.1f} Tm ({pdf_escape(str(value))}) Tj ET"
        )

    def rectangle(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        fill: tuple[float, float, float],
        stroke: tuple[float, float, float] | None = None,
    ) -> None:
        command = f"{pdf_rgb(fill)} rg {x:.1f} {y:.1f} {width:.1f} {height:.1f} re f"
        if stroke:
            command += (
                f" {pdf_rgb(stroke)} RG 0.7 w "
                f"{x:.1f} {y:.1f} {width:.1f} {height:.1f} re S"
            )
        self.page.append(command)

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: tuple[float, float, float] = PDF_LINE,
    ) -> None:
        self.page.append(
            f"{pdf_rgb(color)} RG 0.8 w {x1:.1f} {y1:.1f} m "
            f"{x2:.1f} {y2:.1f} l S"
        )

    def new_page(self, section: str = "") -> None:
        self.pages.append([])
        self.y = PDF_PAGE_HEIGHT - PDF_MARGIN
        self.rectangle(PDF_MARGIN, self.y - 28, 28, 28, PDF_GREEN)
        self.text("OP", PDF_MARGIN + 6, self.y - 18, 10, True, (1, 1, 1))
        self.text(self.brand, PDF_MARGIN + 38, self.y - 12, 11, True)
        self.text(
            self.domain[:42],
            PDF_PAGE_WIDTH - PDF_MARGIN - 205,
            self.y - 12,
            8,
            False,
            PDF_MUTED,
        )
        if section:
            self.text(section.upper(), PDF_MARGIN + 38, self.y - 25, 7, True, PDF_GREEN)
        self.line(PDF_MARGIN, self.y - 38, PDF_PAGE_WIDTH - PDF_MARGIN, self.y - 38)
        self.y -= 58

    def ensure_space(self, height: float, section: str) -> None:
        if self.y - height < 66:
            self.new_page(section)

    def heading(self, value: str, section: str, size: float = 18) -> None:
        self.ensure_space(40, section)
        self.text(value, PDF_MARGIN, self.y, size, True)
        self.y -= size + 12

    def paragraph(
        self,
        value: object,
        section: str,
        size: float = 10,
        color: tuple[float, float, float] = PDF_INK,
        indent: float = 0,
    ) -> None:
        width = PDF_PAGE_WIDTH - (2 * PDF_MARGIN) - indent
        max_chars = max(28, int(width / (size * 0.52)))
        lines = pdf_wrap(value, max_chars)
        leading = size * 1.48
        self.ensure_space((len(lines) * leading) + 6, section)
        for line in lines:
            self.text(line, PDF_MARGIN + indent, self.y, size, False, color)
            self.y -= leading
        self.y -= 4

    def bullet(self, value: object, section: str) -> None:
        lines = pdf_wrap(value, 88)
        height = len(lines) * 14 + 5
        self.ensure_space(height, section)
        self.rectangle(PDF_MARGIN, self.y - 2, 5, 5, PDF_GREEN)
        for index, line in enumerate(lines):
            self.text(line, PDF_MARGIN + 14, self.y, 9.5, index == 0)
            self.y -= 14
        self.y -= 5

    def metric(
        self,
        label: str,
        value: object,
        x: float,
        y: float,
        width: float,
        color: tuple[float, float, float] = PDF_GREEN,
    ) -> None:
        self.rectangle(x, y, width, 62, PDF_PANEL, PDF_LINE)
        self.text(value, x + 12, y + 33, 20, True, color)
        self.text(label.upper(), x + 12, y + 14, 7, True, PDF_MUTED)

    def finding(
        self,
        level: str,
        title: str,
        detail: str,
        section: str,
        abuse_path: str = "",
        business_impact: str = "",
        owner_action: str = "",
        evidence_to_collect: str = "",
    ) -> None:
        title_lines = pdf_wrap(title, 62)
        detail_lines = pdf_wrap(detail, 91)
        blocks = [
            ("HOW AN ATTACKER MAY ABUSE IT", abuse_path),
            ("BUSINESS IMPACT", business_impact),
            ("OWNER ACTION", owner_action),
        ]
        if evidence_to_collect:
            blocks.append(("EVIDENCE TO COLLECT", evidence_to_collect))
        wrapped_blocks = [
            (label, pdf_wrap(value or "Confirm applicability with the asset owner.", 84))
            for label, value in blocks
        ]
        height = 38 + (len(title_lines) * 13) + (len(detail_lines) * 12)
        height += sum(17 + (len(lines) * 11) for _, lines in wrapped_blocks)
        self.ensure_space(height + 12, section)
        bottom = self.y - height
        color = {
            "high": PDF_HIGH,
            "medium": PDF_MEDIUM,
            "low": PDF_LOW,
        }.get(level.lower(), PDF_CYAN)
        self.rectangle(PDF_MARGIN, bottom, PDF_PAGE_WIDTH - (2 * PDF_MARGIN), height, PDF_PANEL, PDF_LINE)
        self.rectangle(PDF_MARGIN, bottom, 6, height, color)
        self.rectangle(PDF_MARGIN + 16, self.y - 19, 52, 17, color)
        self.text(level.upper(), PDF_MARGIN + 23, self.y - 14, 7, True, (1, 1, 1))
        title_y = self.y - 14
        for line in title_lines:
            self.text(line, PDF_MARGIN + 80, title_y, 10.5, True)
            title_y -= 13
        cursor = min(title_y - 4, self.y - 37)
        for line in detail_lines:
            self.text(line, PDF_MARGIN + 16, cursor, 9, False, PDF_MUTED)
            cursor -= 12
        for label, lines in wrapped_blocks:
            self.text(label, PDF_MARGIN + 16, cursor - 3, 7, True, color)
            cursor -= 15
            for line in lines:
                self.text(line, PDF_MARGIN + 16, cursor, 8.8)
                cursor -= 11
            cursor -= 2
        self.y = bottom - 12

    def finish(self) -> bytes:
        total_pages = len(self.pages)
        contact = report_contact()
        for index, commands in enumerate(self.pages, start=1):
            footer = (
                f"Confidential client report | Page {index} of {total_pages}"
                f"{' | ' + contact if contact else ''}"
            )
            commands.append(
                f"{pdf_rgb(PDF_LINE)} RG 0.7 w {PDF_MARGIN} 49 m "
                f"{PDF_PAGE_WIDTH - PDF_MARGIN} 49 l S"
            )
            commands.append(
                f"BT /F1 7.5 Tf {pdf_rgb(PDF_MUTED)} rg 1 0 0 1 "
                f"{PDF_MARGIN} 34 Tm ({pdf_escape(footer)}) Tj ET"
            )
        return pdf_bytes(self.pages)


def pdf_bytes(pages: list[list[str]]) -> bytes:
    """Serialize page drawing commands into a valid PDF 1.4 document."""
    page_ids = [6 + (index * 2) for index in range(len(pages))]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (
            f"<< /Type /Pages /Kids [{' '.join(f'{item} 0 R' for item in page_ids)}] "
            f"/Count {len(pages)} >>"
        ).encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    for index, commands in enumerate(pages):
        page_id = page_ids[index]
        stream_id = page_id + 1
        stream = "\n".join(commands).encode("latin-1", "replace")
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "
                f"{PDF_PAGE_WIDTH} {PDF_PAGE_HEIGHT}] /Resources << /Font "
                f"<< /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                f"/Contents {stream_id} 0 R >>"
            ).encode("ascii")
        )
        objects.append(
            b"<< /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


def report_pdf(report: dict[str, object]) -> bytes:
    """Render a branded, multipage passive intelligence report."""
    builder = PdfReportBuilder(report)
    dns = report.get("dns", {}) if isinstance(report.get("dns"), dict) else {}
    https = report.get("https", {}) if isinstance(report.get("https"), dict) else {}
    email = (
        report.get("email_security", {})
        if isinstance(report.get("email_security"), dict)
        else {}
    )
    web = (
        report.get("web_presence", {})
        if isinstance(report.get("web_presence"), dict)
        else {}
    )
    cert = https.get("certificate", {}) if isinstance(https.get("certificate"), dict) else {}
    headers = https.get("security_headers", [])
    findings = report.get("findings", []) or []
    hypotheses = report.get("vulnerability_hypotheses", []) or []
    seen_roots = {
        str(item.get("root_cause") or item.get("type") or item.get("title") or "").lower()
        for item in findings
    }
    all_findings = [
        {
            "level": item.get("level", "info"),
            "title": item.get("title", "Finding"),
            "detail": item.get("detail", ""),
            "abuse_path": item.get("abuse_path", ""),
            "business_impact": item.get("business_impact", ""),
            "owner_action": item.get("owner_action", ""),
            "evidence_to_collect": item.get("evidence_to_collect", ""),
        }
        for item in findings
    ]
    all_findings.extend(
        {
            "level": item.get("severity", "info"),
            "title": item.get("title", "Review hypothesis"),
            "detail": item.get("evidence", ""),
            "abuse_path": item.get("attacker_path", ""),
            "business_impact": item.get("likely_impact", ""),
            "owner_action": item.get("next_step", ""),
            "evidence_to_collect": item.get("defensive_priority", ""),
        }
        for item in hypotheses
        if str(item.get("root_cause") or item.get("type") or item.get("title") or "").lower()
        not in seen_roots
    )

    builder.new_page("Executive summary")
    builder.text("PASSIVE DOMAIN INTELLIGENCE", PDF_MARGIN, builder.y, 8, True, PDF_GREEN)
    builder.y -= 30
    builder.text(builder.domain, PDF_MARGIN, builder.y, 28, True)
    builder.y -= 28
    builder.paragraph(report.get("summary", ""), "Executive summary", 11, PDF_MUTED)
    builder.y -= 6
    generated = str(report.get("generated_at") or "")
    builder.text(f"Generated: {generated}", PDF_MARGIN, builder.y, 8.5, False, PDF_MUTED)
    builder.y -= 15
    builder.text(f"Analyst: {report_analyst()}", PDF_MARGIN, builder.y, 8.5, False, PDF_MUTED)
    builder.y -= 36
    card_width = (PDF_PAGE_WIDTH - (2 * PDF_MARGIN) - 24) / 3
    addresses = dns.get("addresses", []) if isinstance(dns.get("addresses"), list) else []
    email_label = f"{email.get('score', 0)}/100" if email.get("applicable") else "N/A"
    builder.metric("Security score", f"{report.get('score', 0)}/100", PDF_MARGIN, builder.y - 62, card_width)
    builder.metric("Resolved IPs", len(addresses), PDF_MARGIN + card_width + 12, builder.y - 62, card_width, PDF_CYAN)
    builder.metric("Findings", len(all_findings), PDF_MARGIN + (2 * card_width) + 24, builder.y - 62, card_width, PDF_HIGH if all_findings else PDF_GREEN)
    builder.y -= 92
    if int(report.get("score") or 0) == 100 and all_findings and all(
        str(item.get("level", "")).lower() == "low" for item in all_findings
    ):
        builder.paragraph(
            "Score reflects material risk only. Low-severity notes below do not affect scoring.",
            "Executive summary",
            9.5,
            PDF_MUTED,
        )
        builder.y -= 4
    builder.heading("Scope summary", "Executive summary", 15)
    builder.bullet(f"Email posture: {email_label}. {email.get('scope_note', '')}", "Executive summary")
    builder.bullet(
        f"HTTPS status: {https.get('status') or 'not available'}; "
        f"certificate expires {cert.get('expires') or 'not available'}.",
        "Executive summary",
    )
    builder.bullet(
        f"Public indexing metadata: robots.txt "
        f"{'published' if web.get('robots_txt', {}).get('present') else 'not published'}, "
        f"sitemap.xml {'published' if web.get('sitemap_xml', {}).get('present') else 'not published'}. "
        "Publication is not a vulnerability by itself.",
        "Executive summary",
    )
    builder.heading("Priority actions", "Executive summary", 15)
    for item in recommendations(report):
        builder.bullet(item, "Executive summary")

    builder.new_page("Findings")
    builder.heading("Prioritized findings", "Findings")
    builder.paragraph(
        "Findings are passive observations and review hypotheses. Validate impact in an "
        "authorized environment before presenting them as confirmed vulnerabilities.",
        "Findings",
        9.5,
        PDF_MUTED,
    )
    if all_findings:
        for item in all_findings:
            builder.finding(
                str(item["level"]),
                str(item["title"]),
                str(item["detail"]),
                "Findings",
                str(item.get("abuse_path") or ""),
                str(item.get("business_impact") or ""),
                str(item.get("owner_action") or ""),
                str(item.get("evidence_to_collect") or ""),
            )
    else:
        builder.finding(
            "info",
            "No priority passive finding",
            "The observed public surface did not produce a high-priority hypothesis.",
            "Findings",
            "No attacker path was inferred from passive evidence.",
            "No material business impact was identified from this passive snapshot.",
            "Keep monitoring DNS, TLS and browser security headers for drift.",
            "Baseline DNS, TLS and header state for future drift checks.",
        )

    builder.new_page("Evidence")
    builder.heading("DNS and infrastructure", "Evidence")
    for label, values in (
        ("Resolved IP", addresses),
        ("Nameserver", dns.get("ns", [])),
        ("Mail exchange", dns.get("mx", [])),
        ("CAA", dns.get("caa", [])),
    ):
        safe_values = values if isinstance(values, list) else []
        builder.bullet(
            f"{label}: {', '.join(str(value) for value in safe_values[:8]) or 'not observed'}",
            "Evidence",
        )
    builder.heading("TLS and browser controls", "Evidence", 15)
    builder.paragraph(
        f"Certificate subject: {cert.get('subject') or 'not available'}. "
        f"Expiry: {cert.get('expires') or 'not available'}.",
        "Evidence",
        9.5,
    )
    for item in headers if isinstance(headers, list) else []:
        status = (
            "NOT ASSESSED"
            if item.get("assessed") is False
            else "OK"
            if item.get("present")
            else "MISSING"
        )
        evidence = item.get("value") or item.get("reason") or ""
        builder.bullet(f"{status} - {item.get('name')}: {evidence}", "Evidence")
    builder.heading("Email and public metadata", "Evidence", 15)
    builder.paragraph(
        email.get("scope_note") or "Email scope could not be determined.",
        "Evidence",
        9.5,
    )
    builder.paragraph(
        web.get("indexing_note")
        or "Public indexing files are contextual metadata, not vulnerabilities by default.",
        "Evidence",
        9.5,
        PDF_MUTED,
    )

    builder.new_page("Methodology")
    builder.heading("Methodology and limitations", "Methodology")
    builder.paragraph(
        "OSINTPRO collected passive public signals from DNS, HTTPS responses, certificate "
        "metadata, Certificate Transparency and public well-known resources. It did not "
        "execute exploit payloads, brute force credentials, scan private address ranges or "
        "attempt to modify the target.",
        "Methodology",
    )
    builder.heading("Interpretation rules", "Methodology", 15)
    for item in (
        "Missing email controls are findings only when mail service or an email policy is observed.",
        "robots.txt and sitemap.xml are expected public metadata and are not vulnerabilities by themselves.",
        "OpenID, mobile association files and BIMI are optional unless the product claims those capabilities.",
        "CNAME takeover signals require ownership validation; a managed-provider CNAME alone is not proof of exploitability.",
        "Certificate Transparency is an asset-discovery and monitoring source, not a vulnerability.",
    ):
        builder.bullet(item, "Methodology")
    builder.heading("Passive boundary", "Methodology", 15)
    builder.paragraph(
        "This report is evidence for defensive review, not proof of identity, compromise or "
        "exploitability. Findings should be confirmed by the asset owner or an authorized "
        "security professional.",
        "Methodology",
    )
    return builder.finish()


def web_audit_playbook_payload(report: dict[str, object]) -> dict[str, object]:
    headers = report.get("https", {}).get("security_headers", []) if isinstance(report.get("https"), dict) else []
    web = report.get("web_presence", {}) if isinstance(report.get("web_presence"), dict) else {}
    checklist = [
        {
            "item": item.get("name", ""),
            "status": (
                "not_assessed"
                if item.get("assessed") is False
                else "ok"
                if item.get("present")
                else "missing"
            ),
            "evidence": item.get("value") or item.get("reason") or "",
        }
        for item in headers
    ]
    for label in ("security_txt", "robots_txt", "sitemap_xml", "mta_sts_policy"):
        value = web.get(label, {}) if isinstance(web.get(label), dict) else {}
        checklist.append({
            "item": label.replace("_", "."),
            "status": (
                "not_assessed"
                if value.get("available") is False
                else "ok"
                if value.get("present")
                else "not_published"
                if label in {"robots_txt", "sitemap_xml"}
                else "missing"
            ),
            "evidence": f"HTTP {value.get('status')}" if value.get("status") else "not observed",
        })
    return redact_data({
        "domain": report.get("domain"),
        "report_id": report.get("id"),
        "generated_at": utc_now(),
        "summary": report.get("summary"),
        "checklist": checklist,
        "glossary": [
            {"term": "Scope", "definition": "The exact assets the operator is authorized to review."},
            {"term": "Evidence", "definition": "Headers, status codes, DNS records and screenshots that support the finding."},
            {"term": "Finding", "definition": "A passive signal that should be reviewed or remediated by the owner."},
        ],
        "safe_workflow": [
            "Confirm authorization and write scope.",
            "Collect passive DNS, TLS, headers and public files.",
            "Document evidence without exploit payloads or brute force.",
            "Prioritize fixes and retest passively.",
        ],
    })


def clean_workspace_id(value: str) -> str:
    workspace_id = value.strip().lower()
    if workspace_id in {"current", "default", "all"}:
        return workspace_id
    if UUID_RE.match(workspace_id):
        return workspace_id
    raise ValueError("Invalid workspace id.")


def graph_export_subset(workspace: dict[str, object], workspace_id: str) -> dict[str, object]:
    """Return all graph data or a one-client-folder subgraph.

    The frontend calls the global workspace `current`. A UUID is treated as a
    client folder id, which keeps agency case exports useful without adding a
    separate workspace table before the PostgreSQL migration.
    """
    nodes = list(workspace.get("nodes") or [])
    edges = list(workspace.get("edges") or [])
    if workspace_id in {"current", "default", "all"}:
        return {"workspace_id": workspace_id, "nodes": nodes, "edges": edges}

    root_ids: set[str] = {f"folder:{workspace_id}"}
    dossiers = workspace.get("dossiers") if isinstance(workspace.get("dossiers"), dict) else {}
    for item in dossiers.get("sites", []):
        if item.get("folder_id") == workspace_id and item.get("domain"):
            root_ids.add(f"site:{item['domain']}")
    for item in dossiers.get("people", []):
        if item.get("folder_id") == workspace_id and item.get("username"):
            root_ids.add(f"person:{item['username']}")
    for item in dossiers.get("wallets", []):
        if item.get("folder_id") == workspace_id and item.get("chain") and item.get("address"):
            root_ids.add(f"wallet:{item['chain']}:{item['address']}")

    selected_ids = set(root_ids)
    changed = True
    while changed:
        changed = False
        for edge in edges:
            source = str(edge.get("from"))
            target = str(edge.get("to"))
            if source in selected_ids and target not in selected_ids:
                selected_ids.add(target)
                changed = True
            if target in selected_ids and source not in selected_ids:
                selected_ids.add(source)
                changed = True

    return {
        "workspace_id": workspace_id,
        "nodes": [node for node in nodes if str(node.get("id")) in selected_ids],
        "edges": [
            edge for edge in edges
            if str(edge.get("from")) in selected_ids and str(edge.get("to")) in selected_ids
        ],
    }


def graph_format_jsonld(graph: dict[str, object]) -> bytes:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    payload = {
        "@context": {
            "name": "https://schema.org/name",
            "description": "https://schema.org/description",
            "osint": "https://osintpro.local/schema#",
            "type": "@type",
            "relationship": "osint:relationship",
        },
        "@graph": [
            {
                "@id": str(node.get("id")),
                "type": f"osint:{node.get('type', 'node')}",
                "name": node.get("label", ""),
                "description": node.get("meta", ""),
                "osint:score": node.get("score"),
            }
            for node in nodes
        ] + [
            {
                "@id": f"edge:{index}",
                "type": "osint:Relationship",
                "relationship": edge.get("label", ""),
                "osint:kind": edge.get("kind", "signal"),
                "osint:source": edge.get("from", ""),
                "osint:target": edge.get("to", ""),
            }
            for index, edge in enumerate(edges, 1)
        ],
        "generated_at": utc_now(),
        "workspace_id": graph.get("workspace_id", "current"),
    }
    return json.dumps(redact_data(payload), indent=2).encode("utf-8")


def dot_escape(value: object) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def graph_format_dot(graph: dict[str, object]) -> bytes:
    lines = [
        "digraph OSINTPRO {",
        "  rankdir=LR;",
        '  graph [label="OSINTPRO passive investigation graph", labelloc=t, fontsize=18];',
        "  node [shape=box, style=\"rounded,filled\", fontname=Helvetica];",
        "  edge [fontname=Helvetica, color=\"#6b7280\"];",
    ]
    for node in graph.get("nodes") or []:
        node_type = str(node.get("type", "node"))
        fill = {
            "site": "#d1fae5",
            "person": "#dbeafe",
            "wallet": "#fef3c7",
            "finding": "#fee2e2",
            "risk": "#fee2e2",
            "folder": "#ede9fe",
        }.get(node_type, "#f8fafc")
        label = dot_escape(f"{node.get('label', '')}\\n{node_type}")
        lines.append(f'  "{dot_escape(node.get("id"))}" [label="{label}", fillcolor="{fill}"];')
    for edge in graph.get("edges") or []:
        lines.append(
            f'  "{dot_escape(edge.get("from"))}" -> "{dot_escape(edge.get("to"))}" '
            f'[label="{dot_escape(edge.get("label"))}"];'
        )
    lines.append("}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def graph_format_csv(graph: dict[str, object]) -> bytes:
    nodes = {str(node.get("id")): node for node in graph.get("nodes") or []}
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "source_id",
        "source_label",
        "source_type",
        "relationship",
        "target_id",
        "target_label",
        "target_type",
        "confidence",
        "last_seen",
    ])
    for edge in graph.get("edges") or []:
        source = nodes.get(str(edge.get("from")), {})
        target = nodes.get(str(edge.get("to")), {})
        writer.writerow([
            edge.get("from", ""),
            source.get("label", ""),
            source.get("type", ""),
            edge.get("label", ""),
            edge.get("to", ""),
            target.get("label", ""),
            target.get("type", ""),
            "lead",
            utc_now(),
        ])
    return output.getvalue().encode("utf-8")


def report_findings_csv(report: dict[str, object]) -> bytes:
    """Export owner-ready finding context for spreadsheet review."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "source",
        "level",
        "title",
        "detail",
        "how_attacker_may_abuse_it",
        "business_impact",
        "owner_action",
        "evidence_to_collect",
        "root_cause",
    ])
    for item in report.get("findings", []) or []:
        writer.writerow([
            "finding",
            item.get("level", ""),
            item.get("title", ""),
            item.get("detail", ""),
            item.get("abuse_path", ""),
            item.get("business_impact", ""),
            item.get("owner_action", ""),
            item.get("evidence_to_collect", ""),
            item.get("root_cause") or item.get("type", ""),
        ])
    for item in report.get("vulnerability_hypotheses", []) or []:
        writer.writerow([
            "hypothesis",
            item.get("severity", ""),
            item.get("title", ""),
            item.get("evidence", ""),
            item.get("attacker_path", ""),
            item.get("likely_impact", ""),
            item.get("next_step", ""),
            item.get("defensive_priority", ""),
            item.get("root_cause") or item.get("type", ""),
        ])
    return output.getvalue().encode("utf-8")


def sarif_level(severity: object) -> str:
    value = str(severity or "").lower()
    if value in {"critical", "high"}:
        return "error"
    if value == "medium":
        return "warning"
    return "note"


def format_sarif(audit: dict[str, object]) -> bytes:
    findings = audit.get("findings") if isinstance(audit.get("findings"), list) else []
    rules: dict[str, dict[str, object]] = {}
    results = []
    for finding in findings:
        rule_id = str(
            finding.get("rule_id")
            or repo_rule_id(str(finding.get("category", "Review")), str(finding.get("title", "Finding")))
        )
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.get("title", rule_id),
            "shortDescription": {"text": finding.get("title", rule_id)},
            "fullDescription": {"text": finding.get("why", "")},
            "help": {"text": finding.get("remediation", "Review the finding and confirm applicability.")},
            "properties": {
                "category": finding.get("category", "Review"),
                "severity": finding.get("severity", "info"),
            },
        })
        results.append({
            "ruleId": rule_id,
            "level": sarif_level(finding.get("severity")),
            "message": {"text": finding.get("title", "Repository audit finding")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("path", "")},
                    "region": {"startLine": int(finding.get("line") or 1)},
                }
            }],
            "fixes": [{
                "description": {"text": finding.get("remediation", "Review code and apply the documented remediation.")}
            }],
            "properties": {
                "confidence": finding.get("confidence", "medium"),
                "confidenceScore": finding.get("confidence_score", 0.5),
                "applicability": finding.get("applicability", ""),
                "evidence": finding.get("evidence", ""),
            },
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OSINTPRO Repository Audit Lab",
                    "version": "1.0.0",
                    "informationUri": "https://osintpro-48j4.onrender.com/docs/REPOSITORY_AUDIT_LAB.md",
                    "rules": list(rules.values()),
                }
            },
            "automationDetails": {"id": f"osintpro/{audit.get('repository', 'repository')}"},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": audit.get("generated_at", utc_now()),
                "toolExecutionNotifications": [{
                    "level": "note",
                    "message": {
                        "text": "Static review only. OSINTPRO did not execute repository code or install dependencies."
                    },
                }],
            }],
        }],
    }
    return json.dumps(redact_data(payload), indent=2).encode("utf-8")


class Handler(SimpleHTTPRequestHandler):
    server_version = "OSINTPRO"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self) -> None:
        host = self.headers.get("Host", "")
        if not host.startswith(("127.0.0.1", "localhost")):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "worker-src 'none'; manifest-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        if self.path.startswith("/api/") or self.path.startswith("/admin"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def make_session_cookie(self, user_id: str, max_age: int | None = None) -> str:
        host = self.headers.get("Host", "")
        secure = "" if host.startswith(("127.0.0.1", "localhost")) else "; Secure"
        expiry = "" if max_age is None else f"; Max-Age={max_age}"
        value = "" if max_age == 0 else sign_value(user_id)
        return f"{SESSION_COOKIE}={value}; Path=/; SameSite=Strict; HttpOnly{secure}{expiry}"

    def client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = self.headers.get("X-Real-IP", "")
        if real_ip:
            return real_ip.strip()
        return self.client_address[0] if self.client_address else "unknown"

    def rate_limited(self, path: str) -> bool:
        limit = RATE_LIMITS.get(path)
        if not limit:
            return False
        ip = self.client_ip()
        key = (ip, path)
        now = time.time()
        with RATE_LOCK:
            bucket = [stamp for stamp in RATE_BUCKETS.get(key, []) if now - stamp < RATE_LIMIT_WINDOW]
            if len(bucket) >= limit:
                RATE_BUCKETS[key] = bucket
                return True
            bucket.append(now)
            RATE_BUCKETS[key] = bucket
        return False

    def api_rate_limited(self, key_id: str, path: str) -> bool:
        limit = api_key_rate_limit()
        bucket_key = (key_id, path)
        now = time.time()
        with RATE_LOCK:
            bucket = [stamp for stamp in API_RATE_BUCKETS.get(bucket_key, []) if now - stamp < RATE_LIMIT_WINDOW]
            if len(bucket) >= limit:
                API_RATE_BUCKETS[bucket_key] = bucket
                return True
            bucket.append(now)
            API_RATE_BUCKETS[bucket_key] = bucket
        return False

    def api_user_from_key(self) -> tuple[dict[str, object] | None, dict[str, object] | None, str | None]:
        authorization = str(self.headers.get("Authorization", ""))
        if not authorization.lower().startswith("bearer "):
            return None, None, "Missing API key."
        token = authorization.split(" ", 1)[1].strip()
        if not API_KEY_RE.match(token):
            return None, None, "Invalid API key."
        token_hash = hash_api_key(token)
        now = utc_now()
        with db() as connection:
            row = connection.execute(
                """
                SELECT
                    api_keys.*,
                    users.nickname,
                    users.plan,
                    users.credits
                FROM api_keys
                JOIN users ON users.id = api_keys.user_id
                WHERE api_keys.key_hash = ?
                  AND api_keys.revoked_at IS NULL
                  AND (users.nickname IS NOT NULL OR users.plan = 'Admin')
                """,
                (token_hash,),
            ).fetchone()
            if not row:
                return None, None, "API key not found or revoked."
            if not can_use_api(str(row["plan"])):
                return None, None, "API access requires Agency or Admin."
            connection.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        api_key = {
            "id": row["id"],
            "name": row["name"],
            "prefix": row["prefix"],
            "scopes": json.loads(row["scopes_json"] or "[]"),
        }
        user = {
            "_id": row["user_id"],
            "nickname": row["nickname"],
            "authenticated": True,
            "plan": row["plan"],
            "credits": row["credits"],
            "free_credits": None,
            "monitor_limit": PLAN_LIMITS.get(row["plan"], PLAN_LIMITS["Free"])["monitors"],
        }
        return user, api_key, None

    def api_key_rows_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, name, prefix, created_at, last_used_at, revoked_at
                FROM api_keys
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [dict(public_api_key(row)) for row in rows]

    def registration_limited(self, connection: sqlite3.Connection, user_id: str) -> bool:
        limit = registration_ip_limit()
        ip_value = self.client_ip()
        if not limit or ip_allowed(ip_value, registration_allowlist()):
            return False
        fingerprint = stable_fingerprint(ip_value)
        count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM users
            WHERE signup_fingerprint = ?
              AND nickname IS NOT NULL
              AND id != ?
            """,
            (fingerprint, user_id),
        ).fetchone()["count"]
        return count >= limit

    def send_json(
        self,
        payload: dict[str, object],
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(redact_data(payload)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_html(
        self,
        document: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = redact_text(document).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_head_only(
        self,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def send_page_file(self, filename: str, status: int = 200) -> None:
        path = ROOT / filename
        try:
            document = path.read_text(encoding="utf-8")
        except OSError:
            self.send_json({"error": "File not available"}, 404)
            return
        self.send_html(document, status=status)

    def authenticated_user_row(self) -> sqlite3.Row | None:
        current = self.session_id()
        if not current:
            return None
        with db() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (current,)).fetchone()
        return row if row and row["nickname"] else None

    def send_download(
        self,
        body: bytes,
        content_type: str,
        filename: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Send one attachment response with consistent security headers."""
        clean_name = safe_download_filename(filename, "osintpro-export")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{clean_name}"')
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, limit: int = MAX_BODY_BYTES) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        if length > limit:
            raise ValueError("Request body is too large.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Invalid payload.")
        return payload

    def read_raw_body(self, limit: int = MAX_BODY_BYTES) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length > limit:
            raise ValueError("Request body is too large.")
        return self.rfile.read(length) if length else b""

    def session_id(self) -> str | None:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == SESSION_COOKIE and value:
                return verify_signed_value(value)
        return None

    def get_or_create_user(self) -> tuple[dict[str, object], dict[str, str]]:
        current = self.session_id()
        with db() as connection:
            if current:
                row = connection.execute("SELECT * FROM users WHERE id = ?", (current,)).fetchone()
                if row:
                    return internal_user(row), {}

            user_id = str(uuid.uuid4())
            now = utc_now()
            connection.execute(
                "INSERT INTO users (id, plan, credits, created_at, updated_at) VALUES (?, 'Free', ?, ?, ?)",
                (user_id, FREE_CREDITS, now, now),
            )
            row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return internal_user(row), {
            "Set-Cookie": self.make_session_cookie(user_id)
        }

    def reports_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, domain, score, summary, generated_at
                FROM reports
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def visible_reports_for_user(self, user: dict[str, object]) -> list[dict[str, object]]:
        if not user.get("authenticated"):
            return []
        return self.reports_for_user(str(user["_id"]))

    def social_reports_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, username, score, summary, generated_at
                FROM social_reports
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def visible_social_reports_for_user(self, user: dict[str, object]) -> list[dict[str, object]]:
        if not user.get("authenticated"):
            return []
        return self.social_reports_for_user(str(user["_id"]))

    def wallet_reports_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, chain, address, risk_score, summary, generated_at
                FROM wallet_reports
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def visible_wallet_reports_for_user(self, user: dict[str, object]) -> list[dict[str, object]]:
        if not user.get("authenticated"):
            return []
        return self.wallet_reports_for_user(str(user["_id"]))

    def monitors_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, domain, status, last_score, last_summary, last_checked_at, last_changed_at, created_at
                FROM monitors
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def visible_monitors_for_user(self, user: dict[str, object]) -> list[dict[str, object]]:
        if not user.get("authenticated"):
            return []
        return self.monitors_for_user(str(user["_id"]))

    def folders_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT
                    client_folders.id,
                    client_folders.name,
                    client_folders.created_at,
                    COUNT(DISTINCT reports.id) AS domain_reports,
                    COUNT(DISTINCT social_reports.id) AS social_reports,
                    COUNT(DISTINCT wallet_reports.id) AS wallet_reports,
                    COUNT(DISTINCT monitors.id) AS monitors
                FROM client_folders
                LEFT JOIN reports ON reports.folder_id = client_folders.id AND reports.user_id = client_folders.user_id
                LEFT JOIN social_reports ON social_reports.folder_id = client_folders.id AND social_reports.user_id = client_folders.user_id
                LEFT JOIN wallet_reports ON wallet_reports.folder_id = client_folders.id AND wallet_reports.user_id = client_folders.user_id
                LEFT JOIN monitors ON monitors.folder_id = client_folders.id AND monitors.user_id = client_folders.user_id
                WHERE client_folders.user_id = ?
                GROUP BY client_folders.id
                ORDER BY client_folders.updated_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def wallet_annotations_for_user(self, user_id: str) -> dict[str, dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT chain, address, tags_json, notes, updated_at
                FROM wallet_annotations
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchall()
        annotations = {}
        for row in rows:
            try:
                tags = json.loads(row["tags_json"])
            except json.JSONDecodeError:
                tags = []
            annotations[f"{row['chain']}:{row['address']}"] = {
                "tags": tags if isinstance(tags, list) else [],
                "notes": row["notes"],
                "updated_at": row["updated_at"],
            }
        return annotations

    def playbooks_for_user(self, user_id: str) -> list[dict[str, object]]:
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, report_id, domain, title, created_at, updated_at
                FROM web_audit_playbooks
                WHERE user_id = ?
                ORDER BY updated_at DESC
                LIMIT 50
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def report_comparison(self, user_id: str, domain: str) -> dict[str, object]:
        clean = clean_domain(domain)
        with db() as connection:
            rows = connection.execute(
                """
                SELECT id, domain, score, summary, generated_at, payload_json
                FROM reports
                WHERE user_id = ? AND domain = ?
                ORDER BY created_at DESC
                LIMIT 2
                """,
                (user_id, clean),
            ).fetchall()
        if len(rows) < 2:
            return {"domain": clean, "available": False, "message": "At least two reports are required for comparison."}
        latest = redact_data(json.loads(rows[0]["payload_json"]))
        previous = redact_data(json.loads(rows[1]["payload_json"]))

        def missing_headers(report: dict[str, object]) -> set[str]:
            headers = report.get("https", {}).get("security_headers", [])
            return {str(item.get("name")) for item in headers if not item.get("present")}

        def finding_titles(report: dict[str, object]) -> set[str]:
            return {str(item.get("title")) for item in report.get("findings", []) if item.get("title")}

        latest_missing = missing_headers(latest)
        previous_missing = missing_headers(previous)
        latest_findings = finding_titles(latest)
        previous_findings = finding_titles(previous)
        return redact_data({
            "domain": clean,
            "available": True,
            "latest": {
                "id": rows[0]["id"],
                "score": latest.get("score", rows[0]["score"]),
                "generated_at": latest.get("generated_at", rows[0]["generated_at"]),
                "summary": latest.get("summary", rows[0]["summary"]),
            },
            "previous": {
                "id": rows[1]["id"],
                "score": previous.get("score", rows[1]["score"]),
                "generated_at": previous.get("generated_at", rows[1]["generated_at"]),
                "summary": previous.get("summary", rows[1]["summary"]),
            },
            "delta": int(latest.get("score", 0)) - int(previous.get("score", 0)),
            "fixed_headers": sorted(previous_missing - latest_missing),
            "new_missing_headers": sorted(latest_missing - previous_missing),
            "resolved_findings": sorted(previous_findings - latest_findings),
            "new_findings": sorted(latest_findings - previous_findings),
        })

    def intelligence_workspace(self, user: dict[str, object]) -> dict[str, object]:
        if not user.get("authenticated"):
            return {
                "authenticated": False,
                "nodes": [],
                "edges": [],
                "dossiers": {"sites": [], "people": [], "wallets": []},
                "folders": [],
                "case_summaries": [],
                "playbooks": [],
                "wallet": {
                    "assets": [],
                    "credits": user.get("credits", 0),
                    "plan": user.get("plan", "Free"),
                    "monitor_limit": user.get("monitor_limit", 0),
                    "monitor_used": 0,
                    "domain_reports": 0,
                    "social_reports": 0,
                    "exposure_index": 0,
                },
            }

        with db() as connection:
            report_rows = connection.execute(
                """
                SELECT id, domain, score, summary, generated_at, payload_json, folder_id
                FROM reports
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (user["_id"],),
            ).fetchall()
            social_rows = connection.execute(
                """
                SELECT id, username, score, summary, generated_at, payload_json, folder_id
                FROM social_reports
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (user["_id"],),
            ).fetchall()
            wallet_rows = connection.execute(
                """
                SELECT id, chain, address, risk_score, summary, generated_at, payload_json, folder_id
                FROM wallet_reports
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (user["_id"],),
            ).fetchall()
            monitor_rows = connection.execute(
                """
                SELECT domain, status, last_score, last_checked_at, folder_id
                FROM monitors
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user["_id"],),
            ).fetchall()
            folder_rows = connection.execute(
                """
                SELECT id, name, created_at
                FROM client_folders
                WHERE user_id = ?
                ORDER BY updated_at DESC
                """,
                (user["_id"],),
            ).fetchall()

        nodes: dict[str, dict[str, object]] = {}
        edges: list[dict[str, str]] = []
        sites: list[dict[str, object]] = []
        people: list[dict[str, object]] = []
        wallets: list[dict[str, object]] = []
        assets: list[dict[str, object]] = []
        folders = [dict(row) for row in folder_rows]
        folder_names = {row["id"]: row["name"] for row in folder_rows}
        case_index: dict[str, dict[str, object]] = {
            str(row["id"]): {
                "id": row["id"],
                "name": row["name"],
                "assets": 0,
                "domains": 0,
                "people": 0,
                "wallets": 0,
                "findings": 0,
                "high_risk": 0,
                "scores": [],
                "latest_activity": row["created_at"],
                "top_signals": [],
            }
            for row in folder_rows
        }
        wallet_annotations = self.wallet_annotations_for_user(str(user["_id"]))

        def touch_case(
            folder_id: str | None,
            kind: str,
            posture_score: int,
            findings: list[object],
            latest: str,
            signals: list[str],
        ) -> None:
            if not folder_id or folder_id not in case_index:
                return
            item = case_index[folder_id]
            item["assets"] = int(item["assets"]) + 1
            item["scores"].append(posture_score)
            if kind == "domain":
                item["domains"] = int(item["domains"]) + 1
            if kind == "person":
                item["people"] = int(item["people"]) + 1
            if kind == "wallet":
                item["wallets"] = int(item["wallets"]) + 1
            item["findings"] = int(item["findings"]) + len(findings)
            if posture_score < 55:
                item["high_risk"] = int(item["high_risk"]) + 1
            if latest and latest > str(item["latest_activity"]):
                item["latest_activity"] = latest
            for signal in signals:
                if signal and signal not in item["top_signals"]:
                    item["top_signals"].append(signal)

        def add_node(node_id: str, label: str, node_type: str, score: int | None = None, meta: str = "") -> None:
            if not label:
                return
            nodes[node_id] = redact_data({
                "id": node_id,
                "label": label,
                "type": node_type,
                "score": score,
                "meta": meta,
            })

        def add_edge(source: str, target: str, label: str, kind: str = "signal") -> None:
            if source in nodes and target in nodes:
                edges.append(redact_data({
                    "from": source,
                    "to": target,
                    "label": label,
                    "kind": kind,
                }))

        monitor_map = {row["domain"]: dict(row) for row in monitor_rows}

        for row in report_rows:
            try:
                report = redact_data(json.loads(row["payload_json"]))
            except (TypeError, json.JSONDecodeError):
                report = dict(row)
            domain = str(report.get("domain") or row["domain"])
            root = f"site:{domain}"
            score = int(report.get("score") or row["score"] or 0)
            add_node(root, domain, "site", score, "domain dossier")
            assets.append({"type": "site", "label": domain, "score": score, "monitored": domain in monitor_map})
            folder_id = row["folder_id"]
            folder_name = folder_names.get(folder_id, "") if folder_id else ""
            if folder_name:
                folder_node = f"folder:{folder_id}"
                add_node(folder_node, folder_name, "folder", None, "client folder")
                add_edge(folder_node, root, "contains", "case")

            dns = report.get("dns") or {}
            email = report.get("email_security") or {}
            rdap = report.get("rdap") or {}
            https = report.get("https") or {}
            advanced = report.get("advanced_intel") or {}
            ct = report.get("certificate_transparency") or {}

            for address in (dns.get("addresses") or [])[:6]:
                node_id = f"ip:{address}"
                add_node(node_id, str(address), "ip", None, "resolved address")
                add_edge(root, node_id, "resolves to", "dns")
            for ns in (dns.get("ns") or [])[:6]:
                node_id = f"ns:{ns}"
                add_node(node_id, str(ns), "nameserver", None, "NS")
                add_edge(root, node_id, "nameserver", "dns")
            for mx in (dns.get("mx") or [])[:6]:
                node_id = f"mx:{mx}"
                add_node(node_id, str(mx), "mail", None, "MX")
                add_edge(root, node_id, "mail exchange", "email")
            registrar = rdap.get("registrar")
            if registrar:
                node_id = f"registrar:{registrar}"
                add_node(node_id, str(registrar), "registry", None, "registrar")
                add_edge(root, node_id, "registered via", "registry")
            server = https.get("server")
            if server:
                node_id = f"tech:{server}"
                add_node(node_id, str(server), "technology", None, "server header")
                add_edge(root, node_id, "exposes", "web")
            for tech in (report.get("technology") or [])[:8]:
                node_id = f"tech:{tech}"
                add_node(node_id, str(tech), "technology", None, "tech signal")
                add_edge(root, node_id, "fingerprint", "web")
            for subdomain in (ct.get("subdomains") or [])[:12]:
                node_id = f"subdomain:{subdomain}"
                add_node(node_id, str(subdomain), "subdomain", None, "CT observed")
                add_edge(root, node_id, "certificate transparency", "ct")
            for hint in (advanced.get("takeover_hints") or [])[:5]:
                subdomain = hint.get("subdomain")
                provider = hint.get("provider")
                if subdomain:
                    node_id = f"takeover:{subdomain}"
                    add_node(node_id, str(subdomain), "risk", None, str(provider or "takeover hint"))
                    add_edge(root, node_id, "takeover review", "risk")
            if email.get("applicable"):
                email_node = f"email:{domain}"
                add_node(email_node, "Email posture", "email", int(email.get("score") or 0), "SPF/DMARC/MTA-STS")
                add_edge(root, email_node, "email controls", "email")
            for finding in (report.get("findings") or [])[:6]:
                title = finding.get("title")
                if title:
                    node_id = f"finding:{domain}:{title}"
                    add_node(node_id, str(title), "finding", None, str(finding.get("level") or "signal"))
                    add_edge(root, node_id, "finding", "risk")

            sites.append(redact_data({
                "id": row["id"],
                "domain": domain,
                "score": score,
                "summary": report.get("summary") or row["summary"],
                "generated_at": report.get("generated_at") or row["generated_at"],
                "registrar": registrar or "not available",
                "ips": (dns.get("addresses") or [])[:6],
                "mx": (dns.get("mx") or [])[:4],
                "subdomains": (ct.get("subdomains") or [])[:8],
                "findings": (report.get("findings") or [])[:5],
                "vulnerabilities": (report.get("vulnerability_hypotheses") or [])[:4],
                "monitored": domain in monitor_map,
                "folder_id": folder_id,
                "folder": folder_name,
            }))
            touch_case(
                folder_id,
                "domain",
                score,
                report.get("findings") or [],
                str(report.get("generated_at") or row["generated_at"]),
                [str(item.get("title")) for item in (report.get("findings") or [])[:3] if item.get("title")],
            )

        for row in social_rows:
            try:
                report = redact_data(json.loads(row["payload_json"]))
            except (TypeError, json.JSONDecodeError):
                report = dict(row)
            username = str(report.get("username") or row["username"])
            root = f"person:{username}"
            score = int(report.get("score") or row["score"] or 0)
            profiles = report.get("profiles") or []
            found = [profile for profile in profiles if profile.get("present") is True]
            add_node(root, f"@{username}", "person", score, "nickname dossier")
            assets.append({"type": "person", "label": f"@{username}", "score": score, "monitored": False})
            folder_id = row["folder_id"]
            folder_name = folder_names.get(folder_id, "") if folder_id else ""
            if folder_name:
                folder_node = f"folder:{folder_id}"
                add_node(folder_node, folder_name, "folder", None, "client folder")
                add_edge(folder_node, root, "contains", "case")
            for profile in found[:12]:
                platform = profile.get("platform")
                node_id = f"profile:{username}:{platform}"
                add_node(node_id, str(platform), "profile", None, str(profile.get("confidence") or "observed"))
                add_edge(root, node_id, "public profile", "social")
            for finding in (report.get("findings") or [])[:5]:
                title = finding.get("title")
                if title:
                    node_id = f"social-finding:{username}:{title}"
                    add_node(node_id, str(title), "finding", None, str(finding.get("level") or "signal"))
                    add_edge(root, node_id, "finding", "risk")
            people.append(redact_data({
                "id": row["id"],
                "username": username,
                "score": score,
                "summary": report.get("summary") or row["summary"],
                "generated_at": report.get("generated_at") or row["generated_at"],
                "profiles_found": len(found),
                "profiles": found[:10],
                "findings": (report.get("findings") or [])[:5],
                "folder_id": folder_id,
                "folder": folder_name,
            }))
            touch_case(
                folder_id,
                "person",
                score,
                report.get("findings") or [],
                str(report.get("generated_at") or row["generated_at"]),
                [str(profile.get("platform")) for profile in found[:3] if profile.get("platform")],
            )

        for row in wallet_rows:
            try:
                report = redact_data(json.loads(row["payload_json"]))
            except (TypeError, json.JSONDecodeError):
                report = dict(row)
            chain = str(report.get("chain") or row["chain"])
            address = str(report.get("address") or row["address"])
            root = f"wallet:{chain}:{address}"
            risk_score = int(report.get("risk_score") or row["risk_score"] or 0)
            add_node(root, compact_address(address), "wallet", risk_score, chain)
            assets.append({"type": "wallet", "label": compact_address(address), "score": risk_score, "monitored": False})
            folder_id = row["folder_id"]
            folder_name = folder_names.get(folder_id, "") if folder_id else ""
            annotation = wallet_annotations.get(f"{chain}:{address}", {"tags": [], "notes": ""})
            if folder_name:
                folder_node = f"folder:{folder_id}"
                add_node(folder_node, folder_name, "folder", None, "client folder")
                add_edge(folder_node, root, "contains", "case")
            for tag in annotation.get("tags", [])[:8]:
                tag_node = f"wallet-tag:{tag}"
                add_node(tag_node, str(tag), "tag", None, "manual label")
                add_edge(root, tag_node, "manual tag", "case")

            for tx in (report.get("transactions") or [])[:10]:
                tx_hash = str(tx.get("hash") or "")
                if not tx_hash:
                    continue
                tx_node = f"tx:{chain}:{tx_hash}"
                add_node(tx_node, compact_address(tx_hash), "transaction", None, str(tx.get("direction") or "tx"))
                add_edge(root, tx_node, str(tx.get("direction") or "movement"), "wallet")
            for counterparty in (report.get("counterparties") or [])[:16]:
                other = str(counterparty.get("address") or "")
                if not other:
                    continue
                cp_node = f"wallet:{chain}:{other}"
                add_node(cp_node, compact_address(other), "counterparty", None, str(counterparty.get("direction") or "counterparty"))
                add_edge(root, cp_node, f"{counterparty.get('tx_count', 0)} tx", "wallet")
            for finding in (report.get("findings") or [])[:5]:
                title = finding.get("title")
                if title:
                    node_id = f"wallet-finding:{chain}:{address}:{title}"
                    add_node(node_id, str(title), "finding", None, str(finding.get("level") or "signal"))
                    add_edge(root, node_id, "wallet finding", "risk")

            tx_timeline = sorted(
                [
                    {
                        "timestamp": tx.get("timestamp"),
                        "direction": tx.get("direction"),
                        "value": tx.get("value"),
                        "hash": tx.get("hash"),
                        "short": tx.get("short") or compact_address(str(tx.get("hash") or "")),
                        "url": tx.get("url"),
                    }
                    for tx in (report.get("transactions") or [])[:12]
                ],
                key=lambda item: str(item.get("timestamp") or ""),
                reverse=True,
            )
            wallets.append(redact_data({
                "id": row["id"],
                "chain": chain,
                "address": address,
                "short": compact_address(address),
                "risk_score": risk_score,
                "summary": report.get("summary") or row["summary"],
                "generated_at": report.get("generated_at") or row["generated_at"],
                "balance": report.get("balance"),
                "asset": report.get("asset"),
                "tx_count": report.get("tx_count"),
                "counterparties": (report.get("counterparties") or [])[:8],
                "findings": (report.get("findings") or [])[:5],
                "timeline": tx_timeline,
                "explorer_url": report.get("explorer_url"),
                "folder_id": folder_id,
                "folder": folder_name,
                "annotation": annotation,
            }))
            touch_case(
                folder_id,
                "wallet",
                100 - risk_score,
                report.get("findings") or [],
                str(report.get("generated_at") or row["generated_at"]),
                [str(item.get("title")) for item in (report.get("findings") or [])[:3] if item.get("title")],
            )

        scores = (
            [int(row["score"] or 0) for row in report_rows]
            + [int(row["score"] or 0) for row in social_rows]
            + [100 - int(row["risk_score"] or 0) for row in wallet_rows]
        )
        exposure_index = round(sum(scores) / len(scores)) if scores else 0
        case_summaries = []
        for item in case_index.values():
            score_values = item.pop("scores")
            item["average_score"] = round(sum(score_values) / len(score_values)) if score_values else 0
            item["top_signals"] = item["top_signals"][:5]
            case_summaries.append(item)
        return redact_data({
            "authenticated": True,
            "nodes": list(nodes.values())[:140],
            "edges": edges[:220],
            "dossiers": {"sites": sites, "people": people, "wallets": wallets},
            "folders": self.folders_for_user(str(user["_id"])),
            "case_summaries": sorted(case_summaries, key=lambda item: str(item["latest_activity"]), reverse=True),
            "playbooks": self.playbooks_for_user(str(user["_id"])),
            "wallet": {
                "assets": assets[:60],
                "credits": user.get("credits", 0),
                "plan": user.get("plan", "Free"),
                "monitor_limit": user.get("monitor_limit", 0),
                "monitor_used": len(monitor_rows),
                "domain_reports": len(report_rows),
                "social_reports": len(social_rows),
                "wallet_reports": len(wallet_rows),
                "exposure_index": exposure_index,
            },
        })

    def admin_overview(self) -> dict[str, object]:
        funnel_start = (dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(days=30)).isoformat()
        with db() as connection:
            totals = {
                "users": connection.execute(
                    "SELECT COUNT(*) AS count FROM users WHERE nickname IS NOT NULL"
                ).fetchone()["count"],
                "reports": connection.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"],
                "social_reports": connection.execute("SELECT COUNT(*) AS count FROM social_reports").fetchone()["count"],
                "wallet_reports": connection.execute("SELECT COUNT(*) AS count FROM wallet_reports").fetchone()["count"],
                "repository_reports": connection.execute("SELECT COUNT(*) AS count FROM repository_reports").fetchone()["count"],
                "monitors": connection.execute("SELECT COUNT(*) AS count FROM monitors").fetchone()["count"],
                "stripe_events": connection.execute("SELECT COUNT(*) AS count FROM stripe_events").fetchone()["count"],
                "conversion_events": connection.execute("SELECT COUNT(*) AS count FROM conversion_events").fetchone()["count"],
                "api_keys": connection.execute("SELECT COUNT(*) AS count FROM api_keys WHERE revoked_at IS NULL").fetchone()["count"],
                "webhooks": connection.execute("SELECT COUNT(*) AS count FROM webhooks WHERE active = 1").fetchone()["count"],
                "notification_events": connection.execute("SELECT COUNT(*) AS count FROM notification_events").fetchone()["count"],
            }
            users = connection.execute(
                """
                SELECT
                    users.nickname,
                    users.plan,
                    users.credits,
                    users.created_at,
                    users.updated_at,
                    COUNT(DISTINCT reports.id) AS report_count,
                    COUNT(DISTINCT social_reports.id) AS social_report_count,
                    COUNT(DISTINCT wallet_reports.id) AS wallet_report_count,
                    COUNT(DISTINCT monitors.id) AS monitor_count
                FROM users
                LEFT JOIN reports ON reports.user_id = users.id
                LEFT JOIN social_reports ON social_reports.user_id = users.id
                LEFT JOIN wallet_reports ON wallet_reports.user_id = users.id
                LEFT JOIN monitors ON monitors.user_id = users.id
                WHERE users.nickname IS NOT NULL
                GROUP BY users.id
                ORDER BY users.updated_at DESC
                LIMIT 50
                """
            ).fetchall()
            events = connection.execute(
                """
                SELECT type, status, plan, created_at
                FROM stripe_events
                ORDER BY created_at DESC
                LIMIT 10
                """
            ).fetchall()
            conversion_events = connection.execute(
                """
                SELECT event, plan, source, created_at
                FROM conversion_events
                ORDER BY created_at DESC
                LIMIT 15
                """
            ).fetchall()
            conversion_funnel = connection.execute(
                """
                SELECT event, COALESCE(plan, '-') AS plan, COUNT(*) AS count
                FROM conversion_events
                WHERE created_at >= ?
                GROUP BY event, plan
                ORDER BY count DESC, event ASC
                LIMIT 20
                """,
                (funnel_start,),
            ).fetchall()
        return {
            "totals": totals,
            "production": {
                "stripe_pro_link": bool(os.getenv("OSINTPRO_STRIPE_PRO_URL")),
                "stripe_agency_link": bool(os.getenv("OSINTPRO_STRIPE_AGENCY_URL")),
                "stripe_webhook": bool(stripe_webhook_secret()),
                "cron_secret": bool(cron_secret()),
                "alert_webhook": bool(alert_webhook_url()),
                "database": database_status(),
                "registration_limit": registration_ip_limit(),
                "registration_allowlist": bool(registration_allowlist()),
            },
            "users": [dict(row) for row in users],
            "stripe_events": [dict(row) for row in events],
            "conversion_events": [dict(row) for row in conversion_events],
            "conversion_funnel": [dict(row) for row in conversion_funnel],
            "backups": list_backups(),
        }

    def admin_export(self) -> dict[str, object]:
        with db() as connection:
            users = connection.execute(
                """
                SELECT id, nickname, plan, credits, created_at, updated_at
                FROM users
                WHERE nickname IS NOT NULL
                ORDER BY created_at ASC
                """
            ).fetchall()
            reports = connection.execute(
                """
                SELECT id, user_id, domain, score, summary, generated_at, created_at
                FROM reports
                ORDER BY created_at ASC
                """
            ).fetchall()
            social_reports = connection.execute(
                """
                SELECT id, user_id, username, score, summary, generated_at, created_at
                FROM social_reports
                ORDER BY created_at ASC
                """
            ).fetchall()
            wallet_reports = connection.execute(
                """
                SELECT id, user_id, chain, address, risk_score, summary, generated_at, created_at
                FROM wallet_reports
                ORDER BY created_at ASC
                """
            ).fetchall()
            repository_reports = connection.execute(
                """
                SELECT id, user_id, repository, score, generated_at, created_at
                FROM repository_reports
                ORDER BY created_at ASC
                """
            ).fetchall()
            monitors = connection.execute(
                """
                SELECT id, user_id, domain, status, last_score, last_summary,
                       last_checked_at, last_changed_at, created_at, updated_at
                FROM monitors
                ORDER BY created_at ASC
                """
            ).fetchall()
            stripe_events = connection.execute(
                """
                SELECT id, user_id, plan, type, status, created_at
                FROM stripe_events
                ORDER BY created_at ASC
                """
            ).fetchall()
            conversion_events = connection.execute(
                """
                SELECT id, user_id, event, plan, source, metadata_json, created_at
                FROM conversion_events
                ORDER BY created_at ASC
                """
            ).fetchall()
            folders = connection.execute(
                """
                SELECT id, user_id, name, created_at, updated_at
                FROM client_folders
                ORDER BY created_at ASC
                """
            ).fetchall()
            wallet_annotations = connection.execute(
                """
                SELECT id, user_id, chain, address, tags_json, notes, created_at, updated_at
                FROM wallet_annotations
                ORDER BY created_at ASC
                """
            ).fetchall()
            playbooks = connection.execute(
                """
                SELECT id, user_id, report_id, domain, title, created_at, updated_at
                FROM web_audit_playbooks
                ORDER BY created_at ASC
                """
            ).fetchall()
        return redact_data({
            "exported_at": utc_now(),
            "kind": "osintpro_sanitized_admin_export",
            "users": [dict(row) for row in users],
            "reports": [dict(row) for row in reports],
            "social_reports": [dict(row) for row in social_reports],
            "wallet_reports": [dict(row) for row in wallet_reports],
            "repository_reports": [dict(row) for row in repository_reports],
            "monitors": [dict(row) for row in monitors],
            "stripe_events": [dict(row) for row in stripe_events],
            "conversion_events": [dict(row) for row in conversion_events],
            "client_folders": [dict(row) for row in folders],
            "wallet_annotations": [dict(row) for row in wallet_annotations],
            "web_audit_playbooks": [dict(row) for row in playbooks],
        })

    def fetch_report(self, user_id: str, report_id: str) -> dict[str, object] | None:
        with db() as connection:
            row = connection.execute(
                "SELECT payload_json FROM reports WHERE user_id = ? AND id = ?",
                (user_id, report_id),
            ).fetchone()
        if not row:
            return None
        return redact_data(json.loads(row["payload_json"]))

    def fetch_repository_audit(self, user_id: str, report_id: str) -> dict[str, object] | None:
        with db() as connection:
            row = connection.execute(
                "SELECT payload_json FROM repository_reports WHERE user_id = ? AND id = ?",
                (user_id, report_id),
            ).fetchone()
        if not row:
            return None
        return redact_data(json.loads(row["payload_json"]))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/login", "/register", "/forgot-password"}:
            if self.authenticated_user_row():
                self.send_redirect("/")
                return
            page = {
                "/login": "login.html",
                "/register": "register.html",
                "/forgot-password": "forgot-password.html",
            }[parsed.path]
            self.send_page_file(page)
            return
        if parsed.path.startswith("/reset-password/"):
            token = parsed.path.rsplit("/", 1)[-1]
            with db() as connection:
                valid = reset_row_for_token(connection, token) is not None
            self.send_page_file("reset-password.html" if valid else "reset-expired.html", status=200 if valid else 410)
            return
        if parsed.path == "/settings/security":
            if not self.authenticated_user_row():
                self.send_redirect("/login")
                return
            self.send_page_file("security.html")
            return
        if not parsed.path.startswith("/api/") and parsed.path not in PUBLIC_STATIC_PATHS:
            self.send_json({"error": "File not available"}, 404)
            return
        if parsed.path == "/api/health":
            self.send_json({"ok": True})
            return
        if parsed.path == "/api/meta":
            self.send_json({
                "product": "OSINTPRO",
                "positioning": "Client-ready passive investigation and defensive source-review workspace.",
                "live_demo": "https://osintpro-48j4.onrender.com/",
                "safety_boundary": [
                    "passive public-source intelligence",
                    "no exploit execution",
                    "no brute force",
                    "no credential attacks",
                    "no unauthorized packet capture",
                    "no wallet movement or evasion guidance",
                    "no cheat development or anti-cheat bypass guidance",
                ],
                "modules": [
                    "domain_intel",
                    "social_intel",
                    "wallet_osint",
                    "entity_graph",
                    "web_audit_lab",
                    "repository_audit_lab",
                    "network_traffic_lab",
                    "game_security_lab",
                    "monitoring",
                    "exports",
                ],
                "plans": PLAN_LIMITS,
                "public_docs": {
                    "data_sources": "/docs/DATA_SOURCES.md",
                    "distribution": "/docs/DISTRIBUTION.md",
                    "repository_audit": "/docs/REPOSITORY_AUDIT_LAB.md",
                    "roadmap": "/ROADMAP.md",
                },
            })
            return
        if parsed.path == "/api/feature-flags":
            user, headers = self.get_or_create_user()
            plan = user.get("plan", "Free")
            self.send_json({
                "plan": plan,
                "features": public_feature_flags(plan),
            }, headers=headers)
            return
        if parsed.path == "/api/metrics":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to view account metrics."}, 401, headers)
                return
            try:
                self.send_json(user_growth_metrics(str(user["_id"])), headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 404, headers)
            return
        if parsed.path == "/api/api-keys":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated") and not is_admin_user(user):
                self.send_json({"error": "Sign in to manage API keys."}, 401, headers)
                return
            if not can_use_api(str(user.get("plan", "Free"))):
                self.send_json({"error": "API keys require Agency or Admin."}, 403, headers)
                return
            self.send_json({"api_keys": self.api_key_rows_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path == "/api/webhooks":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to manage webhooks."}, 401, headers)
                return
            if not feature_allowed(user.get("plan", "Free"), "webhooks"):
                self.send_json({"error": "Webhooks require Pro or Agency."}, 402, headers)
                return
            with db() as connection:
                rows = webhook_rows(connection, str(user["_id"]))
            self.send_json({
                "events": sorted(WEBHOOK_EVENTS),
                "webhooks": [public_webhook(row) for row in rows],
                "email_configured": all(smtp_settings()[key] for key in ("host", "user", "password", "sender")),
            }, headers=headers)
            return
        if parsed.path.startswith("/api/v1/reports/"):
            user, api_key, error = self.api_user_from_key()
            if error:
                self.send_json({"error": error}, 401)
                return
            if self.api_rate_limited(str(api_key["id"]), parsed.path):
                self.send_json({"error": "API rate limit reached."}, 429)
                return
            report_id = parsed.path.split("/")[-1]
            if not UUID_RE.match(report_id):
                self.send_json({"error": "Invalid report id."}, 400)
                return
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report not found."}, 404)
                return
            self.send_json({"report": report, "credential_info": {"prefix": api_key["prefix"]}})
            return
        if parsed.path in {"/api/v1/status", "/api/status"}:
            user, api_key, error = self.api_user_from_key()
            if error:
                self.send_json({"error": error}, 401)
                return
            limited = self.api_rate_limited(str(api_key["id"]), parsed.path)
            if limited:
                self.send_json({"error": "API rate limit reached."}, 429)
                return
            self.send_json({
                "plan": user.get("plan"),
                "rate_limit_per_minute": api_key_rate_limit(),
                "credential_info": {"prefix": api_key["prefix"]},
                "available_endpoints": [
                    "POST /api/v1/domain-reports",
                    "GET /api/v1/domains/analyze?domain=example.com",
                    "POST /api/v1/social-reports",
                    "POST /api/v1/wallet-reports",
                    "GET /api/v1/reports/{id}",
                ],
            })
            return
        if parsed.path in {"/api/v1/domains/analyze", "/api/domains/analyze"}:
            user, api_key, error = self.api_user_from_key()
            if error:
                self.send_json({"error": error}, 401)
                return
            if self.api_rate_limited(str(api_key["id"]), parsed.path):
                self.send_json({"error": "API rate limit reached."}, 429)
                return
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            try:
                report = analyze(str(query.get("domain", "")))
                with db() as connection:
                    store_report(connection, str(user["_id"]), report, None)
                    record_conversion_event(connection, str(user["_id"]), "api_domain_report", user.get("plan"), "api_v1_get")
                self.send_json({"report": report, "credential_info": {"prefix": api_key["prefix"]}}, status=201)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            except Exception:
                self.send_json({"error": "API domain report failed. No internal details exposed."}, 500)
            return
        if parsed.path == "/api/session":
            user, headers = self.get_or_create_user()
            self.send_json({
                "user": public_user(user),
                "reports": self.visible_reports_for_user(user),
                "social_reports": self.visible_social_reports_for_user(user),
                "wallet_reports": self.visible_wallet_reports_for_user(user),
                "monitors": self.visible_monitors_for_user(user),
                "folders": self.folders_for_user(str(user["_id"])) if user.get("authenticated") else [],
                "playbooks": self.playbooks_for_user(str(user["_id"])) if user.get("authenticated") else [],
                "pricing": {
                    "pro": {"price": "19", "monitors": 5},
                    "agency": {"price": "79", "monitors": 25},
                },
                "checkout_configured": bool(os.getenv("OSINTPRO_STRIPE_PRO_URL") or os.getenv("OSINTPRO_STRIPE_AGENCY_URL")),
            }, headers=headers)
            return
        if parsed.path == "/api/social/reports":
            user, headers = self.get_or_create_user()
            self.send_json({"social_reports": self.visible_social_reports_for_user(user)}, headers=headers)
            return
        if parsed.path == "/api/wallet/reports":
            user, headers = self.get_or_create_user()
            self.send_json({"wallet_reports": self.visible_wallet_reports_for_user(user)}, headers=headers)
            return
        if parsed.path == "/api/client-folders":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"folders": []}, headers=headers)
                return
            self.send_json({"folders": self.folders_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path == "/api/web-audit/playbooks":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"playbooks": []}, headers=headers)
                return
            self.send_json({"playbooks": self.playbooks_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path == "/api/reports":
            user, headers = self.get_or_create_user()
            self.send_json({"reports": self.visible_reports_for_user(user)}, headers=headers)
            return
        if parsed.path == "/api/reports/compare":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to compare reports."}, 401, headers)
                return
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            try:
                self.send_json(self.report_comparison(str(user["_id"]), str(query.get("domain", ""))), headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return
        if parsed.path == "/api/monitors":
            user, headers = self.get_or_create_user()
            self.send_json({"monitors": self.visible_monitors_for_user(user)}, headers=headers)
            return
        if parsed.path == "/api/intel/workspace":
            user, headers = self.get_or_create_user()
            self.send_json(self.intelligence_workspace(user), headers=headers)
            return
        if parsed.path.startswith("/api/graphs/") and parsed.path.endswith("/export"):
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to export the investigation graph."}, 401, headers)
                return
            try:
                workspace_id = clean_workspace_id(parsed.path.split("/")[3])
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                fmt = str(query.get("format", "jsonld")).lower()
                workspace = self.intelligence_workspace(user)
                graph = graph_export_subset(workspace, workspace_id)
                if not graph["nodes"]:
                    self.send_json({"error": "No graph data available for this workspace."}, 404, headers)
                    return
                if fmt == "jsonld":
                    body = graph_format_jsonld(graph)
                    content_type = "application/ld+json; charset=utf-8"
                    extension = "jsonld"
                elif fmt == "dot":
                    body = graph_format_dot(graph)
                    content_type = "text/vnd.graphviz; charset=utf-8"
                    extension = "dot"
                elif fmt == "csv":
                    body = graph_format_csv(graph)
                    content_type = "text/csv; charset=utf-8"
                    extension = "csv"
                else:
                    self.send_json({"error": "Unsupported graph export format."}, 400, headers)
                    return
                self.send_download(
                    body,
                    content_type,
                    f"osintpro-graph-{workspace_id}-{dt.datetime.now(dt.UTC).strftime('%Y%m%d_%H%M%S')}.{extension}",
                    headers,
                )
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return
        if parsed.path == "/api/network/local":
            user, headers = self.get_or_create_user()
            host = self.headers.get("Host", "")
            if not host.startswith(("127.0.0.1", "localhost")):
                self.send_json({
                    "available": False,
                    "mode": "cloud",
                    "message": "Own-network inspection is available when OSINTPRO runs locally on the device or lab machine. The hosted app will not expose Render server network details.",
                    "safe_next_steps": [
                        "Run OSINTPRO locally on your own computer.",
                        "Open the Network Lab and choose Own Network.",
                        "Capture only traffic from devices and networks you own or are authorized to inspect.",
                    ],
                }, headers=headers)
                return
            self.send_json({"available": True, "mode": "local", "network": local_network_snapshot()}, headers=headers)
            return
        if parsed.path == "/api/admin/status":
            user, headers = self.get_or_create_user()
            if not is_admin_user(user):
                self.send_json({"error": "Admin required."}, 403, headers)
                return
            self.send_json(self.admin_overview(), headers=headers)
            return
        if parsed.path == "/admin/metrics":
            user, headers = self.get_or_create_user()
            header_code = self.headers.get("X-Admin-Code", "")
            if not is_admin_user(user) and not (
                admin_code() and hmac.compare_digest(header_code, admin_code())
            ):
                self.send_json({"error": "Unauthorized"}, 401, headers)
                return
            self.send_json(admin_growth_metrics(), headers=headers)
            return
        if parsed.path == "/api/cron/backup/download":
            if not cron_secret():
                self.send_json({"error": "Cron is not configured."}, 503)
                return
            if not cron_authorized(self.headers):
                self.send_json({"error": "Cron request is not authorized."}, 403)
                return
            try:
                backup = create_sqlite_backup("artifact")
                path = backup_path(str(backup["name"]))
                body = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f"attachment; filename={path.name}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                self.send_json({"error": "Backup download failed. No internal details exposed."}, 500)
            return
        if parsed.path == "/api/admin/export":
            user, headers = self.get_or_create_user()
            if not is_admin_user(user):
                self.send_json({"error": "Admin required."}, 403, headers)
                return
            body = json.dumps(self.admin_export(), indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=osintpro-admin-export.json")
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path.startswith("/api/admin/backups/"):
            user, headers = self.get_or_create_user()
            if not is_admin_user(user):
                self.send_json({"error": "Admin required."}, 403, headers)
                return
            try:
                name = parsed.path.split("/")[-1]
                path = backup_path(name)
                if not path.exists():
                    self.send_json({"error": "Backup not found."}, 404, headers)
                    return
                body = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f"attachment; filename={path.name}")
                self.send_header("Content-Length", str(len(body)))
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/html"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report not found"}, 404, headers)
                return
            self.send_html(report_document(report), headers=headers)
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/repository.json"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            audit = self.fetch_repository_audit(str(user["_id"]), report_id)
            if not audit:
                self.send_json({"error": "Repository audit not found."}, 404, headers)
                return
            self.send_download(
                json.dumps(audit, indent=2).encode("utf-8"),
                "application/json; charset=utf-8",
                f"osintpro-repository-audit-{audit.get('repository') or report_id}.json",
                headers,
            )
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/dependencies"):
            user, headers = self.get_or_create_user()
            if not feature_allowed(user.get("plan", "Free"), "dependency_advisory"):
                self.send_json({"error": "Dependency advisory requires Pro or Agency."}, 402, headers)
                return
            report_id = parsed.path.split("/")[3]
            audit = self.fetch_repository_audit(str(user["_id"]), report_id)
            if not audit:
                self.send_json({"error": "Repository audit not found."}, 404, headers)
                return
            self.send_json({
                "report_id": report_id,
                "repository": audit.get("repository"),
                "dependency_advisories": audit.get("dependency_advisories", []),
            }, headers=headers)
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/sarif"):
            user, headers = self.get_or_create_user()
            if not feature_allowed(user.get("plan", "Free"), "repo_audit_sarif"):
                self.send_json({"error": "SARIF export requires Pro or Agency."}, 402, headers)
                return
            report_id = parsed.path.split("/")[3]
            audit = self.fetch_repository_audit(str(user["_id"]), report_id)
            if not audit:
                self.send_json({"error": "Repository audit not found."}, 404, headers)
                return
            self.send_download(
                format_sarif(audit),
                "application/sarif+json; charset=utf-8",
                f"osintpro-repository-audit-{audit.get('repository') or report_id}.sarif",
                headers,
            )
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/pdf"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report not found"}, 404, headers)
                return
            body = report_pdf(report)
            self.send_download(
                body,
                "application/pdf",
                f"osintpro-{report.get('domain') or report_id}.pdf",
                headers,
            )
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/findings.csv"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report not found"}, 404, headers)
                return
            body = report_findings_csv(report)
            self.send_download(
                body,
                "text/csv; charset=utf-8",
                f"osintpro-findings-{report.get('domain') or report_id}.csv",
                headers,
            )
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/web-audit.csv"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report not found"}, 404, headers)
                return
            payload = web_audit_playbook_payload(report)
            lines = ["item,status,evidence"]
            for item in payload["checklist"]:
                lines.append(",".join(csv_cell(item.get(key, "")) for key in ("item", "status", "evidence")))
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self.send_download(
                body,
                "text/csv; charset=utf-8",
                f"osintpro-web-audit-{report.get('domain') or report_id}.csv",
                headers,
            )
            return
        if parsed.path == "/api/reports.csv":
            user, headers = self.get_or_create_user()
            reports = self.reports_for_user(str(user["_id"]))
            lines = ["domain,score,generated_at,summary"]
            for item in reports:
                values = [item["domain"], item["score"], item["generated_at"], item["summary"]]
                lines.append(",".join(csv_cell(value) for value in values))
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self.send_download(body, "text/csv; charset=utf-8", "osintpro-reports.csv", headers)
            return
        if parsed.path == "/api/wallet/reports.csv":
            user, headers = self.get_or_create_user()
            reports = self.wallet_reports_for_user(str(user["_id"]))
            lines = ["chain,address,risk_score,generated_at,summary"]
            for item in reports:
                values = [item["chain"], item["address"], item["risk_score"], item["generated_at"], item["summary"]]
                lines.append(",".join(csv_cell(value) for value in values))
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self.send_download(
                body,
                "text/csv; charset=utf-8",
                "osintpro-wallet-reports.csv",
                headers,
            )
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/stripe/webhook":
            try:
                payload = self.read_raw_body(MAX_WEBHOOK_BYTES)
                if not verify_stripe_signature(payload, self.headers.get("Stripe-Signature", "")):
                    self.send_json({"error": "Invalid Stripe signature."}, 400)
                    return
                event = json.loads(payload.decode("utf-8"))
                if not isinstance(event, dict):
                    raise ValueError("Invalid Stripe event.")
                self.send_json(apply_stripe_event(event))
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid Stripe event."}, 400)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            return

        if self.rate_limited(parsed.path):
            self.send_json({"error": "Too many requests. Try again shortly."}, 429)
            return
        if parsed.path == "/api/auth/register":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                nickname = normalize_nickname(str(body.get("nickname", "")))
                hashed = password_hash(str(body.get("password", "")))
                now = utc_now()
                with db() as connection:
                    existing = connection.execute("SELECT id FROM users WHERE nickname = ?", (nickname,)).fetchone()
                    if existing:
                        self.send_json({"error": "Nickname already registered. Sign in instead."}, 409, headers)
                        return
                    if not is_admin_user(user) and self.registration_limited(connection, str(user["_id"])):
                        self.send_json(
                            {"error": "Free account limit reached for this connection. Sign in or upgrade to Pro."},
                            429,
                            headers,
                        )
                        return
                    connection.execute(
                        """
                        UPDATE users
                        SET nickname = ?, password_hash = ?, signup_fingerprint = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (nickname, hashed, stable_fingerprint(self.client_ip()), now, user["_id"]),
                    )
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"user": row_to_user(row)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/auth/login":
            try:
                body = self.read_json()
                nickname = normalize_nickname(str(body.get("nickname", "")))
                password = str(body.get("password", ""))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE nickname = ?", (nickname,)).fetchone()
                if not row or not verify_password(password, row["password_hash"]):
                    self.send_json({"error": "Invalid credentials."}, 403)
                    return
                self.send_json({"user": row_to_user(row)}, headers={
                    "Set-Cookie": self.make_session_cookie(str(row["id"]))
                })
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            return

        if parsed.path == "/api/auth/forgot-password":
            generic = {"message": "If that account can receive reset email, a reset link has been sent."}
            try:
                body = self.read_json()
                identifier = str(body.get("email") or body.get("identifier") or body.get("nickname") or "").strip()
                if not identifier:
                    self.send_json({"error": "Account identifier required."}, 400)
                    return
                lookup_email = identifier.lower()
                try:
                    lookup_nickname = normalize_nickname(identifier)
                except ValueError:
                    lookup_nickname = ""
                with db() as connection:
                    row = connection.execute(
                        """
                        SELECT id, email
                        FROM users
                        WHERE lower(coalesce(email, '')) = ? OR nickname = ?
                        """,
                        (lookup_email, lookup_nickname),
                    ).fetchone()
                    if row and row["email"]:
                        token = secrets.token_urlsafe(32)
                        now = utc_now()
                        expires_at = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)).replace(microsecond=0).isoformat()
                        connection.execute(
                            """
                            INSERT INTO password_resets
                                (id, user_id, token_hash, expires_at, created_at)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (str(uuid.uuid4()), row["id"], hash_reset_token(token), expires_at, now),
                        )
                        ok, message = send_password_reset_email(str(row["email"]), token)
                        notification_log(
                            connection,
                            str(row["id"]),
                            "password.reset_requested",
                            "email",
                            "sent" if ok else "skipped",
                            str(row["email"]),
                            message,
                        )
                self.send_json(generic)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            return

        if parsed.path == "/api/auth/reset-password":
            try:
                body = self.read_json()
                token = str(body.get("token", "")).strip()
                new_password = str(body.get("password") or body.get("new_password") or "")
                if not token:
                    self.send_json({"error": "Reset token required."}, 400)
                    return
                new_hash = password_hash(new_password)
                now = utc_now()
                with db() as connection:
                    reset = reset_row_for_token(connection, token)
                    if not reset:
                        self.send_json({"error": "Reset link expired."}, 410)
                        return
                    connection.execute(
                        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                        (new_hash, now, reset["user_id"]),
                    )
                    connection.execute(
                        "UPDATE password_resets SET used_at = ? WHERE token_hash = ?",
                        (now, hash_reset_token(token)),
                    )
                self.send_json({"ok": True})
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            return

        if parsed.path == "/api/auth/logout":
            self.send_json({"ok": True}, headers={
                "Set-Cookie": self.make_session_cookie("", max_age=0)
            })
            return

        if parsed.path == "/api/events":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                with db() as connection:
                    record_conversion_event(
                        connection,
                        str(user["_id"]),
                        clean_event_name(body.get("event")),
                        clean_event_plan(body.get("plan")),
                        clean_event_source(body.get("source")),
                        clean_event_metadata(body.get("metadata", {})),
                    )
                self.send_json({"ok": True}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path in {"/api/auth/password", "/api/auth/change-password"}:
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to change your password."}, 401, headers)
                return
            try:
                body = self.read_json()
                current_password = str(body.get("current_password", ""))
                new_password = str(body.get("new_password", ""))
                new_hash = password_hash(new_password)
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not row or not verify_password(current_password, row["password_hash"]):
                        self.send_json({"error": "Current password is invalid."}, 403, headers)
                        return
                    connection.execute(
                        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                        (new_hash, utc_now(), user["_id"]),
                    )
                self.send_json({"ok": True}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/api-keys":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated") and not is_admin_user(user):
                self.send_json({"error": "Sign in to create API keys."}, 401, headers)
                return
            if not can_use_api(str(user.get("plan", "Free"))):
                self.send_json({"error": "API keys require Agency or Admin."}, 403, headers)
                return
            try:
                body = self.read_json()
                name = clean_api_key_name(body.get("name", "Agency API key"))
                token = generate_api_key()
                now = utc_now()
                with db() as connection:
                    active_count = connection.execute(
                        "SELECT COUNT(*) AS count FROM api_keys WHERE user_id = ? AND revoked_at IS NULL",
                        (user["_id"],),
                    ).fetchone()["count"]
                    if active_count >= 5 and not is_admin_user(user):
                        self.send_json({"error": "API key limit reached for this account."}, 402, headers)
                        return
                    connection.execute(
                        """
                        INSERT INTO api_keys (id, user_id, name, key_hash, prefix, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (str(uuid.uuid4()), user["_id"], name, hash_api_key(token), api_key_prefix(token), now),
                    )
                    rows = connection.execute(
                        """
                        SELECT id, name, prefix, created_at, last_used_at, revoked_at
                        FROM api_keys
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                        """,
                        (user["_id"],),
                    ).fetchall()
                    record_conversion_event(connection, str(user["_id"]), "api_key_created", user.get("plan"), "api_preview")
                self.send_json({
                    "credential": token,
                    "prefix": api_key_prefix(token),
                    "api_keys": [dict(public_api_key(row)) for row in rows],
                    "message": "Copy this API key now. It will not be shown again.",
                }, status=201, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/webhooks":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to create webhooks."}, 401, headers)
                return
            if not feature_allowed(user.get("plan", "Free"), "webhooks"):
                self.send_json({"error": "Webhooks require Pro or Agency."}, 402, headers)
                return
            try:
                body = self.read_json()
                event_type = clean_webhook_event(body.get("event_type"))
                url = clean_webhook_url(body.get("url"))
                now = utc_now()
                with db() as connection:
                    connection.execute(
                        """
                        INSERT INTO webhooks (id, user_id, event_type, url, active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, 1, ?, ?)
                        ON CONFLICT(user_id, event_type, url)
                        DO UPDATE SET active = 1, updated_at = excluded.updated_at
                        """,
                        (str(uuid.uuid4()), user["_id"], event_type, url, now, now),
                    )
                    rows = webhook_rows(connection, str(user["_id"]))
                    record_conversion_event(connection, str(user["_id"]), "webhook_created", user.get("plan"), "monitoring")
                self.send_json({"webhooks": [public_webhook(row) for row in rows]}, status=201, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/notifications/test":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to test notifications."}, 401, headers)
                return
            if not feature_allowed(user.get("plan", "Free"), "webhooks"):
                self.send_json({"error": "Notifications require Pro or Agency."}, 402, headers)
                return
            payload = {
                "domain": "test.example.com",
                "user_id": user["_id"],
                "previous_score": 70,
                "score": 82,
                "summary": "Test notification only. No monitor changed.",
            }
            with db() as connection:
                webhook_summary = deliver_user_webhooks(connection, str(user["_id"]), "monitor.changed", payload)
                email_ok, email_message = send_monitor_email("test.example.com", payload)
                notification_log(
                    connection,
                    str(user["_id"]),
                    "monitor.changed",
                    "email",
                    "sent" if email_ok else "skipped",
                    smtp_settings().get("recipient") or None,
                    email_message,
                )
                record_conversion_event(connection, str(user["_id"]), "notification_test", user.get("plan"), "monitoring")
            self.send_json({
                "ok": True,
                **webhook_summary,
                "email_status": "sent" if email_ok else "skipped",
                "email_message": email_message,
            }, headers=headers)
            return

        if parsed.path == "/api/v1/domain-reports":
            user, api_key, error = self.api_user_from_key()
            if error:
                self.send_json({"error": error}, 401)
                return
            if self.api_rate_limited(str(api_key["id"]), parsed.path):
                self.send_json({"error": "API rate limit reached."}, 429)
                return
            try:
                body = self.read_json()
                report = analyze(str(body.get("target", "")))
                with db() as connection:
                    store_report(connection, str(user["_id"]), report, None)
                    record_conversion_event(connection, str(user["_id"]), "api_domain_report", user.get("plan"), "api_v1")
                self.send_json({"report": report, "credential_info": {"prefix": api_key["prefix"]}}, status=201)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            except Exception:
                self.send_json({"error": "API domain report failed. No internal details exposed."}, 500)
            return

        if parsed.path == "/api/v1/social-reports":
            user, api_key, error = self.api_user_from_key()
            if error:
                self.send_json({"error": error}, 401)
                return
            if self.api_rate_limited(str(api_key["id"]), parsed.path):
                self.send_json({"error": "API rate limit reached."}, 429)
                return
            try:
                body = self.read_json()
                report = analyze_username(str(body.get("username", "")))
                with db() as connection:
                    store_social_report(connection, str(user["_id"]), report, None)
                    record_conversion_event(connection, str(user["_id"]), "api_social_report", user.get("plan"), "api_v1")
                self.send_json({"report": report, "credential_info": {"prefix": api_key["prefix"]}}, status=201)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            except Exception:
                self.send_json({"error": "API social report failed. No internal details exposed."}, 500)
            return

        if parsed.path == "/api/v1/wallet-reports":
            user, api_key, error = self.api_user_from_key()
            if error:
                self.send_json({"error": error}, 401)
                return
            if self.api_rate_limited(str(api_key["id"]), parsed.path):
                self.send_json({"error": "API rate limit reached."}, 429)
                return
            try:
                body = self.read_json()
                report = analyze_wallet(str(body.get("address", "")))
                with db() as connection:
                    store_wallet_report(connection, str(user["_id"]), report, None)
                    record_conversion_event(connection, str(user["_id"]), "api_wallet_report", user.get("plan"), "api_v1")
                self.send_json({"report": report, "credential_info": {"prefix": api_key["prefix"]}}, status=201)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
            except Exception:
                self.send_json({"error": "API wallet report failed. No internal details exposed."}, 500)
            return

        if parsed.path == "/api/client-folders":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to create client folders."}, 401, headers)
                return
            try:
                body = self.read_json()
                name = clean_folder_name(str(body.get("name", "")))
                now = utc_now()
                with db() as connection:
                    connection.execute(
                        """
                        INSERT INTO client_folders (id, user_id, name, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (str(uuid.uuid4()), user["_id"], name, now, now),
                    )
                self.send_json({"folders": self.folders_for_user(str(user["_id"]))}, status=201, headers=headers)
            except sqlite3.IntegrityError:
                self.send_json({"error": "Client folder already exists."}, 409, headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/wallet/annotations":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to save wallet notes."}, 401, headers)
                return
            try:
                body = self.read_json()
                chain, address = clean_wallet_address(str(body.get("address", "")))
                tags = clean_tags(body.get("tags", []))
                notes = clean_case_note(body.get("notes", ""))
                now = utc_now()
                with db() as connection:
                    connection.execute(
                        """
                        INSERT INTO wallet_annotations (id, user_id, chain, address, tags_json, notes, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(user_id, chain, address)
                        DO UPDATE SET tags_json = excluded.tags_json, notes = excluded.notes, updated_at = excluded.updated_at
                        """,
                        (str(uuid.uuid4()), user["_id"], chain, address, json.dumps(tags), notes, now, now),
                    )
                self.send_json({
                    "ok": True,
                    "annotation": {"chain": chain, "address": address, "tags": tags, "notes": notes, "updated_at": now},
                    "workspace": self.intelligence_workspace(user),
                }, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/web-audit/playbooks":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to save Web Audit playbooks."}, 401, headers)
                return
            try:
                body = self.read_json()
                report_id = str(body.get("report_id", ""))
                if not UUID_RE.match(report_id):
                    raise ValueError("Invalid report.")
                report = self.fetch_report(str(user["_id"]), report_id)
                if not report:
                    self.send_json({"error": "Report not found."}, 404, headers)
                    return
                payload = web_audit_playbook_payload(report)
                now = utc_now()
                with db() as connection:
                    connection.execute(
                        """
                        INSERT INTO web_audit_playbooks (id, user_id, report_id, domain, title, payload_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(uuid.uuid4()),
                            user["_id"],
                            report_id,
                            report.get("domain", ""),
                            f"Web Audit Lab - {report.get('domain', '')}",
                            json.dumps(payload),
                            now,
                            now,
                        ),
                    )
                self.send_json({"playbooks": self.playbooks_for_user(str(user["_id"]))}, status=201, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return
        if parsed.path == "/api/repository/audit":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json(MAX_REPO_AUDIT_BYTES + 262144)
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not has_report_access(row):
                        record_conversion_event(
                            connection,
                            str(user["_id"]),
                            "free_credits_exhausted",
                            "Pro",
                            "repository_audit",
                            {"current_plan": row["plan"]},
                        )
                        self.send_json({"error": "Free credits exhausted. Upgrade to Pro to continue."}, 402, headers)
                        return
                    audit = analyze_repository(body.get("files"), body.get("repository"))
                    if should_decrement_report_credit(row):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    prepare_session_report_storage(connection, user, "repository_reports")
                    store_repository_report(connection, str(user["_id"]), audit)
                    record_conversion_event(
                        connection,
                        str(user["_id"]),
                        "repository_audit_run",
                        row["plan"],
                        "repository_audit",
                        {
                            "files_scanned": audit["files_scanned"],
                            "findings": len(audit["findings"]),
                            "score": audit["score"],
                        },
                    )
                    updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"audit": audit, "user": row_to_user(updated)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Repository audit failed. No uploaded source or internal details were logged."}, 500, headers)
            return

        if parsed.path == "/api/analyze":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                target = str(body.get("target", ""))
                folder_id = clean_folder_id(body.get("folder_id"))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not folder_exists(connection, str(user["_id"]), folder_id):
                        self.send_json({"error": "Client folder not found."}, 404, headers)
                        return
                    if not has_report_access(row):
                        record_conversion_event(
                            connection,
                            str(user["_id"]),
                            "free_credits_exhausted",
                            "Pro",
                            "domain_intel",
                            {"current_plan": row["plan"]},
                        )
                        self.send_json({"error": "Free credits exhausted. Upgrade to Pro to continue."}, 402, headers)
                        return

                    report = analyze(target)
                    if should_decrement_report_credit(row):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    prepare_session_report_storage(connection, user, "reports")
                    store_report(connection, str(user["_id"]), report, folder_id)
                    updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"report": report, "user": row_to_user(updated)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Analysis failed. No internal details exposed."}, 500, headers)
            return

        if parsed.path == "/api/social/analyze":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                target = str(body.get("username", ""))
                folder_id = clean_folder_id(body.get("folder_id"))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not folder_exists(connection, str(user["_id"]), folder_id):
                        self.send_json({"error": "Client folder not found."}, 404, headers)
                        return
                    if not has_report_access(row):
                        record_conversion_event(
                            connection,
                            str(user["_id"]),
                            "free_credits_exhausted",
                            "Pro",
                            "social_intel",
                            {"current_plan": row["plan"]},
                        )
                        self.send_json({"error": "Free credits exhausted. Upgrade to Pro to continue."}, 402, headers)
                        return

                    report = analyze_username(target)
                    if should_decrement_report_credit(row):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    prepare_session_report_storage(connection, user, "social_reports")
                    store_social_report(connection, str(user["_id"]), report, folder_id)
                    updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"report": report, "user": row_to_user(updated)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Social OSINT failed. No internal details exposed."}, 500, headers)
            return

        if parsed.path == "/api/wallet/analyze":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                address = str(body.get("address", ""))
                folder_id = clean_folder_id(body.get("folder_id"))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not folder_exists(connection, str(user["_id"]), folder_id):
                        self.send_json({"error": "Client folder not found."}, 404, headers)
                        return
                    if not has_report_access(row):
                        record_conversion_event(
                            connection,
                            str(user["_id"]),
                            "free_credits_exhausted",
                            "Pro",
                            "wallet_trace",
                            {"current_plan": row["plan"]},
                        )
                        self.send_json({"error": "Free credits exhausted. Upgrade to Pro to continue."}, 402, headers)
                        return

                    report = analyze_wallet(address)
                    if should_decrement_report_credit(row):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    prepare_session_report_storage(connection, user, "wallet_reports")
                    store_wallet_report(connection, str(user["_id"]), report, folder_id)
                    updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"report": report, "user": row_to_user(updated)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Wallet OSINT failed. No internal details exposed."}, 500, headers)
            return

        if parsed.path == "/api/monitors":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in or create an account to save monitored domains."}, 401, headers)
                return
            try:
                body = self.read_json()
                domain = clean_domain(str(body.get("domain", "")))
                folder_id = clean_folder_id(body.get("folder_id"))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not folder_exists(connection, str(user["_id"]), folder_id):
                        self.send_json({"error": "Client folder not found."}, 404, headers)
                        return
                    current_count = connection.execute(
                        "SELECT COUNT(*) AS count FROM monitors WHERE user_id = ?",
                        (user["_id"],),
                    ).fetchone()["count"]
                    limit = PLAN_LIMITS.get(row["plan"], PLAN_LIMITS["Free"])["monitors"]
                    if current_count >= limit:
                        record_conversion_event(
                            connection,
                            str(user["_id"]),
                            "monitor_limit_hit",
                            "Pro",
                            "monitoring",
                            {"current_plan": row["plan"], "monitor_count": current_count, "monitor_limit": limit},
                        )
                        self.send_json({"error": f"Monitor limit reached for plan {row['plan']}."}, 402, headers)
                        return
                    now = utc_now()
                    connection.execute(
                        """
                        INSERT INTO monitors (id, user_id, domain, status, created_at, updated_at, folder_id)
                        VALUES (?, ?, ?, 'pending', ?, ?, ?)
                        """,
                        (str(uuid.uuid4()), user["_id"], domain, now, now, folder_id),
                    )
                self.send_json({"monitors": self.monitors_for_user(str(user["_id"]))}, status=201, headers=headers)
            except sqlite3.IntegrityError:
                self.send_json({"error": "Domain already monitored."}, 409, headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/monitors/run":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to run saved monitors."}, 401, headers)
                return
            try:
                with db() as connection:
                    rows = connection.execute(
                        "SELECT * FROM monitors WHERE user_id = ? ORDER BY created_at DESC",
                        (user["_id"],),
                    ).fetchall()
                    summary = run_monitor_rows(connection, rows)
                self.send_json({
                    "monitors": self.monitors_for_user(str(user["_id"])),
                    "reports": self.reports_for_user(str(user["_id"])),
                    "summary": summary,
                }, headers=headers)
            except Exception:
                self.send_json({"error": "Monitor run failed. No internal details exposed."}, 500, headers)
            return

        if parsed.path == "/api/cron/monitors":
            if not cron_secret():
                self.send_json({"error": "Cron is not configured."}, 503)
                return
            if not cron_authorized(self.headers):
                self.send_json({"error": "Cron request is not authorized."}, 403)
                return
            try:
                with db() as connection:
                    rows = connection.execute(
                        """
                        SELECT monitors.*
                        FROM monitors
                        JOIN users ON users.id = monitors.user_id
                        WHERE users.nickname IS NOT NULL
                        ORDER BY
                            CASE WHEN monitors.last_checked_at IS NULL THEN 0 ELSE 1 END,
                            monitors.last_checked_at ASC,
                            monitors.created_at ASC
                        LIMIT ?
                        """,
                        (monitor_batch_limit(),),
                    ).fetchall()
                    summary = run_monitor_rows(connection, rows)
                    remaining = connection.execute(
                        """
                        SELECT COUNT(*) AS count
                        FROM monitors
                        JOIN users ON users.id = monitors.user_id
                        WHERE users.nickname IS NOT NULL
                        """,
                    ).fetchone()["count"]
                self.send_json({
                    "ok": True,
                    "batch_limit": monitor_batch_limit(),
                    "eligible_monitors": remaining,
                    **summary,
                })
            except Exception:
                self.send_json({"error": "Monitor cron failed. No internal details exposed."}, 500)
            return

        if parsed.path == "/api/cron/backup":
            if not cron_secret():
                self.send_json({"error": "Cron is not configured."}, 503)
                return
            if not cron_authorized(self.headers):
                self.send_json({"error": "Cron request is not authorized."}, 403)
                return
            try:
                backup = create_sqlite_backup("cron")
                self.send_json({"ok": True, "backup": backup})
            except Exception:
                self.send_json({"error": "Backup failed. No internal details exposed."}, 500)
            return

        if parsed.path == "/api/admin/login":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
                return
            code = str(body.get("code", ""))
            configured_admin_code = admin_code()
            if not configured_admin_code or not hmac.compare_digest(code, configured_admin_code):
                self.send_json({"error": "Invalid admin code."}, 403, headers)
                return
            with db() as connection:
                connection.execute(
                    "UPDATE users SET plan = 'Admin', updated_at = ? WHERE id = ?",
                    (utc_now(), user["_id"]),
                )
                row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
            self.send_json({
                "user": row_to_user(row),
                "reports": self.reports_for_user(str(user["_id"])),
                "monitors": self.monitors_for_user(str(user["_id"])),
                "admin": self.admin_overview(),
            }, headers=headers)
            return

        if parsed.path == "/api/admin/users/plan":
            user, headers = self.get_or_create_user()
            if not is_admin_user(user):
                self.send_json({"error": "Admin required."}, 403, headers)
                return
            try:
                body = self.read_json()
                nickname = normalize_nickname(str(body.get("nickname", "")))
                plan = str(body.get("plan", "")).capitalize()
                if plan not in PLAN_LIMITS:
                    self.send_json({"error": "Invalid plan."}, 400, headers)
                    return
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE nickname = ?", (nickname,)).fetchone()
                    if not row:
                        self.send_json({"error": "User not found."}, 404, headers)
                        return
                    if row["id"] == user["_id"] and plan != "Admin":
                        self.send_json({"error": "You cannot remove Admin from the current admin account."}, 400, headers)
                        return
                    connection.execute(
                        "UPDATE users SET plan = ?, updated_at = ? WHERE id = ?",
                        (plan, utc_now(), row["id"]),
                    )
                self.send_json({"ok": True, "admin": self.admin_overview()}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/admin/backups":
            user, headers = self.get_or_create_user()
            if not is_admin_user(user):
                self.send_json({"error": "Admin required."}, 403, headers)
                return
            try:
                backup = create_sqlite_backup("manual")
                self.send_json({"ok": True, "backup": backup, "admin": self.admin_overview()}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Backup failed. No internal details exposed."}, 500, headers)
            return

        if parsed.path == "/api/admin/restore":
            user, headers = self.get_or_create_user()
            if not is_admin_user(user):
                self.send_json({"error": "Admin required."}, 403, headers)
                return
            if self.headers.get("X-OSINTPRO-RESTORE") != "RESTORE":
                self.send_json({"error": "Missing restore confirmation."}, 400, headers)
                return
            try:
                payload = self.read_raw_body(MAX_RESTORE_BYTES)
                result = restore_sqlite_backup(payload)
                result["admin"] = self.admin_overview()
                self.send_json(result, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Restore failed. No internal details exposed."}, 500, headers)
            return

        if parsed.path == "/api/billing/checkout":
            user, headers = self.get_or_create_user()
            body = self.read_json()
            plan = str(body.get("plan", "Pro")).capitalize()
            if plan not in {"Pro", "Agency"}:
                self.send_json({"error": "Invalid plan."}, 400, headers)
                return
            if not user.get("authenticated"):
                with db() as connection:
                    record_conversion_event(connection, str(user["_id"]), "checkout_auth_required", plan, "billing")
                self.send_json({"error": "Create an account or sign in before buying a plan."}, 401, headers)
                return
            env_name = "OSINTPRO_STRIPE_AGENCY_URL" if plan == "Agency" else "OSINTPRO_STRIPE_PRO_URL"
            checkout_url = os.getenv(env_name)
            with db() as connection:
                record_conversion_event(connection, str(user["_id"]), "checkout_requested", plan, "billing")
            if checkout_url:
                with db() as connection:
                    record_conversion_event(connection, str(user["_id"]), "checkout_redirect", plan, "stripe")
                self.send_json({"url": add_checkout_reference(checkout_url, str(user["_id"]), plan), "mode": "stripe"}, headers=headers)
                return
            with db() as connection:
                record_conversion_event(connection, str(user["_id"]), "checkout_setup_missing", plan, "billing")
            self.send_json({
                "url": "",
                "mode": "setup",
                "message": f"Configure {env_name} with a Stripe Payment Link to sell the {plan} plan.",
            }, headers=headers)
            return

        self.send_json({"error": "Endpoint not found"}, 404)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/reports":
            user, headers = self.get_or_create_user()
            with db() as connection:
                connection.execute("DELETE FROM reports WHERE user_id = ?", (user["_id"],))
            self.send_json({"reports": []}, headers=headers)
            return
        if parsed.path == "/api/social/reports":
            user, headers = self.get_or_create_user()
            with db() as connection:
                connection.execute("DELETE FROM social_reports WHERE user_id = ?", (user["_id"],))
            self.send_json({"social_reports": []}, headers=headers)
            return
        if parsed.path == "/api/wallet/reports":
            user, headers = self.get_or_create_user()
            with db() as connection:
                connection.execute("DELETE FROM wallet_reports WHERE user_id = ?", (user["_id"],))
            self.send_json({"wallet_reports": []}, headers=headers)
            return
        if parsed.path == "/api/history":
            user, headers = self.get_or_create_user()
            with db() as connection:
                connection.execute("DELETE FROM reports WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM social_reports WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM wallet_reports WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM wallet_annotations WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM web_audit_playbooks WHERE user_id = ?", (user["_id"],))
            self.send_json({"reports": [], "social_reports": [], "wallet_reports": []}, headers=headers)
            return
        if parsed.path == "/api/account":
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to delete your account."}, 401, headers)
                return
            if is_admin_user(user):
                self.send_json({"error": "The current Admin account cannot be deleted here."}, 403, headers)
                return
            with db() as connection:
                connection.execute("DELETE FROM reports WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM social_reports WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM wallet_reports WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM wallet_annotations WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM web_audit_playbooks WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM client_folders WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM monitors WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM api_keys WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM webhooks WHERE user_id = ?", (user["_id"],))
                connection.execute("UPDATE notification_events SET user_id = NULL WHERE user_id = ?", (user["_id"],))
                connection.execute("UPDATE stripe_events SET user_id = NULL WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM users WHERE id = ?", (user["_id"],))
            self.send_json({"ok": True}, headers={
                **headers,
                "Set-Cookie": self.make_session_cookie("", max_age=0),
            })
            return
        if parsed.path.startswith("/api/api-keys/"):
            user, headers = self.get_or_create_user()
            if not user.get("authenticated") and not is_admin_user(user):
                self.send_json({"error": "Sign in to manage API keys."}, 401, headers)
                return
            key_id = parsed.path.split("/")[-1]
            if not UUID_RE.match(key_id):
                self.send_json({"error": "Invalid API key."}, 400, headers)
                return
            with db() as connection:
                connection.execute(
                    """
                    UPDATE api_keys
                    SET revoked_at = ?
                    WHERE id = ? AND user_id = ? AND revoked_at IS NULL
                    """,
                    (utc_now(), key_id, user["_id"]),
                )
                rows = connection.execute(
                    """
                    SELECT id, name, prefix, created_at, last_used_at, revoked_at
                    FROM api_keys
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    """,
                    (user["_id"],),
                ).fetchall()
            self.send_json({"api_keys": [dict(public_api_key(row)) for row in rows]}, headers=headers)
            return
        if parsed.path.startswith("/api/webhooks/"):
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to manage webhooks."}, 401, headers)
                return
            webhook_id = parsed.path.split("/")[-1]
            if not UUID_RE.match(webhook_id):
                self.send_json({"error": "Invalid webhook."}, 400, headers)
                return
            with db() as connection:
                connection.execute(
                    "UPDATE webhooks SET active = 0, updated_at = ? WHERE id = ? AND user_id = ?",
                    (utc_now(), webhook_id, user["_id"]),
                )
                rows = webhook_rows(connection, str(user["_id"]))
            self.send_json({"webhooks": [public_webhook(row) for row in rows]}, headers=headers)
            return
        if parsed.path.startswith("/api/monitors/"):
            user, headers = self.get_or_create_user()
            monitor_id = parsed.path.split("/")[-1]
            with db() as connection:
                connection.execute("DELETE FROM monitors WHERE user_id = ? AND id = ?", (user["_id"], monitor_id))
            self.send_json({"monitors": self.monitors_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path.startswith("/api/client-folders/"):
            user, headers = self.get_or_create_user()
            if not user.get("authenticated"):
                self.send_json({"error": "Sign in to manage client folders."}, 401, headers)
                return
            folder_id = parsed.path.split("/")[-1]
            if not UUID_RE.match(folder_id):
                self.send_json({"error": "Invalid client folder."}, 400, headers)
                return
            with db() as connection:
                connection.execute("UPDATE reports SET folder_id = NULL WHERE user_id = ? AND folder_id = ?", (user["_id"], folder_id))
                connection.execute("UPDATE social_reports SET folder_id = NULL WHERE user_id = ? AND folder_id = ?", (user["_id"], folder_id))
                connection.execute("UPDATE wallet_reports SET folder_id = NULL WHERE user_id = ? AND folder_id = ?", (user["_id"], folder_id))
                connection.execute("UPDATE monitors SET folder_id = NULL WHERE user_id = ? AND folder_id = ?", (user["_id"], folder_id))
                connection.execute("DELETE FROM client_folders WHERE user_id = ? AND id = ?", (user["_id"], folder_id))
            self.send_json({"folders": self.folders_for_user(str(user["_id"]))}, headers=headers)
            return
        self.send_json({"error": "Endpoint not found"}, 404)

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/login", "/register", "/forgot-password"}:
            self.send_head_only()
            return
        if parsed.path.startswith("/reset-password/"):
            token = parsed.path.rsplit("/", 1)[-1]
            with db() as connection:
                valid = reset_row_for_token(connection, token) is not None
            self.send_head_only(status=200 if valid else 410)
            return
        if parsed.path == "/settings/security":
            if not self.authenticated_user_row():
                self.send_redirect("/login")
                return
            self.send_head_only()
            return
        super().do_HEAD()


def server_config() -> tuple[str, int]:
    import argparse

    parser = argparse.ArgumentParser(description="Run OSINTPRO locally")
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8765")))
    args = parser.parse_args()
    return args.host, args.port


def main() -> None:
    init_db()
    host, port = server_config()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"OSINTPRO running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
