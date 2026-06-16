from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import http.client
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
FREE_CREDITS = 10
SESSION_COOKIE = "osintpro_session"
PLAN_LIMITS = {
    "Free": {"credits": 10, "monitors": 0},
    "Pro": {"credits": None, "monitors": 5},
    "Agency": {"credits": None, "monitors": 25},
    "Admin": {"credits": None, "monitors": 9999},
}
PAID_PLANS = {"Pro", "Agency", "Admin"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,32}$")
BTC_ADDRESS_RE = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,90}$", re.IGNORECASE)
EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
UUID_RE = re.compile(r"^[a-f0-9-]{36}$")
EVENT_NAME_RE = re.compile(r"^[a-z0-9_:-]{2,48}$")
EVENT_SOURCE_RE = re.compile(r"^[a-z0-9_:-]{0,48}$")
SECRET_KEY_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|authorization|bearer)\b"
)
SECRET_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*)[^\s,;\"'<>]+"),
    re.compile(r"(?i)(\bauthorization\s*[:=]\s*(?:bearer|basic)\s+)[a-z0-9._~+/=-]+"),
    re.compile(r"\b(?:sk|pk|rk|whsec|ghp|github_pat|xox[baprs])-[-A-Za-z0-9_]{12,}\b"),
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
    "/api/monitors/run": 12,
}
RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}
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
DEFAULT_MONITOR_BATCH_LIMIT = 20
DEFAULT_REGISTRATION_IP_LIMIT = 3
DEFAULT_BACKUP_RETENTION = 14
PUBLIC_STATIC_PATHS = {
    "/",
    "/index.html",
    "/app.js",
    "/styles.css",
    "/admin.html",
    "/admin.js",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
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


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


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


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def row_to_user(row: sqlite3.Row) -> dict[str, object]:
    limits = PLAN_LIMITS.get(row["plan"], PLAN_LIMITS["Free"])
    return {
        "nickname": row["nickname"],
        "authenticated": bool(row["nickname"]),
        "plan": row["plan"],
        "credits": row["credits"],
        "free_credits": FREE_CREDITS,
        "monitor_limit": limits["monitors"],
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


def registration_allowlist() -> list[str]:
    raw = os.getenv("OSINTPRO_REGISTRATION_IP_ALLOWLIST", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


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


def database_status() -> dict[str, object]:
    configured_path = bool(os.getenv("OSINTPRO_DB_PATH"))
    default_path = DATA_DIR / "osintpro.sqlite3"
    on_default_local_path = DB_PATH.resolve() == default_path.resolve()
    backup_count = len(list_backups())
    latest = latest_backup()
    return {
        "configured_path": configured_path,
        "persistent_hint": configured_path and not on_default_local_path,
        "location": "custom" if configured_path else "default",
        "backup_count": backup_count,
        "latest_backup": latest["created_at"] if latest else None,
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
    summary = f"Found {len(found)} likely profiles and {len(uncertain)} uncertain results for ."
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


def dig(domain: str, record_type: str) -> list[str]:
    try:
        result = subprocess.run(
            ["dig", "+short", domain, record_type],
            capture_output=True,
            check=False,
            text=True,
            timeout=4,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return sorted({line.strip().rstrip(".").strip() for line in result.stdout.splitlines() if line.strip()})


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
    try:
        connection = http.client.HTTPSConnection(domain, 443, timeout=HTTP_TIMEOUT)
        connection.request("GET", path, headers={"User-Agent": "OSINTPRO-passive-intel/1.0"})
        response = connection.getresponse()
        status = response.status
        headers = {key.lower(): value for key, value in response.getheaders()}
        body = response.read(HTTP_LIMIT).decode("utf-8", errors="replace")
        connection.close()
    except OSError:
        pass
    return {
        "path": path,
        "present": status is not None and 200 <= status < 400,
        "status": status,
        "content_type": headers.get("content-type"),
        "sample": redact_text(body[:700]),
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

    try:
        connection = http.client.HTTPSConnection(domain, 443, timeout=6)
        connection.request("HEAD", "/", headers={"User-Agent": "OSINTPRO-local-demo/1.0"})
        response = connection.getresponse()
        status = response.status
        headers = {key.lower(): value for key, value in response.getheaders()}
        server = headers.get("server")
        connection.close()
    except OSError:
        pass

    checks = []
    for name in SECURITY_HEADERS:
        value = headers.get(name)
        checks.append({
            "name": name,
            "present": bool(value),
            "value": redact_text(value) if value else value,
            "reason": "Header not found in the HTTPS response" if not value else "",
        })

    return {"status": status, "server": redact_text(server) if server else server, "security_headers": checks}


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
    score = sum([
        20 if flags["mx_present"] else 0,
        20 if flags["spf_present"] else 0,
        20 if flags["dmarc_present"] else 0,
        15 if flags["dmarc_reject"] or flags["dmarc_quarantine"] else 0,
        15 if flags["mta_sts_present"] else 0,
        10 if flags["tls_rpt_present"] else 0,
    ])
    return {
        "score": min(100, score),
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


def risk_findings(report: dict[str, object]) -> list[dict[str, str]]:
    dns = report.get("dns", {})
    https = report.get("https", {})
    email = report.get("email_security", {})
    web = report.get("web_presence", {})
    advanced = report.get("advanced_intel", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    days = cert.get("days_remaining")
    headers = https.get("security_headers", []) if isinstance(https, dict) else []
    findings: list[dict[str, str]] = []

    for item in headers:
        if not item.get("present"):
            findings.append({"level": "medium", "title": f"Missing header: {item['name']}", "detail": "Reduces the publicly observable browser-side security posture."})
    flags = email.get("flags", {})
    if not flags.get("spf_present"):
        findings.append({"level": "high", "title": "SPF missing", "detail": "The domain does not publish an SPF policy in the main TXT records."})
    if not flags.get("dmarc_present"):
        findings.append({"level": "high", "title": "DMARC missing", "detail": "No public anti-impersonation policy was found on _dmarc."})
    if isinstance(days, int) and days < 30:
        findings.append({"level": "high", "title": "TLS expiring soon", "detail": f"The certificate expires in {days} days."})
    if not web.get("security_txt", {}).get("present"):
        findings.append({"level": "low", "title": "security.txt missing", "detail": "No standard public security disclosure channel was found."})
    if not dns.get("caa"):
        findings.append({"level": "low", "title": "CAA missing", "detail": "The domain does not publicly restrict which CAs can issue certificates."})
    signals = advanced.get("signals", {}) if isinstance(advanced, dict) else {}
    if not signals.get("dnssec_enabled"):
        findings.append({"level": "low", "title": "DNSSEC not observed", "detail": "No public DS/DNSKEY records were found from the local resolver."})
    if advanced.get("takeover_hints"):
        findings.append({"level": "high", "title": "CNAME to managed providers", "detail": "Some subdomains point to SaaS/cloud platforms: verify ownership to prevent takeover."})
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
    vulns: list[dict[str, str]] = []

    if not headers.get("content-security-policy", {}).get("present"):
        vulns.append({
            "severity": "medium",
            "confidence": "high",
            "title": "Potentially broader XSS surface",
            "evidence": "Content-Security-Policy was not observed on the main HTTPS response.",
            "next_step": "Validate with authorized application testing and define a CSP for scripts, frames and connect-src.",
        })
    if not headers.get("strict-transport-security", {}).get("present"):
        vulns.append({
            "severity": "medium",
            "confidence": "high",
            "title": "Downgrade/SSL stripping not mitigated by HSTS",
            "evidence": "Strict-Transport-Security was not observed.",
            "next_step": "Enable HSTS with an appropriate max-age after full HTTPS validation.",
        })
    if not headers.get("x-frame-options", {}).get("present") and not headers.get("content-security-policy", {}).get("present"):
        vulns.append({
            "severity": "medium",
            "confidence": "medium",
            "title": "Clickjacking to verify",
            "evidence": "X-Frame-Options and CSP frame-ancestors are missing.",
            "next_step": "Test iframe embedding in an authorized environment and block untrusted frames.",
        })
    if not flags.get("dmarc_present"):
        vulns.append({
            "severity": "high",
            "confidence": "high",
            "title": "Email brand spoofing more likely",
            "evidence": "DMARC record not found on _dmarc.",
            "next_step": "Publish DMARC at least with p=none and reporting, then move toward quarantine/reject.",
        })
    if flags.get("dmarc_present") and not (flags.get("dmarc_reject") or flags.get("dmarc_quarantine")):
        vulns.append({
            "severity": "medium",
            "confidence": "high",
            "title": "DMARC present but not enforced",
            "evidence": "DMARC was found, but no observable quarantine/reject policy is active.",
            "next_step": "Analyze aggregate reports and plan gradual enforcement.",
        })
    if not dns.get("caa"):
        vulns.append({
            "severity": "low",
            "confidence": "high",
            "title": "Weak certificate governance",
            "evidence": "CAA record missing.",
            "next_step": "Restrict the CAs authorized to issue certificates for the domain.",
        })
    if web.get("robots_txt", {}).get("present") or web.get("sitemap_xml", {}).get("present"):
        vulns.append({
            "severity": "info",
            "confidence": "medium",
            "title": "Public map useful for reconnaissance",
            "evidence": "robots.txt or sitemap.xml are publicly available.",
            "next_step": "Verify they do not expose sensitive paths, staging environments or internal endpoints.",
        })
    if advanced.get("takeover_hints"):
        vulns.append({
            "severity": "high",
            "confidence": "medium",
            "title": "Potential subdomain takeover to verify",
            "evidence": "Public CNAMEs to managed providers were observed in Certificate Transparency subdomains.",
            "next_step": "Verify ownership of cloud/SaaS resources before any technical testing.",
        })
    signals = advanced.get("signals", {}) if isinstance(advanced, dict) else {}
    if not signals.get("dnssec_enabled"):
        vulns.append({
            "severity": "low",
            "confidence": "medium",
            "title": "DNS integrity not strengthened by DNSSEC",
            "evidence": "DS/DNSKEY records were not observed.",
            "next_step": "Evaluate DNSSEC with the registrar/DNS provider if compatible with operations.",
        })
    days = cert.get("days_remaining")
    if isinstance(days, int) and days < 45:
        vulns.append({
            "severity": "medium" if days >= 15 else "high",
            "confidence": "high",
            "title": "Operational risk on TLS certificate",
            "evidence": f"Certificate expires in {days} days.",
            "next_step": "Verify automatic renewal and alerting before the critical window.",
        })
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
    if not flags.get("dmarc_reject"):
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
    return [
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
            "control": "Email authentication guardrail",
            "why": "SPF/DMARC/MTA-STS reduce brand abuse and should be treated as detection controls.",
            "cadence": "weekly",
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
    score += sum(5 for item in headers if item["present"])
    score += min(15, int(email.get("score", 0)) // 8)
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

    if not dns.get("mx"):
        items.append("Configure or verify MX records if the domain sends or receives email.")
    txt_values = " ".join(dns.get("txt", [])) if isinstance(dns, dict) else ""
    if "v=spf1" not in txt_values.lower():
        items.append("Add an SPF record to reduce spoofing and email deliverability issues.")
    if not email.get("flags", {}).get("dmarc_present"):
        items.append("Evaluate a DMARC record to protect the brand from email impersonation.")
    if not cert.get("expires"):
        items.append("Verify the TLS certificate: OSINTPRO did not read a valid HTTPS expiry date.")
    missing = [item["name"] for item in headers if not item.get("present")]
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

    missing_headers = [item["name"] for item in https["security_headers"] if not item["present"]]
    if not addresses:
        summary = "The domain does not resolve IP addresses from the local backend."
    elif email["score"] < 45:
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
                send_alert("monitor.changed", {
                    "domain": monitor["domain"],
                    "user_id": monitor["user_id"],
                    "previous_score": monitor["last_score"],
                    "score": report["score"],
                    "summary": report["summary"],
                })
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

    def lines(values: list[str]) -> str:
        if not values:
            return "<span class='muted'>no data</span>"
        return "".join(f"<li>{html.escape(str(value))}</li>" for value in values)

    checks = "".join(
        f"<tr><td>{html.escape(item['name'])}</td><td>{'OK' if item.get('present') else 'Missing'}</td><td>{html.escape(str(item.get('value') or item.get('reason') or ''))}</td></tr>"
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
        f"<tr><td>{html.escape(name)}</td><td>{'OK' if value.get('present') else 'Missing'}</td><td>{html.escape(str(value.get('status') or 'n/a'))}</td></tr>"
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
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(brand)} report - {html.escape(str(report.get("domain", "")))}</title>
  <style>
    body {{ margin: 0; padding: 38px; color: #17201b; font-family: Inter, Arial, sans-serif; }}
    header {{ border-bottom: 2px solid #17201b; margin-bottom: 28px; padding-bottom: 18px; }}
    h1 {{ margin: 0 0 8px; font-size: 38px; }}
    h2 {{ margin-top: 28px; }}
    .meta, .muted {{ color: #667069; }}
    .score {{ float: right; border: 1px solid #d7ded8; border-radius: 8px; padding: 14px 18px; text-align: center; }}
    .score strong {{ display: block; font-size: 42px; color: #0f6b57; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
    section {{ break-inside: avoid; }}
    .box {{ border: 1px solid #d7ded8; border-radius: 8px; padding: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ border-bottom: 1px solid #e1e6e2; padding: 8px; text-align: left; vertical-align: top; }}
    code, li {{ overflow-wrap: anywhere; }}
    @media print {{ body {{ padding: 22px; }} .no-print {{ display: none; }} }}
  </style>
</head>
<body>
  <button class="no-print" onclick="window.print()">Save as PDF</button>
  <header>
    <div class="score"><span>Score</span><strong>{int(report.get("score", 0))}</strong></div>
    <p class="meta">{html.escape(brand)} passive domain intelligence</p>
    <h1>{html.escape(str(report.get("domain", "")))}</h1>
    <p>{html.escape(str(report.get("summary", "")))}</p>
    <p class="meta">Generated: {html.escape(str(report.get("generated_at", "")))}</p>
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
      <div class="box"><h2>Email security</h2><p>Score: {int(email.get("score", 0))}/100</p><ul>{lines(email.get("dmarc", []) + email.get("mta_sts", []) + email.get("tls_rpt", []))}</ul></div>
      <div class="box"><h2>RDAP</h2><p>Registrar: {html.escape(str(rdap.get("registrar") or "not available"))}</p><p class="meta">Created: {html.escape(str(rdap.get("created") or "n/a"))}<br>Expires: {html.escape(str(rdap.get("expires") or "n/a"))}</p></div>
      <div class="box"><h2>Well-known</h2><p>security.txt: {web.get("security_txt", {}).get("status") or "n/a"}<br>robots.txt: {web.get("robots_txt", {}).get("status") or "n/a"}<br>sitemap.xml: {web.get("sitemap_xml", {}).get("status") or "n/a"}</p></div>
      <div class="box"><h2>Certificate Transparency</h2><ul>{subdomain_rows or "<li>no names found</li>"}</ul></div>
    </section>
    <section>
      <h2>Advanced passive OSINT</h2>
      <div class="box">
        <p>DNSSEC: {'OK' if dnssec.get('enabled') else 'not observed'} | BIMI: {'OK' if bimi.get('present') else 'not observed'}</p>
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
      <table><thead><tr><th>Header</th><th>Status</th><th>Valore</th></tr></thead><tbody>{checks}</tbody></table>
    </section>
  </main>
</body>
</html>"""


def pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def report_pdf(report: dict[str, object]) -> bytes:
    title = f"{report_brand()} Report - {report.get('domain', 'target')}"
    text_lines = [
        title,
        f"Generated: {report.get('generated_at', '')}",
        f"Score: {report.get('score', 0)}/100",
        "",
        str(report.get("summary", "")),
        "",
        "Recommendations",
        *[f"- {item}" for item in recommendations(report)[:8]],
        "",
        "Findings",
        *[
            f"- {item.get('level', 'info')}: {item.get('title', '')} - {item.get('detail', '')}"
            for item in (report.get("findings") or [])[:10]
        ],
        "",
        "Passive boundary",
        "This report uses passive public signals only. It does not prove identity and does not include exploit payloads, brute force or invasive scanning.",
    ]
    y = 760
    stream_lines = ["BT", "/F1 11 Tf", "50 790 Td"]
    for raw_line in text_lines:
        line = re.sub(r"\s+", " ", redact_text(str(raw_line)))[:110]
        if y < 70:
            break
        stream_lines.append(f"({pdf_escape(line)}) Tj")
        stream_lines.append("0 -17 Td")
        y -= 17
    stream_lines.append("ET")
    stream = "\n".join(stream_lines).encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
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


def web_audit_playbook_payload(report: dict[str, object]) -> dict[str, object]:
    headers = report.get("https", {}).get("security_headers", []) if isinstance(report.get("https"), dict) else []
    web = report.get("web_presence", {}) if isinstance(report.get("web_presence"), dict) else {}
    checklist = [
        {"item": item.get("name", ""), "status": "ok" if item.get("present") else "missing", "evidence": item.get("value") or item.get("reason") or ""}
        for item in headers
    ]
    for label in ("security_txt", "robots_txt", "sitemap_xml", "mta_sts_policy"):
        value = web.get(label, {}) if isinstance(web.get(label), dict) else {}
        checklist.append({
            "item": label.replace("_", "."),
            "status": "ok" if value.get("present") else "missing",
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
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
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

    def read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("Request body is too large.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError as exc:
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
                    "monitor_limit": user.get("monitor_limit", 1),
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
                "monitor_limit": user.get("monitor_limit", 1),
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
                "monitors": connection.execute("SELECT COUNT(*) AS count FROM monitors").fetchone()["count"],
                "stripe_events": connection.execute("SELECT COUNT(*) AS count FROM stripe_events").fetchone()["count"],
                "conversion_events": connection.execute("SELECT COUNT(*) AS count FROM conversion_events").fetchone()["count"],
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

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/") and parsed.path not in PUBLIC_STATIC_PATHS:
            self.send_json({"error": "File not available"}, 404)
            return
        if parsed.path == "/api/health":
            self.send_json({"ok": True})
            return
        if parsed.path == "/api/meta":
            self.send_json({
                "product": "OSINTPRO",
                "positioning": "Client-ready passive investigation graph for domains, public identities and blockchain wallets.",
                "live_demo": "https://osintpro-48j4.onrender.com/",
                "safety_boundary": [
                    "passive public-source intelligence",
                    "no exploit execution",
                    "no brute force",
                    "no credential attacks",
                    "no unauthorized packet capture",
                    "no wallet movement or evasion guidance",
                ],
                "modules": [
                    "domain_intel",
                    "social_intel",
                    "wallet_osint",
                    "entity_graph",
                    "web_audit_lab",
                    "network_traffic_lab",
                    "monitoring",
                    "exports",
                ],
                "plans": PLAN_LIMITS,
                "public_docs": {
                    "data_sources": "/docs/DATA_SOURCES.md",
                    "distribution": "/docs/DISTRIBUTION.md",
                    "roadmap": "/ROADMAP.md",
                },
            })
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
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/pdf"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report not found"}, 404, headers)
                return
            body = report_pdf(report)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=osintpro-{report_id}.pdf")
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
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
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename=osintpro-web-audit-{report_id}.csv")
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/reports.csv":
            user, headers = self.get_or_create_user()
            reports = self.visible_reports_for_user(user)
            lines = ["domain,score,generated_at,summary"]
            for item in reports:
                values = [item["domain"], item["score"], item["generated_at"], item["summary"]]
                lines.append(",".join(csv_cell(value) for value in values))
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=osintpro-reports.csv")
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/wallet/reports.csv":
            user, headers = self.get_or_create_user()
            reports = self.visible_wallet_reports_for_user(user)
            lines = ["chain,address,risk_score,generated_at,summary"]
            for item in reports:
                values = [item["chain"], item["address"], item["risk_score"], item["generated_at"], item["summary"]]
                lines.append(",".join(csv_cell(value) for value in values))
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=osintpro-wallet-reports.csv")
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
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

        if parsed.path == "/api/auth/password":
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
                    if not is_paid_plan(row["plan"]) and row["credits"] <= 0:
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
                    if not is_paid_plan(row["plan"]):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    if user.get("authenticated"):
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
                    if not is_paid_plan(row["plan"]) and row["credits"] <= 0:
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
                    if not is_paid_plan(row["plan"]):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    if user.get("authenticated"):
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
                    if not is_paid_plan(row["plan"]) and row["credits"] <= 0:
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
                    if not is_paid_plan(row["plan"]):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    if user.get("authenticated"):
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
                connection.execute("UPDATE stripe_events SET user_id = NULL WHERE user_id = ?", (user["_id"],))
                connection.execute("DELETE FROM users WHERE id = ?", (user["_id"],))
            self.send_json({"ok": True}, headers={
                **headers,
                "Set-Cookie": self.make_session_cookie("", max_age=0),
            })
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
