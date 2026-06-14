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
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlparse


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "osintpro.sqlite3"
SECRET_PATH = DATA_DIR / ".osintpro_secret"
FREE_CREDITS = 5
SESSION_COOKIE = "osintpro_session"
PLAN_LIMITS = {
    "Free": {"credits": 5, "monitors": 1},
    "Pro": {"credits": None, "monitors": 5},
    "Agency": {"credits": None, "monitors": 25},
    "Admin": {"credits": None, "monitors": 9999},
}
PAID_PLANS = {"Pro", "Agency", "Admin"}
DEFAULT_ADMIN_CODE = "haizen-admin"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,32}$")
UUID_RE = re.compile(r"^[a-f0-9-]{36}$")
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
    "/api/auth/register": 10,
    "/api/analyze": 30,
    "/api/social/analyze": 30,
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
HTTP_LIMIT = 50000
MAX_BODY_BYTES = 16384
PUBLIC_STATIC_PATHS = {"/", "/index.html", "/app.js", "/styles.css", "/admin.html", "/admin.js", "/favicon.ico"}
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
    DATA_DIR.mkdir(exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                password_hash TEXT,
                plan TEXT NOT NULL DEFAULT 'Free',
                credits INTEGER NOT NULL DEFAULT 5,
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
            """
        )
        ensure_column(connection, "users", "email", "TEXT")
        ensure_column(connection, "users", "password_hash", "TEXT")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def row_to_user(row: sqlite3.Row) -> dict[str, object]:
    limits = PLAN_LIMITS.get(row["plan"], PLAN_LIMITS["Free"])
    return {
        "email": row["email"],
        "authenticated": bool(row["email"]),
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


def admin_code() -> str:
    return os.getenv("OSINTPRO_ADMIN_CODE", DEFAULT_ADMIN_CODE)


def is_paid_plan(plan: str) -> bool:
    return plan in PAID_PLANS


def normalize_email(raw: str) -> str:
    value = raw.strip().lower()
    if not EMAIL_RE.match(value):
        raise ValueError("Inserisci una email valida.")
    return value


def password_hash(password: str, salt: str | None = None) -> str:
    if len(password) < 8:
        raise ValueError("La password deve avere almeno 8 caratteri.")
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
        raise ValueError("Inserisci un dominio valido, per esempio openai.com")
    return value


def clean_username(raw: str) -> str:
    value = raw.strip().lstrip("@")
    if not USERNAME_RE.match(value):
        raise ValueError("Inserisci un nickname valido: 2-32 caratteri, lettere, numeri, punto, underscore o trattino.")
    return value


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
            "title": "Nickname riutilizzato su molte piattaforme",
            "detail": "Il riuso facilita correlazione identita, social graph mapping e brand impersonation checks.",
        })
    if len(found) == 0 and uncertain:
        findings.append({
            "level": "low",
            "title": "Risultati incerti",
            "detail": "Alcune piattaforme limitano le richieste pubbliche; serve verifica manuale.",
        })
    if any(item["platform"] in {"GitHub", "GitLab", "Keybase"} and item["present"] is True for item in profiles):
        findings.append({
            "level": "info",
            "title": "Developer footprint osservabile",
            "detail": "Profili tecnici pubblici possono aiutare attribution, supply-chain review e exposure review.",
        })
    if any(item["platform"] in {"Telegram", "X", "Instagram", "TikTok"} and item["present"] is True for item in profiles):
        findings.append({
            "level": "info",
            "title": "Social handle potenzialmente monetizzabile",
            "detail": "Utile per brand monitoring, creator due diligence o anti-impersonation package.",
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
    summary = f"Trovati {len(found)} profili probabili e {len(uncertain)} risultati incerti per @{username}."
    findings = social_findings(username, profiles)
    recommendations = [
        "Verifica manualmente i profili ad alta confidenza prima di contattare o attribuire.",
        "Monitora piattaforme dove il nickname e libero se il nome appartiene a un brand.",
        "Per creator/brand, blocca handle critici su piattaforme principali.",
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
                "objective": "Correlare presenze pubbliche per attribution autorizzata.",
                "signal": f"{len(found)} profili probabili.",
            },
            {
                "name": "Impersonation gap",
                "objective": "Identificare piattaforme dove un brand dovrebbe riservare il nickname.",
                "signal": f"{len([item for item in profiles if item['present'] is False])} handle non osservati.",
            },
        ],
        "purple_team_controls": [
            {
                "control": "Username watchlist",
                "why": "Nuovi profili con handle simile possono indicare impersonificazione.",
                "cadence": "weekly",
            },
            {
                "control": "Brand handle coverage",
                "why": "Riduce opportunita di account fake su piattaforme ad alta visibilita.",
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
            "reason": "Header non trovato nella risposta HTTPS" if not value else "",
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
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    days = cert.get("days_remaining")
    headers = https.get("security_headers", []) if isinstance(https, dict) else []
    findings: list[dict[str, str]] = []

    for item in headers:
        if not item.get("present"):
            findings.append({"level": "medium", "title": f"Header mancante: {item['name']}", "detail": "Riduce la postura browser-side osservabile pubblicamente."})
    flags = email.get("flags", {})
    if not flags.get("spf_present"):
        findings.append({"level": "high", "title": "SPF assente", "detail": "Il dominio non pubblica una policy SPF nel TXT principale."})
    if not flags.get("dmarc_present"):
        findings.append({"level": "high", "title": "DMARC assente", "detail": "Manca una policy pubblica anti-impersonificazione su _dmarc."})
    if isinstance(days, int) and days < 30:
        findings.append({"level": "high", "title": "TLS in scadenza", "detail": f"Il certificato scade tra {days} giorni."})
    if not web.get("security_txt", {}).get("present"):
        findings.append({"level": "low", "title": "security.txt assente", "detail": "Non e stato trovato un canale pubblico standard per disclosure di sicurezza."})
    if not dns.get("caa"):
        findings.append({"level": "low", "title": "CAA assente", "detail": "Il dominio non limita pubblicamente le CA autorizzate a emettere certificati."})
    return findings[:10]


def vulnerability_hypotheses(report: dict[str, object]) -> list[dict[str, str]]:
    https = report.get("https", {})
    email = report.get("email_security", {})
    web = report.get("web_presence", {})
    dns = report.get("dns", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    headers = {item.get("name"): item for item in https.get("security_headers", [])} if isinstance(https, dict) else {}
    flags = email.get("flags", {})
    vulns: list[dict[str, str]] = []

    if not headers.get("content-security-policy", {}).get("present"):
        vulns.append({
            "severity": "medium",
            "confidence": "high",
            "title": "Possibile superficie XSS piu ampia",
            "evidence": "Content-Security-Policy non osservata sulla risposta HTTPS principale.",
            "next_step": "Validare con test applicativi autorizzati e definire una CSP per script, frame e connect-src.",
        })
    if not headers.get("strict-transport-security", {}).get("present"):
        vulns.append({
            "severity": "medium",
            "confidence": "high",
            "title": "Downgrade/SSL stripping non mitigato da HSTS",
            "evidence": "Strict-Transport-Security non osservato.",
            "next_step": "Abilitare HSTS con max-age adeguato dopo verifica completa di HTTPS.",
        })
    if not headers.get("x-frame-options", {}).get("present") and not headers.get("content-security-policy", {}).get("present"):
        vulns.append({
            "severity": "medium",
            "confidence": "medium",
            "title": "Clickjacking da verificare",
            "evidence": "Mancano X-Frame-Options e CSP frame-ancestors.",
            "next_step": "Testare embedding in iframe in ambiente autorizzato e bloccare frame non fidati.",
        })
    if not flags.get("dmarc_present"):
        vulns.append({
            "severity": "high",
            "confidence": "high",
            "title": "Brand spoofing email piu probabile",
            "evidence": "Record DMARC non trovato su _dmarc.",
            "next_step": "Pubblicare DMARC almeno p=none con reporting, poi passare a quarantine/reject.",
        })
    if flags.get("dmarc_present") and not (flags.get("dmarc_reject") or flags.get("dmarc_quarantine")):
        vulns.append({
            "severity": "medium",
            "confidence": "high",
            "title": "DMARC presente ma non enforcement",
            "evidence": "DMARC trovato, ma senza policy quarantine/reject osservabile.",
            "next_step": "Analizzare report aggregate e pianificare enforcement graduale.",
        })
    if not dns.get("caa"):
        vulns.append({
            "severity": "low",
            "confidence": "high",
            "title": "Governance certificati debole",
            "evidence": "Record CAA assente.",
            "next_step": "Limitare le CA autorizzate a emettere certificati per il dominio.",
        })
    if web.get("robots_txt", {}).get("present") or web.get("sitemap_xml", {}).get("present"):
        vulns.append({
            "severity": "info",
            "confidence": "medium",
            "title": "Mappa pubblica utile alla ricognizione",
            "evidence": "robots.txt o sitemap.xml disponibili pubblicamente.",
            "next_step": "Verificare che non espongano percorsi sensibili, ambienti staging o endpoint interni.",
        })
    days = cert.get("days_remaining")
    if isinstance(days, int) and days < 45:
        vulns.append({
            "severity": "medium" if days >= 15 else "high",
            "confidence": "high",
            "title": "Rischio operativo su certificato TLS",
            "evidence": f"Certificato in scadenza tra {days} giorni.",
            "next_step": "Verificare rinnovo automatico e alerting prima della finestra critica.",
        })
    return vulns[:8]


def red_team_paths(report: dict[str, object]) -> list[dict[str, str]]:
    ct = report.get("certificate_transparency", {})
    email = report.get("email_security", {})
    web = report.get("web_presence", {})
    tech = report.get("technology", [])
    flags = email.get("flags", {})
    paths: list[dict[str, str]] = []

    if ct.get("subdomains"):
        paths.append({
            "name": "CT pivot",
            "objective": "Espandere asset inventory da nomi nei certificati pubblici.",
            "signal": f"{len(ct.get('subdomains', []))} nomi osservabili in Certificate Transparency.",
        })
    if not flags.get("dmarc_reject"):
        paths.append({
            "name": "Brand impersonation drill",
            "objective": "Misurare esposizione a spoofing e phishing simulato autorizzato.",
            "signal": "DMARC non in enforcement reject.",
        })
    if web.get("robots_txt", {}).get("present") or web.get("sitemap_xml", {}).get("present"):
        paths.append({
            "name": "Content discovery",
            "objective": "Revisionare percorsi pubblici indicizzati o dichiarati.",
            "signal": "robots.txt/sitemap.xml disponibili.",
        })
    if tech:
        paths.append({
            "name": "Stack fingerprint",
            "objective": "Correlare tecnologia osservata con hardening e patch policy.",
            "signal": ", ".join(tech[:4]),
        })
    if not paths:
        paths.append({
            "name": "Baseline validation",
            "objective": "Stabilire baseline e monitorare drift su DNS, TLS e header.",
            "signal": "Superficie pubblica limitata dalle fonti passive.",
        })
    return paths[:5]


def purple_team_controls(report: dict[str, object]) -> list[dict[str, str]]:
    return [
        {
            "control": "DNS drift detection",
            "why": "Nuovi MX, NS, CAA o TXT possono indicare cambi infrastrutturali o takeover operativi.",
            "cadence": "daily",
        },
        {
            "control": "Certificate Transparency watch",
            "why": "Nuovi certificati possono rivelare subdomini, shadow IT o emissioni inattese.",
            "cadence": "daily",
        },
        {
            "control": "Email authentication guardrail",
            "why": "SPF/DMARC/MTA-STS riducono abuso del brand e vanno trattati come controlli di detection.",
            "cadence": "weekly",
        },
        {
            "control": "Web header baseline",
            "why": "CSP, HSTS, frame e MIME headers spesso regrediscono durante deploy applicativi.",
            "cadence": "per release",
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
        items.append("Configura o verifica i record MX se il dominio invia o riceve email.")
    txt_values = " ".join(dns.get("txt", [])) if isinstance(dns, dict) else ""
    if "v=spf1" not in txt_values.lower():
        items.append("Aggiungi un record SPF per ridurre spoofing e problemi di deliverability email.")
    if not email.get("flags", {}).get("dmarc_present"):
        items.append("Valuta un record DMARC per proteggere il brand da impersonificazione email.")
    if not cert.get("expires"):
        items.append("Verifica il certificato TLS: OSINTPRO non ha letto una scadenza HTTPS valida.")
    missing = [item["name"] for item in headers if not item.get("present")]
    if missing:
        items.append(f"Aggiungi o rivedi security header mancanti: {', '.join(missing[:4])}.")
    if not items:
        items.append("Mantieni monitoraggio attivo: il profilo pubblico osservato e buono.")
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
    tech = technology_fingerprint(https, web)
    score = score_report(addresses, cert, https["security_headers"], email, web)

    missing_headers = [item["name"] for item in https["security_headers"] if not item["present"]]
    if not addresses:
        summary = "Il dominio non risolve indirizzi IP dal backend locale."
    elif email["score"] < 45:
        summary = "Dominio raggiungibile, ma la postura email pubblica richiede attenzione."
    elif missing_headers:
        summary = f"Dominio raggiungibile. Mancano {len(missing_headers)} security header osservabili."
    else:
        summary = "Dominio raggiungibile con header di sicurezza principali presenti."

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
        "technology": tech,
    }
    report = redact_data(report)
    report["findings"] = risk_findings(report)
    report["recommendations"] = recommendations(report)
    report["vulnerability_hypotheses"] = vulnerability_hypotheses(report)
    report["red_team_paths"] = red_team_paths(report)
    report["purple_team_controls"] = purple_team_controls(report)
    return report


def store_report(connection: sqlite3.Connection, user_id: str, report: dict[str, object]) -> None:
    report = redact_data(report)
    connection.execute(
        """
        INSERT INTO reports (id, user_id, domain, score, summary, generated_at, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        ),
    )


def store_social_report(connection: sqlite3.Connection, user_id: str, report: dict[str, object]) -> None:
    report = redact_data(report)
    connection.execute(
        """
        INSERT INTO social_reports (id, user_id, username, score, summary, generated_at, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        ),
    )


def report_document(report: dict[str, object]) -> str:
    dns = report.get("dns", {})
    https = report.get("https", {})
    cert = https.get("certificate", {}) if isinstance(https, dict) else {}
    headers = https.get("security_headers", []) if isinstance(https, dict) else []
    email = report.get("email_security", {})
    rdap = report.get("rdap", {})
    ct = report.get("certificate_transparency", {})
    web = report.get("web_presence", {})
    findings = report.get("findings", [])
    vulns = report.get("vulnerability_hypotheses", [])
    red_paths = report.get("red_team_paths", [])
    purple_controls = report.get("purple_team_controls", [])

    def lines(values: list[str]) -> str:
        if not values:
            return "<span class='muted'>nessun dato</span>"
        return "".join(f"<li>{html.escape(str(value))}</li>" for value in values)

    checks = "".join(
        f"<tr><td>{html.escape(item['name'])}</td><td>{'OK' if item.get('present') else 'Manca'}</td><td>{html.escape(str(item.get('value') or item.get('reason') or ''))}</td></tr>"
        for item in headers
    )
    recs = "".join(f"<li>{html.escape(item)}</li>" for item in recommendations(report))
    finding_rows = "".join(
        f"<tr><td>{html.escape(item.get('level', ''))}</td><td>{html.escape(item.get('title', ''))}</td><td>{html.escape(item.get('detail', ''))}</td></tr>"
        for item in findings
    )
    subdomain_rows = "".join(f"<li>{html.escape(item)}</li>" for item in ct.get("subdomains", [])[:25])
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
<html lang="it">
<head>
  <meta charset="utf-8">
  <title>OSINTPRO report - {html.escape(str(report.get("domain", "")))}</title>
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
  <button class="no-print" onclick="window.print()">Salva come PDF</button>
  <header>
    <div class="score"><span>Score</span><strong>{int(report.get("score", 0))}</strong></div>
    <p class="meta">OSINTPRO passive domain intelligence</p>
    <h1>{html.escape(str(report.get("domain", "")))}</h1>
    <p>{html.escape(str(report.get("summary", "")))}</p>
    <p class="meta">Generato: {html.escape(str(report.get("generated_at", "")))}</p>
  </header>
  <main>
    <section>
      <h2>Raccomandazioni</h2>
      <div class="box"><ol>{recs}</ol></div>
    </section>
    <section class="grid">
      <div class="box"><h2>IP</h2><ul>{lines(dns.get("addresses", []))}</ul></div>
      <div class="box"><h2>MX</h2><ul>{lines(dns.get("mx", []))}</ul></div>
      <div class="box"><h2>Nameserver</h2><ul>{lines(dns.get("ns", []))}</ul></div>
      <div class="box"><h2>Certificato TLS</h2><p>{html.escape(str(cert.get("subject") or "non disponibile"))}</p><p class="meta">Scadenza: {html.escape(str(cert.get("expires") or "non disponibile"))}</p></div>
    </section>
    <section class="grid">
      <div class="box"><h2>Email security</h2><p>Score: {int(email.get("score", 0))}/100</p><ul>{lines(email.get("dmarc", []) + email.get("mta_sts", []) + email.get("tls_rpt", []))}</ul></div>
      <div class="box"><h2>RDAP</h2><p>Registrar: {html.escape(str(rdap.get("registrar") or "non disponibile"))}</p><p class="meta">Creato: {html.escape(str(rdap.get("created") or "n/a"))}<br>Scade: {html.escape(str(rdap.get("expires") or "n/a"))}</p></div>
      <div class="box"><h2>Well-known</h2><p>security.txt: {web.get("security_txt", {}).get("status") or "n/a"}<br>robots.txt: {web.get("robots_txt", {}).get("status") or "n/a"}<br>sitemap.xml: {web.get("sitemap_xml", {}).get("status") or "n/a"}</p></div>
      <div class="box"><h2>Certificate Transparency</h2><ul>{subdomain_rows or "<li>nessun nome trovato</li>"}</ul></div>
    </section>
    <section>
      <h2>Findings</h2>
      <table><thead><tr><th>Livello</th><th>Finding</th><th>Dettaglio</th></tr></thead><tbody>{finding_rows or "<tr><td>ok</td><td>Nessun finding prioritario</td><td></td></tr>"}</tbody></table>
    </section>
    <section>
      <h2>Red/Purple Team</h2>
      <table><thead><tr><th>Severity</th><th>Ipotesi</th><th>Evidenza</th><th>Next step</th></tr></thead><tbody>{vuln_rows or "<tr><td>ok</td><td>Nessuna ipotesi prioritaria</td><td></td><td></td></tr>"}</tbody></table>
      <h2>Red team paths</h2>
      <table><thead><tr><th>Path</th><th>Obiettivo</th><th>Segnale</th></tr></thead><tbody>{red_rows}</tbody></table>
      <h2>Purple team controls</h2>
      <table><thead><tr><th>Controllo</th><th>Perche</th><th>Cadenza</th></tr></thead><tbody>{purple_rows}</tbody></table>
    </section>
    <section>
      <h2>Security header</h2>
      <table><thead><tr><th>Header</th><th>Stato</th><th>Valore</th></tr></thead><tbody>{checks}</tbody></table>
    </section>
  </main>
</body>
</html>"""


class Handler(SimpleHTTPRequestHandler):
    server_version = "OSINTPRO"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
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

    def rate_limited(self, path: str) -> bool:
        limit = RATE_LIMITS.get(path)
        if not limit:
            return False
        ip = self.client_address[0] if self.client_address else "unknown"
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
            raise ValueError("Richiesta troppo grande.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("JSON non valido.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Payload non valido.")
        return payload

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
            self.send_json({"error": "File non disponibile"}, 404)
            return
        if parsed.path == "/api/health":
            self.send_json({"ok": True})
            return
        if parsed.path == "/api/session":
            user, headers = self.get_or_create_user()
            self.send_json({
                "user": public_user(user),
                "reports": self.reports_for_user(str(user["_id"])),
                "social_reports": self.social_reports_for_user(str(user["_id"])),
                "monitors": self.monitors_for_user(str(user["_id"])),
                "pricing": {
                    "pro": {"price": "19", "monitors": 5},
                    "agency": {"price": "79", "monitors": 25},
                },
                "checkout_configured": bool(os.getenv("OSINTPRO_STRIPE_PRO_URL") or os.getenv("OSINTPRO_STRIPE_AGENCY_URL")),
            }, headers=headers)
            return
        if parsed.path == "/api/social/reports":
            user, headers = self.get_or_create_user()
            self.send_json({"social_reports": self.social_reports_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path == "/api/reports":
            user, headers = self.get_or_create_user()
            self.send_json({"reports": self.reports_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path == "/api/monitors":
            user, headers = self.get_or_create_user()
            self.send_json({"monitors": self.monitors_for_user(str(user["_id"]))}, headers=headers)
            return
        if parsed.path.startswith("/api/reports/") and parsed.path.endswith("/html"):
            user, headers = self.get_or_create_user()
            report_id = parsed.path.split("/")[3]
            report = self.fetch_report(str(user["_id"]), report_id)
            if not report:
                self.send_json({"error": "Report non trovato"}, 404, headers)
                return
            self.send_html(report_document(report), headers=headers)
            return
        if parsed.path == "/api/reports.csv":
            user, headers = self.get_or_create_user()
            reports = self.reports_for_user(str(user["_id"]))
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
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if self.rate_limited(parsed.path):
            self.send_json({"error": "Troppe richieste. Riprova tra poco."}, 429)
            return
        if parsed.path == "/api/auth/register":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                email = normalize_email(str(body.get("email", "")))
                hashed = password_hash(str(body.get("password", "")))
                now = utc_now()
                with db() as connection:
                    existing = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
                    if existing:
                        self.send_json({"error": "Email gia registrata. Accedi con login."}, 409, headers)
                        return
                    connection.execute(
                        "UPDATE users SET email = ?, password_hash = ?, updated_at = ? WHERE id = ?",
                        (email, hashed, now, user["_id"]),
                    )
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"user": row_to_user(row)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/auth/login":
            try:
                body = self.read_json()
                email = normalize_email(str(body.get("email", "")))
                password = str(body.get("password", ""))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                if not row or not verify_password(password, row["password_hash"]):
                    self.send_json({"error": "Credenziali non valide."}, 403)
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

        if parsed.path == "/api/analyze":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                target = str(body.get("target", ""))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not is_paid_plan(row["plan"]) and row["credits"] <= 0:
                        self.send_json({"error": "Crediti esauriti. Passa a Pro o resetta la demo."}, 402, headers)
                        return

                    report = analyze(target)
                    if not is_paid_plan(row["plan"]):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    store_report(connection, str(user["_id"]), report)
                    updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"report": report, "user": row_to_user(updated)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Errore analisi. Nessun dettaglio interno esposto."}, 500, headers)
            return

        if parsed.path == "/api/social/analyze":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                target = str(body.get("username", ""))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    if not is_paid_plan(row["plan"]) and row["credits"] <= 0:
                        self.send_json({"error": "Crediti esauriti. Passa a Pro o resetta la demo."}, 402, headers)
                        return

                    report = analyze_username(target)
                    if not is_paid_plan(row["plan"]):
                        connection.execute(
                            "UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ?",
                            (utc_now(), user["_id"]),
                        )
                    store_social_report(connection, str(user["_id"]), report)
                    updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                self.send_json({"report": report, "user": row_to_user(updated)}, headers=headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            except Exception:
                self.send_json({"error": "Errore social OSINT. Nessun dettaglio interno esposto."}, 500, headers)
            return

        if parsed.path == "/api/monitors":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
                domain = clean_domain(str(body.get("domain", "")))
                with db() as connection:
                    row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
                    current_count = connection.execute(
                        "SELECT COUNT(*) AS count FROM monitors WHERE user_id = ?",
                        (user["_id"],),
                    ).fetchone()["count"]
                    limit = PLAN_LIMITS.get(row["plan"], PLAN_LIMITS["Free"])["monitors"]
                    if current_count >= limit:
                        self.send_json({"error": f"Limite monitor raggiunto per il piano {row['plan']}."}, 402, headers)
                        return
                    now = utc_now()
                    connection.execute(
                        """
                        INSERT INTO monitors (id, user_id, domain, status, created_at, updated_at)
                        VALUES (?, ?, ?, 'pending', ?, ?)
                        """,
                        (str(uuid.uuid4()), user["_id"], domain, now, now),
                    )
                self.send_json({"monitors": self.monitors_for_user(str(user["_id"]))}, status=201, headers=headers)
            except sqlite3.IntegrityError:
                self.send_json({"error": "Dominio gia monitorato."}, 409, headers)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
            return

        if parsed.path == "/api/monitors/run":
            user, headers = self.get_or_create_user()
            try:
                with db() as connection:
                    rows = connection.execute(
                        "SELECT * FROM monitors WHERE user_id = ? ORDER BY created_at DESC",
                        (user["_id"],),
                    ).fetchall()
                    for monitor in rows:
                        report = analyze(monitor["domain"])
                        changed = monitor["last_score"] is not None and int(monitor["last_score"]) != int(report["score"])
                        now = utc_now()
                        store_report(connection, str(user["_id"]), report)
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
                                user["_id"],
                            ),
                        )
                self.send_json({
                    "monitors": self.monitors_for_user(str(user["_id"])),
                    "reports": self.reports_for_user(str(user["_id"])),
                }, headers=headers)
            except Exception:
                self.send_json({"error": "Monitor non completato. Nessun dettaglio interno esposto."}, 500, headers)
            return

        if parsed.path == "/api/admin/login":
            user, headers = self.get_or_create_user()
            try:
                body = self.read_json()
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400, headers)
                return
            code = str(body.get("code", ""))
            if not hmac.compare_digest(code, admin_code()):
                self.send_json({"error": "Codice admin non valido."}, 403, headers)
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
            }, headers=headers)
            return

        if parsed.path == "/api/billing/checkout":
            user, headers = self.get_or_create_user()
            body = self.read_json()
            plan = str(body.get("plan", "Pro")).capitalize()
            if plan not in {"Pro", "Agency"}:
                self.send_json({"error": "Piano non valido."}, 400, headers)
                return
            env_name = "OSINTPRO_STRIPE_AGENCY_URL" if plan == "Agency" else "OSINTPRO_STRIPE_PRO_URL"
            checkout_url = os.getenv(env_name)
            if checkout_url:
                self.send_json({"url": checkout_url, "mode": "stripe"}, headers=headers)
                return
            self.send_json({
                "url": "",
                "mode": "setup",
                "message": f"Configura {env_name} con un Payment Link Stripe per vendere il piano {plan}.",
            }, headers=headers)
            return

        if parsed.path == "/api/billing/simulate-upgrade":
            user, headers = self.get_or_create_user()
            body = self.read_json()
            plan = str(body.get("plan", "Pro")).capitalize()
            if plan not in {"Pro", "Agency"}:
                plan = "Pro"
            with db() as connection:
                connection.execute(
                    "UPDATE users SET plan = ?, updated_at = ? WHERE id = ?",
                    (plan, utc_now(), user["_id"]),
                )
                row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
            self.send_json({"user": row_to_user(row)}, headers=headers)
            return

        if parsed.path == "/api/billing/reset-demo":
            user, headers = self.get_or_create_user()
            with db() as connection:
                connection.execute(
                    "UPDATE users SET plan = 'Free', credits = ?, updated_at = ? WHERE id = ?",
                    (FREE_CREDITS, utc_now(), user["_id"]),
                )
                row = connection.execute("SELECT * FROM users WHERE id = ?", (user["_id"],)).fetchone()
            self.send_json({"user": row_to_user(row)}, headers=headers)
            return

        self.send_json({"error": "Endpoint non trovato"}, 404)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/reports":
            user, headers = self.get_or_create_user()
            with db() as connection:
                connection.execute("DELETE FROM reports WHERE user_id = ?", (user["_id"],))
            self.send_json({"reports": []}, headers=headers)
            return
        if parsed.path.startswith("/api/monitors/"):
            user, headers = self.get_or_create_user()
            monitor_id = parsed.path.split("/")[-1]
            with db() as connection:
                connection.execute("DELETE FROM monitors WHERE user_id = ? AND id = ?", (user["_id"], monitor_id))
            self.send_json({"monitors": self.monitors_for_user(str(user["_id"]))}, headers=headers)
            return
        self.send_json({"error": "Endpoint non trovato"}, 404)


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
