import os
import re
import uuid
import hmac
import secrets
import string
import json
import base64
import logging
import ipaddress
import mimetypes
from xml.etree import ElementTree as ET  # nosec B405 - only builds XML, never parses input
from urllib.parse import urlparse
from datetime import datetime, timedelta

from aiohttp import web
from aiohttp.abc import AbstractAccessLogger
from yarl import URL
import aiohttp_jinja2
import jinja2
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import sqlite3
import aiosqlite

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("credshare")

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Determine VERSION from file
VERSION_FILE_PATH = os.path.join(APP_DIR, "VERSION")
VERSION = "unknown"
if os.path.isfile(VERSION_FILE_PATH):
    with open(VERSION_FILE_PATH, "r") as version_file:
        VERSION = version_file.read().strip() or "unknown"
else:
    parent_dir_version_path = os.path.join(os.path.dirname(APP_DIR), "VERSION")
    if os.path.isfile(parent_dir_version_path):
        with open(parent_dir_version_path, "r") as version_file:
            VERSION = version_file.read().strip() + "-development"
    else:
        VERSION = "unknown"

# Load configuration from environment variables
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "false").lower() == "true"  # Default to False
MAX_USES_QUOTA = int(os.getenv("MAX_USES_QUOTA", 5))
SECRET_EXPIRY_MINUTES = int(os.getenv("SECRET_EXPIRY_MINUTES", 1440))
QUOTA_RENEWAL_MINUTES = int(os.getenv("QUOTA_RENEWAL_MINUTES", 60))
PURGE_INTERVAL_MINUTES = int(os.getenv("PURGE_INTERVAL_MINUTES", 5))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", 5))
# Number of reverse proxies in front of the app that append to X-Forwarded-For.
# 0 disables X-Forwarded-For entirely (use when clients connect directly).
TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", 1))
# Optional list of proxy addresses or CIDR ranges. When set, X-Forwarded-* headers are
# honoured only for connections that come from one of these addresses, so a client that
# reaches the app directly cannot forge its IP.
TRUSTED_PROXY_IPS = [s.strip() for s in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if s.strip()]
# Absolute base URL (e.g. https://credshare.app) used for canonical links, sharing cards
# and command line examples. When empty it is derived from the request headers.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
# Allowed analytics script domains. Only cookie-free, anonymised analytics belong here;
# tag managers can load arbitrary further scripts and would void the privacy policy.
ALLOWED_ANALYTICS_DOMAINS = os.getenv(
    "ALLOWED_ANALYTICS_DOMAINS",
    "plausible.remim.com,plausible.io",
).split(",")
ANALYTICS_SCRIPT_RAW = os.getenv("ANALYTICS_SCRIPT", "")
ANALYTICS_SCRIPT_CSP_RAW = os.getenv("ANALYTICS_SCRIPT_CSP", "")

# Constants to avoid abuse
MAX_CLIENT_SIZE = 1024 * 768  # 0.75MB
MAX_SECRET_SIZE = 1024 * 512  # 0.5MB
MAX_KEY_LENGTH = 1024  # Maximum key length in characters

DATABASE_DIR = os.getenv("DATABASE_DIR", os.path.join(APP_DIR, "database"))
DATABASE_PATH = os.path.join(DATABASE_DIR, "secrets.db")
IP_HASH_SALT_PATH = os.path.join(DATABASE_DIR, "ip_hash_salt")
APP_KEY = "aiohttp_jinja2_environment"

# Ensure the database directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)

_CSP_ORIGIN_RE = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?")
_HOST_RE = re.compile(r"^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$")
_DOWNLOAD_CODE_IN_PATH = re.compile(r"(/(?:unlock|time-left)/)[A-Za-z0-9]+")

# --- Date Adapter and Converter ---


def adapt_datetime_iso(val):
    """Adapt datetime.datetime to timezone-naive ISO 8601 date."""
    return val.isoformat()


sqlite3.register_adapter(datetime, adapt_datetime_iso)


def convert_datetime(val):
    """Convert ISO 8601 datetime to datetime.datetime object."""
    return datetime.fromisoformat(val.decode())


sqlite3.register_converter("DATETIME", convert_datetime)


# --- Analytics script validation ---


def validate_and_sanitize_analytics_script(script_html):
    """Rebuild the analytics <script> tag from an allowlist.

    Only an external script from an allowed domain survives, with the attributes
    src, defer, async and data-*. Inline code and unknown domains yield an empty string.
    """
    if not script_html or not script_html.strip():
        return ""
    script_html = script_html.strip()
    script_pattern = r"<script\s+([^>]*)>(.*?)</script>|<script\s+([^>]*?)\s*/>"
    match = re.search(script_pattern, script_html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    attributes_str = match.group(1) or match.group(3) or ""
    content = match.group(2) or ""
    if content.strip():
        return ""  # Inline JavaScript not allowed
    src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', attributes_str, re.IGNORECASE)
    if not src_match:
        return ""
    src_url = src_match.group(1)
    try:
        parsed_url = urlparse(src_url)
        if parsed_url.scheme not in ("http", "https"):
            return ""
        domain = parsed_url.netloc.lower()
        if not domain:
            return ""
        domain_allowed = False
        for allowed_domain in ALLOWED_ANALYTICS_DOMAINS:
            allowed_domain = allowed_domain.strip().lower()
            if not allowed_domain:
                continue
            if domain == allowed_domain or domain.endswith("." + allowed_domain):
                domain_allowed = True
                break
        if not domain_allowed:
            return ""
    except Exception:
        return ""

    safe_attributes = [f'src="{src_url}"']
    attr_pattern = r'(\w+(?:-\w+)*)\s*=\s*["\']([^"\']+)["\']|(\w+(?:-\w+)*)(?=\s|$)'
    for attr_match in re.finditer(attr_pattern, attributes_str, re.IGNORECASE):
        attr_name = (attr_match.group(1) or attr_match.group(3) or "").lower()
        attr_value = attr_match.group(2) or ""
        if attr_name == "src":
            continue
        if attr_name in ("defer", "async"):
            safe_attributes.append(attr_name)
        elif attr_name.startswith("data-"):
            sanitized_value = re.sub(r'[<>"\']', "", attr_value)
            orig_attr_name = attr_match.group(1) or attr_match.group(3) or attr_name
            safe_attributes.append(f'{orig_attr_name}="{sanitized_value}"')
    return f"<script {' '.join(safe_attributes)}></script>"


def validate_csp_origin(value):
    """Accept a single https origin for the CSP allowlist; anything else is dropped."""
    value = (value or "").strip()
    if not value:
        return ""
    if _CSP_ORIGIN_RE.fullmatch(value):
        return value
    logger.warning("ANALYTICS_SCRIPT_CSP ignored: %r is not a single https origin", value)
    return ""


ANALYTICS_SCRIPT = validate_and_sanitize_analytics_script(ANALYTICS_SCRIPT_RAW)
ANALYTICS_SCRIPT_CSP = validate_csp_origin(ANALYTICS_SCRIPT_CSP_RAW)


# --- Client address handling ---

_ip_hash_salt = None


def get_ip_hash_salt():
    """Return the per-instance secret mixed into IP hashes.

    Without a secret, a SHA-256 of an IPv4 address can be reversed in minutes by hashing
    every possible address. The secret is generated once, stored next to the database
    with owner-only permissions, and never leaves the server. If the directory is not
    writable the secret lives in memory only, which still protects the stored hashes.
    """
    global _ip_hash_salt
    if _ip_hash_salt:
        return _ip_hash_salt
    try:
        with open(IP_HASH_SALT_PATH, "r", encoding="ascii") as handle:
            salt = handle.read().strip()
        if len(salt) >= 32:
            _ip_hash_salt = salt
            return salt
    except OSError:
        pass
    salt = secrets.token_hex(32)
    try:
        os.makedirs(DATABASE_DIR, exist_ok=True)
        fd = os.open(IP_HASH_SALT_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(salt)
    except FileExistsError:
        with open(IP_HASH_SALT_PATH, "r", encoding="ascii") as handle:
            salt = handle.read().strip() or salt
    except OSError as exc:
        logger.warning("IP hash salt kept in memory only (%s): %s", IP_HASH_SALT_PATH, exc)
    _ip_hash_salt = salt
    return salt


def hash_ip(ip):
    return hmac.new(get_ip_hash_salt().encode(), ip.encode(), "sha256").hexdigest()


def _parse_trusted_proxy_networks():
    networks = []
    for entry in TRUSTED_PROXY_IPS:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXY_IPS entry %r", entry)
    return networks


def _headers(request):
    return getattr(request, "headers", None) or {}


def proxy_is_trusted(request):
    """True when X-Forwarded-* headers on this request may be believed.

    With TRUSTED_PROXY_COUNT at zero nothing is trusted. When TRUSTED_PROXY_IPS is set the
    connection must also come from one of those addresses; otherwise a client that bypasses
    the proxy could forge headers.
    """
    if TRUSTED_PROXY_COUNT <= 0:
        return False
    if not TRUSTED_PROXY_IPS:
        return True
    try:
        remote = ipaddress.ip_address(getattr(request, "remote", "") or "")
    except ValueError:
        return False
    return any(remote in network for network in _parse_trusted_proxy_networks())


def normalize_ip(ip):
    """Quota key for an address: the address itself for IPv4, the /64 network for IPv6.

    Residential IPv6 customers hold a /64, so counting per single address would give an
    attacker 2**64 free identities.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((address, 64), strict=False))
    return str(address)


def resolve_client_ip(request):
    """Determine the client's real IP address.

    X-Forwarded-For is only honoured for TRUSTED_PROXY_COUNT proxies. Each proxy appends
    the address it received the request from, so the real client is that many entries
    from the right; anything further left was supplied by the client and cannot be trusted.
    """
    ip = getattr(request, "remote", "") or ""
    if proxy_is_trusted(request):
        forwarded_for = _headers(request).get("X-Forwarded-For", "")
        hops = [hop.strip() for hop in forwarded_for.split(",") if hop.strip()]
        if hops:
            ip = hops[-TRUSTED_PROXY_COUNT] if len(hops) >= TRUSTED_PROXY_COUNT else hops[0]
    return ip


def get_client_ip(request):
    """Retrieve the client's IP address from the request and hash it."""
    return hash_ip(normalize_ip(resolve_client_ip(request)))


def public_base_url(request):
    """Return the absolute base URL clients should use to reach this instance.

    PUBLIC_BASE_URL wins when configured. Otherwise the URL is rebuilt from the request,
    honouring X-Forwarded-Proto / X-Forwarded-Host only when a trusted proxy is configured.
    Returns an empty string if no sane host can be determined, so callers fall back to
    a relative path.
    """
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    scheme = "https" if getattr(request, "secure", False) else "http"
    host = getattr(request, "host", "") or ""
    headers = _headers(request)
    if proxy_is_trusted(request):
        forwarded_proto = headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        if forwarded_proto in ("http", "https"):
            scheme = forwarded_proto
        forwarded_host = headers.get("X-Forwarded-Host", "").split(",")[0].strip()
        if forwarded_host:
            host = forwarded_host
    if HTTPS_ONLY:
        scheme = "https"
    if not _HOST_RE.match(host):
        return ""
    return str(URL.build(scheme=scheme, authority=host))


def expected_hosts(request):
    """Host names this instance answers to, for comparing against an Origin header."""
    hosts = {(getattr(request, "host", "") or "").lower()}
    if proxy_is_trusted(request):
        forwarded_host = _headers(request).get("X-Forwarded-Host", "").split(",")[0].strip()
        if forwarded_host:
            hosts.add(forwarded_host.lower())
    if PUBLIC_BASE_URL:
        hosts.add(urlparse(PUBLIC_BASE_URL).netloc.lower())
    hosts.discard("")
    return hosts


def is_cross_site(request):
    """Reject requests a third-party page triggers in a visitor's browser.

    Browsers label cross-origin requests with Sec-Fetch-Site; older ones at least send
    Origin. Non-browser clients such as curl send neither and are allowed through.
    """
    headers = _headers(request)
    if headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
        return True
    origin = headers.get("Origin", "").strip()
    if not origin:
        return False
    if origin.lower() == "null":
        return True
    return urlparse(origin).netloc.lower() not in expected_hosts(request)


def redact_download_codes(text):
    """Replace unlock codes in a path or URL so log lines cannot be tied to a secret."""
    return _DOWNLOAD_CODE_IN_PATH.sub(r"\1[code]", text)


class ClientIPAccessLogger(AbstractAccessLogger):
    """aiohttp access logger that reports the resolved client IP.

    The default logger prints the socket peer, which behind a reverse proxy is always
    the proxy itself. This mirrors the default log line but uses the same
    TRUSTED_PROXY_COUNT-aware resolution as the quota. Unlock codes are redacted from
    the path and the referrer, as promised in the privacy policy.
    """

    def log(self, request, response, elapsed):
        if request.path == "/healthz":
            return  # container health probes would otherwise dominate the log
        try:
            started = datetime.now().astimezone() - timedelta(seconds=elapsed)
            self.logger.info(
                '%s [%s] "%s %s HTTP/%s.%s" %s %s "%s" "%s"',
                resolve_client_ip(request) or "-",
                started.strftime("%d/%b/%Y:%H:%M:%S %z"),
                request.method,
                redact_download_codes(request.path_qs),
                request.version.major,
                request.version.minor,
                response.status,
                response.body_length,
                redact_download_codes(request.headers.get("Referer", "-")),
                request.headers.get("User-Agent", "-"),
            )
        except Exception:
            self.logger.exception("Error in logging")


# --- Context Processor for Templates ---


async def version_context_processor(request):
    # The nonce is generated by the middleware; fall back to generating one here for
    # renders that bypass it (tests), storing it on the request for the CSP header.
    nonce = request.get("csp_nonce", "")
    if not nonce:
        nonce = secrets.token_urlsafe(16)
        try:
            request["csp_nonce"] = nonce
        except (TypeError, AttributeError):
            pass
    # Absolute URLs for social sharing cards (Open Graph requires absolute image URLs).
    base_url = public_base_url(request)
    path = getattr(request, "path", "") or ""
    return {
        "VERSION": VERSION,
        "ANALYTICS_SCRIPT": ANALYTICS_SCRIPT,
        "CSP_NONCE": nonce,
        "BASE_URL": base_url,
        "PAGE_URL": f"{base_url}{path}" if base_url else "",
    }


# --- Helper Functions ---


async def init_db():
    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                download_code TEXT NOT NULL,
                upload_time DATETIME NOT NULL
            )
        """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_usage (
                ip TEXT PRIMARY KEY,
                uses INTEGER NOT NULL,
                last_access DATETIME NOT NULL
            )
        """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_secrets_download_code ON secrets (download_code)"
        )
        await db.commit()


async def ip_reached_quota(ip):
    """Check the IP usage and reset if the quota renewal period has passed."""
    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute("SELECT uses, last_access FROM ip_usage WHERE ip=?", (ip,)) as cursor:
            row = await cursor.fetchone()
        current_time = datetime.now()
        if row:
            uses, last_access = row
            if last_access < (current_time - timedelta(minutes=QUOTA_RENEWAL_MINUTES)):
                await db.execute("DELETE FROM ip_usage WHERE ip=?", (ip,))
                await db.commit()
                return False
            elif int(uses) >= MAX_USES_QUOTA:
                return True
    return False


def generate_download_code(length=12):
    """Generate a cryptographically secure random download code."""
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def validate_download_code(code):
    """Validate download code format and length."""
    if not code or not isinstance(code, str):
        return False
    # Download codes should be exactly 12 characters of alphanumeric
    if len(code) != 12:
        return False
    # Only allow alphanumeric characters
    if not code.isalnum():
        return False
    return True


def validate_json_content_type(request):
    """Validate that request has correct Content-Type header for JSON."""
    # Handle cases where headers might not exist or might be None
    if not hasattr(request, "headers") or request.headers is None:
        return False
    content_type = request.headers.get("Content-Type", "")
    # Check for application/json (allow charset parameter)
    return "application/json" in content_type.lower()


def humanize_minutes(minutes):
    """60 -> 'an hour', 120 -> '2 hours', 90 -> '90 minutes'."""
    if minutes == 60:
        return "an hour"
    if minutes % 60 == 0:
        return f"{minutes // 60} hours"
    return f"{minutes} minutes"


def analytics_script_host():
    """Host name the analytics script is loaded from, or '' when analytics is off."""
    match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', ANALYTICS_SCRIPT, re.IGNORECASE)
    return urlparse(match.group(1)).netloc if match else ""


def policy_context():
    """Values the privacy and cookie policy pages state about this instance."""
    return {
        "secret_expiry_hours": SECRET_EXPIRY_MINUTES // 60,
        "secret_expiry_minutes": SECRET_EXPIRY_MINUTES % 60,
        "secret_expiry_text": humanize_minutes(SECRET_EXPIRY_MINUTES),
        "max_attempts": MAX_ATTEMPTS,
        "quota_renewal_minutes": QUOTA_RENEWAL_MINUTES,
        "purge_interval_minutes": PURGE_INTERVAL_MINUTES,
        "max_secret_kb": MAX_SECRET_SIZE // 1024,
        "max_secret_chars_text": f"{(MAX_SECRET_SIZE // 2) // 1000 * 1000:,}".replace(",", " "),
        "quota_window_text": humanize_minutes(QUOTA_RENEWAL_MINUTES),
        "analytics_enabled": bool(ANALYTICS_SCRIPT),
        "analytics_host": analytics_script_host(),
    }


def render_no_store(template, request, context, status=200):
    """Render a page that names or consumes per-visitor state; never let a shared cache keep it."""
    response = aiohttp_jinja2.render_template(template, request, context, app_key=APP_KEY)
    response.set_status(status)
    response.headers["Cache-Control"] = "no-store"
    return response


# --- Request Handlers ---


async def index(request):
    secret_expiry_hours = SECRET_EXPIRY_MINUTES // 60
    secret_expiry_minutes = SECRET_EXPIRY_MINUTES % 60

    context = {
        "secret_expiry_hours": secret_expiry_hours,
        "secret_expiry_minutes": secret_expiry_minutes,
        "secret_expiry_text": humanize_minutes(SECRET_EXPIRY_MINUTES),
        "max_attempts": MAX_ATTEMPTS,
        "max_secret_bytes": MAX_SECRET_SIZE,
        "max_secret_kb": MAX_SECRET_SIZE // 1024,
        # The browser encrypts before sending; ciphertext is ~1.4x plaintext, so the
        # textarea limit is stated in characters comfortably inside MAX_SECRET_SIZE.
        "max_secret_chars": MAX_SECRET_SIZE // 2,
        "max_secret_chars_text": f"{(MAX_SECRET_SIZE // 2) // 1000 * 1000:,}".replace(",", " "),
        "max_key_length": MAX_KEY_LENGTH,
        "base_url": public_base_url(request) or "https://credshare.app",
    }
    return aiohttp_jinja2.render_template("index.html", request, context, app_key=APP_KEY)


async def store_secret(encrypted_secret, ip):
    """Common function to store a secret in the database."""
    if len(encrypted_secret) > MAX_SECRET_SIZE:
        return None, f"Secret too large. Maximum size is {MAX_SECRET_SIZE} bytes."

    secret_id = str(uuid.uuid4())
    download_code = generate_download_code()
    upload_time = datetime.now()

    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            (secret_id, encrypted_secret, 0, download_code, upload_time),
        )
        async with db.execute("SELECT 1 FROM ip_usage WHERE ip=?", (ip,)) as cursor:
            exists = await cursor.fetchone()
        if exists:
            await db.execute(
                "UPDATE ip_usage SET uses=uses+1, last_access=? WHERE ip=?",
                (upload_time, ip),
            )
        else:
            await db.execute(
                "INSERT INTO ip_usage (ip, uses, last_access) VALUES (?, 1, ?)",
                (ip, upload_time),
            )
        await db.commit()

    return download_code, None


async def upload_secret(request):
    if is_cross_site(request):
        return web.Response(text="Cross-site requests are not allowed.", status=403)
    ip = get_client_ip(request)
    if await ip_reached_quota(ip):
        return web.Response(
            text="You have exceeded the maximum number of shares for today.", status=429
        )

    reader = await request.multipart()
    field = await reader.next()
    if field is None or field.name != "encryptedsecret":
        return web.Response(text="No secret field in form.", status=400)

    secret = await field.text()

    download_code, error = await store_secret(secret, ip)
    if error:
        return web.Response(text=error, status=400)

    download_url = f"/unlock/{download_code}"
    return web.Response(text=download_url, headers={"Cache-Control": "no-store"})


async def unlock_secret_landing(request):
    download_code = request.match_info["download_code"]
    # Validate download code format
    if not validate_download_code(download_code):
        return render_no_store("404.html", request, {}, status=404)

    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT 1 FROM secrets WHERE download_code=?", (download_code,)
        ) as cursor:
            row = await cursor.fetchone()

    if row:
        download_link = f"/unlock/{download_code}"
        host = getattr(request, "host", "") or ""
        context = {
            "download_link": download_link,
            "download_code": download_code,
            "max_attempts": MAX_ATTEMPTS,
            "max_key_length": MAX_KEY_LENGTH,
            "base_url": public_base_url(request) or f"https://{host}",
        }
        return render_no_store("download.html", request, context)

    return render_no_store("404.html", request, {}, status=404)


async def unlock_secret_logic(download_code, key):
    """
    Common logic for unlocking secrets.
    Returns: (success: bool, result: dict)
    On success: (True, {"secret": decrypted_secret})
    On error: (False, {"error": error_message, "status": http_status, "attempts_remaining": remaining})
    """
    if not download_code or not key:
        return False, {"error": "Missing download_code or key.", "status": 400}

    # Validate download code format
    if not validate_download_code(download_code):
        return False, {"error": "Invalid download code format.", "status": 400}

    # Validate key length
    if not isinstance(key, str) or len(key) > MAX_KEY_LENGTH:
        return False, {
            "error": f"Key too long. Maximum length is {MAX_KEY_LENGTH} characters.",
            "status": 400,
        }

    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT secret, attempts FROM secrets WHERE download_code=?",
            (download_code,),
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            return False, {
                "error": "Invalid download code or key.",
                "status": 404,
            }
        encrypted_secret_json, attempts = row

        try:
            encrypted_data = json.loads(encrypted_secret_json)
            salt = base64.b64decode(encrypted_data["salt"])
            iv = base64.b64decode(encrypted_data["iv"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            aes_key = kdf.derive(key.encode())
            aesgcm = AESGCM(aes_key)
            decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
            decrypted_secret = decrypted_bytes.decode()
        except Exception:
            # Increase the failure count.
            attempts += 1
            if attempts >= MAX_ATTEMPTS:
                await db.execute("DELETE FROM secrets WHERE download_code=?", (download_code,))
                await db.commit()
                return False, {
                    "error": "Incorrect key. Maximum attempts reached. Secret deleted.",
                    "status": 400,
                }
            else:
                await db.execute(
                    "UPDATE secrets SET attempts=? WHERE download_code=?",
                    (attempts, download_code),
                )
                await db.commit()
                remaining = MAX_ATTEMPTS - attempts
                return False, {
                    "error": "Incorrect key.",
                    "status": 400,
                    "attempts_remaining": remaining,
                }

        # Single use is decided by the delete, not the select: two concurrent requests
        # with the right key both decrypt, but only the one that removes the row wins.
        cursor = await db.execute("DELETE FROM secrets WHERE download_code=?", (download_code,))
        await db.commit()
        if cursor.rowcount == 0:
            return False, {"error": "Invalid download code or key.", "status": 404}

    return True, {"secret": decrypted_secret}


def _unlock_error_response(result):
    status = result.get("status", 400)
    response_data = {"error": result["error"]}
    if "attempts_remaining" in result:
        response_data["attempts_remaining"] = result["attempts_remaining"]
    return web.json_response(response_data, status=status, headers={"Cache-Control": "no-store"})


async def unlock_secret(request):
    """
    Web endpoint for unlocking secrets.
    Expects JSON data with:
      - "download_code": the secret identifier.
      - "key": the user-supplied decryption key.
    Returns JSON response.
    """
    if is_cross_site(request):
        return web.json_response({"error": "Cross-site requests are not allowed."}, status=403)

    # Validate Content-Type header
    if not validate_json_content_type(request):
        return web.json_response({"error": "Content-Type must be application/json."}, status=400)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON."}, status=400)

    download_code = data.get("download_code")
    key = data.get("key")

    success, result = await unlock_secret_logic(download_code, key)

    if success:
        return web.json_response(
            {"secret": result["secret"]}, headers={"Cache-Control": "no-store"}
        )
    return _unlock_error_response(result)


async def api_lock_secret(request):
    """
    API endpoint for creating secrets via curl.
    Accepts JSON: {"encrypted_secret": "..."}
    Returns JSON: {"download_code": "...", "url": "..."}
    """
    if is_cross_site(request):
        return web.json_response({"error": "Cross-site requests are not allowed."}, status=403)
    ip = get_client_ip(request)
    if await ip_reached_quota(ip):
        return web.json_response(
            {"error": "You have exceeded the maximum number of shares for today."},
            status=429,
        )

    # Validate Content-Type header
    if not validate_json_content_type(request):
        return web.json_response({"error": "Content-Type must be application/json."}, status=400)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON."}, status=400)

    encrypted_secret = data.get("encrypted_secret")
    if not encrypted_secret:
        return web.json_response({"error": "Missing encrypted_secret field."}, status=400)

    download_code, error = await store_secret(encrypted_secret, ip)
    if error:
        return web.json_response({"error": error}, status=400)

    download_url = f"/unlock/{download_code}"
    return web.json_response(
        {"download_code": download_code, "url": download_url},
        headers={"Cache-Control": "no-store"},
    )


async def api_unlock_secret(request):
    """
    API endpoint for retrieving secrets via curl.
    Accepts JSON: {"download_code": "...", "key": "..."}
    Returns plain text secret on success, JSON error on failure.
    """
    if is_cross_site(request):
        return web.json_response({"error": "Cross-site requests are not allowed."}, status=403)

    # Validate Content-Type header
    if not validate_json_content_type(request):
        return web.json_response({"error": "Content-Type must be application/json."}, status=400)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON."}, status=400)

    download_code = data.get("download_code")
    key = data.get("key")

    success, result = await unlock_secret_logic(download_code, key)

    if success:
        # Return plain text secret on success
        return web.Response(
            text=result["secret"],
            content_type="text/plain",
            headers={"Cache-Control": "no-store"},
        )
    return _unlock_error_response(result)


async def handle_404(request):
    return render_no_store("404.html", request, {}, status=404)


async def check_limit(request):
    ip = get_client_ip(request)
    # Clean up expired records if needed.
    await ip_reached_quota(ip)
    quota_left = MAX_USES_QUOTA
    current_time = datetime.now()
    next_quota_renewal = timedelta(minutes=QUOTA_RENEWAL_MINUTES)

    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute("SELECT uses, last_access FROM ip_usage WHERE ip=?", (ip,)) as cursor:
            row = await cursor.fetchone()
        if row:
            uses, last_access = row
            if last_access >= (current_time - timedelta(minutes=QUOTA_RENEWAL_MINUTES)):
                quota_left = MAX_USES_QUOTA - uses
                next_quota_renewal = (
                    last_access + timedelta(minutes=QUOTA_RENEWAL_MINUTES)
                ) - current_time

    return web.json_response(
        {
            "limit_reached": await ip_reached_quota(ip),
            "quota_left": quota_left,
            "quota_renewal_hours": int(next_quota_renewal.total_seconds() // 3600),
            "quota_renewal_minutes": int((next_quota_renewal.total_seconds() % 3600) // 60),
        },
        headers={"Cache-Control": "no-store"},
    )


async def time_left(request):
    download_code = request.match_info["download_code"]
    no_store = {"Cache-Control": "no-store"}
    # Validate download code format
    if not validate_download_code(download_code):
        return web.json_response(
            {"message": "Invalid download code format."}, status=400, headers=no_store
        )

    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT upload_time FROM secrets WHERE download_code=?", (download_code,)
        ) as cursor:
            row = await cursor.fetchone()
    if row:
        upload_time = row[0]
        expiry_time = upload_time + timedelta(minutes=SECRET_EXPIRY_MINUTES)
        current_time = datetime.now()
        remaining = expiry_time - current_time
        if remaining.total_seconds() > 0:
            hours_left = int(remaining.total_seconds() // 3600)
            minutes_left = int((remaining.total_seconds() % 3600) // 60)
            return web.json_response(
                {
                    "hours_left": hours_left,
                    "minutes_left": minutes_left,
                    "message": "The secret is available",
                },
                headers=no_store,
            )
        else:
            return web.json_response(
                {"message": "The secret has already expired."},
                status=410,
                headers=no_store,
            )
    else:
        return web.json_response(
            {"message": "Download code not found."}, status=404, headers=no_store
        )


async def privacy_policy(request):
    return aiohttp_jinja2.render_template(
        "privacy.html", request, policy_context(), app_key=APP_KEY
    )


async def cookie_policy(request):
    return aiohttp_jinja2.render_template(
        "cookies.html", request, policy_context(), app_key=APP_KEY
    )


async def robots_txt(request):
    # Unlock pages must never be crawled: they name a secret's existence, and the API
    # endpoints consume state. Only the front page and the policies are for indexing.
    lines = [
        "User-agent: *",
        "Disallow: /unlock/",
        "Disallow: /unlock_secret",
        "Disallow: /lock",
        "Disallow: /api/",
        "Disallow: /check-limit",
        "Disallow: /time-left/",
        "Disallow: /healthz",
        "Allow: /",
    ]
    base_url = public_base_url(request)
    if base_url:
        lines.append(f"Sitemap: {base_url}/sitemap.xml")
    return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")


async def sitemap_xml(request):
    base_url = public_base_url(request) or str(request.url.origin())
    urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")
    for page in ("/", "/privacy", "/cookies"):
        ET.SubElement(ET.SubElement(urlset, "url"), "loc").text = base_url + page
    body = ET.tostring(urlset, encoding="unicode", xml_declaration=True) + "\n"
    return web.Response(text=body, content_type="application/xml")


async def healthz(request):
    """Cheap liveness probe for the container health check; not logged."""
    return web.Response(status=204, headers={"Cache-Control": "no-store"})


async def purge_expired():
    """Delete secrets older than the expiry time and clean up the ip_usage table."""
    expiry_time = datetime.now() - timedelta(minutes=SECRET_EXPIRY_MINUTES)
    async with aiosqlite.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute("DELETE FROM secrets WHERE upload_time < ?", (expiry_time,))
        cutoff_time = datetime.now() - timedelta(minutes=QUOTA_RENEWAL_MINUTES)
        await db.execute("DELETE FROM ip_usage WHERE last_access < ?", (cutoff_time,))
        await db.commit()


# --- Middleware ---


@web.middleware
async def security_headers_middleware(request, handler):
    # Generate nonce for this request (used in CSP and made available to templates)
    nonce = secrets.token_urlsafe(16)
    request["csp_nonce"] = nonce

    response = await handler(request)

    # Hide server information - remove headers that reveal server details
    for header in ("Server", "X-Powered-By", "X-Runtime", "X-Version"):
        if header in response.headers:
            del response.headers[header]

    # Content Security Policy: nonce-based scripts, self-hosted styles and fonts only.
    script_src_parts = ["'self'", f"'nonce-{nonce}'"]
    default_src_parts = ["'self'"]
    if ANALYTICS_SCRIPT_CSP:
        script_src_parts.append(ANALYTICS_SCRIPT_CSP)
        default_src_parts.append(ANALYTICS_SCRIPT_CSP)

    csp_parts = [
        f"default-src {' '.join(default_src_parts)}",
        f"script-src {' '.join(script_src_parts)}",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_parts) + ";"

    # Add Permissions-Policy header to restrict dangerous features
    response.headers["Permissions-Policy"] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=(), "
        "ambient-light-sensor=(), "
        "autoplay=(), "
        "encrypted-media=(), "
        "fullscreen=(self), "
        "picture-in-picture=()"
    )

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    # Use HSTS if serving over HTTPS
    if HTTPS_ONLY:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    # Referrer information policy
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# --- Application Factory ---


async def create_app(purge_interval_minutes=PURGE_INTERVAL_MINUTES):
    if not PUBLIC_BASE_URL:
        logger.warning(
            "PUBLIC_BASE_URL is not set; absolute links are derived from request headers."
        )
    if TRUSTED_PROXY_COUNT > 0 and not TRUSTED_PROXY_IPS:
        logger.warning(
            "X-Forwarded-For is trusted from any connection. Bind the app to the proxy only, "
            "or set TRUSTED_PROXY_IPS."
        )

    # Limit requests to 0.75MB
    app = web.Application(
        client_max_size=MAX_CLIENT_SIZE, middlewares=[security_headers_middleware]
    )

    # Remove Server header using signal handler (aiohttp adds it automatically)
    # This ensures the header is removed even if aiohttp adds it after middleware runs
    async def on_response_prepare(request, response):
        server_keys = [key for key in response.headers.keys() if key.lower() == "server"]
        for key in server_keys:
            del response.headers[key]

    app.on_response_prepare.append(on_response_prepare)

    aiohttp_jinja2.setup(
        app,
        loader=jinja2.FileSystemLoader(os.path.join(APP_DIR, "templates")),
        app_key=APP_KEY,
        context_processors=[version_context_processor],
    )

    # Initialize the database
    await init_db()

    # Define routes
    app.router.add_get("/", index)
    app.router.add_post("/lock", upload_secret)
    app.router.add_get("/unlock/{download_code}", unlock_secret_landing)
    app.router.add_post("/unlock_secret", unlock_secret)
    app.router.add_get("/check-limit", check_limit)
    app.router.add_get("/time-left/{download_code}", time_left)
    # API endpoints for CLI/curl usage
    app.router.add_post("/api/lock", api_lock_secret)
    app.router.add_post("/api/unlock", api_unlock_secret)
    app.router.add_get("/privacy", privacy_policy)
    app.router.add_get("/cookies", cookie_policy)
    app.router.add_get("/robots.txt", robots_txt)
    app.router.add_get("/sitemap.xml", sitemap_xml)
    app.router.add_get("/healthz", healthz)
    # Self-hosted fonts: aiohttp's static handler keeps its own MIME table, snapshotted at
    # import time, so the type is registered both globally and on that table.
    mimetypes.add_type("font/woff2", ".woff2")
    try:
        from aiohttp.web_fileresponse import CONTENT_TYPES

        CONTENT_TYPES.add_type("font/woff2", ".woff2")
    except ImportError:  # older aiohttp: the global table is used
        pass
    app.router.add_static("/static", os.path.join(APP_DIR, "static"))
    app.router.add_get("/{tail:.*}", handle_404)

    # Run initial cleanup
    await purge_expired()

    # Schedule periodic background cleanup
    scheduler = AsyncIOScheduler()
    scheduler.add_job(purge_expired, "interval", minutes=purge_interval_minutes)
    scheduler.start()

    async def shutdown_scheduler(app):
        scheduler.shutdown(wait=False)

    app.on_cleanup.append(shutdown_scheduler)

    return app


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    app = asyncio.run(create_app())
    # Binding to 0.0.0.0 is required for container deployment
    web.run_app(
        app,
        host="0.0.0.0",  # nosec B104
        port=8080,
        access_log_class=ClientIPAccessLogger,
    )
