import os
import uuid
import secrets
import string
import hashlib
import json
import base64
from datetime import datetime, timedelta

from aiohttp import web
import aiohttp_jinja2
import jinja2
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import sqlite3
import aiosqlite

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Determine VERSION from file
VERSION_FILE_PATH = os.path.join(os.path.dirname(__file__), "VERSION")
VERSION = "unknown"
if os.path.isfile(VERSION_FILE_PATH):
    with open(VERSION_FILE_PATH, "r") as version_file:
        VERSION = version_file.read().strip() or "unknown"
else:
    parent_dir_version_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "VERSION"
    )
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
ANALYTICS_SCRIPT = os.getenv("ANALYTICS_SCRIPT", "")
ANALYTICS_SCRIPT_CSP = os.getenv("ANALYTICS_SCRIPT_CSP", "")

# Constants to avoid abuse
MAX_CLIENT_SIZE = 1024 * 768  # 0.75MB
MAX_SECRET_SIZE = 1024 * 512  # 0.5MB
MAX_KEY_LENGTH = 1024  # Maximum key length in characters

DATABASE_DIR = "/app/database"
DATABASE_PATH = os.path.join(DATABASE_DIR, "secrets.db")
APP_KEY = "aiohttp_jinja2_environment"

# Ensure the database directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)

# --- Date Adapter and Converter (kept as in your example) ---


def adapt_datetime_iso(val):
    """Adapt datetime.datetime to timezone-naive ISO 8601 date."""
    return val.isoformat()


sqlite3.register_adapter(datetime, adapt_datetime_iso)


def convert_datetime(val):
    """Convert ISO 8601 datetime to datetime.datetime object."""
    return datetime.fromisoformat(val.decode())


sqlite3.register_converter("DATETIME", convert_datetime)


# --- Context Processor for Templates ---
async def version_context_processor(_):
    return {"VERSION": VERSION, "ANALYTICS_SCRIPT": ANALYTICS_SCRIPT}


# --- Helper Functions ---


async def init_db():
    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
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
        await db.commit()


def hash_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()


def get_client_ip(request):
    """Retrieve the client's IP address from the request and hash it."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = request.remote
    return hash_ip(ip)


async def ip_reached_quota(ip):
    """Check the IP usage and reset if the quota renewal period has passed."""
    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
        async with db.execute(
            "SELECT uses, last_access FROM ip_usage WHERE ip=?", (ip,)
        ) as cursor:
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
    if not hasattr(request, 'headers') or request.headers is None:
        return False
    content_type = request.headers.get("Content-Type", "")
    # Check for application/json (allow charset parameter)
    return "application/json" in content_type.lower()


# --- Request Handlers ---


async def index(request):
    secret_expiry_hours = SECRET_EXPIRY_MINUTES // 60
    secret_expiry_minutes = SECRET_EXPIRY_MINUTES % 60

    context = {
        "secret_expiry_hours": secret_expiry_hours,
        "secret_expiry_minutes": secret_expiry_minutes,
        "max_attempts": MAX_ATTEMPTS,
    }
    return aiohttp_jinja2.render_template(
        "index.html", request, context, app_key=APP_KEY
    )


async def store_secret(encrypted_secret, ip):
    """Common function to store a secret in the database."""
    if len(encrypted_secret) > MAX_SECRET_SIZE:
        return None, f"Secret too large. Maximum size is {MAX_SECRET_SIZE} bytes."

    secret_id = str(uuid.uuid4())
    download_code = generate_download_code()
    upload_time = datetime.now()

    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
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
    return web.Response(text=download_url)


async def unlock_secret_landing(request):
    download_code = request.match_info["download_code"]
    # Validate download code format
    if not validate_download_code(download_code):
        response = aiohttp_jinja2.render_template("404.html", request, {}, app_key=APP_KEY)
        response.set_status(404)
        return response

    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
        async with db.execute(
            "SELECT secret FROM secrets WHERE download_code=?", (download_code,)
        ) as cursor:
            row = await cursor.fetchone()

    if row:
        download_link = f"/unlock/{download_code}"
        # Get base URL for CLI examples
        # Prefer HTTPS - check X-Forwarded-Proto header first (if behind proxy),
        # then use request.scheme, defaulting to https for security
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
        if forwarded_proto == "https":
            scheme = "https"
        elif forwarded_proto == "http":
            scheme = "http"
        elif request.scheme == "https":
            scheme = "https"
        else:
            # Default to https for security (if scheme is http, we still prefer https)
            scheme = "https"
        host = request.host
        base_url = f"{scheme}://{host}"
        context = {
            "download_link": download_link,
            "download_code": download_code,
            "max_attempts": MAX_ATTEMPTS,
            "base_url": base_url,
        }
        return aiohttp_jinja2.render_template(
            "download.html", request, context, app_key=APP_KEY
        )

    response = aiohttp_jinja2.render_template("404.html", request, {}, app_key=APP_KEY)
    response.set_status(404)
    return response


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
        return False, {"error": f"Key too long. Maximum length is {MAX_KEY_LENGTH} characters.", "status": 400}

    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
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
                await db.execute(
                    "DELETE FROM secrets WHERE download_code=?", (download_code,)
                )
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

        # On success, delete the secret.
        await db.execute("DELETE FROM secrets WHERE download_code=?", (download_code,))
        await db.commit()

    return True, {"secret": decrypted_secret}


async def unlock_secret(request):
    """
    Web endpoint for unlocking secrets.
    Expects JSON data with:
      - "download_code": the secret identifier.
      - "key": the user-supplied decryption key.
    Returns JSON response.
    """
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
        return web.json_response({"secret": result["secret"]})
    else:
        status = result.get("status", 400)
        response_data = {"error": result["error"]}
        if "attempts_remaining" in result:
            response_data["attempts_remaining"] = result["attempts_remaining"]
        return web.json_response(response_data, status=status)


async def api_lock_secret(request):
    """
    API endpoint for creating secrets via curl.
    Accepts JSON: {"encrypted_secret": "..."}
    Returns JSON: {"download_code": "...", "url": "..."}
    """
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
    return web.json_response({"download_code": download_code, "url": download_url})


async def api_unlock_secret(request):
    """
    API endpoint for retrieving secrets via curl.
    Accepts JSON: {"download_code": "...", "key": "..."}
    Returns plain text secret on success, JSON error on failure.
    """
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
        return web.Response(text=result["secret"], content_type="text/plain")
    else:
        # Return JSON error with appropriate HTTP status
        status = result.get("status", 400)
        response_data = {"error": result["error"]}
        if "attempts_remaining" in result:
            response_data["attempts_remaining"] = result["attempts_remaining"]
        return web.json_response(response_data, status=status)


async def handle_404(request):
    response = aiohttp_jinja2.render_template("404.html", request, {}, app_key=APP_KEY)
    response.set_status(404)
    return response


async def check_limit(request):
    ip = get_client_ip(request)
    # Clean up expired records if needed.
    await ip_reached_quota(ip)
    quota_left = MAX_USES_QUOTA
    current_time = datetime.now()
    next_quota_renewal = timedelta(minutes=QUOTA_RENEWAL_MINUTES)

    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
        async with db.execute(
            "SELECT uses, last_access FROM ip_usage WHERE ip=?", (ip,)
        ) as cursor:
            row = await cursor.fetchone()
        if row:
            uses, last_access = row
            if last_access >= (current_time - timedelta(minutes=QUOTA_RENEWAL_MINUTES)):
                quota_left = MAX_USES_QUOTA - uses
                next_quota_renewal = (
                    last_access + timedelta(minutes=QUOTA_RENEWAL_MINUTES)
                ) - current_time

    if await ip_reached_quota(ip):
        return web.json_response(
            {
                "limit_reached": True,
                "quota_left": quota_left,
                "quota_renewal_hours": int(next_quota_renewal.total_seconds() // 3600),
                "quota_renewal_minutes": int(
                    (next_quota_renewal.total_seconds() % 3600) // 60
                ),
            }
        )
    else:
        return web.json_response(
            {
                "limit_reached": False,
                "quota_left": quota_left,
                "quota_renewal_hours": int(next_quota_renewal.total_seconds() // 3600),
                "quota_renewal_minutes": int(
                    (next_quota_renewal.total_seconds() % 3600) // 60
                ),
            }
        )


async def time_left(request):
    download_code = request.match_info["download_code"]
    # Validate download code format
    if not validate_download_code(download_code):
        return web.json_response({"message": "Invalid download code format."}, status=400)

    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
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
                }
            )
        else:
            return web.json_response(
                {"message": "The secret has already expired."}, status=410
            )
    else:
        return web.json_response({"message": "Download code not found."}, status=404)


async def purge_expired():
    """Delete secrets older than the expiry time and clean up the ip_usage table."""
    expiry_time = datetime.now() - timedelta(minutes=SECRET_EXPIRY_MINUTES)
    async with aiosqlite.connect(
        DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES
    ) as db:
        await db.execute("DELETE FROM secrets WHERE upload_time < ?", (expiry_time,))
        cutoff_time = datetime.now() - timedelta(minutes=QUOTA_RENEWAL_MINUTES)
        await db.execute("DELETE FROM ip_usage WHERE last_access < ?", (cutoff_time,))
        await db.commit()


# --- Middleware ---


@web.middleware
async def security_headers_middleware(request, handler):
    response = await handler(request)
    # Set Content Security Policy
    csp = (
        "default-src 'self' {analytics_script_csp}; "
        "script-src 'self' 'unsafe-inline' {analytics_script_csp}; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:;"
    ).format(analytics_script_csp=ANALYTICS_SCRIPT_CSP)
    response.headers["Content-Security-Policy"] = csp
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
    # Limit requests to 0.5MB
    app = web.Application(
        client_max_size=MAX_CLIENT_SIZE, middlewares=[security_headers_middleware]
    )

    aiohttp_jinja2.setup(
        app,
        loader=jinja2.FileSystemLoader("./templates"),
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
    app.router.add_static("/static", "./static")
    app.router.add_get("/{tail:.*}", handle_404)

    # Run initial cleanup
    await purge_expired()

    # Schedule periodic background cleanup
    scheduler = AsyncIOScheduler()
    scheduler.add_job(purge_expired, "interval", minutes=purge_interval_minutes)
    scheduler.start()

    return app


if __name__ == "__main__":
    import asyncio

    app = asyncio.run(create_app())
    web.run_app(app, host="0.0.0.0", port=8080)
