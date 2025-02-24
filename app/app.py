from apscheduler.schedulers.asyncio import AsyncIOScheduler
from aiohttp import web
from datetime import datetime, timedelta
import os
import sqlite3
import uuid
import random
import string
import aiohttp_jinja2
import jinja2
import hashlib
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VERSION_FILE_PATH = os.path.join(os.path.dirname(__file__), 'VERSION')
VERSION = "unknown"

if os.path.isfile(VERSION_FILE_PATH):
    with open(VERSION_FILE_PATH, 'r') as version_file:
        VERSION = version_file.read().strip() or "unknown"
else:
    parent_dir_version_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'VERSION')
    if os.path.isfile(parent_dir_version_path):
        with open(parent_dir_version_path, 'r') as version_file:
            VERSION = version_file.read().strip() + "-development"
    else:
        VERSION = "unknown"

# Load configuration from environment variables
MAX_USES_QUOTA = int(os.getenv('MAX_USES_QUOTA', 5))  # Default to 5 uses per day
SECRET_EXPIRY_MINUTES = int(os.getenv('SECRET_EXPIRY_MINUTES', 1440))  # Default to 1440 minutes (24 hours)
QUOTA_RENEWAL_MINUTES = int(os.getenv('QUOTA_RENEWAL_MINUTES', 60))  # Default to 60 minutes (1 hour)
PURGE_INTERVAL_MINUTES = int(os.getenv('PURGE_INTERVAL_MINUTES', 5))  # Default to purge every 5 minutes
MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 5))  # Defaults to 5 attemps
ANALYTICS_SCRIPT = os.getenv('ANALYTICS_SCRIPT', '')

DATABASE_DIR = '/app/database'
DATABASE_PATH = os.path.join(DATABASE_DIR, 'secrets.db')
APP_KEY = 'aiohttp_jinja2_environment'

# Ensure the database directory exist
os.makedirs(DATABASE_DIR, exist_ok=True)


def adapt_datetime_iso(val):
    """Adapt datetime.datetime to timezone-naive ISO 8601 date."""
    return val.isoformat()
sqlite3.register_adapter(datetime, adapt_datetime_iso)

def convert_datetime(val):
    """Convert ISO 8601 datetime to datetime.datetime object."""
    return datetime.fromisoformat(val.decode())
sqlite3.register_converter("DATETIME", convert_datetime)



# Initialize the database
conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS secrets
             (id TEXT PRIMARY KEY, secret TEXT, attempts INTEGER, download_code TEXT, upload_time DATETIME)''')
c.execute('''CREATE TABLE IF NOT EXISTS ip_usage
             (ip TEXT, uses INTEGER, last_access DATETIME)''')
conn.commit()


# Define a context processor to add VERSION and ANALYTICS_SCRIPT to all templates
async def version_context_processor(_):
    return {
        'VERSION': VERSION, 
        'ANALYTICS_SCRIPT': ANALYTICS_SCRIPT
    }


def hash_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

def get_client_ip(request):
    """Retrieve the client's IP address from the request."""
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # The X-Forwarded-For header can contain multiple IPs, the first one is the client's original IP
        ip = forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote
    return hash_ip(ip)

def ip_reached_quota(ip):
    """Check the IP usage and delete the record if it has expired."""
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute("SELECT uses, last_access FROM ip_usage WHERE ip=?", (ip,))
    result = c.fetchone()
    current_time = datetime.now()

    if result:
        uses, last_access = result

        if last_access < (current_time - timedelta(minutes=QUOTA_RENEWAL_MINUTES)):
            # Reset the usage count for a new day
            c.execute("DELETE FROM ip_usage WHERE ip=?", (ip,))
            conn.commit()
            conn.close()
            return False
        elif int(uses) >= MAX_USES_QUOTA:
            conn.close()
            return True

    conn.close()
    return False
    
def generate_download_code(length=12):
    """Generate a random download code."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

async def index(request):
    ip = get_client_ip(request)
    secret_expiry_hours = SECRET_EXPIRY_MINUTES // 60
    secret_expiry_minutes = SECRET_EXPIRY_MINUTES % 60

    context = {
        'secret_expiry_hours': secret_expiry_hours,
        'secret_expiry_minutes': secret_expiry_minutes,
        'max_attempts': MAX_ATTEMPTS
    }
    return aiohttp_jinja2.render_template('index.html', request, context, app_key=APP_KEY)


async def upload_secret(request):
    ip = get_client_ip(request)
    if ip_reached_quota(ip):
        return web.Response(text="You have exceeded the maximum number of shares for today.", status=429)

    reader = await request.multipart()

    field = await reader.next()

    if field.name != 'encryptedsecret':
        return web.Response(text="No secret field in form.", status=400)

    secret = await field.text()

    # Generate a unique secret ID and create the path
    secret_id = str(uuid.uuid4())
    download_code = generate_download_code()

    # Store the secret info in the database
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    upload_time = datetime.now()
    c.execute("INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)", (secret_id, secret, 0, download_code, upload_time))

    # Incrment the usage count for the IP
    c.execute("SELECT 1 FROM ip_usage WHERE ip=?", (ip,))
    result = c.fetchone()
    if result:
        c.execute("UPDATE ip_usage SET uses=uses+1, last_access=? WHERE ip=?", (upload_time, ip))
    else:
        c.execute("INSERT INTO ip_usage (ip, uses, last_access) VALUES (?, 1, ?)", (ip, upload_time))
    
    conn.commit()
    conn.close()

    # Generate the download link
    download_url = f"/unlock/{download_code}"

    return web.Response(text=download_url)

async def unlock_secret_landing(request):
    download_code = request.match_info['download_code']

    # Retrieve the secret info from the database
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute("SELECT secret FROM secrets WHERE download_code=?", (download_code,))
    result = c.fetchone()
    if result:
        secret = result[0]
        download_link = f"/unlock/{download_code}"
        context = {
            'download_link': download_link,
            'download_code': download_code,
            'max_attempts': MAX_ATTEMPTS
        }
       
        conn.commit()

        conn.close()
        return aiohttp_jinja2.render_template('download.html', request, context, app_key=APP_KEY)

    conn.close()

    # Code not found 
    response = aiohttp_jinja2.render_template('404.html', request, {}, app_key=APP_KEY)
    response.set_status(404)
    return response



async def unlock_secret(request):
    """
    Expects JSON data with:
      - "download_code": the secret identifier (from the URL or embedded in the page)
      - "key": the user-supplied decryption key.
    
    Attempts to decrypt the secret stored in the DB. On failure, increments the
    attempts counter and deletes the secret after 3 failed tries.
    """
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON."}, status=400)

    download_code = data.get("download_code")
    key = data.get("key")
    
    if not download_code or not key:
        return web.json_response({"error": "Missing download_code or key."}, status=400)

    # Retrieve the encrypted secret and current attempt count from the database.
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute("SELECT secret, attempts FROM secrets WHERE download_code=?", (download_code,))
    row = c.fetchone()
    if not row:
        conn.close()
        return web.json_response({"error": "Secret not found or already unlocked."}, status=404)
    
    encrypted_secret_json, attempts = row

    try:
        # Parse the JSON string stored in the DB.
        encrypted_data = json.loads(encrypted_secret_json)
        salt = base64.b64decode(encrypted_data['salt'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Derive the AES-GCM key using PBKDF2 with the same parameters as in the client.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,             # 256-bit key
            salt=salt,
            iterations=100000,     # same iteration count used on the client
            backend=default_backend()
        )
        aes_key = kdf.derive(key.encode())  # key derived from the provided password
        
        # Decrypt using AESGCM. Note: the additional authenticated data (AAD) is None.
        aesgcm = AESGCM(aes_key)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
        decrypted_secret = decrypted_bytes.decode()
    except Exception as e:
        # Decryption failed (likely a wrong key). Increment the attempt counter.
        attempts += 1
        if attempts >= MAX_ATTEMPTS:
            # Delete the secret after MAX_ATTEMPTS failed attempts.
            c.execute("DELETE FROM secrets WHERE download_code=?", (download_code,))
        else:
            c.execute("UPDATE secrets SET attempts=? WHERE download_code=?", (attempts, download_code))
        conn.commit()
        conn.close()
        return web.json_response({"error": "Incorrect key."}, status=400)
    
    # Decryption succeeded, so delete the secret record.
    c.execute("DELETE FROM secrets WHERE download_code=?", (download_code,))
    conn.commit()
    conn.close()

    # Return the decrypted secret.
    return web.json_response({"secret": decrypted_secret})



async def handle_404(request):
    response = aiohttp_jinja2.render_template('404.html', request, {}, app_key=APP_KEY)
    response.set_status(404)
    return response

async def check_limit(request):
    ip = get_client_ip(request)

    ip_reached_quota(ip) # To delete expired records

    quota_left = MAX_USES_QUOTA
    current_time = datetime.now()
    next_quota_renewal = (current_time + timedelta(minutes=QUOTA_RENEWAL_MINUTES)) - current_time
    
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute("SELECT uses, last_access FROM ip_usage WHERE ip=?", (ip,))
    result = c.fetchone()

    if result:
        uses, last_access = result

        if last_access >= (current_time - timedelta(minutes=QUOTA_RENEWAL_MINUTES)):
            quota_left = MAX_USES_QUOTA - uses
            next_quota_renewal = last_access + timedelta(minutes=QUOTA_RENEWAL_MINUTES) - current_time

    conn.close()

    quota_renewal_hours = int(next_quota_renewal.total_seconds() // 3600)
    quota_renewal_minutes = int((next_quota_renewal.total_seconds() % 3600) // 60)

    if ip_reached_quota(ip):
        return web.json_response({"limit_reached": True,
                                  "quota_left": quota_left,
                                  "quota_renewal_hours": quota_renewal_hours,
                                  "quota_renewal_minutes": quota_renewal_minutes})
    else:
        return web.json_response({"limit_reached": False,
                                  "quota_left": quota_left,
                                  "quota_renewal_hours": quota_renewal_hours,
                                  "quota_renewal_minutes": quota_renewal_minutes})

async def time_left(request):
    download_code = request.match_info['download_code']

    # Retrieve the secret info from the database
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    c.execute("SELECT upload_time FROM secrets WHERE download_code=?", (download_code,))
    result = c.fetchone()
    conn.close()

    if result:
        upload_time = result[0]
        expiry_time = upload_time + timedelta(minutes=SECRET_EXPIRY_MINUTES)
        current_time = datetime.now()
        time_left = expiry_time - current_time

        if time_left.total_seconds() > 0:
            hours_left = int(time_left.total_seconds() // 3600)
            minutes_left = int((time_left.total_seconds() % 3600) // 60)
            return web.json_response({
                "hours_left": hours_left,
                "minutes_left": minutes_left,
                "message": "The secret is available"
            })
        else:
            return web.json_response({
                "message": "The secret has already expired."
            }, status=410)
    else:
        return web.json_response({
            "message": "Download code not found."
        }, status=404)

def purge_expired():
    """Delete secrets older than the configured expiry time and clean up the ip_usage database."""
    expiry_time = datetime.now() - timedelta(minutes=SECRET_EXPIRY_MINUTES)
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()

    # Delete old secrets
    c.execute("DELETE FROM secrets WHERE upload_time < ?", (expiry_time,))

    # Clean up ip_usage database
    cutoff_time = datetime.now() - timedelta(minutes=QUOTA_RENEWAL_MINUTES)
    #cutoff_time = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')
    c.execute("DELETE FROM ip_usage WHERE last_access < ?", (cutoff_time,))

    conn.commit()
    conn.close()


async def create_app(purge_interval_minutes=PURGE_INTERVAL_MINUTES):
    app = web.Application()
    
    # Setup Jinja2 with the application key
    aiohttp_jinja2.setup(
        app,
        loader=jinja2.FileSystemLoader('./templates'),
        app_key=APP_KEY,
        context_processors=[version_context_processor]
    )
    
    # Define routes in the correct order
    app.router.add_get('/', index)
    app.router.add_post('/lock', upload_secret)
    app.router.add_get('/unlock/{download_code}', unlock_secret_landing)
    app.router.add_post('/unlock_secret', unlock_secret)
    app.router.add_get('/check-limit', check_limit)
    app.router.add_get('/time-left/{download_code}', time_left)
    app.router.add_static('/static', './static')
    app.router.add_get('/{tail:.*}', handle_404)

    # Perform cleanup and consistency check on startup
    purge_expired()

    # Schedule the background cleanup task using APScheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(purge_expired, 'interval', minutes=purge_interval_minutes)
    scheduler.start()

    return app

if __name__ == '__main__':
    web.run_app(create_app(), host='0.0.0.0', port=8080)