![Test Status](https://img.shields.io/github/actions/workflow/status/remimikalsen/sharepass/tests.yaml?label=tests)
![Coverage Badge](https://raw.githubusercontent.com/remimikalsen/sharepass/refs/heads/main/tests/coverage-badge.svg)
![Build Status](https://img.shields.io/github/actions/workflow/status/remimikalsen/sharepass/build.yaml)
![License](https://img.shields.io/github/license/remimikalsen/sharepass)
![Version](https://img.shields.io/github/tag/remimikalsen/sharepass)

# CredShare

**CredShare is a simple and secure sharing service for passwords or other secrets.**

CredShare allows you to share sensitive information safely over the internet. Enter your secret and a key to encrypt it in your browser, and you’ll receive a secure, shareable link. Once the secret is unlocked or expires, it’s automatically deleted.

CredShare maintains anonymity while limiting usage by hashing client IP addresses. You can customize quotas, renewal intervals, secret expiry, and more.

CredShare is asynchronous by nature, allowing it to scale efficiently even on modest hardware. For additional scalability, you can deploy multiple CredShare containers behind a load balancer.

> **Note:** CredShare doesn’t encrypt network traffic on its own. Run it behind a reverse proxy (e.g., Nginx or Traefik) that terminates TLS, set `HTTPS_ONLY=true` and `PUBLIC_BASE_URL`, and tell CredShare how many proxies sit in front of it with `TRUSTED_PROXY_COUNT` (and optionally which addresses, with `TRUSTED_PROXY_IPS`) so that `X-Forwarded-For` is only believed where it should be. See [Configuration Options](#configuration-options).

## Table of Contents

- [Features](#features)
- [How it Works](#how-it-works)
  - [Create the Secret](#create-the-secret)
  - [Unlocking the Secret](#unlocking-the-secret)
  - [Quota Management](#quota-management)
  - [Secret Expiry and Purging](#secret-expiry-and-purging)
- [Setup and Configuration](#setup-and-configuration)
  - [Using a Pre-Built Image](#using-a-pre-built-image)
  - [Building the Image Yourself](#building-the-image-yourself)
    - [Clone the Repository](#clone-the-repository)
    - [Using Docker Compose](#using-docker-compose)
    - [Using Docker](#using-docker)
- [Configuration Options](#configuration-options)
- [Accessing the Web Interface](#accessing-the-web-interface)
- [API Usage (CLI/curl)](#api-usage-clicurl)
- [Developer Notes](#developer-notes)

## Features

- **Secure Secret Sharing:** Encrypt secrets in your browser before they are sent to the server.
- **One-Time Access:** Secrets are deleted after being viewed or after a set expiry time.
- **Usage Quotas:** Limits on uploads per IP address to prevent abuse.
- **Configurable:** Adjustable settings for expiry, quota renewal, and purge intervals.
- **Private by Design:** No accounts, no cookies, no third-party requests. Fonts and assets are self-hosted, IP addresses are stored only as salted hashes, and the built-in privacy and cookie policies describe exactly what the instance keeps, using its live configuration.
- **Accessible:** WCAG 2.2 AA colour contrast in both light and dark themes, keyboard-friendly forms, screen-reader announcements for every state.

## How it Works

### Create the Secret

1. The user enters the secret and the key for unlocking it.
2. The browser encrypts the secret with the key, generates a unique download code, and stores the encrypted secret in a SQLite database.
3. The user receives a download link that can be used to enter the unlock code.

### Unlocking the Secret

1. Users can unlock a secret using the provided download link.
2. The server verifies the download code and prompts for the unlocking key.
3. If the unlocking key matches, the secret is revealed.
4. The user can choose to copy the secret to the clipboard or view it on screen.
5. The encrypted secret is deleted from the server once unlocked.
6. If the unlocking attempts exceed the limit, the encrypted secret is deleted.
7. The download link is valid for a single use and also expires after a specified time.

### Quota Management

- The app tracks the number of uploads per IP address to enforce a time-based usage quota.
- The quota resets periodically based on the configured interval.

### Secret Expiry and Purging

- Uploaded secrets have an expiry time after which they are deleted.
- A scheduled task periodically purges expired secrets and cleans up the database.

## Setup and Configuration

### Using a Pre-Built Image

If you trust the pre-built images, fetch the latest image and run it:

```sh
docker pull ghcr.io/remimikalsen/credshare:v1
```

Configure it with the parameters indicated below, or use the `docker-compose.yml` example in the repository.

### Building the Image Yourself

If you prefer to build from source for security reasons, follow these steps:

#### Clone the Repository

```sh
git clone https://github.com/remimikalsen/sharepass
```

#### Using Docker Compose

Modify the `docker-compose.yml` file so the build/image section looks like this:

```yaml
services:
  sharepass:
    ...
    container_name: sharepass
    # image: ghcr.io/remimikalsen/credshare:v1
    build:
      context: .
      dockerfile: Dockerfile.sharepass
    ...
```

Then build and run the image:

```sh
cd sharepass
docker compose up -d
```

#### Using Docker

```sh
cd sharepass
docker build -t sharepass-image -f Dockerfile.sharepass .
docker run -d \
  --name sharepass \
  --restart unless-stopped \
  -p 8080:8080 \
  -e MAX_USES_QUOTA=5 \
  -e MAX_ATTEMPTS=5 \
  -e SECRET_EXPIRY_MINUTES=1440 \
  -e QUOTA_RENEWAL_MINUTES=60 \
  -e PURGE_INTERVAL_MINUTES=5 \
  -e TRUSTED_PROXY_COUNT=1 \
  -e PUBLIC_BASE_URL=https://credshare.example \
  -v /sharepass/database:/app/database \
  sharepass-image
```

## Configuration Options

Modify `--env` variables or your `docker-compose.yml` file to match your setup:

- `HTTPS_ONLY`: Set to true to enable the Strict-Transport-Security header and force https in generated links (default: false)
- `PUBLIC_BASE_URL`: Absolute URL clients use to reach the service, e.g. `https://credshare.app`. Used for canonical links, sharing cards, the sitemap and CLI examples. Always set it in production; when empty it is derived from the request headers and a warning is logged at start-up (default: '').
- `TRUSTED_PROXY_COUNT`: Number of reverse proxies that append to `X-Forwarded-For`. `1` for one proxy such as Nginx or Traefik, `0` if clients connect directly. With the wrong value the quota can be bypassed with a forged header (default: 1).
- `TRUSTED_PROXY_IPS`: Optional comma-separated proxy addresses or CIDR ranges. When set, `X-Forwarded-*` headers are only believed for connections from these addresses (default: '').
- `MAX_USES_QUOTA`: Maximum uploads allowed per IP address (default: 5).
- `MAX_ATTEMPTS`: Maximum number of unlocking attempts (default: 5).
- `SECRET_EXPIRY_MINUTES`: Time in minutes before a secret expires (default: 1440 minutes or 24 hours).
- `QUOTA_RENEWAL_MINUTES`: Interval for resetting the usage quota (default: 60 minutes).
- `PURGE_INTERVAL_MINUTES`: Interval for purging expired secrets (default: 5 minutes).
- `ANALYTICS_SCRIPT`: Complete `<script>` tag for cookie-free, anonymised analytics such as Plausible. Only an external script from an allowed domain is accepted; inline code is rejected (default: '').
- `ALLOWED_ANALYTICS_DOMAINS`: Comma-separated domains the analytics script may be loaded from (default: `plausible.remim.com,plausible.io`).
- `ANALYTICS_SCRIPT_CSP`: The https origin of the analytics script, added to the CSP header, e.g. `https://plausible.yourdomain.com` (default: '').

The IP addresses used for the quota are stored as salted hashes. The salt is generated on first start and kept in `ip_hash_salt` next to the database with owner-only permissions, so keep the database directory on a persistent volume.

The container answers `GET /healthz` with 204 for health checks; it is not written to the access log. `/privacy` and `/cookies` describe what the instance stores, with retention figures taken from the configuration above.

Ensure that the database directory exists on your system to persist the database.

## Accessing the Web Interface

Visit [http://localhost:8080](http://localhost:8080). The pages an instance serves:

| Path | Purpose |
|---|---|
| `/` | Share a secret |
| `/unlock/<code>` | Unlock page for a shared secret (`noindex`, never cached) |
| `/privacy`, `/cookies` | Privacy and cookie policy, with figures taken from the configuration |
| `/robots.txt`, `/sitemap.xml` | Only the front page and the policies are offered for indexing |
| `/healthz` | Liveness probe, returns 204 and is excluded from the access log |

The theme button in the header cycles Auto, Light and Dark. Auto follows the operating system and stores nothing; Light and Dark store one word in `localStorage`.

## API Usage (CLI/curl)

Sharepass can also be used as a CLI tool via its API endpoints. Secrets created via the web interface can be retrieved via curl, and vice versa.

### Using the CLI Helper

A Python helper script is provided for easy encryption:

```sh
# Encrypt a secret and generate a curl command
python sharepass_cli.py "my secret" -k "my-key" -o curl

# Or output just the encryption JSON for custom usage
python sharepass_cli.py "my secret" -k "my-key"

# Read secret from stdin
echo "my secret" | python sharepass_cli.py - -k "my-key"
```

### Creating a Secret via API

**Unix/Linux/Mac (bash):**

```sh
# 1. Encrypt the secret using the helper script
ENCRYPTED=$(python sharepass_cli.py "my secret" -k "my-key")

# 2. Create the secret via API (encrypted_secret must be a JSON string)
curl -X POST http://localhost:8080/api/lock \
  -H 'Content-Type: application/json' \
  -d "{\"encrypted_secret\": \"$ENCRYPTED\"}"

# Response: {"download_code": "abc123...", "url": "/unlock/abc123..."}
```

**Windows PowerShell:**

```powershell
# 1. Encrypt the secret using the helper script
$ENCRYPTED = python sharepass_cli.py "my secret" -k "my-key"

# 2. Create the secret via API using Invoke-RestMethod
$body = @{
    encrypted_secret = $ENCRYPTED
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:8080/api/lock `
  -Method Post `
  -ContentType "application/json" `
  -Body $body

# Or using curl.exe explicitly (if available)
curl.exe -X POST http://localhost:8080/api/lock `
  -H "Content-Type: application/json" `
  -d "{\"encrypted_secret\": \"$ENCRYPTED\"}"
```

### Retrieving a Secret via API

**Unix/Linux/Mac (bash):**

```sh
# Unlock and retrieve the secret
curl -X POST http://localhost:8080/api/unlock \
  -H 'Content-Type: application/json' \
  -d '{"download_code": "abc123...", "key": "my-key"}'

# Response: {"secret": "my secret"}
```

**Windows PowerShell:**

```powershell
# Unlock and retrieve the secret using Invoke-RestMethod
$body = @{
    download_code = "abc123..."
    key = "my-key"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:8080/api/unlock `
  -Method Post `
  -ContentType "application/json" `
  -Body $body

# Or using curl.exe explicitly (if available)
curl.exe -X POST http://localhost:8080/api/unlock `
  -H "Content-Type: application/json" `
  -d '{"download_code": "abc123...", "key": "my-key"}'
```

### API Endpoints

- `POST /api/lock` - Create a secret
  - Request: `{"encrypted_secret": "..."}` (JSON string from encryption)
  - Response: `{"download_code": "...", "url": "/unlock/..."}`

- `POST /api/unlock` - Retrieve a secret
  - Request: `{"download_code": "...", "key": "..."}`
  - Response: `{"secret": "..."}` or error message

The encryption format matches the web interface: AES-GCM with PBKDF2 key derivation (100,000 iterations, SHA-256).

## Developer Notes

### Python dependencies

Set up a Python virtual environment for local development to manage Python package versions correctly.

There are two sets of pinned dependencies:

- `requirements.in` / `requirements.txt` — **production** dependencies (used in Docker).
- `requirements-dev.in` / `requirements-dev.txt` — **dev/test** dependencies (pre-commit, pip-tools, pip-audit, pytest, etc.), constrained against the production pins.

#### Initial setup

```sh
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install pip-tools

# Compile both requirement files
pip-compile requirements.in
pip-compile requirements-dev.in

# Install everything for local development
pip-sync requirements.txt requirements-dev.txt
```

#### Upgrading dependencies

```sh
# Upgrade production deps
pip-compile --upgrade requirements.in

# Re-compile dev deps (picks up new production constraints)
pip-compile --upgrade requirements-dev.in

# Audit for known vulnerabilities before installing
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt

# Apply the upgrades
pip-sync requirements.txt requirements-dev.txt
```

#### Production vs. development

- **Production (Docker):** Only `requirements.txt` is installed — the Dockerfile never sees dev dependencies.
- **Local development:** Always sync both files so that `pre-commit`, test tools, and dev utilities stay installed:

  ```sh
  pip-sync requirements.txt requirements-dev.txt
  ```

> **Security note:** Avoid using `pip install --upgrade <package>` directly, as it may pull in untested or incompatible versions. Instead, always use `pip-compile --upgrade` to resolve and pin all dependencies in a reproducible way. Then run `pip-audit` to check for known vulnerabilities before applying them with `pip-sync`. This ensures every upgrade is audited, recorded in version control, and tested before deployment.

### Javascript dependencies

Npm is used to manage packages and webpack to bundle a minimal highlight.js package for the unlock page. Icons are an inline SVG sprite in `base.html` and fonts (Plus Jakarta Sans, JetBrains Mono) are self-hosted from `app/static/fonts`, so nothing else is copied from `node_modules` and a page load makes no third-party request.

Brand assets (favicons, social card) are rendered from `app/static/brand/favicon.svg`. After editing the SVG, regenerate the PNGs with `python dev-tools/render_brand_assets.py` (needs Playwright with Chromium, which the test requirements install). The header mark in `app/templates/base.html` is a copy of the same paths and is updated by hand.

To upgrade npm packages (although, the latest versions are automatically installed on each docker build):

Safe updates:

```sh
npm update
```

Update including across major versjons (breaking):

```
npm outdated && npx npm-check-updates -u && npm install
```
