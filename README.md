![Build Status](https://img.shields.io/github/actions/workflow/status/remimikalsen/sharepass/build.yaml)
![License](https://img.shields.io/github/license/remimikalsen/sharepass)
![Version](https://img.shields.io/github/tag/remimikalsen/sharepass)

# CredShare

**CredShare is a simple and secure sharing service for passwords or other secrets.**

CredShare allows you to share sensitive information safely over the internet. Enter your secret and a key to encrypt it in your browser, and you’ll receive a secure, shareable link. Once the secret is unlocked or expires, it’s automatically deleted.

CredShare maintains anonymity while limiting usage by hashing client IP addresses. You can customize quotas, renewal intervals, secret expiry, and more.

CredShare is asynchronous by nature, allowing it to scale efficiently even on modest hardware. For additional scalability, you can deploy multiple CredShare containers behind a load balancer.

> **Note:** CredShare doesn’t encrypt network traffic on its own. For secure transmission, it is recommended to run it behind a reverse proxy (e.g., Nginx or Traefik) that terminates TLS. CredShare reads the `X-Forwarded-For` header to determine the originating client IP.

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
- [Developer Notes](#developer-notes)

## Features

- **Secure Secret Sharing:** Encrypt secrets in your browser before they are sent to the server.
- **One-Time Access:** Secrets are deleted after being viewed or after a set expiry time.
- **Usage Quotas:** Limits on uploads per IP address to prevent abuse.
- **Configurable:** Adjustable settings for expiry, quota renewal, and purge intervals.

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
  -v /sharepass/database:/app/database \
  sharepass-image
```

## Configuration Options

Modify `--env` variables or your `docker-compose.yml` file to match your setup:

- `MAX_USES_QUOTA`: Maximum uploads allowed per IP address (default: 5).
- `MAX_ATTEMPTS`: Maximum number of unlocking attempts (default: 5).
- `SECRET_EXPIRY_MINUTES`: Time in minutes before a secret expires (default: 1440 minutes or 24 hours).
- `QUOTA_RENEWAL_MINUTES`: Interval for resetting the usage quota (default: 60 minutes).
- `PURGE_INTERVAL_MINUTES`: Interval for purging expired secrets (default: 5 minutes).
- `ANALYTICS_SCRIPT`: Complete script tag needed for tracking (default: '').

Ensure that the database directory exists on your system to persist the database.

## Accessing the Web Interface

Visit [http://localhost:8080](http://localhost:8080).

## Developer Notes

### Python dependencies

Set up a Python virtual environment for local development to manage Python package versions correctly:

- `pip-tools` is used to compile canonical requirements in `requirements.in`.
- `requirements.txt` is generated using:

  ```sh
  pip-compile requirements.in
  ```

- To upgrade `requirements.txt`, run:

  ```sh
  pip-compile --upgrade requirements.in
  pip install -r requirements.txt  
  pip-sync requirements.txt
  ```

### Javascript dependencies

Npm is used to manage packages and webpack to bundle a minimal hightlight package.

To upgrade npm packages (although, the latest versions are automatically installed on each docker build):

Safe updates: 

```sh
npm update
```

Update including across major versjons (breaking):

```
npm outdated && npx npm-check-updates -u && npm install
```

NOTE! The the version in package.json will follow the version in the "VERSION" file. This happens in the github actions build step.
