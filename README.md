# CredShare.app

**CredShare.app is a simple and secure sharing service for password or other secrets.**

With CredShare.app, you can safely share passwords or other secrets over the internet. Enter the secret you want to share, plus a simple key for unlocking the secret. You will get a shareable, secure link back. The provided link is valid for a limited amount of time. You can share the link, or use it yourself, but once the secret is unlocked, it's deleted.

CredShare.app is anonymous, but still limits usage through hashing the client IP and storing it in the CredShare.app database. Quotas, quota renewal, locked secrets expiration and much more can be customized.

CredShare.app doesnt' by itself encrypt traffic, but it's easy enouth to put it behind a reverse proxy like Nginx or Traefik. CredShare.app will read the X-Forwarded-For headers to get the origining client's IP address.


## How does it work?

### Create the secret

- The user enters the secret and the key for unlocking it.
- The browser then encrypts the secret with the key, generates a unique download code, and stores the encrypted secret in a SQLite database.
- The user receives a download link that can be used to enter the unlock code.

### Unlocking the secret

- Users can unlock a secret using the provided download link.
- The server verifies the download code, and asks for the unlocking key.
- If the unlocking key matches the secret will be made available to the user.
- The user can choose to copy the secret to the clipboard, or view it on screen.
- The encrypted secret will be deleted from the server once unlocked
- The encrypted secret will be deleted from the server after a configurable amount of unsuccessful unlocking attempts.
- The download link is valid for a single use and also expires after a specified time.

### Quota management

- The app tracks the number of uploads per IP address to enforce a time based usage quota.
- The quota is reset periodically based on the configured interval.

### Secret expiry and purging

- Uploaded secrets have an expiry time after which they are deleted.
- A scheduled task periodically purges expired secrets and cleans up the database.

## Setup and configuration instructions

### Clone the repository

```
git clone https://github.com/remimikalsen/sharepass
```

### Docker compose
```
cd sharepass
docker compose up -d
```

### Docker only assure clean build
```
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


### Configuration
Change --env variables and your local paths in the docker command or in docker-compose.yml to reflect your setup.

- `MAX_USES_QUOTA`: Maximum number of uploads allowed per IP address (default: 5).
- `MAX_ATTEMPTS`: Maxium number of attempts at unlocking the secret (default: 5).
- `SECRET_EXPIRY_MINUTES`: Time in minutes after which a secret expires (default: 1440 minutes or 24 hours).
- `QUOTA_RENEWAL_MINUTES`: Interval in minutes for resetting the usage quota (default: 60 minutes).
- `PURGE_INTERVAL_MINUTES`: Interval in minutes for purging expired secrets and cleaning up the datbase (default: 5 minutes).
- `ANALYTICS_SCRIPT`: The complete script tag needed for tracking from e.g. Plausible (default: '').

These environment variables allow the app to be configured for different deployment scenarios and usage patterns.

Make sure that the database directory exists on your computer to persist the database.

## Accessing the web interface

Visit http://localhost:8080



## TODO
Make Plausible optional and configurable, instead of hardcoded
Streamline and standardize inclusion of static assets (highlights with webpack and feather)
Clean up code
