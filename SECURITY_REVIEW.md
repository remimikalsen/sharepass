# Security Review - CredShare (sharepass)

**Review date:** 2026-10-31 (section 0; the September 2026 review follows unchanged except where marked)
**Reviewer:** AI-assisted security audit (Claude), verified locally with pip-audit, npm audit, bandit, OpenGrep, Trivy (repository and image), flake8, the unit suite (60 tests) and the Playwright end-to-end suite (5 tests)
**Project:** CredShare, version 1.3.18 at the time of review, branch `security-update-oct-2026`

---

## Executive summary

CredShare is a small aiohttp service for one-time secret sharing. Secrets are encrypted in the browser with AES-256-GCM under a PBKDF2-derived key; the server stores ciphertext, the recipient submits the key once, and the row is deleted on unlock. The fundamentals from the previous review still hold: parameterised SQL, autoescaped templates, nonce-based CSP, a non-root container, and automated scanning in CI.

This review went a level deeper alongside the September 2026 redesign and found one high and several medium weaknesses, all fixed in the same change set with regression tests. A focused review of the finished branch found no further high or medium issues; three low-severity observations remain open and are listed below.

**Overall security grade after remediation: A-**. Residual risks are inherent to an anonymous secret-sharing service and are listed in section 9.

---

## 0. October 2026 update

Two months after the redesign, the dependency scanners reported new advisories and a code review of the request paths found concurrency and resource-limit gaps that scanners cannot see. Every finding below was reproduced with a failing test before the fix; the regression tests are in `tests/unit/test_hardening.py` and `tests/unit/test_create_secret.py`.

| Severity | Finding | Fix |
|----------|---------|-----|
| High | aiohttp 3.14.3 carried nine advisories: denial of service via a missing initial request timeout (CVE-2026-111064), file-descriptor exhaustion in multipart handling (CVE-2026-111066), unbounded memory and CPU use (GHSA-2g87-pp6c-29x5), request smuggling through ambiguous framing (CVE-2026-111750), scheme spoofing (CVE-2026-111748) and three cookie issues. multidict 6.7.1 leaked memory in items-view operations (CVE-2026-104874) | aiohttp 3.14.5, multidict 7.2.1, cryptography 50.0.2 (wheels rebuilt against OpenSSL 4.0.3); `requirements.txt` recompiled with pip-compile |
| High | `/lock` read the multipart body through `request.multipart()`, which aiohttp does not cover with `client_max_size`. A single oversized field was buffered in full before the size check in `store_secret`, so one request could consume hundreds of megabytes | The declared `Content-Length` is checked first and the field is read in chunks with a cap; both paths answer 413. A non-multipart body now gets 400 instead of raising a 500 |
| Medium | The wrong-key counter was read, then written back as count + 1. Concurrent wrong keys all read the same count, so a burst of 20 attempts left the counter at 1 and `MAX_ATTEMPTS` could be bypassed indefinitely | The attempt is reserved atomically: `UPDATE … SET attempts = attempts + 1 … RETURNING` runs before decryption, so each request consumes exactly one attempt |
| Medium | The share quota was check-then-insert. Twelve concurrent shares against a quota of three all succeeded | The quota is checked again and counted inside a `BEGIN IMMEDIATE` transaction in `store_secret` |
| Medium | The purge scheduler was started inside `create_app()`, which `__main__` ran under `asyncio.run()`. That loop is closed before `web.run_app` starts the serving loop, so the periodic purge never fired: only the start-up purge ran, and expired secrets and quota rows stayed in the database until the next restart. Verified with a one-minute interval: a stale row survived 80 s | The scheduler starts from `on_startup` on the serving loop, `run_app` awaits the factory, and a test checks the job is bound to the running loop. Re-run of the probe: the stale row was gone after the first interval |
| Medium | An expired secret that the purge had not yet removed could still be unlocked (noted as open in September) | Expiry is enforced in the unlock statement itself |
| Medium | The builder stage used `node:25-alpine`; Node 25 reached end of life on 1 June 2026 and receives no security fixes | `node:26-alpine` (active LTS since 28 October 2026, supported to April 2029) |
| Medium | `python:3.14-slim` lagged behind Debian: 14 HIGH findings with fixes published (openssl, libsqlite3, libpcre2, gzip, perl-base), and the three perl-base CRITICAL entries in `.trivyignore` now have fixes | `apt-get upgrade` in the final image stage; the `.trivyignore` entries were removed, so the file is empty again |
| Low | The three open observations from section 2: the access log printed the resolved address verbatim, and a `Host` with an out-of-range port raised inside `URL.build` and returned 500 | `loggable_client_ip()` parses the address and logs `-` otherwise; `ValueError` is caught in `public_base_url` and `sitemap_xml` |
| Low | With fewer `X-Forwarded-For` entries than `TRUSTED_PROXY_COUNT`, the leftmost (client-supplied) entry was used | Falls back to the peer address |
| Low | JSON bodies that parsed but were not objects (a list, a string) raised inside the handlers and returned 500 | `read_json_object()` answers 400 |
| Low | PBKDF2 key derivation ran on the event loop for every unlock attempt, stalling all other requests for tens of milliseconds each | Runs in a worker thread via `asyncio.to_thread` |
| Low | No `Cross-Origin-Opener-Policy` | `same-origin` added to the header set |
| Info | The pip-audit fallback in `security.yaml` used `--format table`, which pip-audit rejects, so a failing audit printed usage text instead of the findings | `--format columns` |
| Info | `tests.yaml` asked for `contents: write` but only uploads artifacts | `contents: read` |
| Info | No Dependabot (open since September); GitHub Actions pins were one to two releases behind | `.github/dependabot.yml` for pip, npm, GitHub Actions and Docker; setup-node, upload-artifact, create-github-app-token, setup-buildx and codeql-action re-pinned to current SHAs |
| Info | npm: moderate advisory in fast-uri (build-time only, via webpack); dev tooling carried advisories in filelock, urllib3 and virtualenv | `npm audit fix`, webpack 5.112; `requirements-dev.txt` recompiled |

Verification on the review date: pip-audit clean for both requirement files; `npm audit` 0 findings; bandit and OpenGrep (`--config auto`, 498 rules) clean; `trivy fs` clean; `trivy image` on the rebuilt image 0 CRITICAL and 0 HIGH with a fix available; 60 unit tests and 5 end-to-end tests pass; the image was started with the compose hardening flags and exercised over HTTP (lock, wrong key, unlock, repeat unlock, list body, urlencoded body, 900 KB multipart, forged `X-Forwarded-For`).

**Still open after this update:** security-event logging (section 9); base image digests not pinned (Dependabot now proposes digest updates once pins exist); the PBKDF2 iteration count of 100 000 is below the current OWASP guidance of 600 000 for PBKDF2-HMAC-SHA256. Raising it requires an `iterations` field in the envelope so that secrets stored under the old count remain unlockable, and multiplies the per-unlock CPU cost accordingly; it is a design change rather than a patch and is left for a separate change.

---

## 1. Findings fixed in the redesign (September 2026)

Regression tests: `tests/unit/test_hardening.py`, `tests/e2e/test_no_third_party_requests.py`.

| Severity | Finding | Fix |
|----------|---------|-----|
| High | `X-Forwarded-For` was trusted unconditionally and the *leftmost* entry used, so any client could forge its IP and bypass the share quota | `TRUSTED_PROXY_COUNT` (rightmost trusted hop) and optional `TRUSTED_PROXY_IPS`; start-up warning when unrestricted |
| Medium | Single use was not atomic: two concurrent requests with the right key both received the secret | The `DELETE` after decryption decides the winner; a zero row count returns 404 |
| Medium | Quota keyed on the exact IPv6 address, giving a /64 holder 2^64 identities | IPv6 normalised to its /64 network before hashing |
| Medium | IP hashes were unsalted SHA-256, reversible for IPv4 by enumeration | HMAC-SHA-256 with a per-instance secret stored 0600 next to the database |
| Medium | `ANALYTICS_SCRIPT` was rendered verbatim (`\|safe`), allowing arbitrary inline script via configuration; `ANALYTICS_SCRIPT_CSP` spliced into the CSP unvalidated | Script rebuilt from an allowlist (external src on an allowed domain, `defer`/`async`/`data-*` only); CSP origin validated as a single https origin |
| Low | CSP carried `'unsafe-inline'` for styles and lacked `object-src`, `base-uri`, `form-action`, `frame-ancestors` | `style-src 'self'; font-src 'self'` plus the missing directives; all inline `style` attributes removed from templates |
| Low | No cross-site check on `/lock`; a third-party page could drain a visitor's quota with a simple multipart POST | `Sec-Fetch-Site` plus `Origin` fallback on every state-changing endpoint; header-less clients (curl) still allowed |
| Low | Unlock landing page, 404 page and per-client JSON were cacheable | `Cache-Control: no-store` |
| Low | Compose published port 8080 on all interfaces while trusting `X-Forwarded-For`; container had no `read_only`, `cap_drop` or `no-new-privileges`; pip left in the image | Port bound to `127.0.0.1`, hardening options added, application code root-owned, pip removed |
| Info | Health check rendered the front page every 30 s and filled the access log; access log showed the proxy's address | `/healthz` (204, not logged); access logger reports the resolved client IP and redacts unlock codes from path and referrer |
| Info | No index on `secrets.download_code` | Index created at start-up |
| Medium | `app/database/` was not excluded from the Docker build context, so a local SQLite file and the per-instance IP-hash salt from the build machine were copied into the image as root-owned files. The container then failed to start with a read-only database, and the salt would have been shared by every deployment built from that machine | `app/database/` added to `.dockerignore`; the Dockerfile removes and recreates the directory empty before handing it to `appuser` |

## 2. Open observations from the branch review (low severity)

A separate review of the finished branch, focused on newly introduced code, found no high or medium issues. These three remained open in September; the first two were fixed in October (section 0), the third stands:

| Severity | Observation | Recommendation |
|----------|-------------|----------------|
| Low | The access logger writes the resolved client address verbatim. With `TRUSTED_PROXY_IPS` empty (the default), a client that reaches the app directly controls that field, so escape sequences or fake fields can be planted in the IP column. Newlines are blocked by aiohttp; compose binds to loopback | Parse with `ipaddress.ip_address()` and log `-` when it does not parse |
| Low | `public_base_url` accepts a `Host` such as `x.y:99999` past its regex, then `yarl.URL.build` raises on the out-of-range port inside the template context processor, turning any HTML request with that header into a 500. No traceback is exposed | Catch `ValueError` and return an empty base URL |
| Low | When `PUBLIC_BASE_URL` is unset, `X-Forwarded-Host` from any connection is reflected (escaped) into the canonical link, Open Graph URL and sitemap. Impact is limited to canonical poisoning behind a shared cache | Already mitigated by the start-up warning and documentation; set `PUBLIC_BASE_URL` in production |

---

## 3. Dependency security

- **Python:** `requirements.txt` is pinned via pip-compile; dev and test tooling live in `requirements-dev.txt` and are not installed in the image. `pip-audit -r requirements.txt` reported no known vulnerabilities on the review date. pip-audit and bandit run in `.github/workflows/security.yaml` and as pre-commit hooks.
- **JavaScript:** `.npmrc` sets `ignore-scripts=true`, `strict-ssl=true`, `audit-level=high` and `package-lock=true`. `npm audit --audit-level=high` runs in the Dockerfile before install and in every workflow. The only runtime dependency is highlight.js (core plus JSON and YAML grammars); `feather-icons` and `prismjs` were removed in the redesign. The `glob` override remains.
- GitHub Actions are pinned to full commit SHAs with the version in a trailing comment (done 2026-09-04; the previous `trivy-action@0.33.1` reference pointed at a tag that does not exist, the tag is `v0.33.1`). Dependabot was added in October 2026 for pip, npm, GitHub Actions and Docker base images.

## 4. Scanning and CI

Verified present in the workflows:

- Trivy filesystem and image scans (`security.yaml`, `build.yaml`), SARIF uploaded to the GitHub Security tab, build fails on CRITICAL findings; `.trivyignore` is empty.
- OpenGrep SAST and secret scanning, SARIF upload.
- npm audit, pip-audit and bandit as described above.
- Pre-commit hooks: Trivy, OpenGrep, pip-audit, bandit, private-key detection, YAML/JSON/TOML validation, black and flake8 on `app/`.
- SBOMs in CycloneDX and SPDX format generated from the built image and attached to releases.

## 5. Container and deployment

- Multi-stage build; only the webpack bundle is copied from the Node stage, never `node_modules`.
- Final image: `python:3.14-slim`, non-root `appuser`, application code owned by root and read-only to the app, only `/app/database` writable (SQLite file and the IP-hash salt), pip removed after install, `PYTHONDONTWRITEBYTECODE=1`.
- Health check calls `/healthz` on loopback with Python only (no curl in the image).
- `docker-compose.yml`: port bound to `127.0.0.1`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, `tmpfs /tmp`, database on a named volume.
- The redesign kit (`redesign/`) and development files are excluded from the build context via `.dockerignore`.
- **Base images:** `node:26-alpine` (since October 2026; Node 25 went end of life in June 2026) and `python:3.14-slim`. The final stage runs `apt-get upgrade` so Debian security updates published after the base image are included. **Open:** base image digests are not pinned.
- **Accepted base-image findings:** the three `perl-base` CRITICAL CVEs accepted in September (CVE-2026-13221, CVE-2026-42496, CVE-2026-8376) were fixed by Debian in October and are pulled in by the upgrade step; `.trivyignore` is empty again. What remains in the Debian layer is a tail of HIGH findings in essential system packages (util-linux, ncurses, systemd libraries) that Debian marks as affected with no fix. Everything installed by the application itself (Python packages) is clean, and `setuptools` in the image is current.
- **Recommendation:** terminate TLS at a reverse proxy, set `HTTPS_ONLY=true`, `PUBLIC_BASE_URL`, `TRUSTED_PROXY_COUNT` to match the number of proxies and, where possible, `TRUSTED_PROXY_IPS`.

## 6. Application configuration and headers

- **Content-Security-Policy:** `default-src 'self'; script-src 'self' 'nonce-…'; style-src 'self'; font-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'`, plus the validated analytics origin when configured. No `'unsafe-inline'` anywhere. The nonce is generated per request in the middleware and read by the template context processor.
- Also set: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: same-origin`, `Permissions-Policy` (geolocation, camera, microphone, payment, USB, sensors and media features denied), `Strict-Transport-Security` when `HTTPS_ONLY=true`. The `Server` header is removed.
- `Cache-Control: no-store` on the unlock page, the 404 page, every JSON endpoint and every unlock response.
- **Cross-site requests:** `/lock`, `/unlock_secret`, `/api/lock` and `/api/unlock` reject `Sec-Fetch-Site: cross-site`, `Origin: null` and any `Origin` that does not match the instance's host, trusted forwarded host or `PUBLIC_BASE_URL`. Clients that send neither header (curl) are allowed, so no CORS configuration is needed or provided.
- `HTTPS_ONLY` defaults to `false` so that local and plain-HTTP development works. This is deliberate and documented; production deployments must set it.

## 7. Input validation, injection and output encoding

- Download codes are validated as exactly 12 alphanumeric characters before any database access. They are generated with `secrets.choice` from a 62-character alphabet (about 71 bits).
- Keys are limited to `MAX_KEY_LENGTH` characters; request bodies to `MAX_CLIENT_SIZE`; stored ciphertext to `MAX_SECRET_SIZE`. JSON endpoints require `Content-Type: application/json`.
- All SQL is parameterised. No shell, subprocess, pickle, YAML or `eval` use.
- Jinja2 autoescaping is on (verified in the installed `aiohttp_jinja2`). Every server-provided value reaches the templates in attribute or text context; the JSON-LD block uses only the base URL, which is either the trusted `PUBLIC_BASE_URL` or a host that passed a strict character allowlist.
- Client-side DOM is built with `textContent`, `createTextNode` and `replaceChildren`. The one `innerHTML` assignment takes highlight.js output, which escapes its input before wrapping tokens; plain text falls back to `textContent`. Server values are read from `data-` attributes rather than interpolated into script.
- The analytics `<script>` tag from configuration is rebuilt from an allowlist of attributes and domains; inline code is rejected.

## 8. Cryptography and data protection

- **Client-side encryption:** AES-256-GCM with a random 12-byte nonce; key derived with PBKDF2-HMAC-SHA-256, 100 000 iterations, random 16-byte salt. The browser, the CLI helper and the server-side decrypt use identical parameters.
- **Unlock:** the recipient's key is used in memory for one request; neither key nor plaintext is written to disk or logs. Deletion on success is immediate and atomic. After `MAX_ATTEMPTS` wrong keys the row is deleted.
- **Expiry:** expired rows are removed by the purge job every `PURGE_INTERVAL_MINUTES`; the unlock handler does not itself check age, so an expired secret remains unlockable until the next purge run. Stated in the privacy policy; a code fix would be a few lines if a hard cut-off is wanted.
- **IP addresses:** stored only as HMAC-SHA-256 of the normalised address (IPv6 reduced to /64) under a per-instance secret created `O_EXCL` with mode 0600. Records are deleted about `QUOTA_RENEWAL_MINUTES` after the last share.
- **Secrets in the repository:** none. Configuration is via environment variables; scanning by OpenGrep, Trivy and the private-key pre-commit hook.

## 9. Logging and privacy

- Custom access logger prints the resolved client IP, method, path, status, size, referrer and user agent. Unlock codes are redacted from path and referrer. `/healthz` is not logged. Request bodies are never logged.
- No page load makes a third-party request: fonts, styles, scripts and images are self-hosted, proven by an end-to-end test that records every request. Analytics, when enabled, is limited to allowlisted cookie-free hosts and disclosed in both policies.
- `robots.txt` disallows every URL that names or consumes a secret; the unlock and 404 pages are `noindex`.
- The privacy and cookie policies (`/privacy`, `/cookies`) were reviewed against the code on the review date and take their retention figures from configuration. The theme toggle stores nothing unless Light or Dark is chosen.
- **Open:** there is no dedicated security-event logging (failed unlock attempts, quota rejections); only the access log line with its status code records them.

## 10. Residual risks (accepted)

- **Server-side decryption by design.** The recipient sends the key to the server to unlock. The server therefore handles the plaintext for one request. This is inherent to the current API and stated in the privacy policy; an end-to-end design with browser-side decryption would remove it.
- **Offline brute force of weak passphrases.** Anyone holding a database copy can attempt passphrases offline; PBKDF2 at 100 000 iterations slows but does not prevent this. The policy words this as "cannot read it without the key".
- Naive local timestamps: a DST change shifts deadlines by an hour.
- In-memory salt fallback when the database directory is unwritable resets quotas on restart.
- Clients behind large NATs share one quota.
- Unfixed Debian CVEs in essential packages of the base image, listed above; re-evaluate when Debian ships fixes or when the base image changes.

---

## Priority recommendations

Items 1, 2, 4 and 6 of the September list were done in October 2026 (section 0). Remaining:

**Medium**
1. Add security-event logging for failed unlocks and quota rejections, or rely on the access log by policy.
2. Raise the PBKDF2 iteration count with a versioned envelope (section 0).

**Low**
3. Pin base image digests.

---

## Security checklist

- [x] npm audit, pip-audit, bandit in CI and pre-commit
- [x] Trivy filesystem and image scanning, OpenGrep SAST, SBOM generation
- [x] Non-root container, root-owned code, read-only root filesystem, no capabilities
- [x] CSP without `'unsafe-inline'`, full directive set, per-request nonces
- [x] Full security header set, `Server` header removed
- [x] Cross-site request rejection on state-changing endpoints
- [x] Salted IP hashing, IPv6 /64 normalisation
- [x] Proxy trust configuration for `X-Forwarded-For`
- [x] Atomic single-use unlock
- [x] Self-hosted assets, zero third-party requests, verified by test
- [x] Privacy and cookie policies checked against code
- [x] Request size enforced on the multipart upload path
- [x] Atomic attempt counting and quota accounting
- [x] Periodic purge verified to run on the serving loop
- [ ] Security-event logging
- [x] Actions pinned to commit SHAs
- [x] Dependabot
- [ ] Base image digests pinned

---

## Testing performed

- Unit tests: 48, including 16 added for the hardening (proxy trust, IPv6 normalisation, salted hashing, concurrent unlock, cross-site rejection, analytics sanitiser, CSP origin validation, log redaction, header and route checks, font MIME type, `no-store`).
- End-to-end (Playwright): 5, including the theme toggle's three states and the zero-third-party-request check with self-hosted fonts loaded.
- `pip-audit -r requirements.txt`: no known vulnerabilities. `flake8` and `black`: clean.
- Manual header inspection with curl; WCAG contrast computed for every colour pair in both themes.
- `trivy fs` (vuln, secret, misconfig; all severities, dev dependencies included): clean. `trivy image` on the built image: 0 CRITICAL after the accepted `perl-base` entries; no fixable HIGH findings. OpenGrep SAST (`--config auto`): clean after three fixes (curl-to-shell replaced with `gh api`, `min-release-age=7` in `.npmrc`, sitemap built with ElementTree).
- The built image was started with the compose hardening flags (`read_only`, `cap_drop ALL`, `no-new-privileges`, tmpfs `/tmp`, database volume) and exercised over HTTP.

## Manual testing recommendations

1. Behind the real proxy, send a share with a forged `X-Forwarded-For: 1.2.3.4` and confirm the quota is still tracked per real client.
2. Unlock the same link from two clients at the same moment and confirm exactly one receives the secret.
3. Confirm the access log shows `/unlock/[code]` rather than the real code, and that `/healthz` never appears.

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
