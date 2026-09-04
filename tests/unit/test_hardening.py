"""Tests for the hardening, SEO and policy routes introduced with the September 2026 redesign."""

import asyncio
import json

import pytest
import pytest_asyncio

import app.app as credshare
from sharepass_cli import encrypt_secret


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch, aiohttp_client):
    monkeypatch.setattr(credshare, "DATABASE_DIR", str(tmp_path))
    monkeypatch.setattr(credshare, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(credshare, "IP_HASH_SALT_PATH", str(tmp_path / "ip_hash_salt"))
    monkeypatch.setattr(credshare, "_ip_hash_salt", None)
    monkeypatch.setattr(credshare, "MAX_USES_QUOTA", 50)
    app = await credshare.create_app(purge_interval_minutes=60)
    return await aiohttp_client(app)


async def _lock(client, secret="hello", key="k"):
    resp = await client.post(
        "/api/lock",
        json={"encrypted_secret": encrypt_secret(secret, key)},
    )
    assert resp.status == 200, await resp.text()
    return (await resp.json())["download_code"]


# --- single-use claim -------------------------------------------------------------


async def test_concurrent_unlocks_release_the_secret_once(client):
    code = await _lock(client, "only once", "k")
    payload = {"download_code": code, "key": "k"}
    responses = await asyncio.gather(
        *[client.post("/api/unlock", json=payload) for _ in range(6)]
    )
    statuses = sorted(r.status for r in responses)
    assert statuses.count(200) == 1, statuses
    assert all(s in (200, 404) for s in statuses)
    landing = await client.get(f"/unlock/{code}")
    assert landing.status == 404


async def test_unlock_landing_is_not_cacheable_and_not_indexed(client):
    code = await _lock(client)
    resp = await client.get(f"/unlock/{code}")
    assert resp.status == 200
    assert resp.headers["Cache-Control"] == "no-store"
    body = await resp.text()
    assert "noindex" in body
    assert code in body
    gone = await client.get("/unlock/AAAAAAAAAAAA")
    assert gone.status == 404
    assert gone.headers["Cache-Control"] == "no-store"


# --- quota key normalisation -----------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("203.0.113.9", "203.0.113.9"),
        ("2001:db8:abcd:1234:aaaa:bbbb:cccc:dddd", "2001:db8:abcd:1234::/64"),
        ("2001:db8:abcd:1234::1", "2001:db8:abcd:1234::/64"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
        ("not-an-ip", "not-an-ip"),
    ],
)
def test_normalize_ip(raw, expected):
    assert credshare.normalize_ip(raw) == expected


def test_ip_hash_is_salted_and_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(credshare, "DATABASE_DIR", str(tmp_path))
    monkeypatch.setattr(credshare, "IP_HASH_SALT_PATH", str(tmp_path / "salt"))
    monkeypatch.setattr(credshare, "_ip_hash_salt", None)
    first = credshare.hash_ip("203.0.113.9")
    assert first == credshare.hash_ip("203.0.113.9")
    # Not a plain SHA-256 of the address.
    import hashlib

    assert first != hashlib.sha256(b"203.0.113.9").hexdigest()
    assert (tmp_path / "salt").stat().st_mode & 0o777 == 0o600
    # A fresh process with the same file derives the same hash.
    monkeypatch.setattr(credshare, "_ip_hash_salt", None)
    assert credshare.hash_ip("203.0.113.9") == first


# --- proxy trust ---------------------------------------------------------------------


class Req:
    def __init__(self, remote="10.0.0.5", headers=None, host="credshare.app", secure=False):
        self.remote = remote
        self.headers = headers or {}
        self.host = host
        self.secure = secure
        self.path = "/"


def test_forwarded_for_uses_rightmost_trusted_hop(monkeypatch):
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_COUNT", 1)
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_IPS", [])
    req = Req(headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7"})
    assert credshare.resolve_client_ip(req) == "198.51.100.7"


def test_forwarded_for_ignored_without_proxy(monkeypatch):
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_COUNT", 0)
    req = Req(headers={"X-Forwarded-For": "1.2.3.4"})
    assert credshare.resolve_client_ip(req) == "10.0.0.5"


def test_forwarded_for_ignored_from_unknown_proxy(monkeypatch):
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_COUNT", 1)
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_IPS", ["172.18.0.0/16"])
    forged = Req(remote="203.0.113.50", headers={"X-Forwarded-For": "1.2.3.4"})
    assert credshare.resolve_client_ip(forged) == "203.0.113.50"
    via_proxy = Req(remote="172.18.0.2", headers={"X-Forwarded-For": "1.2.3.4"})
    assert credshare.resolve_client_ip(via_proxy) == "1.2.3.4"


def test_public_base_url_prefers_config(monkeypatch):
    monkeypatch.setattr(credshare, "PUBLIC_BASE_URL", "https://credshare.app")
    assert credshare.public_base_url(Req(host="evil.example")) == "https://credshare.app"
    monkeypatch.setattr(credshare, "PUBLIC_BASE_URL", "")
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_COUNT", 1)
    monkeypatch.setattr(credshare, "TRUSTED_PROXY_IPS", [])
    req = Req(host="localhost:8080", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "credshare.app"})
    assert credshare.public_base_url(req) == "https://credshare.app"
    assert credshare.public_base_url(Req(host="bad host!")) == ""


# --- cross-site protection ---------------------------------------------------------


async def test_cross_site_lock_is_rejected(client):
    resp = await client.post(
        "/api/lock",
        json={"encrypted_secret": encrypt_secret("x", "k")},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status == 403
    resp = await client.post(
        "/api/lock",
        json={"encrypted_secret": encrypt_secret("x", "k")},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert resp.status == 403


async def test_same_origin_and_headerless_lock_are_allowed(client):
    same = await client.post(
        "/api/lock",
        json={"encrypted_secret": encrypt_secret("x", "k")},
        headers={"Origin": f"http://{client.host}:{client.port}"},
    )
    assert same.status == 200
    curl = await client.post("/api/lock", json={"encrypted_secret": encrypt_secret("x", "k")})
    assert curl.status == 200


# --- analytics validation -----------------------------------------------------------


@pytest.mark.parametrize(
    "script, expected",
    [
        ("", ""),
        ('<script defer data-domain="credshare.app" src="https://plausible.io/js/script.js"></script>',
         '<script src="https://plausible.io/js/script.js" defer data-domain="credshare.app"></script>'),
        ('<script src="https://evil.example/x.js"></script>', ""),
        ('<script src="https://plausible.io/a.js">alert(1)</script>', ""),
        ('<script>alert(1)</script>', ""),
        ('<script src="https://plausible.io/a.js" onload="alert(1)"></script>',
         '<script src="https://plausible.io/a.js"></script>'),
    ],
)
def test_analytics_script_sanitizer(script, expected):
    assert credshare.validate_and_sanitize_analytics_script(script) == expected


def test_csp_origin_validation():
    assert credshare.validate_csp_origin("https://plausible.io") == "https://plausible.io"
    assert credshare.validate_csp_origin("https://a.example:8443") == "https://a.example:8443"
    assert credshare.validate_csp_origin("http://plausible.io") == ""
    assert credshare.validate_csp_origin("https://a.example 'unsafe-inline'") == ""


def test_download_codes_are_redacted_from_logs():
    assert credshare.redact_download_codes("/unlock/AbCdEf123456?x=1") == "/unlock/[code]?x=1"
    assert credshare.redact_download_codes("/time-left/AbCdEf123456") == "/time-left/[code]"
    assert credshare.redact_download_codes("https://credshare.app/unlock/AbCdEf123456") == (
        "https://credshare.app/unlock/[code]"
    )
    assert credshare.redact_download_codes("/privacy") == "/privacy"


# --- headers and routes -------------------------------------------------------------


async def test_csp_has_no_unsafe_inline_and_locks_down_sources(client):
    resp = await client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "style-src 'self'" in csp
    assert "font-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp
    body = await resp.text()
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in body
    assert "Server" not in resp.headers


async def test_seo_and_policy_routes(client):
    robots = await client.get("/robots.txt")
    assert robots.status == 200
    text = await robots.text()
    assert "Disallow: /unlock/" in text and "Disallow: /api/" in text
    sitemap = await client.get("/sitemap.xml")
    assert sitemap.status == 200
    assert "/privacy" in await sitemap.text()
    health = await client.get("/healthz")
    assert health.status == 204
    for page in ("/privacy", "/cookies"):
        resp = await client.get(page)
        assert resp.status == 200
        body = await resp.text()
        assert str(credshare.MAX_ATTEMPTS) in body or page == "/cookies"
        assert "localStorage" in body or page == "/privacy"
    index = await client.get("/")
    body = await index.text()
    assert 'rel="canonical"' in body
    assert 'property="og:image"' in body
    assert "application/ld+json" in body


async def test_fonts_are_served_with_the_right_type(client):
    resp = await client.get("/static/fonts/PlusJakartaSans-400-latin.woff2")
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("font/woff2")


async def test_json_endpoints_are_not_cacheable(client):
    code = await _lock(client)
    for path in ("/check-limit", f"/time-left/{code}"):
        resp = await client.get(path)
        assert resp.status == 200
        assert resp.headers["Cache-Control"] == "no-store"
    resp = await client.post("/unlock_secret", json={"download_code": code, "key": "wrong"})
    assert resp.status == 400
    assert resp.headers["Cache-Control"] == "no-store"
    assert (await resp.json())["attempts_remaining"] == credshare.MAX_ATTEMPTS - 1
