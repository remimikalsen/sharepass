import pytest
from aiohttp import web

from app.app import security_headers_middleware, HTTPS_ONLY, ANALYTICS_SCRIPT_CSP


@pytest.fixture
def minimal_app():
    # Create a minimal aiohttp app that uses only the security middleware.
    app = web.Application(middlewares=[security_headers_middleware])

    # Add a simple route that returns a basic response.
    async def handler(request):
        return web.Response(text="Hello, World!")

    app.router.add_get("/", handler)
    return app


@pytest.mark.asyncio
async def test_security_headers(aiohttp_client, minimal_app):
    # Create a test client using the minimal app.
    client = await aiohttp_client(minimal_app)
    resp = await client.get("/")

    # Verify that the security middleware has added the expected headers.

    # Check the Content Security Policy header.
    csp = resp.headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    # Verify that script-src does NOT contain unsafe-inline (should use nonces instead)
    # For non-template responses, nonce may not be present, but unsafe-inline should still not be in script-src
    script_src_part = csp.split("script-src")[1].split(";")[0] if "script-src" in csp else ""
    assert "'unsafe-inline'" not in script_src_part, "CSP script-src should not contain unsafe-inline"
    # Also verify that your analytics script CSP, if provided, appears.
    if ANALYTICS_SCRIPT_CSP:
        assert ANALYTICS_SCRIPT_CSP in csp

    # Check the Permissions-Policy header.
    permissions_policy = resp.headers.get("Permissions-Policy")
    assert permissions_policy is not None, "Permissions-Policy header is missing"
    assert "geolocation=()" in permissions_policy, "Permissions-Policy should restrict geolocation"

    # Check the X-Content-Type-Options header.
    xcto = resp.headers.get("X-Content-Type-Options")
    assert xcto == "nosniff"

    # Check the X-Frame-Options header.
    xfo = resp.headers.get("X-Frame-Options")
    assert xfo == "SAMEORIGIN"

    # Check the Referrer-Policy header.
    rp = resp.headers.get("Referrer-Policy")
    assert rp == "same-origin"

    # If HTTPS_ONLY is True, the Strict-Transport-Security header should be set.
    if HTTPS_ONLY:
        hsts = resp.headers.get("Strict-Transport-Security")
        assert hsts is not None
    else:
        # Otherwise, it should not be present.
        assert "Strict-Transport-Security" not in resp.headers
