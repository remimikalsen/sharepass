import pytest
from playwright.sync_api import Page
from urllib.parse import urlparse


@pytest.mark.e2e
def test_page_load_makes_no_third_party_requests(page: Page, base_url: str):
    """The privacy policy claims fonts and assets are self-hosted; prove it."""
    origin_host = urlparse(base_url).netloc
    external = []

    def on_request(request):
        host = urlparse(request.url).netloc
        if host and host != origin_host:
            external.append(request.url)

    page.on("request", on_request)
    for path in ("/", "/privacy", "/cookies", "/nope"):
        page.goto(f"{base_url}{path}", wait_until="networkidle", timeout=10_000)
    assert external == [], f"Unexpected third-party requests: {external}"

    # The self-hosted fonts actually loaded (checked on the front page, which uses both families).
    page.goto(f"{base_url}/", wait_until="networkidle", timeout=10_000)
    loaded = page.evaluate(
        """async () => {
          await document.fonts.ready;
          return [...document.fonts].filter(f => f.status === 'loaded').map(f => f.family);
        }"""
    )
    assert any("Plus Jakarta Sans" in f for f in loaded), f"Plus Jakarta Sans not loaded: {loaded}"
    assert any("JetBrains Mono" in f for f in loaded), f"JetBrains Mono not loaded: {loaded}"
    assert external == [], f"Unexpected third-party requests: {external}"
