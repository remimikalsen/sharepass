import pytest
from playwright.sync_api import Page


@pytest.mark.e2e
def test_404_page(page: Page, base_url: str):
    """Navigating to a non-existent route shows the 404 page with a 404 status."""
    response = page.goto(f"{base_url}/this-route-does-not-exist", timeout=10_000)
    assert response.status == 404
    assert "Page not found" in page.content(), "Expected 404 message was not found on the page."
    assert "noindex" in page.content()
