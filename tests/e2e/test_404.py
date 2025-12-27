import pytest
from playwright.sync_api import Page


@pytest.mark.e2e
def test_404_page(page: Page, base_url: str):
    """
    Test that navigating to a non-existent route displays the 404 page.
    """
    # Navigate to a non-existent URL.
    page.goto(f"{base_url}/this-route-does-not-exist", timeout=10_000)

    # Wait for the page to load and then check that the content indicates a 404 error.
    # Adjust the selector or text check as appropriate for your 404 page.
    content = page.content()
    assert "404 - Page Not Found" in content, "Expected 404 message was not found on the page."
