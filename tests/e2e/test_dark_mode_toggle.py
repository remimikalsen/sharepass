import pytest
from playwright.sync_api import Page


@pytest.mark.e2e
def test_dark_mode_toggle(page: Page, base_url: str):
    # Navigate to the home page.
    page.goto(base_url, timeout=10_000)

    # Check initial theme from localStorage.
    initial_theme = page.evaluate("() => localStorage.getItem('theme')")
    # If no theme is saved, the default is "light".
    assert initial_theme in [
        None,
        "light",
    ], f"Expected initial theme to be light, got {initial_theme}"

    # Verify that body does not have the dark class.
    body_has_dark = page.evaluate("() => document.body.classList.contains('dark')")
    assert not body_has_dark, "Expected body not to have 'dark' class initially"

    # Verify that the toggle button shows the moon icon (🌙).
    toggle_text = page.inner_text("#theme-toggle")
    assert toggle_text == "🌙", f"Expected toggle text '🌙', got '{toggle_text}'"

    # Click the toggle button to switch to dark mode.
    page.click("#theme-toggle")

    # Verify that localStorage theme is now "dark".
    new_theme = page.evaluate("() => localStorage.getItem('theme')")
    assert new_theme == "dark", f"Expected localStorage theme to be 'dark', got '{new_theme}'"

    # Check that the body now has the 'dark' class.
    body_has_dark = page.evaluate("() => document.body.classList.contains('dark')")
    assert body_has_dark, "Expected body to have 'dark' class after toggling"

    # Verify that the toggle button text changes to sun icon (☀️).
    toggle_text = page.inner_text("#theme-toggle")
    assert toggle_text == "☀️", f"Expected toggle text '☀️', got '{toggle_text}'"

    # Click the toggle button again to switch back to light mode.
    page.click("#theme-toggle")

    # Verify that localStorage theme is now "light".
    reverted_theme = page.evaluate("() => localStorage.getItem('theme')")
    assert (
        reverted_theme == "light"
    ), f"Expected localStorage theme to be 'light', got '{reverted_theme}'"

    # Verify that the body no longer has the 'dark' class.
    body_has_dark = page.evaluate("() => document.body.classList.contains('dark')")
    assert not body_has_dark, "Expected body not to have 'dark' class after second toggle"

    # Verify that the toggle button text reverts to moon icon (🌙).
    toggle_text = page.inner_text("#theme-toggle")
    assert toggle_text == "🌙", f"Expected toggle text '🌙', got '{toggle_text}'"
