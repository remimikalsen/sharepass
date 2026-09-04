import pytest
from playwright.sync_api import Page


@pytest.mark.e2e
def test_theme_toggle_cycles_auto_light_dark(page: Page, base_url: str):
    """The header button cycles Auto -> Light -> Dark -> Auto.

    Auto stores nothing (the localStorage key is removed) and sets no data-theme;
    Light and Dark store one word and set data-theme on <html>.
    """
    page.goto(base_url, timeout=10_000)

    def stored():
        return page.evaluate("() => localStorage.getItem('theme')")

    def attr():
        return page.evaluate("() => document.documentElement.getAttribute('data-theme')")

    def label():
        return page.inner_text("#theme-toggle").strip()

    # Default: Auto, nothing stored, no explicit theme.
    assert stored() is None
    assert attr() is None
    assert label().endswith("Auto")

    page.click("#theme-toggle")
    assert stored() == "light"
    assert attr() == "light"
    assert label().endswith("Light")

    page.click("#theme-toggle")
    assert stored() == "dark"
    assert attr() == "dark"
    assert label().endswith("Dark")

    # Back to Auto: the stored key must be deleted, not set to "auto".
    page.click("#theme-toggle")
    assert stored() is None
    assert attr() is None
    assert label().endswith("Auto")

    # A stored choice is applied before first paint on the next load.
    page.click("#theme-toggle")
    page.click("#theme-toggle")
    assert stored() == "dark"
    page.reload()
    assert attr() == "dark"
    assert label().endswith("Dark")
