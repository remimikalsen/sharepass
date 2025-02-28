import pytest
from playwright.sync_api import Page, expect
from app.app import MAX_ATTEMPTS  # Ensure MAX_ATTEMPTS is imported from your app


@pytest.mark.e2e
def test_secret_sharing_flow(page: Page, base_url: str):
    """
    E2E test for the secret sharing flow:
      1. Get initial quota.
      2. Submit a secret and encryption key on the index page.
      3. Verify that the quota is reduced.
      4. Go to the unlock page from the returned link.
      5. Attempt unlocking with a wrong key (expect error).
      6. Verify that the number of remaining attempts is correctly calculated.
      7. Unlock with the correct key and verify that the secret is revealed.
      8. Verify that the secret is deleted after unlocking.
    """

    # Helper to get quota info from /check-limit
    def get_quota_info() -> int:
        with page.expect_response(f"{base_url}/check-limit") as response_info:
            page.goto(f"{base_url}/check-limit", wait_until="networkidle")
        response = response_info.value
        assert response.ok, f"Failed to fetch /check-limit: status {response.status}"
        data = response.json()
        return data.get("quota_left", 0)

    #
    # 1. Check initial quota
    #
    initial_quota = get_quota_info()
    print(f"Initial quota: {initial_quota}")

    #
    # 2. Go to the index page and share a secret.
    #
    page.goto(base_url, timeout=10_000)
    expect(page).to_have_title("CredShare.app - Secure password sharing")

    # Set your test secret and keys.
    secret_text = "This is a test secret."
    correct_key = "correctkey"
    wrong_key = "wrongkey"

    # Fill in the secret (textarea with id "secret")
    page.fill("textarea#secret", secret_text)
    # Fill in the encryption key (input with id "key")
    page.fill("input#key", correct_key)

    # Click the "Share it!" button
    page.click("#upload-button")

    # Wait for either success or error message.
    success_selector = "#success-message"
    error_selector = "#error-message"
    page.wait_for_selector(f"{success_selector}, {error_selector}")

    # If error message is visible, fail the test.
    if page.is_visible(error_selector):
        error_text = page.inner_text(error_selector)
        pytest.fail(f"Secret sharing failed with error: {error_text}")

    # Parse the success message and extract the landing link.
    success_text = page.inner_text(success_selector)
    print("Success message:", success_text)
    landing_link_el = page.locator(".success-link").first
    landing_url = landing_link_el.get_attribute("href")
    assert landing_url, "Landing page link not found in success message."
    print("Landing URL:", landing_url)

    #
    # 3. Check that the quota was reduced by one.
    #
    new_quota = get_quota_info()
    print(f"Quota after sharing: {new_quota}")
    assert (
        new_quota == initial_quota - 1
    ), f"Expected quota to be reduced by 1, but got {new_quota}. Initial was {initial_quota}."

    #
    # 4. Visit the landing (unlock) page.
    #
    page.goto(landing_url, timeout=10_000)
    # Confirm that the page contains the expected header.
    expect(page.locator("h2").first).to_have_text("Unlock the secret")

    #
    # 5. Attempt to unlock the secret using a wrong key.
    #
    page.fill("input#key", wrong_key)
    page.click("#unlock-button")
    # Wait for an error message in the unlock page (e.g. in #download-key-error)
    page.wait_for_selector("#download-key-error", timeout=5000)
    wrong_key_error = page.inner_text("#download-key-error")
    assert wrong_key_error, "Expected an error message when using the wrong key."
    print("Error message for wrong key:", wrong_key_error)

    #
    # 6. Verify that the number of remaining attempts is correctly calculated.
    #
    # After one wrong attempt, the remaining attempts should be MAX_ATTEMPTS - 1.
    expected_remaining = MAX_ATTEMPTS - 1
    assert (
        str(expected_remaining) in wrong_key_error
    ), f"Expected remaining attempts '{expected_remaining}' in error message, got '{wrong_key_error}'"

    #
    # 7. Unlock the secret with the correct key.
    #
    # Clear the wrong key and enter the correct key.
    page.fill("input#key", correct_key)
    page.click("#unlock-button")
    # Wait for the secret to be revealed in the element with id "secret-code"
    page.wait_for_selector("#secret-code", timeout=5000)
    revealed_secret = page.inner_text("#secret-code")
    assert (
        revealed_secret == secret_text
    ), f"Expected secret '{secret_text}' but got '{revealed_secret}'."
    print("Secret successfully revealed:", revealed_secret)

    #
    # 8. Check that the secret is deleted after unlocking.
    #
    # Attempt to unlock the secret again (expect a 404).
    page.wait_for_timeout(3000)
    response = page.goto(landing_url, timeout=5000)
    # Check for a 404 status.
    assert (
        response.status == 404
    ), f"Expected status 404 after unlocking, got {response.status}."
