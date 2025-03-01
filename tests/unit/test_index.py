import pytest
import jinja2
from app.app import index, APP_KEY, SECRET_EXPIRY_MINUTES, MAX_ATTEMPTS


# Dummy request for index endpoint.
class DummyRequest:
    def __init__(self):
        # Create a dummy Jinja2 environment with a simple index.html template.
        # This template simply outputs the context variables.
        # The goal of this test is to see that the index function passes the correct context to the template.
        env = jinja2.Environment(
            loader=jinja2.DictLoader(
                {
                    "index.html": (
                        "<html><body>"
                        "Index Page: secret_expiry_hours={{ secret_expiry_hours }}, "
                        "secret_expiry_minutes={{ secret_expiry_minutes }}, "
                        "max_attempts={{ max_attempts }}"
                        "</body></html>"
                    )
                }
            )
        )
        self.config_dict = {APP_KEY: env}
        self.app = {APP_KEY: env}

    # Provide a get() method if needed by the renderer.
    def get(self, key, default=None):
        return default


@pytest.mark.asyncio
async def test_index_renders():
    request = DummyRequest()
    response = await index(request)
    # Verify the status and rendered content.
    assert response.status == 200
    text = response.text

    expected_hours = SECRET_EXPIRY_MINUTES // 60
    expected_minutes = SECRET_EXPIRY_MINUTES % 60
    expected_attempts = MAX_ATTEMPTS

    # Check that the rendered output contains the expected context values.
    assert f"secret_expiry_hours={expected_hours}" in text
    assert f"secret_expiry_minutes={expected_minutes}" in text
    assert f"max_attempts={expected_attempts}" in text
