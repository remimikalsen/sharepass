import pytest
import sqlite3
from datetime import datetime
import pytest_asyncio
import aiosqlite
import jinja2

from app.app import unlock_secret_landing, init_db, APP_KEY


# Dummy request class that provides the minimal attributes required by aiohttp_jinja2.
class DummyRequest:
    def __init__(self, download_code):
        self.match_info = {"download_code": download_code}
        self.remote = "127.0.0.1"
        # Create a minimal Jinja2 environment with simple templates.
        # The objective is not to replicate the download template, but to check that the python function passes the correct context to the template.
        env = jinja2.Environment(
            loader=jinja2.DictLoader(
                {
                    "download.html": "<html><body>Download Page: {{ download_code }}</body></html>",
                    "404.html": "<html><body>404 Not Found</body></html>",
                }
            )
        )
        self.config_dict = {APP_KEY: env}
        self.app = {APP_KEY: env}

    # Provide a dummy get() method since render_template calls request.get(...)
    def get(self, key, default=None):
        return default


# Fixture to set up a temporary database.
@pytest_asyncio.fixture
async def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()
    yield str(db_file)


@pytest.mark.asyncio
async def test_unlock_secret_landing_found(test_db):
    download_code = "testcode123"
    now = datetime.now()
    # Insert a secret record into the temporary DB.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            ("dummy_id", "dummy secret", 0, download_code, now),
        )
        await db.commit()

    # Create a dummy request with the matching download code.
    request = DummyRequest(download_code)
    response = await unlock_secret_landing(request)
    content = response.text
    assert "Download Page:" in content, "Expected the download page to be rendered."
    assert (
        download_code in content
    ), "The download code should appear in the rendered page."


@pytest.mark.asyncio
async def test_unlock_secret_landing_not_found(test_db):
    download_code = "nonexistent"
    # Do not insert any secret record for this code.
    request = DummyRequest(download_code)
    response = await unlock_secret_landing(request)
    assert response.status == 404, "Expected a 404 response for a nonexistent secret."
    content = response.text
    assert "404 Not Found" in content, "Expected the 404 template to be rendered."
