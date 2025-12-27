import pytest
import sqlite3
import jinja2
import aiosqlite

from app.app import (
    init_db,
    version_context_processor,
    handle_404,
    APP_KEY,
    VERSION,
    ANALYTICS_SCRIPT,
)


# 1. Test the database initialization.
@pytest.mark.asyncio
async def test_init_db(tmp_path, monkeypatch):
    # Set up a temporary database file.
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()

    # Connect to the database and verify that both tables exist.
    async with aiosqlite.connect(str(db_file), detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute("SELECT name FROM sqlite_master WHERE type='table'") as cursor:
            rows = await cursor.fetchall()
            tables = {row[0] for row in rows}
    assert "secrets" in tables, "Table 'secrets' was not created."
    assert "ip_usage" in tables, "Table 'ip_usage' was not created."


# 2. Test the version context processor.
@pytest.mark.asyncio
async def test_version_context_processor():
    # The processor doesn't really use the request, so a dummy object is sufficient.
    dummy_request = object()
    context = await version_context_processor(dummy_request)
    assert (
        context.get("VERSION") == VERSION
    ), "VERSION in context does not match module-level VERSION."
    assert (
        context.get("ANALYTICS_SCRIPT") == ANALYTICS_SCRIPT
    ), "ANALYTICS_SCRIPT in context does not match module-level value."


# 3. Test the 404 handler.
@pytest.mark.asyncio
async def test_handle_404():
    # Create a dummy Jinja2 environment with a minimal 404 template.
    # The goal of this test is to verify that the 404 handler renders a template and returns the correct status code.
    env = jinja2.Environment(
        loader=jinja2.DictLoader({"404.html": "<html><body>404 Not Found</body></html>"})
    )

    # Create a dummy request that mimics what aiohttp_jinja2.setup() would provide.
    class DummyRequest:
        def __init__(self):
            self.config_dict = {APP_KEY: env}
            # Set app as a dictionary so that __setitem__ works.
            self.app = {APP_KEY: env}

        def get(self, key, default=None):
            return default

    request = DummyRequest()
    response = await handle_404(request)
    assert response.status == 404, f"Expected status 404 but got {response.status}"
    # Check that the rendered text includes content from our dummy 404 template.
    assert "404 Not Found" in response.text, "Rendered 404 page does not contain expected text."
