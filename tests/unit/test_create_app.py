import os
import shutil
import pytest
from aiohttp import web
from app.app import create_app


@pytest.mark.asyncio
async def test_create_app(tmp_path):
    # Create a dummy static folder in the temporary directory.
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    # Change the working directory so that './static' resolves correctly.
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        app = await create_app(purge_interval_minutes=999)
        assert isinstance(app, web.Application)

        # Extract canonical route patterns.
        route_patterns = [resource.canonical for resource in app.router.resources()]

        # Expected routes (excluding the catch-all route).
        expected_routes = [
            "/",
            "/lock",
            "/unlock/{download_code}",
            "/unlock_secret",
            "/check-limit",
            "/time-left/{download_code}",
            "/static",
        ]

        # Omitting the tail that should return 404 - not critical for the app.

        for expected in expected_routes:
            assert any(
                expected in pattern for pattern in route_patterns
            ), f"Route {expected} not found."

    finally:
        os.chdir(old_cwd)
        shutil.rmtree(static_dir)
