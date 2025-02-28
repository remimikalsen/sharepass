import pytest
import sqlite3
import json
from datetime import datetime, timedelta

import pytest_asyncio
import aiosqlite

from app.app import time_left, init_db, SECRET_EXPIRY_MINUTES


# Fixture to set up a temporary database.
@pytest_asyncio.fixture
async def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()
    yield str(db_file)


# Dummy request class for time_left endpoint.
class DummyRequest:
    def __init__(self, download_code):
        self.match_info = {'download_code': download_code}
        self.remote = "127.0.0.1"  # Provide a dummy IP.


@pytest.mark.asyncio
async def test_time_left_available(test_db):
    """
    Verify that time_left returns remaining time details for a secret that is still available.
    """
    download_code = "avail123"
    # Insert a secret with an upload_time of now.
    now = datetime.now()
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            ("dummy_id_avail", "dummy secret", 0, download_code, now),
        )
        await db.commit()

    request = DummyRequest(download_code)
    response = await time_left(request)
    assert response.status == 200, f"Expected 200 OK but got {response.status}"
    data = json.loads(response.text)
    assert "hours_left" in data, "Expected 'hours_left' in response"
    assert "minutes_left" in data, "Expected 'minutes_left' in response"
    assert (
        data.get("message") == "The secret is available"
    ), "Unexpected message returned"


@pytest.mark.asyncio
async def test_time_left_expired(test_db):
    """
    Verify that time_left returns a 410 status and an expiry message for an expired secret.
    """
    download_code = "expired123"
    # Insert a secret with an upload_time older than SECRET_EXPIRY_MINUTES.
    past_time = datetime.now() - timedelta(minutes=SECRET_EXPIRY_MINUTES + 1)
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            ("dummy_id_exp", "dummy secret", 0, download_code, past_time),
        )
        await db.commit()

    request = DummyRequest(download_code)
    response = await time_left(request)
    assert (
        response.status == 410
    ), f"Expected 410 for expired secret, got {response.status}"
    data = json.loads(response.text)
    assert (
        data.get("message") == "The secret has already expired."
    ), "Unexpected expiry message"


@pytest.mark.asyncio
async def test_time_left_not_found(test_db):
    """
    Verify that time_left returns a 404 status if no secret is found for the provided download code.
    """
    download_code = "nonexistent"
    request = DummyRequest(download_code)
    response = await time_left(request)
    assert (
        response.status == 404
    ), f"Expected 404 for nonexistent secret, got {response.status}"
    data = json.loads(response.text)
    assert (
        data.get("message") == "Download code not found."
    ), "Unexpected message for not found secret"
