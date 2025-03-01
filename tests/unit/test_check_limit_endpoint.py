import json
import pytest
import sqlite3
from datetime import datetime

import pytest_asyncio
import aiosqlite

from app.app import check_limit, init_db, MAX_USES_QUOTA, hash_ip


@pytest_asyncio.fixture
async def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()
    yield str(db_file)


# Dummy request class for check_limit.
class DummyRequestForCheckLimit:
    def __init__(self, ip):
        self.headers = {"X-Forwarded-For": ip}
        self.remote = ip


@pytest.mark.asyncio
async def test_check_limit(test_db):
    ip = "127.0.0.1"
    ip_hash = hash_ip(ip)
    now = datetime.now()

    # Insert a record with 2 uses.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            "INSERT INTO ip_usage (ip, uses, last_access) VALUES (?, ?, ?)",
            (ip_hash, 2, now),
        )
        await db.commit()

    request = DummyRequestForCheckLimit(ip)
    response = await check_limit(request)
    data = json.loads(response.text)
    expected_quota = MAX_USES_QUOTA - 2
    assert (
        data.get("quota_left") == expected_quota
    ), f"Expected quota_left {expected_quota}, got {data.get('quota_left')}"
