import pytest
import sqlite3
from datetime import datetime, timedelta

import pytest_asyncio
import aiosqlite

from app.app import purge_expired, init_db, SECRET_EXPIRY_MINUTES


@pytest_asyncio.fixture
async def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()
    yield str(db_file)


@pytest.mark.asyncio
async def test_purge_expired(test_db):
    now = datetime.now()
    expired_time = now - timedelta(minutes=SECRET_EXPIRY_MINUTES + 1)

    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        # Insert an expired secret.
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            ("expired_secret", "dummy secret", 0, "code_expired", expired_time),
        )
        # Insert an expired ip_usage record.
        await db.execute(
            "INSERT INTO ip_usage (ip, uses, last_access) VALUES (?, ?, ?)",
            ("expired_ip", 5, expired_time),
        )
        await db.commit()

    # Run purge_expired.
    await purge_expired()

    # Verify that the expired secret is removed.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT * FROM secrets WHERE id=?", ("expired_secret",)
        ) as cursor:
            secret_row = await cursor.fetchone()
        async with db.execute(
            "SELECT * FROM ip_usage WHERE ip=?", ("expired_ip",)
        ) as cursor:
            ip_row = await cursor.fetchone()

    assert secret_row is None, "Expired secret was not purged."
    assert ip_row is None, "Expired ip_usage record was not purged."
