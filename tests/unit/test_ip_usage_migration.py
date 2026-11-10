import sqlite3
from datetime import datetime, timedelta

import aiosqlite
import pytest

import app.app as credshare

LEGACY_SCHEMA = "CREATE TABLE ip_usage (ip TEXT, uses INTEGER NOT NULL, last_access DATETIME NOT NULL)"


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setattr(credshare, "DATABASE_PATH", str(path))
    return str(path)


async def _pk_columns(path):
    async with aiosqlite.connect(path) as db:
        async with db.execute("PRAGMA table_info(ip_usage)") as cursor:
            return [row[1] for row in await cursor.fetchall() if row[5]]


async def test_store_secret_works_on_legacy_ip_usage_without_primary_key(db_path):
    # Reproduces production: a table without the constraint made the upsert raise
    # "ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint".
    async with aiosqlite.connect(db_path) as db:
        await db.execute(LEGACY_SCHEMA)
        await db.commit()
    await credshare.init_db()

    code, error, status = await credshare.store_secret("ciphertext", "1.2.3.4")
    assert (error, status) == (None, 200)
    assert code


async def test_init_db_migrates_legacy_ip_usage_and_merges_duplicates(db_path):
    now = datetime.now()
    old = now - timedelta(minutes=5)
    async with aiosqlite.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(LEGACY_SCHEMA)
        await db.executemany(
            "INSERT INTO ip_usage (ip, uses, last_access) VALUES (?, ?, ?)",
            [("a", 2, old), ("a", 4, now), ("b", 1, now)],
        )
        await db.commit()

    await credshare.init_db()
    await credshare.init_db()  # idempotent

    assert await _pk_columns(db_path) == ["ip"]
    async with aiosqlite.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute("SELECT ip, uses, last_access FROM ip_usage ORDER BY ip") as cursor:
            rows = await cursor.fetchall()
    assert rows == [("a", 4, now), ("b", 1, now)]


async def test_store_secret_resets_stale_window(db_path):
    await credshare.init_db()
    stale = datetime.now() - timedelta(minutes=credshare.QUOTA_RENEWAL_MINUTES + 1)
    async with aiosqlite.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        await db.execute(
            "INSERT INTO ip_usage (ip, uses, last_access) VALUES (?, ?, ?)",
            ("ip", credshare.MAX_USES_QUOTA, stale),
        )
        await db.commit()

    _, error, status = await credshare.store_secret("ciphertext", "ip")
    assert (error, status) == (None, 200)
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT uses FROM ip_usage WHERE ip='ip'") as cursor:
            assert await cursor.fetchall() == [(1,)]
