import json
import sqlite3

import aiohttp
import aiosqlite
import pytest_asyncio

import app.app as credshare


# The upload handler reads the multipart body through aiohttp's streaming reader, so it is
# exercised through a real client rather than a dummy request object.
@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch, aiohttp_client):
    monkeypatch.setattr(credshare, "DATABASE_DIR", str(tmp_path))
    monkeypatch.setattr(credshare, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(credshare, "IP_HASH_SALT_PATH", str(tmp_path / "ip_hash_salt"))
    monkeypatch.setattr(credshare, "_ip_hash_salt", None)
    app = await credshare.create_app(purge_interval_minutes=60)
    return await aiohttp_client(app)


def form_with(field_name, value):
    # The browser's FormData always posts multipart/form-data; aiohttp's would fall back to
    # urlencoded for a lone text field.
    data = aiohttp.FormData(default_to_multipart=True)
    data.add_field(field_name, value)
    return data


async def test_upload_secret_creates_record(client):
    # Create a dummy encrypted secret payload.
    test_payload = json.dumps(
        {
            "salt": "dGVzdF9zYWx0",  # "test_salt" in base64.
            "iv": "dGVzdF9pdl9mb3JfdGVzdA==",  # "test_iv_for_test" in base64.
            "ciphertext": "dGVzdF9jaXBoZXJ0ZXh0",  # "test_ciphertext" in base64.
        }
    )

    response = await client.post("/lock", data=form_with("encryptedsecret", test_payload))

    # Verify that the response status is 200 and its text starts with "/unlock/".
    assert response.status == 200, f"Unexpected status: {response.status}"
    download_url = await response.text()
    assert download_url.startswith("/unlock/"), f"Expected a download URL, got: {download_url}"
    assert response.headers["Cache-Control"] == "no-store"

    # Verify that a secret record was created in the database.
    async with aiosqlite.connect(credshare.DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute("SELECT secret, download_code, upload_time FROM secrets") as cursor:
            row = await cursor.fetchone()
            assert row is not None, "No secret record created in the database."
            secret_value, download_code, upload_time = row

            # Check that the stored secret contains the payload we provided.
            assert test_payload in secret_value, "Stored secret does not match the test payload."

            # Verify that the download code in the record matches the one in the response URL.
            assert download_url.endswith(
                download_code
            ), "Download URL does not match the record's download code."


async def test_upload_secret_requires_the_secret_field(client):
    response = await client.post("/lock", data=form_with("something_else", "x"))
    assert response.status == 400
    assert "No secret field" in await response.text()


async def test_upload_secret_rejects_non_multipart_bodies(client):
    response = await client.post("/lock", data={"encryptedsecret": "x"})
    assert response.status == 400
    response = await client.post("/lock", json={"encryptedsecret": "x"})
    assert response.status == 400
