import pytest
import sqlite3
import json

import pytest_asyncio
import aiosqlite

from app.app import upload_secret, init_db


# Fixture to set up a temporary database.
@pytest_asyncio.fixture
async def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()
    yield str(db_file)


# Dummy classes to simulate a multipart request.
class DummyField:
    def __init__(self, name, text_value):
        self.name = name
        self._text = text_value

    async def text(self):
        return self._text


class DummyMultipart:
    def __init__(self, field):
        self.field = field
        self._returned = False

    async def next(self):
        if not self._returned:
            self._returned = True
            return self.field
        return None


class DummyRequest:
    def __init__(self, field):
        self.field = field
        self.headers = {}
        self.remote = "127.0.0.1"  # Provide a dummy IP.

    async def multipart(self):
        return DummyMultipart(self.field)


@pytest.mark.asyncio
async def test_upload_secret_creates_record(test_db):
    # Create a dummy encrypted secret payload.
    test_payload = json.dumps(
        {
            "salt": "dGVzdF9zYWx0",  # "test_salt" in base64.
            "iv": "dGVzdF9pdl9mb3JfdGVzdA==",  # "test_iv_for_test" in base64.
            "ciphertext": "dGVzdF9jaXBoZXJ0ZXh0",  # "test_ciphertext" in base64.
        }
    )

    # Create a dummy field with name 'encryptedsecret'.
    field = DummyField("encryptedsecret", test_payload)
    # Create a dummy request that will return our field in its multipart().
    request = DummyRequest(field)

    # Call the upload_secret endpoint.
    response = await upload_secret(request)

    # Verify that the response status is 200 and its text starts with "/unlock/".
    assert response.status == 200, f"Unexpected status: {response.status}"
    download_url = response.text
    assert download_url.startswith(
        "/unlock/"
    ), f"Expected a download URL, got: {download_url}"

    # Verify that a secret record was created in the database.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT secret, download_code, upload_time FROM secrets"
        ) as cursor:
            row = await cursor.fetchone()
            assert row is not None, "No secret record created in the database."
            secret_value, download_code, upload_time = row

            # Check that the stored secret contains the payload we provided.
            assert (
                test_payload in secret_value
            ), "Stored secret does not match the test payload."

            # Verify that the download code in the record matches the one in the response URL.
            assert download_url.endswith(
                download_code
            ), "Download URL does not match the record's download code."
