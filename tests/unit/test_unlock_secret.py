import os
import json
import base64
import sqlite3
from datetime import datetime

import pytest
import pytest_asyncio
import aiosqlite

from app.app import unlock_secret, init_db, MAX_ATTEMPTS

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Fixture to set up a temporary database.
@pytest_asyncio.fixture
async def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.app.DATABASE_PATH", str(db_file))
    await init_db()
    yield str(db_file)


# Helper function to mimic the encryption logic.
def encrypt_secret_for_test(secret: str, key: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    aes_key = kdf.derive(key.encode())
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, secret.encode(), None)
    encrypted_data = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    return json.dumps(encrypted_data)


# Dummy request class to simulate a JSON POST request.
class DummyJSONRequest:
    def __init__(self, data):
        self._data = data
        self.remote = "127.0.0.1"  # Provide a dummy IP.

    async def json(self):
        return self._data


@pytest.mark.asyncio
async def test_unlock_secret_success(test_db):
    """
    Test that the unlock_secret endpoint successfully decrypts and deletes the secret
    when the correct key is provided.
    """
    secret_text = "This is a top secret message."
    correct_key = "supersecret"
    download_code = "testcode123"  # Arbitrary download code.

    # Encrypt the secret using our helper.
    encrypted_payload = encrypt_secret_for_test(secret_text, correct_key)

    # Insert the secret record manually into the database.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        now = datetime.now()
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            ("dummy_id", encrypted_payload, 0, download_code, now),
        )
        await db.commit()

    # Create a dummy request with the correct key.
    request_data = {"download_code": download_code, "key": correct_key}
    request = DummyJSONRequest(request_data)

    # Call the unlock_secret handler.
    response = await unlock_secret(request)
    result = json.loads(response.text)

    # Verify that the secret is correctly decrypted.
    assert "secret" in result, f"Expected decrypted secret in response, got {result}"
    assert (
        result["secret"] == secret_text
    ), f"Expected secret '{secret_text}' but got '{result['secret']}'"

    # Verify that the record has been deleted.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT * FROM secrets WHERE download_code=?", (download_code,)
        ) as cursor:
            row = await cursor.fetchone()
    assert row is None, "Secret record was not deleted after successful unlock."


@pytest.mark.asyncio
async def test_unlock_secret_wrong_key(test_db):
    """
    Test that the unlock_secret endpoint returns an error with remaining attempts
    when an incorrect key is provided.
    """
    secret_text = "This is another secret."
    correct_key = "correctkey"
    wrong_key = "wrongkey"
    download_code = "testcode456"

    # Encrypt the secret using our helper.
    encrypted_payload = encrypt_secret_for_test(secret_text, correct_key)

    # Insert the secret record manually into the database with 0 attempts.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        now = datetime.now()
        await db.execute(
            "INSERT INTO secrets (id, secret, attempts, download_code, upload_time) VALUES (?, ?, ?, ?, ?)",
            ("dummy_id2", encrypted_payload, 0, download_code, now),
        )
        await db.commit()

    # Create a dummy request with the wrong key.
    request_data = {"download_code": download_code, "key": wrong_key}
    request = DummyJSONRequest(request_data)

    # Call the unlock_secret handler.
    response = await unlock_secret(request)
    result = json.loads(response.text)

    # Verify that an error is returned.
    assert "error" in result, f"Expected an error message, got {result}"
    expected_remaining = MAX_ATTEMPTS - 1  # After one wrong attempt.
    assert (
        result.get("attempts_remaining") == expected_remaining
    ), f"Expected remaining attempts {expected_remaining}, got {result.get('attempts_remaining')}"

    # Verify that the attempts count was updated in the database.
    async with aiosqlite.connect(test_db, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        async with db.execute(
            "SELECT attempts FROM secrets WHERE download_code=?", (download_code,)
        ) as cursor:
            row = await cursor.fetchone()
    assert row is not None, "Secret record should still exist after wrong attempt."
    attempts_in_db = row[0]
    assert attempts_in_db == 1, f"Expected attempts count 1, got {attempts_in_db}"
