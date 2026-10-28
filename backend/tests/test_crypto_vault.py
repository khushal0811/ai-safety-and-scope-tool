"""Unit tests for Cryptographic Vault Engine (AES-256-GCM) and Vault API."""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.engine.crypto_vault import (
    decrypt_api_key,
    encrypt_api_key,
    get_master_key_bytes,
    mask_api_key,
)
from app.main import app

client = TestClient(app)

TEST_USER_ID = "a56d57aa-1324-4e6b-ad40-de772556d670"
OTHER_USER_ID = "00000000-0000-0000-0000-000000000001"


def test_master_key_derivation():
    """Verify master key derivation returns exactly 32 bytes (256 bits)."""
    key = get_master_key_bytes()
    assert isinstance(key, bytes)
    assert len(key) == 32

    # Custom 64-char hex key
    hex_key = "a" * 64
    derived = get_master_key_bytes(hex_key)
    assert len(derived) == 32
    assert derived == bytes.fromhex(hex_key)


def test_master_key_missing_raises_runtime_error(monkeypatch):
    """Verify missing KEY_VAULT_MASTER_KEY refuses to fall back to public/weak keys."""
    monkeypatch.setattr(settings, "KEY_VAULT_MASTER_KEY", None)
    with pytest.raises(RuntimeError, match="KEY_VAULT_MASTER_KEY is not set"):
        get_master_key_bytes(None)


def test_openrouter_key_encryption_decryption_roundtrip():
    """Verify OpenRouter API key encrypts and decrypts losslessly with user_id AAD."""
    raw_key = "sk-or-v1-abcdef0123456789abcdef0123456789"
    encrypted = encrypt_api_key(raw_key, TEST_USER_ID)

    assert encrypted != raw_key
    assert len(encrypted) > len(raw_key)

    decrypted = decrypt_api_key(encrypted, TEST_USER_ID)
    assert decrypted == raw_key


def test_groq_key_encryption_decryption_roundtrip():
    """Verify Groq API key encrypts and decrypts losslessly with user_id AAD."""
    raw_key = "gsk_9876543210fedcba9876543210fedcba"
    encrypted = encrypt_api_key(raw_key, TEST_USER_ID)

    assert encrypted != raw_key
    assert len(encrypted) > len(raw_key)

    decrypted = decrypt_api_key(encrypted, TEST_USER_ID)
    assert decrypted == raw_key


def test_random_nonce_generation():
    """Verify two encryptions of the exact same key produce different ciphertexts."""
    raw_key = "sk-or-v1-constant_secret_key"
    enc1 = encrypt_api_key(raw_key, TEST_USER_ID)
    enc2 = encrypt_api_key(raw_key, TEST_USER_ID)

    assert enc1 != enc2
    assert decrypt_api_key(enc1, TEST_USER_ID) == raw_key
    assert decrypt_api_key(enc2, TEST_USER_ID) == raw_key


def test_tampered_ciphertext_fails_auth_tag():
    """Verify tampered ciphertext or corrupted data triggers authentication tag failure."""
    raw_key = "sk-or-v1-secure_key"
    encrypted = encrypt_api_key(raw_key, TEST_USER_ID)

    # Tamper with characters in the ciphertext
    tampered = encrypted[:-4] + "AAAA"

    with pytest.raises(ValueError):
        decrypt_api_key(tampered, TEST_USER_ID)


def test_cross_user_aad_mismatch_fails_decryption():
    """Verify ciphertext encrypted for User A cannot be decrypted under User B's identity."""
    raw_key = "sk-or-v1-bound-to-user-a"
    encrypted = encrypt_api_key(raw_key, TEST_USER_ID)

    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_api_key(encrypted, OTHER_USER_ID)


def test_key_masking():
    """Verify key masking shows prefix and suffix while obscuring the secret."""
    or_key = "sk-or-v1-abcdef123456"
    groq_key = "gsk_1234567890abcdef"

    assert mask_api_key(or_key) == "sk-or-…3456"
    assert mask_api_key(groq_key) == "gsk_12…cdef"
    assert mask_api_key("") == ""
    assert mask_api_key(None) == ""
    assert mask_api_key("short") == "••••••"


def test_vault_api_status_guest():
    """Verify guest user returns is_configured=False."""
    res = client.get("/api/vault/status")
    assert res.status_code == 200
    data = res.json()
    assert data["is_configured"] is False
    assert data["has_openrouter_key"] is False


def test_vault_api_invalid_uuid():
    """Verify invalid user_id UUID returns is_configured=False."""
    res = client.get("/api/vault/status?user_id=invalid-uuid")
    assert res.status_code == 200
    data = res.json()
    assert data["is_configured"] is False


def test_vault_api_save_unauthenticated_returns_401():
    """Verify POST /api/vault/keys rejects unauthenticated requests and ignores body user_id."""
    res = client.post(
        "/api/vault/keys",
        json={"user_id": TEST_USER_ID, "openrouter_key": "sk-or-v1-attempt"},
    )
    assert res.status_code == 401


def test_vault_api_production_blocks_header_spoofing(monkeypatch):
    """Verify X-User-Id header spoofing is completely ignored when ENVIRONMENT != 'development'."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    # Attempt to spoof identity on POST /api/vault/keys
    res_save = client.post(
        "/api/vault/keys",
        headers={"X-User-Id": TEST_USER_ID},
        json={"openrouter_key": "sk-or-v1-spoof"},
    )
    assert res_save.status_code == 401

    # Attempt to spoof identity on DELETE /api/vault/keys
    res_del = client.delete(
        f"/api/vault/keys?user_id={TEST_USER_ID}",
        headers={"X-User-Id": TEST_USER_ID},
    )
    assert res_del.status_code == 401

    # Attempt to spoof identity on POST /api/vault/verify-key
    res_ver = client.post(
        "/api/vault/verify-key",
        headers={"X-User-Id": TEST_USER_ID},
        json={},
    )
    assert res_ver.status_code == 401


def test_vault_api_verify_unauthenticated_returns_401():
    """Verify POST /api/vault/verify-key requires authentication."""
    res = client.post("/api/vault/verify-key", json={"openrouter_key": "sk-or-v1-test"})
    assert res.status_code == 401


def test_vault_api_verify_empty_returns_400():
    """Verify POST /api/vault/verify-key rejects authenticated requests with no keys."""
    res = client.post(
        "/api/vault/verify-key",
        headers={"X-User-Id": TEST_USER_ID},
        json={},
    )
    assert res.status_code == 400


def test_vault_api_verify_key_mock_success(monkeypatch):
    """Verify POST /api/vault/verify-key handles 200 OK from OpenRouter."""
    import httpx

    class MockResponse:
        status_code = 200
        text = '{"data":{"label":"Test Key","limit":100,"usage":5}}'

        def json(self):
            return {"data": {"label": "Test Key", "limit": 100, "usage": 5}}

    async def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    res = client.post(
        "/api/vault/verify-key",
        headers={"X-User-Id": TEST_USER_ID},
        json={"openrouter_key": "sk-or-v1-valid-test-key"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert len(data["results"]) == 1
    assert data["results"][0]["valid"] is True
    assert data["results"][0]["provider"] == "OpenRouter"


def test_vault_api_verify_key_mock_unauthorized(monkeypatch):
    """Verify POST /api/vault/verify-key handles 401 Unauthorized from OpenRouter."""
    import httpx

    class MockResponse:
        status_code = 401
        text = '{"error":{"message":"Invalid key"}}'

        def json(self):
            return {"error": {"message": "Invalid key"}}

    async def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    res = client.post(
        "/api/vault/verify-key",
        headers={"X-User-Id": TEST_USER_ID},
        json={"openrouter_key": "sk-or-v1-bad-key"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert len(data["results"]) == 1
    assert data["results"][0]["valid"] is False
    assert data["results"][0]["status_code"] == 401
