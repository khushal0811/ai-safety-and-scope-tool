"""Unit tests for Cryptographic Vault Engine (AES-256-GCM) and Vault API."""

import pytest
from fastapi.testclient import TestClient

from app.engine.crypto_vault import (
    decrypt_api_key,
    encrypt_api_key,
    get_master_key_bytes,
    mask_api_key,
)
from app.main import app

client = TestClient(app)


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


def test_openrouter_key_encryption_decryption_roundtrip():
    """Verify OpenRouter API key encrypts and decrypts losslessly."""
    raw_key = "sk-or-v1-abcdef0123456789abcdef0123456789"
    encrypted = encrypt_api_key(raw_key)

    assert encrypted != raw_key
    assert len(encrypted) > len(raw_key)

    decrypted = decrypt_api_key(encrypted)
    assert decrypted == raw_key


def test_groq_key_encryption_decryption_roundtrip():
    """Verify Groq API key encrypts and decrypts losslessly."""
    raw_key = "gsk_9876543210fedcba9876543210fedcba"
    encrypted = encrypt_api_key(raw_key)

    assert encrypted != raw_key
    assert len(encrypted) > len(raw_key)

    decrypted = decrypt_api_key(encrypted)
    assert decrypted == raw_key


def test_random_nonce_generation():
    """Verify two encryptions of the exact same key produce different ciphertexts."""
    raw_key = "sk-or-v1-constant_secret_key"
    enc1 = encrypt_api_key(raw_key)
    enc2 = encrypt_api_key(raw_key)

    assert enc1 != enc2
    assert decrypt_api_key(enc1) == raw_key
    assert decrypt_api_key(enc2) == raw_key


def test_tampered_ciphertext_fails_auth_tag():
    """Verify tampered ciphertext or corrupted data triggers authentication tag failure."""
    raw_key = "sk-or-v1-secure_key"
    encrypted = encrypt_api_key(raw_key)

    # Tamper with characters in the ciphertext
    tampered = encrypted[:-4] + "AAAA"

    with pytest.raises(ValueError):
        decrypt_api_key(tampered)


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


def test_vault_api_save_invalid_uuid():
    """Verify POST /api/vault/keys rejects invalid UUID."""
    res = client.post("/api/vault/keys", json={"user_id": "not-a-uuid", "openrouter_key": "sk-or-..."})
    assert res.status_code == 400
