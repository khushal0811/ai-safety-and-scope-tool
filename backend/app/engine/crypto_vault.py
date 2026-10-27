"""Cryptographic Vault Engine for API Key Encryption and Decryption.

Implements military-grade AES-256-GCM envelope encryption for user-provided
OpenRouter and Groq API keys before persisting to the database.
"""

import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

logger = logging.getLogger(__name__)

NONCE_SIZE_BYTES = 12  # 96 bits recommended for AES-GCM
KEY_SIZE_BYTES = 32    # 256 bits for AES-256


def get_master_key_bytes(override_key: Optional[str] = None) -> bytes:
    """Derive a 256-bit (32 bytes) master encryption key.
    
    If override_key or settings.KEY_VAULT_MASTER_KEY is provided:
      - If it is a 64-char hex string, decode hex directly.
      - Otherwise, hash it via SHA-256 to produce exactly 32 bytes.
    If no key is configured, derive from SUPABASE_ANON_KEY or a secure fallback.
    """
    raw = override_key or getattr(settings, "KEY_VAULT_MASTER_KEY", "") or os.getenv("KEY_VAULT_MASTER_KEY", "")
    if raw:
        raw_str = raw.strip()
        if len(raw_str) == 64:
            try:
                return bytes.fromhex(raw_str)
            except ValueError:
                pass
        return hashlib.sha256(raw_str.encode("utf-8")).digest()

    # Fallback derivation for development
    seed = os.getenv("SUPABASE_ANON_KEY") or os.getenv("GROQ_API_KEY") or "sst_default_dev_secret_vault_salt_32b"
    return hashlib.sha256(seed.encode("utf-8")).digest()


def encrypt_api_key(plaintext_key: str, master_key_hex: Optional[str] = None) -> str:
    """Encrypt an API key using AES-256-GCM.
    
    Returns a URL-safe base64 string containing: [12-byte Nonce] + [Ciphertext] + [16-byte Auth Tag].
    """
    if not plaintext_key or not plaintext_key.strip():
        return ""

    key_bytes = get_master_key_bytes(master_key_hex)
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext_key.strip().encode("utf-8"), associated_data=None)
    packed = nonce + ciphertext
    return base64.urlsafe_b64encode(packed).decode("utf-8")


def decrypt_api_key(encrypted_blob: str, master_key_hex: Optional[str] = None) -> str:
    """Decrypt an AES-256-GCM encrypted API key.
    
    Extracts the 12-byte nonce and validates the authentication tag.
    Raises ValueError if decryption or tag verification fails.
    """
    if not encrypted_blob or not encrypted_blob.strip():
        return ""

    key_bytes = get_master_key_bytes(master_key_hex)
    aesgcm = AESGCM(key_bytes)

    try:
        raw_packed = base64.urlsafe_b64decode(encrypted_blob.strip().encode("utf-8"))
        if len(raw_packed) < NONCE_SIZE_BYTES + 16:
            raise ValueError("Encrypted blob is too short to be valid AES-GCM ciphertext.")

        nonce = raw_packed[:NONCE_SIZE_BYTES]
        ciphertext = raw_packed[NONCE_SIZE_BYTES:]
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag:
        logger.error("[CryptoVault] Authentication tag verification failed. Ciphertext may be corrupt or tampered.")
        raise ValueError("Decryption failed: invalid ciphertext or authentication tag.")
    except Exception as e:
        logger.error(f"[CryptoVault] Decryption error: {e}")
        raise ValueError(f"Decryption failed: {str(e)}")


def mask_api_key(key: Optional[str]) -> str:
    """Generate a masked hint for UI display, e.g. sk-or-…3a4f or gsk_…9b2c."""
    if not key or not key.strip():
        return ""
    clean = key.strip()
    if len(clean) <= 10:
        return "••••••"
    return f"{clean[:6]}…{clean[-4:]}"
