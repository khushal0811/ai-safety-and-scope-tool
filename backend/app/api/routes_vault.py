"""API routes for encrypted User API Vault.

Provides endpoints to securely store, verify, and revoke encrypted user API keys
(OpenRouter and custom Groq keys) using AES-256-GCM.
"""

import logging
import time
from typing import List, Optional
import httpx

from fastapi import APIRouter, Depends, HTTPException, Header, Query
from pydantic import BaseModel, Field

from app.api.deps import get_authenticated_user_id, require_authenticated_user_id
from app.db.supabase_client import (
    get_user_vault_keys,
    get_user_vault_status,
    is_valid_uuid,
    revoke_user_vault_keys,
    save_user_vault_keys,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vault", tags=["API Key Vault"])


class KeyVerificationItem(BaseModel):
    """Validation result for a specific provider key."""

    provider: str
    valid: bool
    status_code: int
    message: str
    latency_ms: float
    details: Optional[dict] = None


class VerifyKeyRequest(BaseModel):
    """Request payload to test validity of entered or stored API keys."""

    openrouter_key: Optional[str] = Field(None, description="OpenRouter API key to test")
    groq_key: Optional[str] = Field(None, description="Groq API key to test")
    user_id: Optional[str] = Field(None, description="Authenticated user UUID")


class VerifyKeyResponse(BaseModel):
    """Response containing provider verification results."""

    success: bool
    results: List[KeyVerificationItem]


class VaultKeysPayload(BaseModel):
    """Payload for saving encrypted user API keys."""

    user_id: Optional[str] = Field(None, description="Authenticated user UUID")
    openrouter_key: Optional[str] = Field(None, description="OpenRouter API key (sk-or-v1-...)")
    groq_key: Optional[str] = Field(None, description="Custom Groq API key (gsk_...)")


class VaultStatusResponse(BaseModel):
    """Response containing vault configuration status and masked hints."""

    is_configured: bool
    has_openrouter_key: bool
    openrouter_hint: Optional[str] = None
    has_groq_key: bool
    groq_hint: Optional[str] = None


@router.get("/status", response_model=VaultStatusResponse)
async def get_vault_status(
    user_id: Optional[str] = Depends(get_authenticated_user_id),
):
    """Check whether the user has encrypted keys configured in their vault."""
    if not user_id or not is_valid_uuid(user_id):
        return VaultStatusResponse(
            is_configured=False,
            has_openrouter_key=False,
            openrouter_hint=None,
            has_groq_key=False,
            groq_hint=None,
        )

    try:
        status = get_user_vault_status(user_id)
        return VaultStatusResponse(**status)
    except Exception as e:
        logger.error(f"[VaultAPI] Error getting vault status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve vault status.")


@router.post("/keys")
async def save_vault_keys(
    payload: VaultKeysPayload,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
):
    """Encrypt and store OpenRouter and/or Groq API keys in the database vault."""
    effective_uid = user_id or payload.user_id
    if not effective_uid or not is_valid_uuid(effective_uid):
        raise HTTPException(status_code=400, detail="A valid user UUID is required.")

    try:
        res = save_user_vault_keys(
            user_id=effective_uid,
            openrouter_key=payload.openrouter_key,
            groq_key=payload.groq_key,
        )
        return {
            "success": True,
            "message": "API keys encrypted with AES-256-GCM and saved to your private database vault.",
            "data": res,
        }
    except Exception as e:
        logger.error(f"[VaultAPI] Failed to save vault keys: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/keys")
async def revoke_vault_keys(
    user_id: Optional[str] = Depends(get_authenticated_user_id),
    target_user_id: Optional[str] = Query(None, alias="user_id"),
):
    """Permanently revoke and delete the user's API vault record from the database."""
    effective_uid = user_id or target_user_id
    if not effective_uid or not is_valid_uuid(effective_uid):
        raise HTTPException(status_code=400, detail="A valid user UUID is required to revoke keys.")

    try:
        success = revoke_user_vault_keys(user_id)
        return {
            "success": success,
            "message": "API keys permanently revoked and wiped from database vault.",
        }
    except Exception as e:
        logger.error(f"[VaultAPI] Failed to revoke vault keys: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-key", response_model=VerifyKeyResponse)
async def verify_api_keys(
    payload: VerifyKeyRequest,
    x_openrouter_key: Optional[str] = Header(None, alias="X-OpenRouter-Key"),
    x_groq_key: Optional[str] = Header(None, alias="X-Groq-Key"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
):
    """Test and verify custom API key connectivity against upstream providers (OpenRouter / Groq)."""
    target_openrouter = payload.openrouter_key or x_openrouter_key
    target_groq = payload.groq_key or x_groq_key
    target_uid = payload.user_id or x_user_id

    # If keys not explicitly passed, inspect user's encrypted vault
    if target_uid and is_valid_uuid(target_uid) and (not target_openrouter or not target_groq):
        try:
            vault_keys = get_user_vault_keys(target_uid)
            if not target_openrouter and vault_keys.get("openrouter_key"):
                target_openrouter = vault_keys["openrouter_key"]
            if not target_groq and vault_keys.get("groq_key"):
                target_groq = vault_keys["groq_key"]
        except Exception as e:
            logger.warning(f"[VaultAPI] Could not load vault keys for verification: {e}")

    results: List[KeyVerificationItem] = []

    # 1. Test OpenRouter Key
    if target_openrouter and target_openrouter.strip():
        k = target_openrouter.strip()
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    "https://openrouter.ai/api/v1/auth/key",
                    headers={
                        "Authorization": f"Bearer {k}",
                        "HTTP-Referer": "https://github.com/khushal0811/ai-safety-and-scope-tool",
                        "X-Title": "Vallum - AI Safety & Scope Boundary Engine",
                    },
                )
                latency = round((time.perf_counter() - start) * 1000, 1)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    label = data.get("label") or "Active Key"
                    results.append(
                        KeyVerificationItem(
                            provider="OpenRouter",
                            valid=True,
                            status_code=200,
                            message=f"OpenRouter key is valid and connected ({label}).",
                            latency_ms=latency,
                            details={"label": label, "limit": data.get("limit"), "usage": data.get("usage")},
                        )
                    )
                elif res.status_code == 401:
                    results.append(
                        KeyVerificationItem(
                            provider="OpenRouter",
                            valid=False,
                            status_code=401,
                            message="Invalid OpenRouter key: 401 Unauthorized. Please verify your key on openrouter.ai/keys.",
                            latency_ms=latency,
                        )
                    )
                elif res.status_code == 402:
                    results.append(
                        KeyVerificationItem(
                            provider="OpenRouter",
                            valid=False,
                            status_code=402,
                            message="OpenRouter account has insufficient credits (402 Payment Required).",
                            latency_ms=latency,
                        )
                    )
                else:
                    results.append(
                        KeyVerificationItem(
                            provider="OpenRouter",
                            valid=False,
                            status_code=res.status_code,
                            message=f"OpenRouter returned HTTP {res.status_code}: {res.text[:120]}",
                            latency_ms=latency,
                        )
                    )
        except httpx.TimeoutException:
            results.append(
                KeyVerificationItem(
                    provider="OpenRouter",
                    valid=False,
                    status_code=408,
                    message="Connection timed out while contacting OpenRouter API.",
                    latency_ms=8000.0,
                )
            )
        except Exception as e:
            results.append(
                KeyVerificationItem(
                    provider="OpenRouter",
                    valid=False,
                    status_code=500,
                    message=f"Connection error contacting OpenRouter: {str(e)}",
                    latency_ms=0.0,
                )
            )

    # 2. Test Groq Key (if user passed a custom override)
    if target_groq and target_groq.strip():
        gk = target_groq.strip()
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {gk}"},
                )
                latency = round((time.perf_counter() - start) * 1000, 1)
                if res.status_code == 200:
                    results.append(
                        KeyVerificationItem(
                            provider="Groq",
                            valid=True,
                            status_code=200,
                            message="Custom Groq API key is valid and operational.",
                            latency_ms=latency,
                        )
                    )
                elif res.status_code == 401:
                    results.append(
                        KeyVerificationItem(
                            provider="Groq",
                            valid=False,
                            status_code=401,
                            message="Invalid Groq key: 401 Unauthorized. Please check your Groq API console.",
                            latency_ms=latency,
                        )
                    )
                else:
                    results.append(
                        KeyVerificationItem(
                            provider="Groq",
                            valid=False,
                            status_code=res.status_code,
                            message=f"Groq returned HTTP {res.status_code}: {res.text[:120]}",
                            latency_ms=latency,
                        )
                    )
        except httpx.TimeoutException:
            results.append(
                KeyVerificationItem(
                    provider="Groq",
                    valid=False,
                    status_code=408,
                    message="Connection timed out while contacting Groq API.",
                    latency_ms=8000.0,
                )
            )
        except Exception as e:
            results.append(
                KeyVerificationItem(
                    provider="Groq",
                    valid=False,
                    status_code=500,
                    message=f"Connection error contacting Groq: {str(e)}",
                    latency_ms=0.0,
                )
            )

    if not results:
        raise HTTPException(
            status_code=400,
            detail="No API key provided to test. Enter an OpenRouter key before testing.",
        )

    all_valid = all(r.valid for r in results)
    return VerifyKeyResponse(success=all_valid, results=results)
