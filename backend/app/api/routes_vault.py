"""API routes for encrypted User API Vault.

Provides endpoints to securely store, verify, and revoke encrypted user API keys
(OpenRouter and custom Groq keys) using AES-256-GCM.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel, Field

from app.db.supabase_client import (
    get_user_vault_status,
    is_valid_uuid,
    revoke_user_vault_keys,
    save_user_vault_keys,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vault", tags=["API Key Vault"])


class VaultKeysPayload(BaseModel):
    """Payload for saving encrypted user API keys."""

    user_id: str = Field(..., description="Authenticated user UUID")
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
    user_id: Optional[str] = Query(None, description="Authenticated user UUID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
):
    """Check whether the user has encrypted keys configured in their vault."""
    active_uid = user_id or x_user_id
    if not active_uid or not is_valid_uuid(active_uid):
        return VaultStatusResponse(
            is_configured=False,
            has_openrouter_key=False,
            openrouter_hint=None,
            has_groq_key=False,
            groq_hint=None,
        )

    try:
        status = get_user_vault_status(active_uid)
        return VaultStatusResponse(**status)
    except Exception as e:
        logger.error(f"[VaultAPI] Error getting vault status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve vault status.")


@router.post("/keys")
async def save_vault_keys(payload: VaultKeysPayload):
    """Encrypt and store OpenRouter and/or Groq API keys in the database vault."""
    if not is_valid_uuid(payload.user_id):
        raise HTTPException(status_code=400, detail="A valid user UUID is required.")

    try:
        res = save_user_vault_keys(
            user_id=payload.user_id,
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
    user_id: Optional[str] = Query(None, description="Authenticated user UUID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
):
    """Permanently revoke and delete the user's API vault record from the database."""
    active_uid = user_id or x_user_id
    if not active_uid or not is_valid_uuid(active_uid):
        raise HTTPException(status_code=400, detail="A valid user UUID is required to revoke keys.")

    try:
        success = revoke_user_vault_keys(active_uid)
        return {
            "success": success,
            "message": "API keys permanently revoked and wiped from database vault.",
        }
    except Exception as e:
        logger.error(f"[VaultAPI] Failed to revoke vault keys: {e}")
        raise HTTPException(status_code=500, detail=str(e))
