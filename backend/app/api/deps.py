"""FastAPI dependencies for server-side authentication and JWT verification.

Enforces cryptographic token validation (Supabase JWT via Authorization: Bearer <token>)
and securely derives the authenticated user_id, preventing client-side user impersonation.
"""

import logging
import os
from typing import Optional
from fastapi import Header, HTTPException, Query, Request, status
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.db.supabase_client import get_supabase, is_valid_uuid, verify_supabase_jwt

logger = logging.getLogger(__name__)


async def get_authenticated_user_id(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    user_id: Optional[str] = Query(None, alias="user_id"),
) -> Optional[str]:
    """Extract and cryptographically verify the calling user's identity.

    Returns the verified user UUID from a valid Supabase Bearer token, or None
    if no token was provided. NEVER trusts a client-supplied X-User-Id header
    or user_id query param as identity outside of local development.
    """
    if authorization and authorization.strip().lower().startswith("bearer "):
        # Blocking network call to Supabase: run off the event loop
        verified = await run_in_threadpool(verify_supabase_jwt, authorization)
        if not verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired Supabase authentication token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return verified["id"]

    if authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header format. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # No Authorization header: never derive identity from a client-controlled
    # X-User-Id header or user_id query parameter. Guests are anonymous (None).
    return None


async def get_local_dev_user_id(
    request: Request,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
) -> str:
    """Opt-in local-development identity, for routes that explicitly depend on it.

    Only active when ENVIRONMENT=development, ALLOW_DEV_UID_FALLBACK is set, and the
    request comes from loopback. Never used by require_authenticated_user_id().
    """
    if (
        settings.ENVIRONMENT != "development"
        or os.getenv("ALLOW_DEV_UID_FALLBACK", "").strip().lower() not in ("1", "true", "yes")
        or request.client is None
        or request.client.host not in ("127.0.0.1", "::1")
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    if not x_user_id or not is_valid_uuid(x_user_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="A valid development user UUID is required.")
    logger.warning("[Auth] DEV-ONLY local UID identity used.")
    return x_user_id


async def require_authenticated_user_id(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    user_id: Optional[str] = Query(None, alias="user_id"),
) -> str:
    """Strict dependency requiring authenticated user identity.
    
    Rejects unauthenticated requests with HTTP 401.
    """
    uid = await get_authenticated_user_id(
        authorization=authorization,
        x_user_id=x_user_id,
        user_id=user_id,
    )
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return uid
