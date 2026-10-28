"""FastAPI dependencies for server-side authentication and JWT verification.

Enforces cryptographic token validation (Supabase JWT via Authorization: Bearer <token>)
and securely derives the authenticated user_id, preventing client-side user impersonation.
"""

import logging
from typing import Optional
from fastapi import Header, HTTPException, Query, status

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
        verified = verify_supabase_jwt(authorization)
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

    # Unauthenticated identity fallback is permitted ONLY in local development,
    # and only ever for manual testing — never reachable in a deployed environment.
    if settings.ENVIRONMENT == "development":
        candidate_uid = user_id or x_user_id
        if candidate_uid and is_valid_uuid(candidate_uid):
            logger.warning(
                f"[Auth] DEV-ONLY unauthenticated uid fallback used: {candidate_uid}. "
                "This path is disabled whenever ENVIRONMENT != 'development'."
            )
            return candidate_uid

    return None


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
