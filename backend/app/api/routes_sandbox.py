"""FastAPI API routes for Phase 4.5 Ephemeral Micro-Sandbox Dry-Run Environment."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_authenticated_user_id
from app.db import fetch_custom_roe_by_id
from app.engine.roe_integrity import roe_scope_from_row
from app.engine.sandbox import IsolatedVirtualSandbox
from app.models.sandbox import (
    SandboxDryRunRequest,
    SandboxDryRunResponse,
    SandboxStatusResponse,
)

router = APIRouter(prefix="/api/sandbox", tags=["Sandbox"])


@router.post("/dry-run", response_model=SandboxDryRunResponse)
async def dry_run_command(
    request: SandboxDryRunRequest,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> SandboxDryRunResponse:
    """Execute pre-flight syntax and flag validation in a network-egress disabled micro-sandbox."""
    # Resolve the active RoE exactly. A custom RoE is looked up by id; an
    # unknown or missing scope is a 404 rather than an unpoliced dry-run.
    if not request.roe_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="A Rules of Engagement scope is required for a sandbox dry-run.",
        )

    roe = None
    custom_row = fetch_custom_roe_by_id(request.roe_id, user_id=user_id)
    if not custom_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown custom Rules of Engagement id: {request.roe_id!r}",
        )
    roe = roe_scope_from_row(custom_row)

    result = IsolatedVirtualSandbox.dry_run(
        command_str=request.command,
        roe=roe,
        strict_syntax=request.strict_syntax,
        timeout_ms=request.timeout_ms,
    )
    return result


@router.get("/status", response_model=SandboxStatusResponse)
async def get_sandbox_status() -> SandboxStatusResponse:
    """Retrieve micro-sandbox capabilities and isolation security status."""
    return IsolatedVirtualSandbox.get_status()
