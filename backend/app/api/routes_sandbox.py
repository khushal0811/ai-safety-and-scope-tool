"""FastAPI API routes for Phase 4.5 Ephemeral Micro-Sandbox Dry-Run Environment."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_authenticated_user_id
from app.data.presets import get_roe_preset_by_id, ROE_PRESETS
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
    # Resolve active RoE if provided
    roe = None
    if request.roe_id:
        roe = get_roe_preset_by_id(request.roe_id)
        if not roe:
            for p in ROE_PRESETS:
                if p.roe_id.lower() == request.roe_id.lower():
                    roe = p
                    break

    result = IsolatedVirtualSandbox.dry_run(
        command_str=request.command,
        roe=roe,
        strict_syntax=request.strict_syntax,
    )
    return result


@router.get("/status", response_model=SandboxStatusResponse)
async def get_sandbox_status() -> SandboxStatusResponse:
    """Retrieve micro-sandbox capabilities and isolation security status."""
    return IsolatedVirtualSandbox.get_status()
