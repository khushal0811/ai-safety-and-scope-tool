"""FastAPI endpoints for deterministic safety and scope auditing."""

import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from app.api.deps import get_authenticated_user_id, require_authenticated_user_id
from app.db import (
    delete_audit_logs,
    fetch_audit_history,
    fetch_audit_metrics,
    is_database_connected,
    is_valid_uuid,
    save_audit_log,
)
from app.engine.verifier import evaluate_audit_async, evaluate_deterministic_command
from app.models.audit import AuditRequest, AuditResult, DeterministicAuditRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["Scope & Safety Audit"])


class DeleteAuditsPayload(BaseModel):
    """Payload to permanently delete one or more audit logs."""

    audit_ids: List[str] = Field(..., description="List of audit UUIDs/IDs to permanently delete")
    user_id: Optional[str] = Field(None, description="Owner Supabase user UUID (optional if Authorization header provided)")


@router.delete("/history")
async def delete_audit_history(
    payload: DeleteAuditsPayload,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> Dict[str, Any]:
    """Permanently delete specified audit records from Supabase PostgreSQL audit_logs table."""
    effective_uid = user_id or payload.user_id
    if not effective_uid or not is_valid_uuid(effective_uid):
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    success = delete_audit_logs(audit_ids=payload.audit_ids, user_id=effective_uid)
    return {"success": success, "deleted_count": len(payload.audit_ids)}


@router.post("", response_model=AuditResult)
@router.post("/full", response_model=AuditResult)
async def audit_model_output(
    request: AuditRequest,
    background_tasks: BackgroundTasks,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> AuditResult:
    """Audit raw model output against active Rules of Engagement (RoE) with intelligent remediation.
    
    Automatically persists result to Supabase audit_logs table via background task.
    """
    t0 = time.perf_counter()
    result = await evaluate_audit_async(request)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    # Persist to Supabase asynchronously without blocking user response
    data = result.model_dump(mode="json")
    data["roe_id"] = getattr(request.roe, "roe_id", getattr(request.roe, "id", "UNKNOWN"))
    background_tasks.add_task(save_audit_log, data, user_id, elapsed_ms)

    return result


@router.post("/deterministic", response_model=AuditResult)
async def audit_command_deterministic(
    request: DeterministicAuditRequest,
    background_tasks: BackgroundTasks,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> AuditResult:
    """Perform instant deterministic inspection on a CLI command string."""
    from app.data.presets import ROE_PRESETS, get_roe_preset_by_id

    effective_roe = request.roe
    if effective_roe is None:
        effective_roe = get_roe_preset_by_id(request.roe_id) or ROE_PRESETS[0]
        request = request.model_copy(update={"roe": effective_roe})

    t0 = time.perf_counter()
    result = evaluate_deterministic_command(request)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    data = result.model_dump(mode="json")
    data["roe_id"] = getattr(effective_roe, "roe_id", getattr(effective_roe, "id", "UNKNOWN"))
    background_tasks.add_task(save_audit_log, data, user_id, elapsed_ms)

    return result


@router.get("/history", response_model=List[Dict[str, Any]])
async def get_audit_history(
    user_id: Optional[str] = Depends(get_authenticated_user_id),
    limit: int = Query(default=50, ge=1, le=200, description="Max audit entries to return"),
) -> List[Dict[str, Any]]:
    """Retrieve historical audits from Supabase PostgreSQL audit_logs table."""
    return fetch_audit_history(user_id=user_id, limit=limit)


@router.get("/metrics", response_model=Dict[str, Any])
async def get_audit_metrics(
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> Dict[str, Any]:
    """Retrieve aggregated audit metrics and compliance rates from Supabase PostgreSQL."""
    return fetch_audit_metrics(user_id=user_id)


@router.get("/db-status", response_model=Dict[str, Any])
async def get_db_status() -> Dict[str, Any]:
    """Verify Supabase PostgreSQL connectivity and operational status."""
    connected = is_database_connected()
    return {
        "status": "connected" if connected else "disconnected",
        "database": "Supabase PostgreSQL",
        "authenticated": connected,
    }
