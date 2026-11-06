"""FastAPI endpoints for deterministic safety and scope auditing."""

import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
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
from app.engine.roe_integrity import (
    RoeScopeMismatchError,
    bind_audit_roe,
    canonical_roe_dict,
    compute_roe_hash,
)
from app.models.audit import AuditRequest, AuditResult, DeterministicAuditRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["Scope & Safety Audit"])


class DeleteAuditsPayload(BaseModel):
    """Payload to soft-delete one or more audit logs."""

    audit_ids: List[str] = Field(..., description="List of audit UUIDs/IDs to mark deleted")


@router.delete("/history")
async def delete_audit_history(
    payload: DeleteAuditsPayload,
    user_id: str = Depends(require_authenticated_user_id),
) -> Dict[str, Any]:
    """Soft-delete specified audit records; tombstones stay in the attestation chain."""
    deleted = delete_audit_logs(audit_ids=payload.audit_ids, user_id=user_id)
    if deleted is None:
        raise HTTPException(status_code=500, detail="Failed to soft-delete audit logs.")
    return {"success": True, "deleted_count": deleted}


@router.post("", response_model=AuditResult)
@router.post("/full", response_model=AuditResult)
async def audit_model_output(
    request: AuditRequest,
    # Requires a verified user: this path can invoke the AI Judge, which spends the server's LLM key
    user_id: str = Depends(require_authenticated_user_id),
) -> AuditResult:
    """Audit raw model output against active Rules of Engagement (RoE) with intelligent remediation.
    
    Persists result to Supabase audit_logs table before returning so immediate report exports include it.
    """
    # The client-supplied scope is a claim: reject it when it does not match the
    # stored preset/custom RoE for the claimed roe_id (AUDIT_005 High 5).
    try:
        effective_roe = bind_audit_roe(request.roe, user_id)
    except RoeScopeMismatchError as e:
        raise HTTPException(status_code=409, detail=str(e))
    request = request.model_copy(update={"roe": effective_roe})

    t0 = time.perf_counter()
    result = await evaluate_audit_async(request)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    # Persist the canonical scope actually used, not just its id, so the report
    # cannot be made to print different boundaries after the fact.
    data = result.model_dump(mode="json")
    data["roe_id"] = effective_roe.roe_id
    data["roe_hash"] = compute_roe_hash(effective_roe)
    data["roe_snapshot"] = canonical_roe_dict(effective_roe)
    await run_in_threadpool(save_audit_log, data, user_id, elapsed_ms)

    return result


@router.post("/deterministic", response_model=AuditResult)
async def audit_command_deterministic(
    request: DeterministicAuditRequest,
    user_id: Optional[str] = Depends(get_authenticated_user_id),
) -> AuditResult:
    """Perform instant deterministic inspection on a CLI command string."""
    effective_roe = request.roe
    if effective_roe is None:
        if not request.roe_id:
            raise HTTPException(
                status_code=422,
                detail="A scope is required: provide a parsed RoE object or a saved custom roe_id.",
            )
        from app.db import fetch_custom_roe_by_id
        from app.engine.roe_integrity import roe_scope_from_row

        row = fetch_custom_roe_by_id(request.roe_id, user_id=user_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown custom scope: {request.roe_id!r}")
        effective_roe = roe_scope_from_row(row)
        request = request.model_copy(update={"roe": effective_roe})

    try:
        effective_roe = bind_audit_roe(effective_roe, user_id)
    except RoeScopeMismatchError as e:
        raise HTTPException(status_code=409, detail=str(e))
    request = request.model_copy(update={"roe": effective_roe})

    t0 = time.perf_counter()
    result = evaluate_deterministic_command(request)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    data = result.model_dump(mode="json")
    data["roe_id"] = effective_roe.roe_id
    data["roe_hash"] = compute_roe_hash(effective_roe)
    data["roe_snapshot"] = canonical_roe_dict(effective_roe)
    await run_in_threadpool(save_audit_log, data, user_id, elapsed_ms)

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
async def get_db_status(
    user_id: str = Depends(require_authenticated_user_id),
) -> Dict[str, Any]:
    """Verify Supabase PostgreSQL connectivity. Requires authentication; reports only connectivity."""
    connected = is_database_connected()
    return {"status": "connected" if connected else "disconnected"}


@router.get("/report")
async def get_compliance_report(
    roe_id: str = Query(default="ROE-PRESET-NET-001", description="Rules of Engagement preset or custom ID"),
    format: str = Query(default="markdown", description="Report format: 'markdown', 'pdf', or 'json'"),
    audit_id: Optional[str] = Query(default=None, description="Optional specific audit_id to filter the report to"),
    user_id: str = Depends(require_authenticated_user_id),
):
    """Generate formal, signed RoE compliance attestation report, scoped to the caller's own audit history."""
    from app.engine.reporter import generate_compliance_report

    try:
        content, media_type, filename = generate_compliance_report(
            roe_id=roe_id,
            format=format,
            user_id=user_id,
            audit_id=audit_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        },
    )
