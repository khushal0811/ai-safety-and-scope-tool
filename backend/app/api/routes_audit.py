"""FastAPI endpoints for deterministic safety and scope auditing."""

from fastapi import APIRouter
from app.engine.verifier import evaluate_audit_async, evaluate_deterministic_command
from app.models.audit import AuditRequest, AuditResult, DeterministicAuditRequest

router = APIRouter(prefix="/api/audit", tags=["Scope & Safety Audit"])


@router.post("", response_model=AuditResult)
@router.post("/full", response_model=AuditResult)
async def audit_model_output(request: AuditRequest) -> AuditResult:
    """Audit raw model output against active Rules of Engagement (RoE) with intelligent remediation."""
    return await evaluate_audit_async(request)


@router.post("/deterministic", response_model=AuditResult)
async def audit_command_deterministic(request: DeterministicAuditRequest) -> AuditResult:
    """Perform instant deterministic inspection on a CLI command string."""
    return evaluate_deterministic_command(request)
