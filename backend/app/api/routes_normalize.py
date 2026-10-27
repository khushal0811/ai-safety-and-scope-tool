"""FastAPI endpoints for IP normalization and obfuscation resolution."""

from fastapi import APIRouter
from app.engine.ip_validator import normalize_ip_candidate
from app.models.audit import NormalizeIpRequest, NormalizeIpResponse

router = APIRouter(prefix="/api/normalize-ip", tags=["IP Normalization"])


@router.post("", response_model=NormalizeIpResponse)
async def normalize_ip_endpoint(request: NormalizeIpRequest) -> NormalizeIpResponse:
    """Normalize hex, octal, decimal, or IPv6-mapped notation to canonical dot-decimal."""
    norm = normalize_ip_candidate(request.target)

    is_loopback = False
    is_private = False
    is_multicast = False
    is_reserved = False

    if norm.ip_obj:
        is_loopback = norm.ip_obj.is_loopback
        is_private = norm.ip_obj.is_private
        is_multicast = norm.ip_obj.is_multicast
        is_reserved = norm.ip_obj.is_reserved

    return NormalizeIpResponse(
        raw_token=norm.raw_token,
        normalized=norm.canonical if norm.is_valid else None,
        is_valid=norm.is_valid,
        is_obfuscated=norm.is_obfuscated,
        format_detected=norm.format_type,
        is_loopback=is_loopback,
        is_private=is_private,
        is_multicast=is_multicast,
        is_reserved=is_reserved,
    )
