"""Canonical Rules-of-Engagement identity and audit-time scope binding.

A client-supplied RoE is only a claim. Before an audit is evaluated, the claim
must match the canonical preset or stored custom RoE for that ``roe_id``. The
canonical hash and snapshot are then persisted with the audit so a report can
prove which scope the verdict was actually produced under (AUDIT_005 High 5).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Dict, List, Optional, Union

from app.data.presets import ROE_PRESETS, get_roe_preset_by_id
from app.models.roe import RoeScope


class RoeScopeMismatchError(ValueError):
    """Raised when a submitted RoE does not match the stored scope for its id."""


def _canonical_cidrs(values: List[str]) -> List[str]:
    normalized = set()
    for value in values or []:
        try:
            normalized.add(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        except ValueError:
            normalized.add(str(value).strip())
    return sorted(normalized)


def _canonical_ips(values: List[str]) -> List[str]:
    normalized = set()
    for value in values or []:
        text = str(value).strip()
        try:
            normalized.add(str(ipaddress.ip_network(text, strict=False)))
            continue
        except ValueError:
            pass
        try:
            normalized.add(str(ipaddress.ip_address(text)))
            continue
        except ValueError:
            normalized.add(text.lower().rstrip("."))
    return sorted(normalized)


def _canonical_domains(values: List[str]) -> List[str]:
    return sorted({str(value).strip().lower().rstrip(".") for value in values or [] if str(value).strip()})


def _canonical_names(values: List[str], *, lowercase: bool) -> List[str]:
    out = {str(value).strip() for value in values or [] if str(value).strip()}
    if lowercase:
        out = {value.lower() for value in out}
    return sorted(out)


def canonical_roe_dict(roe: Union[RoeScope, Dict[str, Any]]) -> Dict[str, Any]:
    """Return a deterministic, semantically-normalized representation of a scope."""
    data = roe.model_dump(mode="json") if isinstance(roe, RoeScope) else dict(roe)
    return {
        "roe_id": str(data.get("roe_id") or "").strip(),
        "name": str(data.get("name") or "").strip(),
        "engagement_type": str(data.get("engagement_type") or "").strip(),
        "summary": str(data.get("summary") or "").strip(),
        "allowed_cidrs": _canonical_cidrs(data.get("allowed_cidrs") or []),
        "allowed_domains": _canonical_domains(data.get("allowed_domains") or []),
        "target_hosts": _canonical_ips(data.get("target_hosts") or []),
        "prohibited_ips": _canonical_ips(data.get("prohibited_ips") or []),
        "allowed_tools": _canonical_names(data.get("allowed_tools") or [], lowercase=True),
        "whitelisted_system_utilities": _canonical_names(
            data.get("whitelisted_system_utilities") or [], lowercase=True
        ),
        "prohibited_tools": _canonical_names(data.get("prohibited_tools") or [], lowercase=True),
        "prohibited_flags": _canonical_names(data.get("prohibited_flags") or [], lowercase=False),
        "prohibited_actions": _canonical_names(data.get("prohibited_actions") or [], lowercase=True),
        "max_nmap_timing": int(data.get("max_nmap_timing") if data.get("max_nmap_timing") is not None else 3),
    }


def compute_roe_hash(roe: Union[RoeScope, Dict[str, Any]]) -> str:
    """SHA-256 over the canonical scope definition used for attestation binding."""
    payload = json.dumps(
        canonical_roe_dict(roe),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def roe_scope_from_row(row: Dict[str, Any]) -> RoeScope:
    """Build a RoeScope from a custom_roes database row."""
    return RoeScope(
        roe_id=row.get("roe_id"),
        name=row.get("name", "Custom Scope"),
        engagement_type=row.get("engagement_type", "Custom Assessment"),
        summary=row.get("summary", ""),
        allowed_cidrs=row.get("allowed_cidrs") or [],
        allowed_domains=row.get("allowed_domains") or [],
        target_hosts=row.get("target_hosts") or [],
        prohibited_ips=row.get("prohibited_ips") or [],
        allowed_tools=row.get("allowed_tools") or [],
        prohibited_tools=row.get("prohibited_tools") or [],
        prohibited_flags=row.get("prohibited_flags") or [],
        prohibited_actions=row.get("prohibited_actions") or [],
        max_nmap_timing=row.get("max_nmap_timing", 3),
    )


def resolve_roe_scope(roe_id: str, user_id: Optional[str]) -> Optional[RoeScope]:
    """Resolve a preset or the caller's custom RoE by id, without silent substitution."""
    preset = get_roe_preset_by_id(roe_id)
    if not preset:
        for candidate in ROE_PRESETS:
            if candidate.roe_id.lower() == str(roe_id).lower():
                preset = candidate
                break
    if preset:
        return preset

    try:
        from app.db import fetch_custom_roe_by_id

        row = fetch_custom_roe_by_id(roe_id, user_id=user_id)
    except Exception:
        row = None
    return roe_scope_from_row(row) if row else None


def bind_audit_roe(submitted: RoeScope, user_id: Optional[str]) -> RoeScope:
    """Validate a submitted RoE against stored scope and return the canonical scope.

    An unrecognised ``roe_id`` is allowed only as a brand-new scope definition;
    that definition is then snapshotted with the audit and becomes the scope the
    report must display. A recognised id with different boundaries is rejected.
    """
    canonical = resolve_roe_scope(submitted.roe_id, user_id)
    if canonical is None:
        return submitted

    if compute_roe_hash(submitted) != compute_roe_hash(canonical):
        raise RoeScopeMismatchError(
            f"Submitted RoE boundaries do not match the stored scope for roe_id="
            f"{submitted.roe_id!r}; refusing to audit against an unverified scope."
        )
    return canonical
