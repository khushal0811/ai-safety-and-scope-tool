"""Server-side attestation primitives for audit log integrity.

The attestation key never leaves the backend. Each audit row is signed when it
is written, so a client that can reach the database through PostgREST cannot
fabricate a compliant row or recompute the chain (AUDIT_005 High 5).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_EPHEMERAL_ATTESTATION_KEY: Optional[bytes] = None

# Fields covered by the write-time record signature. `deleted_at` is excluded:
# soft deletion is an append-only marker applied after the immutable record was
# signed, while the report chain separately binds the marker into its payload.
SIGNED_RECORD_FIELDS = (
    "audit_id",
    "user_id",
    "roe_id",
    "roe_hash",
    "mode",
    "selected_model",
    "user_prompt",
    "raw_model_output",
    "extracted_commands",
    "targets",
    "verdict",
    "violation_details",
    "safe_sanitized_command",
    "modifications_made",
    "explanation",
    "execution_time_ms",
    "created_at",
    "chain_index",
    "prev_hash",
)


def attestation_key() -> bytes:
    """Server-side secret used for HMAC-SHA256 attestation signatures.

    Without a secret, anyone with write access to audit_logs could recompute
    every hash. A per-process fallback keeps development usable but cannot
    verify across restarts.
    """
    global _EPHEMERAL_ATTESTATION_KEY
    from app.config import settings

    if settings.ATTESTATION_HMAC_KEY:
        return settings.ATTESTATION_HMAC_KEY.encode("utf-8")
    if _EPHEMERAL_ATTESTATION_KEY is None:
        import secrets

        logger.warning(
            "[Attestation] ATTESTATION_HMAC_KEY is not configured; using a per-process random key. "
            "Attestations cannot be verified after a restart."
        )
        _EPHEMERAL_ATTESTATION_KEY = secrets.token_bytes(32)
    return _EPHEMERAL_ATTESTATION_KEY


def canonical_record_payload(record: Dict[str, Any]) -> str:
    """Deterministic JSON serialization of the fields covered by a record signature."""
    payload = {field: record.get(field) for field in SIGNED_RECORD_FIELDS}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def genesis_hash(roe_id: str) -> str:
    """Chain seed for the first audit record of a given RoE."""
    seed = f"vallum-audit-genesis|{roe_id}"
    return hmac.new(attestation_key(), seed.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_record_signature(record: Dict[str, Any]) -> str:
    """HMAC over the immutable audit record and its chain predecessor."""
    payload = f"{record.get('prev_hash', '')}|{record.get('chain_index', '')}|{canonical_record_payload(record)}"
    return hmac.new(attestation_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_record_signature(record: Dict[str, Any]) -> bool:
    """Constant-time verification of a stored write-time record signature."""
    stored = record.get("chain_hash")
    if not stored or not record.get("prev_hash"):
        return False
    expected = compute_record_signature(record)
    return hmac.compare_digest(str(stored), expected)
