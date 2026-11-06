"""Supabase database client and data persistence repository.

Zero Host Execution: Operates strictly over HTTPS via Supabase REST/PostgREST.
"""

import json
import logging
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_supabase_client = None


def is_valid_uuid(val: Optional[str]) -> bool:
    """Validate whether a string is a standard RFC UUID."""
    if not val:
        return False
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def get_supabase():
    """Lazy initialize and return the Supabase client."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = os.getenv("SUPABASE_URL", "").strip()
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY", "")
    ).strip()

    if not url or not key or "your-project-id" in url:
        return None

    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception as e:
        logger.error(f"[Supabase] Initialization failed: {e}")
        return None


def is_database_connected() -> bool:
    """Check if the Supabase database is configured and reachable."""
    client = get_supabase()
    if client is None:
        return False
    try:
        res = client.table("roe_presets").select("roe_id").limit(1).execute()
        return res is not None
    except Exception:
        return False


class UnscopedQueryError(ValueError):
    """Raised when a tenant-owned table is queried without a user scope."""


# Tables that hold per-tenant rows. Reads must go through _user_scoped_query()
# so tenant isolation does not depend on each caller remembering a filter.
_USER_SCOPED_TABLES = frozenset(
    {"audit_logs", "custom_roes", "user_api_vault", "benchmark_runs"}
)


def _user_scoped_query(
    client: Any,
    table: str,
    user_id: Optional[str],
    *,
    columns: str = "*",
    include_public: bool = False,
    public_only: bool = False,
):
    """Build the only sanctioned read query for a tenant-owned table.

    - A valid user_id scopes the query to that user. include_public=True widens
      it to the user's rows plus public (user_id IS NULL) rows.
    - A missing or invalid user_id raises unless public_only=True, in which case
      only public rows are returned. There is no way to read tenant rows without
      a valid user_id.
    """
    if table not in _USER_SCOPED_TABLES:
        raise UnscopedQueryError(f"{table!r} is not a user-scoped table.")

    query = client.table(table).select(columns)

    if is_valid_uuid(user_id):
        if include_public:
            return query.or_(f"user_id.eq.{user_id},user_id.is.null")
        return query.eq("user_id", user_id)

    if public_only:
        return query.is_("user_id", "null")

    raise UnscopedQueryError(f"Refusing unscoped read of {table!r}.")


def _previous_chain_head(client: Any, user_id: str, roe_id: str) -> tuple[str, int]:
    """Return (prev_hash, chain_index) for the next record in a user+RoE chain."""
    from app.engine.attestation import genesis_hash

    res = (
        _user_scoped_query(client, "audit_logs", user_id, columns="chain_index, chain_hash")
        .eq("roe_id", roe_id)
        .order("chain_index", desc=True)
        .limit(1)
        .execute()
    )
    rows = res.data or []
    if rows and rows[0].get("chain_hash") and rows[0].get("chain_index") is not None:
        return str(rows[0]["chain_hash"]), int(rows[0]["chain_index"]) + 1
    return genesis_hash(roe_id), 1


def save_audit_log(
    audit_data: Dict[str, Any],
    user_id: Optional[str] = None,
    execution_time_ms: int = 0,
) -> bool:
    """Save an evaluated audit result with a server-signed, write-time chain link.

    Strict Privacy Rule: Only persists when user_id is a valid UUID. Guest audits are never stored.
    An audit without a bound RoE snapshot/hash is refused: an unattested row must
    never enter the attestation ledger (AUDIT_005 High 5).
    """
    if not is_valid_uuid(user_id):
        return False

    roe_hash = audit_data.get("roe_hash")
    roe_snapshot = audit_data.get("roe_snapshot")
    if not roe_hash or not isinstance(roe_snapshot, dict):
        logger.error("[Supabase] Refusing audit log insert without RoE snapshot/hash binding.")
        return False

    client = get_supabase()
    if not client:
        return False

    created_at = audit_data.get("created_at") or datetime.now(timezone.utc).isoformat()
    roe_id = audit_data.get("roe_id") or roe_snapshot.get("roe_id") or "UNKNOWN"

    base_payload = {
        "audit_id": audit_data.get("audit_id"),
        "user_id": user_id,
        "roe_id": roe_id,
        "roe_hash": roe_hash,
        "roe_snapshot": roe_snapshot,
        "mode": audit_data.get("mode", "live"),
        "selected_model": audit_data.get("selected_model", "unknown"),
        "user_prompt": audit_data.get("user_prompt", ""),
        "raw_model_output": audit_data.get("raw_model_output", ""),
        "extracted_commands": audit_data.get("extracted_commands", []),
        "targets": audit_data.get("targets", []),
        "verdict": audit_data.get("verdict", "Unsafe"),
        "violation_details": audit_data.get("violation_details", []),
        "safe_sanitized_command": audit_data.get("safe_sanitized_command"),
        "modifications_made": audit_data.get("modifications_made", []),
        "explanation": audit_data.get("explanation", ""),
        "override_log": audit_data.get("override_log", []),
        "needs_review": audit_data.get("needs_review", False),
        "execution_time_ms": execution_time_ms,
        "created_at": created_at,
        "deleted_at": None,
    }

    from app.engine.attestation import compute_record_signature

    # The chain head is signed at write time with the server-only HMAC key. Retry
    # once on a concurrent insert collision of (user_id, roe_id, chain_index).
    for _attempt in range(3):
        try:
            prev_hash, chain_index = _previous_chain_head(client, user_id, str(roe_id))
            payload = dict(base_payload)
            payload["chain_index"] = chain_index
            payload["prev_hash"] = prev_hash
            payload["chain_hash"] = compute_record_signature(payload)
            client.table("audit_logs").insert(payload).execute()
            return True
        except Exception as e:
            last_error = e
            logger.warning(f"[Supabase] Audit log insert attempt failed, retrying chain head: {e}")

    logger.error(f"[Supabase] Failed to persist audit log: {last_error}")
    return False


def fetch_audit_history(user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve active audit history for the authenticated user.

    Soft-deleted rows remain in the attestation ledger but are hidden from the
    ordinary history view.
    """
    if not is_valid_uuid(user_id):
        return []

    client = get_supabase()
    if not client:
        return []

    try:
        res = (
            _user_scoped_query(client, "audit_logs", user_id)
            .is_("deleted_at", "null")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch audit history: {e}")
        return []


def fetch_audit_logs_for_roe(
    roe_id: str,
    user_id: Optional[str] = None,
    limit: int = 500,
    audit_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve all audit logs for a specific RoE ID, scoped strictly to the given user.

    Soft-deleted rows are deliberately INCLUDED: deletion is a flag in the
    attestation chain, never an omission (AUDIT_005 High 5).

    Returns an empty list if no valid user_id is provided — this function must
    never return data across users.
    """
    if not is_valid_uuid(user_id):
        return []

    client = get_supabase()
    if not client:
        return []

    try:
        query = (
            _user_scoped_query(client, "audit_logs", user_id)
            .eq("roe_id", roe_id)
        )
        if audit_id:
            query = query.eq("audit_id", audit_id)
        res = query.order("chain_index", desc=False).limit(limit).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch audit logs for RoE {roe_id} (user {user_id}): {e}")
        # Raise rather than return []: an outage must never look like an empty, fully compliant record set
        raise RuntimeError("Audit log store is unavailable; refusing to issue an attestation.") from e


def delete_audit_logs(audit_ids: List[str], user_id: str) -> Optional[int]:
    """Soft-delete audit logs owned by user_id.

    Hard deletion is intentionally impossible from the application: a tombstone
    must remain in the attestation ledger. Returns the number of rows newly
    marked deleted, or None if the update could not be performed.
    """
    if not is_valid_uuid(user_id) or not audit_ids:
        return 0

    client = get_supabase()
    if not client:
        return None

    try:
        res = (
            client.table("audit_logs")
            .update({"deleted_at": datetime.now(timezone.utc).isoformat()})
            .in_("audit_id", audit_ids)
            .eq("user_id", user_id)
            .is_("deleted_at", "null")
            .select("audit_id")
            .execute()
        )
        return len(res.data or [])
    except Exception as e:
        logger.error(f"[Supabase] Failed to soft-delete audit logs: {e}")
        return None


def fetch_audit_metrics(user_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculate aggregated telemetry metrics for authenticated user only."""
    if not is_valid_uuid(user_id):
        return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}

    client = get_supabase()
    if not client:
        return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}

    try:


        # Aggregation happens in PostgreSQL (see migration 011), not by scanning every row here
        res = client.rpc("audit_metrics", {"p_user_id": user_id}).execute()
        row = (res.data[0] if isinstance(res.data, list) and res.data else res.data) or {}

        return {
            "total": int(row.get("total") or 0),
            "unsafe": int(row.get("unsafe") or 0),
            "correct": int(row.get("correct") or 0),
            "incorrect": int(row.get("incorrect") or 0),
            "pass_rate": int(row.get("pass_rate") or 0),
            "avg_latency_ms": int(row.get("avg_latency_ms") or 0),
        }
    except Exception as e:
        logger.error(f"[Supabase] Failed to calculate metrics: {e}")
        return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}


# Runtime state lives outside the source tree: it can contain prompts, model outputs, and user IDs
LOCAL_BENCHMARKS_FILE = os.path.join(
    os.getenv("VALLUM_STATE_DIR", os.path.expanduser("~/.vallum")),
    "benchmark_runs_local.json",
)


def _load_local_benchmarks() -> List[Dict[str, Any]]:
    if not os.path.exists(LOCAL_BENCHMARKS_FILE):
        return []
    try:
        with open(LOCAL_BENCHMARKS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[LocalBenchmarkStore] Read error: {e}")
        return []


_local_store_lock = threading.RLock()


def _save_local_benchmarks(data: List[Dict[str, Any]]) -> None:
    """Write the local store atomically: temp file in the same directory, fsync, then replace."""
    directory = os.path.dirname(LOCAL_BENCHMARKS_FILE)
    try:
        os.makedirs(directory, exist_ok=True)
        with _local_store_lock:
            fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".benchmarks-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, LOCAL_BENCHMARKS_FILE)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
    except Exception as e:
        logger.warning(f"[LocalBenchmarkStore] Write error: {e}")


def save_benchmark_run(
    benchmark_data: Dict[str, Any],
    user_id: Optional[str] = None,
) -> bool:
    """Save an evaluated multi-LLM benchmark run to PostgreSQL table benchmark_runs with local storage guarantee.
    
    Strict Privacy Rule: Only persists when user_id is a valid UUID. Guest runs are never stored.
    """
    if not is_valid_uuid(user_id):
        return False

    created_at = benchmark_data.get("created_at") or datetime.now(timezone.utc).isoformat()
    payload = {
        "benchmark_id": benchmark_data.get("benchmark_id"),
        "user_id": user_id,
        "roe_id": benchmark_data.get("roe_id") or "UNKNOWN",
        "scenario_title": benchmark_data.get("scenario_title") or "Custom Benchmark",
        "prompt": benchmark_data.get("prompt", ""),
        "total_models": benchmark_data.get("total_models", 0),
        "compliance_rate": benchmark_data.get("compliance_rate", 0.0),
        "scope_violation_rate": benchmark_data.get("scope_violation_rate", 0.0),
        "scope_violation_count": benchmark_data.get("scope_violation_count", 0),
        "policy_violation_rate": benchmark_data.get("policy_violation_rate", 0.0),
        "policy_violation_count": benchmark_data.get("policy_violation_count", 0),
        "hallucination_rate": benchmark_data.get("hallucination_rate", 0.0),
        "average_latency_ms": benchmark_data.get("average_latency_ms", 0.0),
        "fastest_model": benchmark_data.get("fastest_model"),
        "summary": benchmark_data.get("summary", {}),
        "items": benchmark_data.get("items", []),
        "created_at": created_at,
    }

    # 1. Guarantee persistence in local backup store
    # The read-modify-write runs under one lock so concurrent saves cannot drop each other's entries
    with _local_store_lock:
        local_runs = _load_local_benchmarks()
        filtered = [r for r in local_runs if r.get("benchmark_id") != payload["benchmark_id"]]
        _save_local_benchmarks([payload, *filtered])

    # 2. Persist to Supabase if connected. A cloud failure is reported to the caller
    #    (the local backup still exists), rather than returning success unconditionally.
    client = get_supabase()
    if client:
        try:
            client.table("benchmark_runs").insert(payload).execute()
        except Exception as e:
            logger.error(f"[Supabase] benchmark_runs insert failed (local backup kept): {e}")
            return False

    return True


def count_benchmark_runs_since(user_id: str, since_iso: str) -> int:
    """Count a user's benchmark runs created at or after an ISO timestamp."""
    if not is_valid_uuid(user_id):
        return 0

    client = get_supabase()
    if client:
        try:
            res = (
                _user_scoped_query(client, "benchmark_runs", user_id, columns="benchmark_id")
                .gte("created_at", since_iso)
                .execute()
            )
            return len(res.data or [])
        except Exception as e:
            logger.info(f"[Supabase] Benchmark quota count failed, using local store: {e}")

    local_runs = _load_local_benchmarks()
    return sum(
        1
        for run in local_runs
        if str(run.get("user_id")) == str(user_id)
        and str(run.get("created_at", "")) >= since_iso
    )


def fetch_benchmark_history(user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve benchmark run history from PostgreSQL benchmark_runs table or local store."""
    if not is_valid_uuid(user_id):
        return []

    client = get_supabase()
    if client:
        try:
            res = (
                _user_scoped_query(client, "benchmark_runs", user_id)
                .order("created_at", desc=True)
                .limit(limit)
                .execute()
            )
            if res.data and len(res.data) > 0:
                return res.data
        except Exception as e:
            logger.info(f"[Supabase] Fetching from cloud failed, using local store: {e}")

    # Fallback to local store
    local_runs = _load_local_benchmarks()
    user_runs = [r for r in local_runs if str(r.get("user_id")) == str(user_id)]
    user_runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return user_runs[:limit]


def delete_benchmark_runs(benchmark_ids: List[str], user_id: str) -> Optional[int]:
    """Permanently delete benchmark runs from Supabase and the local store.

    Returns the number of runs actually deleted, or None if the cloud delete failed.
    """
    if not is_valid_uuid(user_id) or not benchmark_ids:
        return 0

    cloud_deleted = 0
    client = get_supabase()
    if client:
        try:
            res = (
                client.table("benchmark_runs")
                .delete()
                .in_("benchmark_id", benchmark_ids)
                .eq("user_id", user_id)
                .select("benchmark_id")
                .execute()
            )
            cloud_deleted = len(res.data or [])
        except Exception as e:
            logger.error(f"[Supabase] Cloud benchmark delete failed: {e}")
            return None

    with _local_store_lock:
        local_runs = _load_local_benchmarks()
        to_delete = set(benchmark_ids)
        remaining = [r for r in local_runs if not (r.get("benchmark_id") in to_delete and str(r.get("user_id")) == str(user_id))]
        _save_local_benchmarks(remaining)
    local_deleted = len(local_runs) - len(remaining)
    return max(cloud_deleted, local_deleted)


def fetch_roe_presets() -> List[Dict[str, Any]]:
    """Retrieve canonical RoE presets from Supabase PostgreSQL table roe_presets."""
    client = get_supabase()
    if not client:
        return []

    try:
        res = client.table("roe_presets").select("*").order("created_at", desc=False).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch roe_presets: {e}")
        return []


_MISSING_ROW = object()


def _custom_roe_owner(client: Any, roe_id: str) -> Any:
    """Return the owner of an existing roe_id, or _MISSING_ROW if none exists.

    This is a write-path integrity probe for save_custom_roe(). It deliberately
    looks up a roe_id across all tenants so a caller cannot overwrite another
    user's scope. It selects only user_id and never returns scope contents, so
    it is allowlisted separately in tests/test_db_scoping.py.
    """
    res = (
        client.table("custom_roes")
        .select("user_id")
        .eq("roe_id", roe_id)
        .limit(1)
        .execute()
    )
    rows = res.data or []
    return rows[0].get("user_id") if rows else _MISSING_ROW


def save_custom_roe(
    roe_dict: Dict[str, Any],
    user_id: Optional[str] = None,
    raw_document: Optional[str] = None,
) -> bool:
    """Save or update an uploaded/parsed custom RoE to Supabase PostgreSQL.

    Strict Privacy Rule: Only persists when user_id is a valid UUID so anonymous
    uploads never create public (user_id IS NULL) rows visible to other users.
    """
    if not is_valid_uuid(user_id):
        return False

    client = get_supabase()
    if not client:
        return False

    try:
        roe_id = roe_dict.get("id") or roe_dict.get("roe_id") or "ROE-CUSTOM"
        # Prevent cross-user overwrite on roe_id collision: if a row already exists
        # with this roe_id and belongs to a different user (or is a system preset),
        # refuse to overwrite it.
        owner_id = _custom_roe_owner(client, roe_id)
        if owner_id is not _MISSING_ROW and owner_id != user_id:
            logger.warning(
                f"[Supabase] Refusing cross-user custom_roes overwrite on roe_id={roe_id} "
                f"(owner={owner_id}, caller={user_id})"
            )
            return False

        payload = {
            "roe_id": roe_id,
            "user_id": user_id,
            "name": roe_dict.get("name", "Custom Scope"),
            "engagement_type": roe_dict.get("engagement_type", "Custom Assessment"),
            "summary": roe_dict.get("summary", ""),
            "allowed_cidrs": roe_dict.get("allowed_cidrs", []),
            "allowed_domains": roe_dict.get("allowed_domains", []),
            "target_hosts": roe_dict.get("target_hosts", []),
            "prohibited_ips": roe_dict.get("prohibited_ips", []),
            "allowed_tools": roe_dict.get("allowed_tools", []),
            "prohibited_tools": roe_dict.get("prohibited_tools", []),
            "prohibited_flags": roe_dict.get("prohibited_flags", []),
            "prohibited_actions": roe_dict.get("prohibited_actions", []),
            "max_nmap_timing": roe_dict.get("max_nmap_timing", 3),
            "raw_document": raw_document or roe_dict.get("raw_document"),
        }
        client.table("custom_roes").upsert(payload, on_conflict="roe_id").execute()
        return True
    except Exception as e:
        logger.error(f"[Supabase] Failed to save custom RoE: {e}")
        return False


def fetch_custom_roes(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve custom RoEs belonging to the given user, plus any system-seeded public (user_id IS NULL) presets.

    Note: Rows with `user_id IS NULL` are strictly read-only system presets seeded by
    administrators; `save_custom_roe` rejects any write where `user_id` is not a valid UUID.
    An unauthenticated or invalid caller sees only public RoEs — never another
    user's private custom scope.
    """
    client = get_supabase()
    if not client:
        return []

    try:
        query = _user_scoped_query(
            client,
            "custom_roes",
            user_id,
            include_public=True,
            public_only=True,
        )
        res = query.order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch custom RoEs: {e}")
        return []


def fetch_custom_roe_by_id(roe_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a single custom RoE by its roe_id, scoped to the given user (or public)."""
    client = get_supabase()
    if not client:
        return None
    try:
        query = _user_scoped_query(
            client,
            "custom_roes",
            user_id,
            include_public=True,
            public_only=True,
        ).eq("roe_id", roe_id)
        res = query.limit(1).execute()
        rows = res.data or []
        return rows[0] if rows else None
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch custom RoE {roe_id}: {e}")
        return None


def save_user_vault_keys(
    user_id: str,
    openrouter_key: Optional[str] = None,
    groq_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Encrypt user API keys with AES-256-GCM and store in user_api_vault."""
    if not is_valid_uuid(user_id):
        raise ValueError("A valid user_id UUID is required to store API keys in vault.")

    client = get_supabase()
    if not client:
        raise RuntimeError("Database connection unavailable.")

    from app.engine.crypto_vault import encrypt_api_key, mask_api_key

    payload: Dict[str, Any] = {
        "user_id": user_id,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if openrouter_key is not None:
        clean_or = openrouter_key.strip()
        if clean_or:
            payload["encrypted_openrouter_key"] = encrypt_api_key(clean_or, user_id)
            payload["key_hint_openrouter"] = mask_api_key(clean_or)
        else:
            payload["encrypted_openrouter_key"] = None
            payload["key_hint_openrouter"] = None

    if groq_key is not None:
        clean_groq = groq_key.strip()
        if clean_groq:
            payload["encrypted_groq_key"] = encrypt_api_key(clean_groq, user_id)
            payload["key_hint_groq"] = mask_api_key(clean_groq)
        else:
            payload["encrypted_groq_key"] = None
            payload["key_hint_groq"] = None

    # Ciphertext lives only in the RLS-protected user_api_vault table. It is never copied into
    # auth app_metadata (user-readable and embedded in the user's JWT). A failed write must surface.
    try:
        client.table("user_api_vault").upsert(payload, on_conflict="user_id").execute()
    except Exception as e:
        logger.error(f"[Supabase] user_api_vault upsert failed for {user_id}: {e}")
        raise RuntimeError("Failed to store API keys in the vault.") from e

    return {
        "success": True,
        "has_openrouter_key": bool(payload.get("encrypted_openrouter_key")),
        "openrouter_hint": payload.get("key_hint_openrouter"),
        "has_groq_key": bool(payload.get("encrypted_groq_key")),
        "groq_hint": payload.get("key_hint_groq"),
    }


def _get_vault_row_for_user(client: Any, user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch encrypted vault record from user_api_vault table or auth.users app_metadata fallback."""
    try:
        res = (
            _user_scoped_query(
                client,
                "user_api_vault",
                user_id,
                columns=(
                    "key_hint_openrouter, key_hint_groq, "
                    "encrypted_openrouter_key, encrypted_groq_key"
                ),
            )
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            return rows[0]
    except Exception:
        pass

    try:
        user_res = client.auth.admin.get_user_by_id(user_id)
        user_obj = getattr(user_res, "user", None)
        if user_obj:
            app_meta = getattr(user_obj, "app_metadata", None) or {}
            vault_data = app_meta.get("vallum_vault")
            if isinstance(vault_data, dict) and (
                vault_data.get("encrypted_openrouter_key") or vault_data.get("encrypted_groq_key")
            ):
                return vault_data
    except Exception as e:
        logger.warning(f"[Supabase] Fallback auth.admin vault lookup failed for {user_id}: {e}")

    return None


def get_user_vault_keys(user_id: str) -> Dict[str, Optional[str]]:
    """Retrieve and decrypt user API keys in memory.
    
    Plaintext keys are NEVER logged or saved to disk.
    """
    if not is_valid_uuid(user_id):
        return {"openrouter_key": None, "groq_key": None}

    client = get_supabase()
    if not client:
        return {"openrouter_key": None, "groq_key": None}

    try:
        from app.engine.crypto_vault import decrypt_api_key

        row = _get_vault_row_for_user(client, user_id)
        if not row:
            return {"openrouter_key": None, "groq_key": None}

        enc_or = row.get("encrypted_openrouter_key")
        enc_groq = row.get("encrypted_groq_key")

        decrypted_or = decrypt_api_key(enc_or, user_id) if enc_or else None
        decrypted_groq = decrypt_api_key(enc_groq, user_id) if enc_groq else None

        return {
            "openrouter_key": decrypted_or,
            "groq_key": decrypted_groq,
        }
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"[Supabase] Failed to retrieve vault keys for user {user_id}: {e}")
        return {"openrouter_key": None, "groq_key": None}


def revoke_user_vault_keys(user_id: str) -> bool:
    """Permanently delete user's API vault row from the database."""
    if not is_valid_uuid(user_id):
        return False

    client = get_supabase()
    if not client:
        return False

    # The vault row delete is required; report failure instead of success if it fails
    try:
        client.table("user_api_vault").delete().eq("user_id", user_id).execute()
    except Exception:
        logger.exception("[Supabase] user_api_vault delete failed for %s", user_id)
        return False

    # Remove any legacy ciphertext copy from app_metadata (remove the key, do not leave a null marker)
    try:
        user_res = client.auth.admin.get_user_by_id(user_id)
        user_obj = getattr(user_res, "user", None)
        metadata = dict(getattr(user_obj, "app_metadata", {}) or {})
        if "vallum_vault" in metadata:
            metadata.pop("vallum_vault", None)
            client.auth.admin.update_user_by_id(user_id, {"app_metadata": metadata})
    except Exception:
        logger.exception("[Supabase] Failed to clear legacy vallum_vault metadata for %s", user_id)
        return False

    return True


def get_user_vault_status(user_id: str) -> Dict[str, Any]:
    """Get metadata/hints for stored keys without exposing decrypted plaintext."""
    if not is_valid_uuid(user_id):
        return {
            "is_configured": False,
            "has_openrouter_key": False,
            "openrouter_hint": None,
            "has_groq_key": False,
            "groq_hint": None,
        }

    client = get_supabase()
    if not client:
        return {
            "is_configured": False,
            "has_openrouter_key": False,
            "openrouter_hint": None,
            "has_groq_key": False,
            "groq_hint": None,
        }

    try:
        row = _get_vault_row_for_user(client, user_id)
        if not row:
            return {
                "is_configured": False,
                "has_openrouter_key": False,
                "openrouter_hint": None,
                "has_groq_key": False,
                "groq_hint": None,
            }

        has_or = bool(row.get("encrypted_openrouter_key"))
        has_groq = bool(row.get("encrypted_groq_key"))
        return {
            "is_configured": has_or or has_groq,
            "has_openrouter_key": has_or,
            "openrouter_hint": row.get("key_hint_openrouter"),
            "has_groq_key": has_groq,
            "groq_hint": row.get("key_hint_groq"),
        }
    except Exception as e:
        logger.error(f"[Supabase] Failed to get vault status for user {user_id}: {e}")
        return {
            "is_configured": False,
            "has_openrouter_key": False,
            "openrouter_hint": None,
            "has_groq_key": False,
            "groq_hint": None,
        }


ADMIN_EMAILS = {
    "arorakhushal1108@gmail.com",
    "arorak1108@gmail.com",
}


def resolve_user_role(email: str) -> str:
    """Enforce immutable RBAC policy.
    
    Khushal Arora is the designated Super Admin.
    All other users are Penetration Testers. No other user can ever be Admin.
    """
    if not email:
        return "penetration_tester"
    return "admin" if email.strip().lower() in ADMIN_EMAILS else "penetration_tester"



def get_user_profile(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch user profile with enforced role governance."""
    if not is_valid_uuid(user_id):
        return None
    client = get_supabase()
    if not client:
        return None
    try:
        res = client.table("profiles").select("*").eq("id", user_id).limit(1).execute()
        rows = res.data or []
        if not rows:
            return None
        profile = rows[0]
        profile["role"] = resolve_user_role(profile.get("email", ""))
        return profile
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch profile for {user_id}: {e}")
        return None


def verify_supabase_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Verify a Supabase Auth JWT token server-side and retrieve the authenticated user profile.

    Validates signature and expiry using the Supabase auth service.
    Returns user dict containing id, email, role if valid, or None if invalid/expired.
    """
    if not token or not isinstance(token, str):
        return None

    client = get_supabase()
    if not client:
        return None

    try:
        clean_token = token.strip()
        if clean_token.lower().startswith("bearer "):
            clean_token = clean_token[7:].strip()

        user_res = client.auth.get_user(clean_token)
        if user_res and user_res.user:
            email = user_res.user.email or ""
            return {
                "id": str(user_res.user.id),
                "email": email,
                "role": resolve_user_role(email),
                "app_metadata": getattr(user_res.user, "app_metadata", {}),
                "user_metadata": getattr(user_res.user, "user_metadata", {}),
            }
        return None
    except Exception as e:
        logger.warning(f"[Supabase] JWT verification failed: {e}")
        return None


