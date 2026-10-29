"""Supabase database client and data persistence repository.

Zero Host Execution: Operates strictly over HTTPS via Supabase REST/PostgREST.
"""

import json
import logging
import os
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


def save_audit_log(
    audit_data: Dict[str, Any],
    user_id: Optional[str] = None,
    execution_time_ms: int = 0,
) -> bool:
    """Save an evaluated audit result to the PostgreSQL audit_logs table.
    
    Strict Privacy Rule: Only persists when user_id is a valid UUID. Guest audits are never stored.
    """
    if not is_valid_uuid(user_id):
        return False

    client = get_supabase()
    if not client:
        return False

    try:
        payload = {
            "audit_id": audit_data.get("audit_id"),
            "user_id": user_id,
            "roe_id": audit_data.get("roe_id") or "UNKNOWN",
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
            "execution_time_ms": execution_time_ms,
        }

        client.table("audit_logs").insert(payload).execute()
        return True
    except Exception as e:
        logger.error(f"[Supabase] Failed to persist audit log: {e}")
        return False


def fetch_audit_history(user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve audit history from PostgreSQL audit_logs table for authenticated user only."""
    if not is_valid_uuid(user_id):
        return []

    client = get_supabase()
    if not client:
        return []

    try:
        res = client.table("audit_logs").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(limit).execute()
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
    """Retrieve audit logs for a specific RoE ID, scoped strictly to the given user.

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
            client.table("audit_logs")
            .select("*")
            .eq("roe_id", roe_id)
            .eq("user_id", user_id)
        )
        if audit_id:
            query = query.eq("audit_id", audit_id)
        res = query.order("created_at", desc=False).limit(limit).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch audit logs for RoE {roe_id} (user {user_id}): {e}")
        return []


def delete_audit_logs(audit_ids: List[str], user_id: str) -> bool:
    """Permanently delete one or more audit logs from PostgreSQL table audit_logs."""
    if not is_valid_uuid(user_id) or not audit_ids:
        return False

    client = get_supabase()
    if not client:
        return False

    try:
        client.table("audit_logs").delete().in_("audit_id", audit_ids).eq("user_id", user_id).execute()
        return True
    except Exception as e:
        logger.error(f"[Supabase] Failed to delete audit logs: {e}")
        return False


def fetch_audit_metrics(user_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculate aggregated telemetry metrics for authenticated user only."""
    if not is_valid_uuid(user_id):
        return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}

    client = get_supabase()
    if not client:
        return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}

    try:
        res = client.table("audit_logs").select("verdict, execution_time_ms").eq("user_id", user_id).execute()
        rows = res.data or []

        total = len(rows)
        if total == 0:
            return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}

        unsafe = sum(1 for r in rows if r.get("verdict") == "Unsafe")
        correct = sum(1 for r in rows if r.get("verdict") == "Correct")
        incorrect = sum(1 for r in rows if r.get("verdict") == "Incorrect")
        total_latency = sum(r.get("execution_time_ms", 0) for r in rows)

        pass_rate = round((correct / total) * 100) if total > 0 else 0
        avg_latency = round(total_latency / total) if total > 0 else 0

        return {
            "total": total,
            "unsafe": unsafe,
            "correct": correct,
            "incorrect": incorrect,
            "pass_rate": pass_rate,
            "avg_latency_ms": avg_latency,
        }
    except Exception as e:
        logger.error(f"[Supabase] Failed to calculate metrics: {e}")
        return {"total": 0, "unsafe": 0, "correct": 0, "incorrect": 0, "pass_rate": 0, "avg_latency_ms": 0}


LOCAL_BENCHMARKS_FILE = os.path.join(os.path.dirname(__file__), "benchmark_runs_local.json")


def _load_local_benchmarks() -> List[Dict[str, Any]]:
    if not os.path.exists(LOCAL_BENCHMARKS_FILE):
        return []
    try:
        with open(LOCAL_BENCHMARKS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[LocalBenchmarkStore] Read error: {e}")
        return []


def _save_local_benchmarks(data: List[Dict[str, Any]]) -> None:
    try:
        with open(LOCAL_BENCHMARKS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
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
    local_runs = _load_local_benchmarks()
    filtered = [r for r in local_runs if r.get("benchmark_id") != payload["benchmark_id"]]
    _save_local_benchmarks([payload, *filtered])

    # 2. Persist to Supabase if connected
    client = get_supabase()
    if client:
        try:
            client.table("benchmark_runs").insert(payload).execute()
        except Exception as e:
            logger.warning(f"[Supabase] Table insert failed (local backup active): {e}")

    return True


def fetch_benchmark_history(user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve benchmark run history from PostgreSQL benchmark_runs table or local store."""
    if not is_valid_uuid(user_id):
        return []

    client = get_supabase()
    if client:
        try:
            res = client.table("benchmark_runs").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(limit).execute()
            if res.data and len(res.data) > 0:
                return res.data
        except Exception as e:
            logger.info(f"[Supabase] Fetching from cloud failed, using local store: {e}")

    # Fallback to local store
    local_runs = _load_local_benchmarks()
    user_runs = [r for r in local_runs if str(r.get("user_id")) == str(user_id)]
    user_runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return user_runs[:limit]


def delete_benchmark_runs(benchmark_ids: List[str], user_id: str) -> bool:
    """Permanently delete one or more benchmark runs from Supabase and local store."""
    if not is_valid_uuid(user_id) or not benchmark_ids:
        return False

    client = get_supabase()
    if client:
        try:
            client.table("benchmark_runs").delete().in_("benchmark_id", benchmark_ids).eq("user_id", user_id).execute()
        except Exception as e:
            logger.warning(f"[Supabase] Cloud delete failed: {e}")

    local_runs = _load_local_benchmarks()
    to_delete = set(benchmark_ids)
    remaining = [r for r in local_runs if not (r.get("benchmark_id") in to_delete and str(r.get("user_id")) == str(user_id))]
    _save_local_benchmarks(remaining)
    return True


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
        existing = (
            client.table("custom_roes")
            .select("user_id")
            .eq("roe_id", roe_id)
            .limit(1)
            .execute()
        )
        if existing.data:
            owner_id = existing.data[0].get("user_id")
            if owner_id != user_id:
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
        query = client.table("custom_roes").select("*").order("created_at", desc=True)
        if user_id and is_valid_uuid(user_id):
            query = query.or_(f"user_id.eq.{user_id},user_id.is.null")
        else:
            query = query.is_("user_id", "null")
        res = query.execute()
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
        query = client.table("custom_roes").select("*").eq("roe_id", roe_id)
        if user_id and is_valid_uuid(user_id):
            query = query.or_(f"user_id.eq.{user_id},user_id.is.null")
        else:
            query = query.is_("user_id", "null")
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

    try:
        client.table("user_api_vault").upsert(payload, on_conflict="user_id").execute()
    except Exception as e:
        logger.warning(f"[Supabase] user_api_vault table upsert fallback to auth.admin app_metadata: {e}")

    # Also persist encrypted vault payload in Supabase Auth user app_metadata so it works
    # even when the optional user_api_vault table migration has not been applied.
    try:
        client.auth.admin.update_user_by_id(
            user_id,
            {"app_metadata": {"vallum_vault": payload}},
        )
    except Exception as e:
        logger.warning(f"[Supabase] Failed to sync vault to auth.admin app_metadata for {user_id}: {e}")

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
            client.table("user_api_vault")
            .select("key_hint_openrouter, key_hint_groq, encrypted_openrouter_key, encrypted_groq_key")
            .eq("user_id", user_id)
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

    deleted = False
    try:
        client.table("user_api_vault").delete().eq("user_id", user_id).execute()
        deleted = True
    except Exception as e:
        logger.warning(f"[Supabase] user_api_vault table delete warning for {user_id}: {e}")

    try:
        client.auth.admin.update_user_by_id(
            user_id,
            {"app_metadata": {"vallum_vault": None}},
        )
        deleted = True
    except Exception as e:
        logger.warning(f"[Supabase] Failed to clear auth.admin vallum_vault for {user_id}: {e}")

    return deleted


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


