"""Supabase database client and data persistence repository.

Zero Host Execution: Operates strictly over HTTPS via Supabase REST/PostgREST.
"""

import logging
import os
import time
import uuid
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
    key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY", "")).strip()

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
    """Save or update an uploaded/parsed custom RoE to Supabase PostgreSQL."""
    client = get_supabase()
    if not client:
        return False

    try:
        roe_id = roe_dict.get("id") or roe_dict.get("roe_id") or "ROE-CUSTOM"
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
    """Retrieve custom RoEs belonging to user or created during the session."""
    client = get_supabase()
    if not client:
        return []

    try:
        query = client.table("custom_roes").select("*").order("created_at", desc=True)
        if user_id:
            query = query.or_(f"user_id.eq.{user_id},user_id.is.null")
        res = query.execute()
        return res.data or []
    except Exception as e:
        logger.error(f"[Supabase] Failed to fetch custom RoEs: {e}")
        return []


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
            payload["encrypted_openrouter_key"] = encrypt_api_key(clean_or)
            payload["key_hint_openrouter"] = mask_api_key(clean_or)
        else:
            payload["encrypted_openrouter_key"] = None
            payload["key_hint_openrouter"] = None

    if groq_key is not None:
        clean_groq = groq_key.strip()
        if clean_groq:
            payload["encrypted_groq_key"] = encrypt_api_key(clean_groq)
            payload["key_hint_groq"] = mask_api_key(clean_groq)
        else:
            payload["encrypted_groq_key"] = None
            payload["key_hint_groq"] = None

    client.table("user_api_vault").upsert(payload, on_conflict="user_id").execute()
    return {
        "success": True,
        "has_openrouter_key": bool(payload.get("encrypted_openrouter_key")),
        "openrouter_hint": payload.get("key_hint_openrouter"),
        "has_groq_key": bool(payload.get("encrypted_groq_key")),
        "groq_hint": payload.get("key_hint_groq"),
    }


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

        res = client.table("user_api_vault").select("encrypted_openrouter_key, encrypted_groq_key").eq("user_id", user_id).limit(1).execute()
        rows = res.data or []
        if not rows:
            return {"openrouter_key": None, "groq_key": None}

        row = rows[0]
        enc_or = row.get("encrypted_openrouter_key")
        enc_groq = row.get("encrypted_groq_key")

        decrypted_or = decrypt_api_key(enc_or) if enc_or else None
        decrypted_groq = decrypt_api_key(enc_groq) if enc_groq else None

        return {
            "openrouter_key": decrypted_or,
            "groq_key": decrypted_groq,
        }
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

    try:
        client.table("user_api_vault").delete().eq("user_id", user_id).execute()
        return True
    except Exception as e:
        logger.error(f"[Supabase] Failed to revoke vault keys for user {user_id}: {e}")
        return False


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
        res = client.table("user_api_vault").select("key_hint_openrouter, key_hint_groq, encrypted_openrouter_key, encrypted_groq_key").eq("user_id", user_id).limit(1).execute()
        rows = res.data or []
        if not rows:
            return {
                "is_configured": False,
                "has_openrouter_key": False,
                "openrouter_hint": None,
                "has_groq_key": False,
                "groq_hint": None,
            }

        row = rows[0]
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
