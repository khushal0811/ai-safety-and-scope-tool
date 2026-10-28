"""Database package export."""

from app.db.supabase_client import (
    get_supabase,
    is_database_connected,
    save_audit_log,
    fetch_audit_history,
    delete_audit_logs,
    fetch_audit_metrics,
    save_benchmark_run,
    fetch_benchmark_history,
    delete_benchmark_runs,
    fetch_roe_presets,
    save_custom_roe,
    fetch_custom_roes,
    is_valid_uuid,
    verify_supabase_jwt,
)

__all__ = [
    "get_supabase",
    "is_database_connected",
    "save_audit_log",
    "fetch_audit_history",
    "delete_audit_logs",
    "fetch_audit_metrics",
    "save_benchmark_run",
    "fetch_benchmark_history",
    "delete_benchmark_runs",
    "fetch_roe_presets",
    "save_custom_roe",
    "fetch_custom_roes",
    "is_valid_uuid",
    "verify_supabase_jwt",
]

