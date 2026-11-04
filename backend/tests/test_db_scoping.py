"""Regression guards for AUDIT_003 Info I3: tenant-scoped database reads.

The Supabase client prefers the service-role key, so Row Level Security does not
protect tenant isolation. These tests make the Python-side scoping structural:

1. Tenant-owned tables may only be accessed inside app/db/supabase_client.py.
2. Inside that module, direct .table(...) access is an explicit allowlist of
   write/service-role paths. New direct reads fail CI instead of shipping.
3. Every read helper emits a user_id filter (or an explicit public-only filter).
4. The scoped-query helper refuses to build an unscoped query.
"""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.db import supabase_client


BACKEND_DIR = Path(__file__).resolve().parents[1]
APP_DIR = BACKEND_DIR / "app"
DB_MODULE = APP_DIR / "db" / "supabase_client.py"

# Tables that hold per-tenant rows and must be read through _user_scoped_query().
SCOPED_TABLES = {"audit_logs", "custom_roes", "user_api_vault", "benchmark_runs"}

# Direct .table(...) access allowed inside supabase_client.py.
# Every entry is either a write (service-role required by migration 012) or the
# one documented write-path ownership probe.
EXPECTED_DIRECT_ACCESS = {
    ("save_audit_log", "audit_logs", "insert"),
    ("delete_audit_logs", "audit_logs", "update"),
    ("_custom_roe_owner", "custom_roes", "select"),
    ("save_custom_roe", "custom_roes", "upsert"),
    ("save_benchmark_run", "benchmark_runs", "insert"),
    ("delete_benchmark_runs", "benchmark_runs", "delete"),
    ("save_user_vault_keys", "user_api_vault", "upsert"),
    ("revoke_user_vault_keys", "user_api_vault", "delete"),
}

USER_ID = "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _function_owners(tree: ast.AST) -> dict:
    """Map id(node) -> name of the innermost enclosing function."""
    owners: dict = {}

    def visit(node: ast.AST, current):
        for child in ast.iter_child_nodes(node):
            name = (
                child.name
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                else current
            )
            owners[id(child)] = name
            visit(child, name)

    visit(tree, None)
    return owners


def _parent_map(tree: ast.AST) -> dict:
    return {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _direct_table_access(path: Path) -> set:
    """Return (function, table, first_chained_method) for literal .table() calls."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    owners = _function_owners(tree)
    parents = _parent_map(tree)
    found = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "table":
            continue
        if not node.args:
            continue
        first_arg = node.args[0]
        if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
            continue
        table = first_arg.value
        if table not in SCOPED_TABLES:
            continue

        parent = parents.get(id(node))
        first_method = (
            parent.attr
            if isinstance(parent, ast.Attribute) and parent.value is node
            else None
        )
        found.add((owners.get(id(node)), table, first_method))

    return found


# ---------------------------------------------------------------------------
# Static guards
# ---------------------------------------------------------------------------

def test_tenant_tables_are_not_accessed_outside_db_module():
    violations = []
    for path in sorted(APP_DIR.rglob("*.py")):
        if path == DB_MODULE:
            continue
        for function, table, method in _direct_table_access(path):
            location = path.relative_to(BACKEND_DIR)
            violations.append(
                f"{location}:{function} -> .table({table!r}).{method}()"
            )

    assert not violations, (
        "Tenant-owned tables must be read through app.db.supabase_client helpers:\n"
        + "\n".join(violations)
    )


def test_direct_tenant_table_access_matches_allowlist():
    actual = _direct_table_access(DB_MODULE)
    assert actual == EXPECTED_DIRECT_ACCESS, (
        "Direct tenant-table access changed. Reads must use _user_scoped_query(); "
        "writes must be explicitly allowlisted.\n"
        f"Unexpected: {sorted(actual - EXPECTED_DIRECT_ACCESS)}\n"
        f"Missing:    {sorted(EXPECTED_DIRECT_ACCESS - actual)}"
    )


# ---------------------------------------------------------------------------
# Runtime scope-shape guards
# ---------------------------------------------------------------------------

class _RecordingQuery:
    def __init__(self, table: str, calls: list):
        self.table = table
        self.calls = calls
        self.calls.append(("table", table))

    def select(self, columns="*"):
        self.calls.append(("select", columns))
        return self

    def eq(self, column, value):
        self.calls.append(("eq", column, value))
        return self

    def or_(self, expression):
        self.calls.append(("or_", expression))
        return self

    def is_(self, column, value):
        self.calls.append(("is_", column, value))
        return self

    def in_(self, column, values):
        self.calls.append(("in_", column, values))
        return self

    def order(self, *args, **kwargs):
        self.calls.append(("order", args, kwargs))
        return self

    def limit(self, count):
        self.calls.append(("limit", count))
        return self

    def execute(self):
        return SimpleNamespace(data=[])


class _FakeAdmin:
    def get_user_by_id(self, user_id):
        return SimpleNamespace(user=None)


class _FakeAuth:
    def __init__(self):
        self.admin = _FakeAdmin()


class _RecordingClient:
    def __init__(self):
        self.calls: list = []
        self.auth = _FakeAuth()

    def table(self, name):
        return _RecordingQuery(name, self.calls)


def _record(monkeypatch, func, *args, **kwargs):
    client = _RecordingClient()
    monkeypatch.setattr(supabase_client, "get_supabase", lambda: client)
    result = func(*args, **kwargs)
    return client.calls, result


def test_fetch_audit_history_applies_user_filter(monkeypatch):
    calls, _ = _record(monkeypatch, supabase_client.fetch_audit_history, USER_ID)
    assert ("eq", "user_id", USER_ID) in calls
    assert ("is_", "deleted_at", "null") in calls


def test_fetch_audit_logs_for_roe_applies_user_filter(monkeypatch):
    calls, _ = _record(
        monkeypatch,
        supabase_client.fetch_audit_logs_for_roe,
        "ROE-1",
        user_id=USER_ID,
    )
    assert ("eq", "user_id", USER_ID) in calls
    assert ("eq", "roe_id", "ROE-1") in calls


def test_fetch_benchmark_history_applies_user_filter(monkeypatch):
    calls, _ = _record(monkeypatch, supabase_client.fetch_benchmark_history, USER_ID)
    assert ("eq", "user_id", USER_ID) in calls


def test_fetch_custom_roes_includes_only_caller_and_public(monkeypatch):
    calls, _ = _record(monkeypatch, supabase_client.fetch_custom_roes, USER_ID)
    assert ("or_", f"user_id.eq.{USER_ID},user_id.is.null") in calls


def test_fetch_custom_roes_without_identity_is_public_only(monkeypatch):
    calls, _ = _record(monkeypatch, supabase_client.fetch_custom_roes, None)
    assert ("is_", "user_id", "null") in calls
    assert not any(call[0] == "or_" for call in calls)


def test_fetch_custom_roes_invalid_identity_is_public_only(monkeypatch):
    calls, _ = _record(monkeypatch, supabase_client.fetch_custom_roes, "not-a-uuid")
    assert ("is_", "user_id", "null") in calls
    assert not any(call[0] == "or_" for call in calls)


def test_fetch_custom_roe_by_id_applies_user_filter(monkeypatch):
    calls, _ = _record(
        monkeypatch,
        supabase_client.fetch_custom_roe_by_id,
        "ROE-1",
        user_id=USER_ID,
    )
    assert ("or_", f"user_id.eq.{USER_ID},user_id.is.null") in calls
    assert ("eq", "roe_id", "ROE-1") in calls


def test_vault_status_applies_user_filter(monkeypatch):
    calls, _ = _record(monkeypatch, supabase_client.get_user_vault_status, USER_ID)
    assert ("eq", "user_id", USER_ID) in calls


# ---------------------------------------------------------------------------
# Helper refusal guarantees
# ---------------------------------------------------------------------------

def test_scoped_query_applies_valid_user():
    client = _RecordingClient()
    supabase_client._user_scoped_query(client, "audit_logs", USER_ID)
    assert ("select", "*") in client.calls
    assert ("eq", "user_id", USER_ID) in client.calls


def test_scoped_query_rejects_missing_or_invalid_user():
    client = _RecordingClient()

    with pytest.raises(supabase_client.UnscopedQueryError):
        supabase_client._user_scoped_query(client, "audit_logs", None)

    with pytest.raises(supabase_client.UnscopedQueryError):
        supabase_client._user_scoped_query(client, "user_api_vault", "not-a-uuid")


def test_scoped_query_rejects_non_tenant_table():
    client = _RecordingClient()
    with pytest.raises(supabase_client.UnscopedQueryError):
        supabase_client._user_scoped_query(client, "roe_presets", USER_ID)


def test_scoped_query_allows_explicit_public_projection():
    client = _RecordingClient()
    supabase_client._user_scoped_query(
        client, "custom_roes", None, public_only=True
    )
    assert ("is_", "user_id", "null") in client.calls
