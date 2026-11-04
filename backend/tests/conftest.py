"""Pytest fixtures and configuration."""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure app is discoverable on python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.data.presets import ROE_PRESETS
from app.main import app
from app.models.roe import RoeScope


@pytest.fixture
def network_recon_roe() -> RoeScope:
    """Standard network reconnaissance RoE fixture."""
    return ROE_PRESETS[0]  # ROE-PRESET-NET-001


@pytest.fixture
def web_pentest_roe() -> RoeScope:
    """Standard web application pentest RoE fixture."""
    return ROE_PRESETS[1]  # ROE-PRESET-WEB-002


@pytest.fixture
def client() -> TestClient:
    """Synchronous FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def _uuid_bearer_tokens_for_tests(monkeypatch):
    """Test identity: 'Authorization: Bearer <uuid>' resolves to that user.

    Identity is only ever taken from a verified token; tests that need a signed-in user
    send a bearer token whose value is the user UUID. Any other token is verified normally.
    """
    from app.api import deps
    from app.db.supabase_client import is_valid_uuid

    real_verify = deps.verify_supabase_jwt

    def fake_verify(authorization):
        parts = authorization.strip().split(" ", 1)
        token = parts[1].strip() if len(parts) == 2 else ""
        if is_valid_uuid(token):
            return {"id": token}
        return real_verify(authorization)

    monkeypatch.setattr(deps, "verify_supabase_jwt", fake_verify)
