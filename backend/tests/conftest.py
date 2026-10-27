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
