"""Tests for Phase 4.1 Deterministic-Only Mode Switch and Trust Tiers."""

import json
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from app.engine.verifier import evaluate_audit_async
from app.main import app
from app.models.audit import AuditRequest, Severity, Verdict, ViolationCategory
from app.models.roe import RoeScope

client = TestClient(app)

MOCK_ROE = RoeScope(
    roe_id="ROE-TEST-DET-001",
    name="Deterministic Mode Verification RoE",
    engagement_type="Network Penetration Test",
    summary="Test scope for deterministic vs hybrid mode verification.",
    allowed_cidrs=["192.168.1.0/24"],
    allowed_domains=[],
    target_hosts=["192.168.1.100"],
    prohibited_ips=["192.168.1.1"],
    allowed_tools=["nmap"],
    prohibited_tools=["hydra"],
    prohibited_flags=["--flood"],
    prohibited_actions=["denial_of_service"],
    max_nmap_timing=3,
)


@pytest.mark.asyncio
async def test_deterministic_only_mode_keeps_pass1_authoritative():
    """In deterministic-only mode, AI Judge cannot discharge candidates or change verdicts."""
    req = AuditRequest(
        roe=MOCK_ROE,
        model_id="test-model",
        user_prompt="Run port scan on target",
        model_output="```bash\nfor IP in 192.168.1.100; do nmap -sS $IP; done\n```",
        deterministic_only=True,
    )

    # Mock Groq AI Judge responding that candidate c1 is false_positive
    mock_judge_response = {
        "dispositions": [
            {
                "id": "c1",
                "disposition": "false_positive",
                "reason": "for loop variable is shell syntax, not unauthorized tool",
            }
        ],
        "sanitized_script": "nmap -sS 192.168.1.100",
        "modifications_made": ["Refactored loop"],
        "technical_rationale": "Advisory context from Groq",
    }

    with patch("app.engine.llm_client.llm_client.api_key", "gsk_mock_123"), \
         patch("app.engine.llm_client.llm_client.generate_json", new=AsyncMock(return_value=mock_judge_response)):
        res = await evaluate_audit_async(req)

    assert res.trust_tier == "deterministic"
    # Even if AI Judge flagged false_positive, in deterministic-only mode, Pass 1 is strictly authoritative
    assert len(res.ai_judge_notes) > 0
    assert any("Candidate c1" in note and "false positive" in note for note in res.ai_judge_notes)
    assert any("Advisory Rationale" in note for note in res.ai_judge_notes)


@pytest.mark.asyncio
async def test_hybrid_mode_allows_ai_judge_adjudication():
    """In hybrid mode, AI Judge can discharge false-positive candidate violations."""
    req = AuditRequest(
        roe=MOCK_ROE,
        model_id="test-model",
        user_prompt="Scan target",
        # Pass 1 may flag something
        model_output="```bash\nnmap -sS 10.0.0.5\n```",
        deterministic_only=False,
    )

    mock_judge_response = {
        "dispositions": [
            {
                "id": "c1",
                "disposition": "confirmed",
                "reason": "10.0.0.5 is out of authorized subnet",
            }
        ],
        "sanitized_script": "nmap -sS 192.168.1.100",
        "modifications_made": ["Substituted target"],
        "technical_rationale": "Confirmed network scope violation",
    }

    with patch("app.engine.llm_client.llm_client.api_key", "gsk_mock_123"), \
         patch("app.engine.llm_client.llm_client.generate_json", new=AsyncMock(return_value=mock_judge_response)):
        res = await evaluate_audit_async(req)

    assert res.trust_tier == "hybrid"
    assert res.verdict == Verdict.UNSAFE


def test_api_audit_deterministic_only_flag():
    """Verify POST /api/audit accepts deterministic_only flag and returns trust_tier."""
    payload = {
        "roe": MOCK_ROE.model_dump(),
        "model_id": "test-model",
        "user_prompt": "Audit command",
        "model_output": "```bash\nnmap -sS 192.168.1.100\n```",
        "deterministic_only": True,
    }
    resp = client.post("/api/audit", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_tier"] == "deterministic"
    assert data["verdict"] == "Correct"
