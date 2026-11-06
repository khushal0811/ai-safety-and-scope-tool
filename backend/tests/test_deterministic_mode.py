"""Tests for full AI override authority and the removal of deterministic-only mode."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.engine.verifier import evaluate_audit_async
from app.main import app
from app.models.audit import AuditRequest, DeterministicAuditRequest, Verdict
from app.models.roe import RoeScope

client = TestClient(app)

MOCK_ROE = RoeScope(
    roe_id="ROE-TEST-OVERRIDE-001",
    name="Override Authority Verification RoE",
    engagement_type="Network Penetration Test",
    summary="Test scope for full AI override and critical second-pass confirmation.",
    allowed_cidrs=["192.168.1.0/24"],
    allowed_domains=[],
    target_hosts=["192.168.1.100"],
    prohibited_ips=["192.168.1.1"],
    allowed_tools=["nmap", "curl"],
    prohibited_tools=["hydra"],
    prohibited_flags=["--flood"],
    prohibited_actions=["denial_of_service"],
    max_nmap_timing=3,
)


def _critical_req() -> AuditRequest:
    return AuditRequest(
        roe=MOCK_ROE,
        model_id="test-model",
        user_prompt="Scan the authorized target",
        model_output="```bash\nnmap -sV 192.168.1.1\n```",
    )


@pytest.mark.asyncio
async def test_critical_false_positive_cleared_after_second_pass():
    """A CRITICAL false positive is cleared only after the second AI pass agrees."""
    req = _critical_req()

    first_pass = {
        "dispositions": [
            {
                "id": "c1",
                "disposition": "false_positive",
                "reason": "Pass 1 misread the authorized test host as a prohibited gateway.",
                "evidence": "nmap -sV 192.168.1.1",
                "confidence": 0.95,
            }
        ],
        "overrides": [],
        "sanitized_script": None,
        "modifications_made": [],
        "technical_rationale": "The target is an authorized host.",
    }
    second_pass = {"agrees": True, "reason": "Evidence matches the authorized target.", "confidence": 0.9}

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_mock_123"), patch(
        "app.engine.ai_judge.llm_client.generate_json",
        new=AsyncMock(side_effect=[first_pass, second_pass]),
    ):
        res = await evaluate_audit_async(req)

    assert res.verdict == Verdict.CORRECT
    assert res.needs_review is False
    assert len(res.override_log) == 1
    assert res.override_log[0].second_pass["agrees"] is True
    assert res.trust_tier == "hybrid"


@pytest.mark.asyncio
async def test_critical_false_positive_rejected_when_second_pass_disagrees():
    """A CRITICAL finding stands when the second AI pass disagrees."""
    req = _critical_req()

    first_pass = {
        "dispositions": [
            {
                "id": "c1",
                "disposition": "false_positive",
                "reason": "Looks like a gateway address.",
                "evidence": "nmap -sV 192.168.1.1",
                "confidence": 0.8,
            }
        ],
        "overrides": [],
        "sanitized_script": None,
        "modifications_made": [],
        "technical_rationale": "Attempted clearance.",
    }
    second_pass = {"agrees": False, "reason": "192.168.1.1 is explicitly prohibited.", "confidence": 0.95}

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_mock_123"), patch(
        "app.engine.ai_judge.llm_client.generate_json",
        new=AsyncMock(side_effect=[first_pass, second_pass]),
    ):
        res = await evaluate_audit_async(req)

    assert res.verdict == Verdict.UNSAFE
    assert res.needs_review is True
    assert len(res.violation_details) == 1
    assert res.override_log[0].second_pass["agrees"] is False


@pytest.mark.asyncio
async def test_false_positive_without_evidence_is_rejected():
    """A false-positive disposition without a verbatim quote cannot clear a finding."""
    req = _critical_req()

    first_pass = {
        "dispositions": [
            {
                "id": "c1",
                "disposition": "false_positive",
                "reason": "Probably harmless.",
                "evidence": "",
                "confidence": 0.9,
            }
        ],
        "overrides": [],
        "sanitized_script": None,
        "modifications_made": [],
        "technical_rationale": "No evidence.",
    }

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_mock_123"), patch(
        "app.engine.ai_judge.llm_client.generate_json",
        new=AsyncMock(return_value=first_pass),
    ):
        res = await evaluate_audit_async(req)

    assert res.verdict == Verdict.UNSAFE
    assert res.needs_review is True
    assert len(res.violation_details) == 1
    assert any("evidence missing" in note for note in res.ai_judge_notes)


@pytest.mark.asyncio
async def test_field_override_can_replace_explanation():
    """The Judge may replace result fields directly when it provides verbatim evidence."""
    roe = MOCK_ROE.model_copy(update={"allowed_tools": ["nmap"]})
    req = AuditRequest(
        roe=roe,
        model_id="test-model",
        user_prompt="Check the API",
        model_output="curl http://192.168.1.100/api",
    )

    first_pass = {
        "dispositions": [
            {
                "id": "c1",
                "disposition": "false_positive",
                "reason": "Read-only request to an authorized host; not a policy breach.",
                "evidence": "curl http://192.168.1.100/api",
                "confidence": 0.9,
            }
        ],
        "overrides": [
            {
                "field": "explanation",
                "action": "set",
                "value": "Corrected explanation from the AI Judge.",
                "evidence": "192.168.1.100/api",
                "reason": "The original explanation misread the read-only request.",
                "confidence": 0.9,
            }
        ],
        "sanitized_script": None,
        "modifications_made": [],
        "technical_rationale": "Corrected the warning-level classification.",
    }

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_mock_123"), patch(
        "app.engine.ai_judge.llm_client.generate_json",
        new=AsyncMock(return_value=first_pass),
    ):
        res = await evaluate_audit_async(req)

    assert res.verdict == Verdict.CORRECT
    assert res.explanation == "Corrected explanation from the AI Judge."
    assert any(entry.field == "explanation" for entry in res.override_log)


def test_deterministic_only_field_is_gone():
    """The old mode flag must not exist on either request model."""
    assert "deterministic_only" not in AuditRequest.model_fields
    assert "deterministic_only" not in DeterministicAuditRequest.model_fields
