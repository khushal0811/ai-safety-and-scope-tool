"""Tests for override-log persistence and judge usage accounting."""

from unittest.mock import AsyncMock, patch

import pytest

from app.db import supabase_client
from app.engine.verifier import evaluate_audit_async
from app.models.audit import AuditRequest
from app.models.roe import RoeScope


def _roe() -> RoeScope:
    return RoeScope(
        roe_id="ROE-TEST-USAGE-001",
        name="Usage Accounting RoE",
        engagement_type="Network Penetration Test",
        summary="Scope for override persistence and usage tests.",
        allowed_cidrs=["192.168.1.0/24"],
        allowed_domains=[],
        target_hosts=["192.168.1.100"],
        prohibited_ips=["192.168.1.1"],
        allowed_tools=["nmap"],
        prohibited_tools=["hydra"],
        prohibited_flags=[],
        prohibited_actions=[],
        max_nmap_timing=3,
    )


def test_save_audit_log_persists_override_log(monkeypatch):
    """The override log and review flag reach the audit_logs insert payload."""
    calls = {}

    class FakeQuery:
        def insert(self, payload):
            calls["payload"] = payload
            return self

        def execute(self):
            return None

    class FakeClient:
        def table(self, name):
            calls["table"] = name
            return FakeQuery()

    monkeypatch.setattr(supabase_client, "get_supabase", lambda: FakeClient())
    monkeypatch.setattr(supabase_client, "_previous_chain_head", lambda *args, **kwargs: ("prev", 1))
    monkeypatch.setattr("app.engine.attestation.compute_record_signature", lambda payload: "hash")

    override_log = [
        {
            "field": "violation:c1",
            "action": "clear",
            "evidence": "nmap -sV 192.168.1.1",
            "reason": "Authorized host misread.",
        }
    ]

    ok = supabase_client.save_audit_log(
        {
            "audit_id": "AUDIT-OV-1",
            "roe_id": "ROE-TEST-USAGE-001",
            "roe_hash": "hash",
            "roe_snapshot": {"roe_id": "ROE-TEST-USAGE-001"},
            "override_log": override_log,
            "needs_review": True,
        },
        user_id="11111111-1111-1111-1111-111111111111",
    )

    assert ok is True
    assert calls["table"] == "audit_logs"
    assert calls["payload"]["override_log"] == override_log
    assert calls["payload"]["needs_review"] is True


@pytest.mark.asyncio
async def test_judge_usage_is_aggregated_into_audit_result():
    """Token usage from judge calls is aggregated onto the audit result."""
    req = AuditRequest(
        roe=_roe(),
        model_id="test-model",
        user_prompt="Check the API",
        model_output="curl http://192.168.1.100/api",
    )

    async def fake_generate_json(system_prompt, user_prompt, temperature=0.0, max_tokens=0, usage_sink=None):
        if usage_sink is not None:
            usage_sink.append(
                {"model": "deepseek/deepseek-v4.1-flash", "prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}
            )
        return {
            "dispositions": [
                {
                    "id": "c1",
                    "disposition": "false_positive",
                    "reason": "Read-only request to an authorized host.",
                    "evidence": "curl http://192.168.1.100/api",
                    "confidence": 0.9,
                }
            ],
            "overrides": [],
            "sanitized_script": None,
            "modifications_made": [],
            "technical_rationale": "No breach.",
        }

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_mock_123"), patch(
        "app.engine.ai_judge.llm_client.generate_json", new=fake_generate_json
    ):
        res = await evaluate_audit_async(req)

    assert res.ai_judge_usage == {
        "calls": 1,
        "prompt_tokens": 120,
        "completion_tokens": 30,
        "total_tokens": 150,
    }
