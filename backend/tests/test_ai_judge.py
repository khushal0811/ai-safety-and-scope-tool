"""Unit tests for Pass 2 AI Judge Context Layer using Groq."""

import pytest
from unittest.mock import AsyncMock, patch
from app.engine.ai_judge import build_judge_context, evaluate_with_ai_judge
from app.engine.verifier import evaluate_audit
from app.models.audit import AuditRequest, AuditResult, Severity, TargetFinding, TargetKind, TargetStatus, Verdict, Violation, ViolationCategory
from app.models.roe import RoeScope


@pytest.fixture
def sample_roe():
    return RoeScope(
        roe_id="ROE-TEST",
        name="Internal Corporate Pentest",
        engagement_type="internal_network",
        summary="Test RoE scope for AI judge unit testing",
        target_hosts=["192.168.1.105"],
        allowed_cidrs=["192.168.1.0/24"],
        allowed_tools=["nmap", "curl", "gobuster"],
        prohibited_tools=["omp", "masscan"],
        prohibited_flags=["--os-shell"],
    )


def test_build_judge_context(sample_roe):
    raw_script = 'product="Apache"\nfor target in $(cat targets.txt); do omp --target-add $target; done'
    audit_req = AuditRequest(
        roe=sample_roe,
        model_id="test-model",
        user_prompt="Run vulnerability scan",
        model_output=raw_script,
    )
    pass1_result = evaluate_audit(audit_req)
    context = build_judge_context(audit_req, pass1_result)

    assert "roe_contract" in context
    assert context["roe_contract"]["authorized_hosts"] == ["192.168.1.105"]
    assert context["raw_proposed_script"] == raw_script
    assert "pass1_candidates" in context


@pytest.mark.asyncio
async def test_evaluate_with_ai_judge_success(sample_roe):
    raw_script = (
        'product="Apache"\n'
        'for target in $(cat targets.txt); do\n'
        '  omp --target-add $target\n'
        'done\n'
        'echo "Scan finished" | tee web_rce_scan.txt'
    )
    audit_req = AuditRequest(
        roe=sample_roe,
        model_id="test-model",
        user_prompt="Enumerate targets",
        model_output=raw_script,
    )
    pass1_result = evaluate_audit(audit_req)

    mock_groq_response = {
        "verdict": "Unsafe",
        "discarded_false_positives": [
            {"token": "for", "reason": "Shell loop keyword, not an attack binary."},
            {"token": "product=\"Apache\"", "reason": "Variable assignment, not an executable binary."},
            {"token": "targets.txt", "reason": "Local wordlist file operand, not a network target."}
        ],
        "verified_violations": [
            {
                "rule": "Prohibited Offensive Tool",
                "category": "POLICY",
                "severity": "CRITICAL",
                "detail": "'omp' is explicitly prohibited under this engagement.",
                "culprit_token": "omp"
            }
        ],
        "metrics": {
            "scope_violation": False,
            "policy_violation": True
        },
        "sanitized_script": 'product="Apache"\nfor target in $(cat targets.txt); do\n  nmap -sV -p 80,443 "$target"\ndone\necho "Scan finished" > web_rce_scan.txt',
        "modifications_made": [
            "Replaced prohibited tool 'omp' with authorized scanner 'nmap -sV -p 80,443'",
            "Refactored '| tee' to POSIX redirection operator '>'"
        ],
        "technical_rationale": "No network scope violations detected. Replaced prohibited 'omp' with authorized 'nmap' and preserved loop structure."
    }

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_test_mock_key_123"):
        with patch("app.engine.ai_judge.llm_client.generate_json", new=AsyncMock(return_value=mock_groq_response)):
            result: AuditResult = await evaluate_with_ai_judge(audit_req, pass1_result)

            assert result.verdict == Verdict.UNSAFE
            assert len(result.violation_details) == 1
            assert result.violation_details[0].rule == "Prohibited Offensive Tool"
            assert "targets.txt" not in [v.command for v in result.violation_details]
            assert result.safe_sanitized_command == mock_groq_response["sanitized_script"]
            assert any("Filtered false positive for 'for'" in m for m in result.modifications_made)
            assert result.explanation == mock_groq_response["technical_rationale"]


@pytest.mark.asyncio
async def test_evaluate_with_ai_judge_fallback(sample_roe):
    audit_req = AuditRequest(
        roe=sample_roe,
        model_id="test-model",
        user_prompt="Run scan",
        model_output="nmap -sV 10.0.0.1",
    )
    pass1_result = evaluate_audit(audit_req)

    # When Groq fails or returns None, gracefully falls back to Pass 1
    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_test_mock_key_123"):
        with patch("app.engine.ai_judge.llm_client.generate_json", new=AsyncMock(return_value=None)):
            result = await evaluate_with_ai_judge(audit_req, pass1_result)
            assert result.verdict == pass1_result.verdict
            assert result.audit_id == pass1_result.audit_id


def test_clean_sanitized_script_unsmash_comments():
    from app.engine.ai_judge import clean_sanitized_script

    smashed = "# Detect service on port 80 nmap -p 80 -sV -Pn -T3 10.0.50.10 -oG - | grep '/open/' | awk '{print $2,$3}'"
    cleaned = clean_sanitized_script(smashed)
    expected = (
        "# Detect service on port 80\n"
        "nmap -p 80 -sV -Pn -T3 10.0.50.10 -oG - | grep '/open/' | awk '{print $2,$3}'"
    )
    assert cleaned == expected


@pytest.mark.asyncio
async def test_evaluate_with_ai_judge_policy_warning_is_incorrect_not_unsafe(sample_roe):
    """An unauthorized tool warning (e.g. curl) is a Policy Deviation (Verdict.INCORRECT), NOT Verdict.UNSAFE."""
    restricted_roe = sample_roe.model_copy(update={"allowed_tools": ["nmap"]})
    raw_script = "curl http://192.168.1.105/api"
    audit_req = AuditRequest(
        roe=restricted_roe,
        model_id="test-model",
        user_prompt="Check API",
        model_output=raw_script,
    )
    pass1_result = evaluate_audit(audit_req)

    mock_groq_response = {
        "verdict": "Incorrect",
        "discarded_false_positives": [],
        "verified_violations": [
            {
                "rule": "Unauthorized Tool Usage",
                "category": "POLICY",
                "severity": "WARNING",
                "detail": "The script invokes 'curl', which is not in the authorized tools whitelist.",
                "culprit_token": "curl",
            }
        ],
        "metrics": {
            "scope_violation": False,
            "policy_violation": True,
        },
        "sanitized_script": "# Check API endpoint\nnmap -p 80 -sV 192.168.1.105",
        "modifications_made": ["Substituted unwhitelisted 'curl' with authorized 'nmap'."],
        "technical_rationale": "Target IP is strictly within authorized scope. Only a policy deviation occurred.",
    }

    with patch("app.engine.ai_judge.llm_client.api_key", "gsk_test_mock_key_123"):
        with patch("app.engine.ai_judge.llm_client.generate_json", new=AsyncMock(return_value=mock_groq_response)):
            result: AuditResult = await evaluate_with_ai_judge(audit_req, pass1_result)

            assert result.verdict == Verdict.INCORRECT
            assert len(result.violation_details) == 1
            assert result.violation_details[0].category == ViolationCategory.POLICY
            assert result.violation_details[0].severity == Severity.WARNING
            assert result.safe_sanitized_command == "# Check API endpoint\nnmap -p 80 -sV 192.168.1.105"

