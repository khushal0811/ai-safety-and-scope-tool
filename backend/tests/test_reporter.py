"""Tests for Phase 4.4: Formal RoE Compliance Attestation & Reporting.

Verifies:
1. Cryptographic SHA-256 hash chain generation and determinism.
2. Tamper-evidence (avalanche effect upon any record modification).
3. Markdown attestation report rendering with scope matrix and ledger.
4. ReportLab PDF attestation generation (valid binary PDF structure).
5. JSON export structure with complete chain metadata.
6. FastAPI GET /api/audit/report endpoint responses (Markdown, PDF, JSON).
7. CLI shim report command generation.
"""

import json
import os
import tempfile
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.data.presets import get_roe_preset_by_id
from app.engine.reporter import (
    compute_hash_chain,
    generate_compliance_report,
    generate_compliance_report_markdown,
    generate_compliance_report_pdf,
)
from app.main import app

client = TestClient(app)


# Sample audit log fixtures
SAMPLE_RECORDS = [
    {
        "audit_id": "AUDIT-001",
        "created_at": "2026-10-27T10:00:00Z",
        "extracted_commands": ["nmap -sS -p 80,443 192.168.1.50"],
        "raw_model_output": "nmap -sS -p 80,443 192.168.1.50",
        "verdict": "Correct",
        "safe_sanitized_command": None,
        "violation_details": [],
    },
    {
        "audit_id": "AUDIT-002",
        "created_at": "2026-10-27T10:05:00Z",
        "extracted_commands": ["nmap -T5 192.168.1.1"],
        "raw_model_output": "nmap -T5 192.168.1.1",
        "verdict": "Unsafe",
        "safe_sanitized_command": "nmap -T3 192.168.1.50",
        "violation_details": [
            {"type": "PROHIBITED_TARGET", "detail": "Target 192.168.1.1 is prohibited gateway"},
            {"type": "AGGRESSIVE_TIMING", "detail": "Timing -T5 exceeds maximum allowable -T3"},
        ],
    },
    {
        "audit_id": "AUDIT-003",
        "created_at": "2026-10-27T10:10:00Z",
        "extracted_commands": ["gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/common.txt"],
        "raw_model_output": "gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/common.txt",
        "verdict": "Correct",
        "safe_sanitized_command": None,
        "violation_details": [],
    },
]


# ==============================================================================
# 1. Cryptographic Hash Chain Invariants
# ==============================================================================

def test_compute_hash_chain_determinism():
    """Verify that hashing identical records with the same seed produces identical chains."""
    seed = "ROE-PRESET-NET-001|Network Pentest Standard"
    chain1, root1 = compute_hash_chain(SAMPLE_RECORDS, seed)
    chain2, root2 = compute_hash_chain(SAMPLE_RECORDS, seed)

    assert len(chain1) == len(SAMPLE_RECORDS)
    assert root1 == root2
    for r1, r2 in zip(chain1, chain2):
        assert r1["chain_index"] == r2["chain_index"]
        assert r1["prev_hash"] == r2["prev_hash"]
        assert r1["chain_hash"] == r2["chain_hash"]


def test_compute_hash_chain_tamper_detection():
    """Altering any command, verdict, or parameter must alter all subsequent hashes and root hash."""
    seed = "ROE-PRESET-NET-001|Network Pentest Standard"
    _, original_root = compute_hash_chain(SAMPLE_RECORDS, seed)

    # Tamper with the second record: change verdict from Unsafe to Correct
    tampered_records = [
        dict(SAMPLE_RECORDS[0]),
        dict(SAMPLE_RECORDS[1], verdict="Correct"),
        dict(SAMPLE_RECORDS[2]),
    ]

    _, tampered_root = compute_hash_chain(tampered_records, seed)
    assert original_root != tampered_root, "Tampered record failed to change the root hash!"

    # Tamper with command content in first record
    tampered_records_cmd = [
        dict(SAMPLE_RECORDS[0], extracted_commands=["nmap -sS -p 80,443 10.0.0.1"]),
        dict(SAMPLE_RECORDS[1]),
        dict(SAMPLE_RECORDS[2]),
    ]
    _, tampered_cmd_root = compute_hash_chain(tampered_records_cmd, seed)
    assert original_root != tampered_cmd_root


def test_compute_hash_chain_empty_records():
    """Empty audit records should still generate a valid deterministic root hash from seed."""
    seed = "ROE-EMPTY-TEST"
    chain, root_hash = compute_hash_chain([], seed)
    assert chain == []
    assert len(root_hash) == 64  # valid SHA-256 hex string


# ==============================================================================
# 2. Markdown Report Generation
# ==============================================================================

def test_generate_compliance_report_markdown():
    """Verify Markdown report contains all required attestation sections and cryptographic ledger."""
    roe = get_roe_preset_by_id("ROE-PRESET-NET-001")
    assert roe is not None

    md = generate_compliance_report_markdown(roe=roe, records=SAMPLE_RECORDS, user_id="tester@vallum.security")

    assert "# FORMAL RULES OF ENGAGEMENT COMPLIANCE & SAFETY ATTESTATION" in md
    assert "Document Reference:" in md
    assert roe.name in md
    assert "tester@vallum.security" in md
    assert "## 1. Executive Statement of Attestation" in md
    assert "## 2. Contracted Scope Boundaries & Constraints" in md
    assert "## 3. Engagement Scope Compliance Metrics" in md
    assert "## 4. Cryptographic Audit Trail & Chain of Custody" in md
    assert "## 5. Standard Compliance Alignment Matrix" in md
    assert "## 6. Attestation Seal & Non-Repudiation Block" in md
    assert "66.7%" in md  # 2 of 3 ops compliant
    assert "33.3%" in md  # 1 of 3 ops intercepted as Unsafe
    assert "Scope of This Attestation:" in md
    assert "AUDIT TRAIL INTEGRITY: VERIFIED (TAMPER-EVIDENT)" in md
    assert "│  Engagement ID:" in md
    assert "AUDIT-001" in md
    assert "AUDIT-002" in md
    assert "nmap -T5 192.168.1.1" in md


def test_compute_hash_chain_joins_multiple_extracted_commands():
    """Verify multiple extracted_commands in a single audit record are all joined into command_display and hashed."""
    records = [
        {
            "audit_id": "AUDIT-MULTI",
            "created_at": "2026-10-27T10:00:00Z",
            "extracted_commands": ["nmap -sS 192.168.1.50", "nikto -h 192.168.1.50"],
            "raw_model_output": "nmap -sS 192.168.1.50\nnikto -h 192.168.1.50",
            "verdict": "Correct",
            "safe_sanitized_command": None,
            "violation_details": [],
        }
    ]
    chained, root1 = compute_hash_chain(records, "SEED-1")
    assert chained[0]["command_display"] == "nmap -sS 192.168.1.50; nikto -h 192.168.1.50"

    # Modifying the second command must alter the hash chain root
    records_modified = [
        dict(records[0], extracted_commands=["nmap -sS 192.168.1.50", "nikto -h 10.0.0.1"])
    ]
    _, root2 = compute_hash_chain(records_modified, "SEED-1")
    assert root1 != root2


# ==============================================================================
# 3. PDF Attestation Generation
# ==============================================================================

def test_generate_compliance_report_pdf():
    """Verify ReportLab PDF builds a valid binary stream starting with %PDF-."""
    roe = get_roe_preset_by_id("ROE-PRESET-NET-001")
    assert roe is not None

    pdf_bytes = generate_compliance_report_pdf(roe=roe, records=SAMPLE_RECORDS, user_id="admin@vallum.internal")

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes


# ==============================================================================
# 4. Report Dispatcher
# ==============================================================================

def test_generate_compliance_report_dispatcher_markdown():
    with patch("app.engine.reporter.fetch_audit_logs_for_roe", return_value=SAMPLE_RECORDS):
        content, media_type, filename = generate_compliance_report(
            roe_id="ROE-PRESET-NET-001",
            format="markdown",
            user_id="analyst@client.org",
        )
        assert "text/markdown" in media_type
        assert filename.endswith(".md")
        assert "FORMAL RULES OF ENGAGEMENT" in content


def test_generate_compliance_report_dispatcher_pdf():
    with patch("app.engine.reporter.fetch_audit_logs_for_roe", return_value=SAMPLE_RECORDS):
        content, media_type, filename = generate_compliance_report(
            roe_id="ROE-PRESET-NET-001",
            format="pdf",
            user_id="analyst@client.org",
        )
        assert media_type == "application/pdf"
        assert filename.endswith(".pdf")
        assert content.startswith(b"%PDF-")


def test_generate_compliance_report_dispatcher_json():
    with patch("app.engine.reporter.fetch_audit_logs_for_roe", return_value=SAMPLE_RECORDS):
        content, media_type, filename = generate_compliance_report(
            roe_id="ROE-PRESET-NET-001",
            format="json",
            user_id="analyst@client.org",
        )
        assert media_type == "application/json"
        assert filename.endswith(".json")
        parsed = json.loads(content)
        assert parsed["total_operations"] == 3
        assert "root_hash" in parsed
        assert len(parsed["records"]) == 3


# ==============================================================================
# 5. FastAPI Endpoint GET /api/audit/report
# ==============================================================================

TEST_REPORT_USER_ID = "a56d57aa-1324-4e6b-ad40-de772556d670"


def test_api_audit_report_unauthenticated_returns_401():
    """Verify GET /api/audit/report rejects unauthenticated callers with 401."""
    response = client.get("/api/audit/report?roe_id=ROE-PRESET-NET-001&format=markdown")
    assert response.status_code == 401


def test_fetch_audit_logs_for_roe_refuses_missing_or_invalid_user_id(monkeypatch):
    """Verify fetch_audit_logs_for_roe returns [] immediately when user_id is None or invalid."""
    from app.db import supabase_client

    def fail_if_called():
        raise AssertionError("get_supabase() must not be called when user_id is missing/invalid")

    monkeypatch.setattr(supabase_client, "get_supabase", fail_if_called)
    assert supabase_client.fetch_audit_logs_for_roe("ROE-PRESET-NET-001", user_id=None) == []
    assert supabase_client.fetch_audit_logs_for_roe("ROE-PRESET-NET-001", user_id="") == []
    assert supabase_client.fetch_audit_logs_for_roe("ROE-PRESET-NET-001", user_id="not-a-uuid") == []


def test_api_audit_report_markdown_endpoint():
    with patch("app.engine.reporter.fetch_audit_logs_for_roe", return_value=SAMPLE_RECORDS):
        response = client.get(
            "/api/audit/report?roe_id=ROE-PRESET-NET-001&format=markdown",
            headers={"X-User-Id": TEST_REPORT_USER_ID},
        )
        assert response.status_code == 200
        assert "text/markdown" in response.headers.get("content-type", "")
        assert "attachment" in response.headers.get("content-disposition", "")
        assert "FORMAL RULES OF ENGAGEMENT" in response.text


def test_api_audit_report_pdf_endpoint():
    with patch("app.engine.reporter.fetch_audit_logs_for_roe", return_value=SAMPLE_RECORDS):
        response = client.get(
            "/api/audit/report?roe_id=ROE-PRESET-NET-001&format=pdf",
            headers={"X-User-Id": TEST_REPORT_USER_ID},
        )
        assert response.status_code == 200
        assert "application/pdf" in response.headers.get("content-type", "")
        assert "attachment" in response.headers.get("content-disposition", "")
        assert response.content.startswith(b"%PDF-")


def test_api_audit_report_json_endpoint():
    with patch("app.engine.reporter.fetch_audit_logs_for_roe", return_value=SAMPLE_RECORDS):
        response = client.get(
            "/api/audit/report?roe_id=ROE-PRESET-NET-001&format=json",
            headers={"X-User-Id": TEST_REPORT_USER_ID},
        )
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        data = response.json()
        assert data["total_operations"] == 3
        assert "root_hash" in data


# ==============================================================================
# 6. CLI Report Generation (vallum-cli report)
# ==============================================================================

def test_cli_report_markdown_generation():
    from app.cli.shim import cmd_report, build_parser

    parser = build_parser()
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "attestation.md")
        args = parser.parse_args(["report", "--roe", "ROE-PRESET-NET-001", "--format", "markdown", "-o", out_file])

        exit_code = cmd_report(args)
        assert exit_code == 0
        assert os.path.exists(out_file)
        with open(out_file, "r") as f:
            content = f.read()
            assert "FORMAL RULES OF ENGAGEMENT" in content
