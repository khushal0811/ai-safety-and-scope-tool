"""Tests for Phase 4.2 vallum-shim CLI Interceptor Daemon."""

import argparse
import io
import json
import sys
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.cli.shim import (
    cmd_check,
    cmd_init,
    cmd_roe,
    cmd_run,
    evaluate_command_audit,
    get_config,
    resolve_roe_locally,
)
from app.main import app

client = TestClient(app)


def test_cli_evaluate_command_safe_in_scope():
    """Verify that an in-scope target returns Correct verdict and 0 violations."""
    result, source = evaluate_command_audit(
        command="nmap -sS -p 80 192.168.1.105",
        roe_spec="ROE-PRESET-NET-001",
        force_offline=True,
    )
    assert result["verdict"] == "Correct"
    assert len(result["violation_details"]) == 0
    assert len(result["targets"]) == 1
    assert result["targets"][0]["status"] == "in_scope"
    assert result["targets"][0]["token"] == "192.168.1.105"


def test_cli_evaluate_command_out_of_scope():
    """Verify that an out-of-scope target returns Unsafe verdict with CRITICAL violation."""
    result, source = evaluate_command_audit(
        command="nmap -sS -p 80 10.0.0.5",
        roe_spec="ROE-PRESET-NET-001",
        force_offline=True,
    )
    assert result["verdict"] == "Unsafe"
    assert any(v["category"] == "scope" for v in result["violation_details"])
    assert result["targets"][0]["status"] == "out_of_scope"
    assert result["safe_sanitized_command"] is not None


def test_cli_cmd_check_exit_codes(capsys):
    """Verify exit codes: 0 for compliant, 1 for security breach."""
    args_safe = argparse.Namespace(
        command=["nmap", "-sS", "-p", "80", "192.168.1.105"],
        roe="ROE-PRESET-NET-001",
        daemon_url=None,
        offline=True,
        quiet=False,
        json=False,
        strict=False,
    )
    rc_safe = cmd_check(args_safe)
    captured_safe = capsys.readouterr()
    assert rc_safe == 0
    assert "[✓] VALLUM: PASS" in captured_safe.out

    args_unsafe = argparse.Namespace(
        command=["nmap", "-sS", "-p", "80", "10.0.0.5"],
        roe="ROE-PRESET-NET-001",
        daemon_url=None,
        offline=True,
        quiet=False,
        json=False,
        strict=False,
    )
    rc_unsafe = cmd_check(args_unsafe)
    captured_unsafe = capsys.readouterr()
    assert rc_unsafe == 1
    assert "[✗] VALLUM: BLOCKED" in captured_unsafe.out


def test_cli_cmd_check_quiet_mode(capsys):
    """Verify quiet mode suppresses all stdout while preserving return codes."""
    args_quiet_safe = argparse.Namespace(
        command=["nmap", "-sS", "192.168.1.105"],
        roe="ROE-PRESET-NET-001",
        daemon_url=None,
        offline=True,
        quiet=True,
        json=False,
        strict=False,
    )
    rc_safe = cmd_check(args_quiet_safe)
    captured = capsys.readouterr()
    assert rc_safe == 0
    assert captured.out == ""

    args_quiet_unsafe = argparse.Namespace(
        command=["rm", "-rf", "/"],
        roe="ROE-PRESET-NET-001",
        daemon_url=None,
        offline=True,
        quiet=True,
        json=False,
        strict=False,
    )
    rc_unsafe = cmd_check(args_quiet_unsafe)
    captured = capsys.readouterr()
    assert rc_unsafe == 1
    assert captured.out == ""


def test_cli_cmd_check_json_output(capsys):
    """Verify --json emits parseable structured JSON."""
    args_json = argparse.Namespace(
        command=["nmap", "-sS", "192.168.1.105"],
        roe="ROE-PRESET-NET-001",
        daemon_url=None,
        offline=True,
        quiet=False,
        json=True,
        strict=False,
    )
    rc = cmd_check(args_json)
    captured = capsys.readouterr()
    assert rc == 0
    parsed = json.loads(captured.out)
    assert parsed["verdict"] == "Correct"
    assert "audit_id" in parsed


def test_cli_roe_command(capsys):
    """Verify RoE preset listing, resolution, and inspection."""
    # List presets
    args_list = argparse.Namespace(action="list", target=None)
    rc_list = cmd_roe(args_list)
    out_list = capsys.readouterr().out
    assert rc_list == 0
    assert "ROE-PRESET-NET-001" in out_list
    assert "ROE-PRESET-WEB-002" in out_list

    # Show active scope
    args_show = argparse.Namespace(action="show", target=None)
    rc_show = cmd_roe(args_show)
    out_show = capsys.readouterr().out
    assert rc_show == 0
    assert "Active Scope Configuration:" in out_show

    # Set active scope
    args_set = argparse.Namespace(action="set", target="web")
    rc_set = cmd_roe(args_set)
    out_set = capsys.readouterr().out
    assert rc_set == 0
    assert "ROE-PRESET-WEB-002" in out_set

    # Reset back to net
    cmd_roe(argparse.Namespace(action="set", target="net"))


def test_cli_init_shell_wrapper(capsys):
    """Verify shell init script contains vallum() interceptor function."""
    args_init = argparse.Namespace(shell="zsh", install=False)
    rc = cmd_init(args_init)
    out = capsys.readouterr().out
    assert rc == 0
    assert "vallum() {" in out
    assert "vallum-cli check" in out


def test_cli_run_dry_run(capsys):
    """Verify run --dry-run validates without executing command on host."""
    args_dry = argparse.Namespace(
        command=["nmap", "-sS", "192.168.1.105"],
        roe="ROE-PRESET-NET-001",
        daemon_url=None,
        offline=True,
        quiet=False,
        strict=False,
        dry_run=True,
        fix=False,
    )
    rc = cmd_run(args_dry)
    out = capsys.readouterr().out
    assert rc == 0
    assert "[DRY-RUN] Command passed inspection. Execution skipped." in out


def test_api_deterministic_endpoint_with_roe_id():
    """Verify POST /api/audit/deterministic resolves roe_id without full RoeScope payload."""
    payload = {
        "command": "nmap -sS 192.168.1.105",
        "roe_id": "ROE-PRESET-NET-001",
    }
    resp = client.post("/api/audit/deterministic", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Correct"
    assert len(data["targets"]) == 1
    assert data["targets"][0]["status"] == "in_scope"
