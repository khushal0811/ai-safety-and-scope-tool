"""Unit tests for tool whitelist, banned tools, and argument parameters."""

from app.engine.parser import parse_cli_command
from app.engine.tool_rules import check_tool_and_flags
from app.models.audit import Severity, ViolationCategory
from app.models.roe import RoeScope


def test_banned_tool_detected(network_recon_roe: RoeScope):
    cmd = parse_cli_command("hping3 -S 192.168.1.105")
    viols, mods = check_tool_and_flags(cmd, network_recon_roe)
    assert len(viols) == 1
    assert viols[0].rule == "Prohibited Offensive Tool"
    assert viols[0].severity == Severity.CRITICAL


def test_tool_outside_whitelist(web_pentest_roe: RoeScope):
    # hydra is prohibited on web_pentest_roe; nmap is allowed; masscan is outside whitelist
    cmd = parse_cli_command("masscan -p80 10.10.20.15")
    viols, mods = check_tool_and_flags(cmd, web_pentest_roe)
    assert len(viols) == 1
    assert viols[0].rule == "Tool Outside Authorized Whitelist"
    assert viols[0].severity == Severity.WARNING


def test_nmap_aggressive_timing_throttled(network_recon_roe: RoeScope):
    cmd = parse_cli_command("nmap -sV -T5 192.168.1.105")
    viols, mods = check_tool_and_flags(cmd, network_recon_roe)
    assert any("Aggressive Scan Timing Template" in v.rule for v in viols)
    assert any("Throttled nmap timing from -T5 to -T3" in m for m in mods)


def test_prohibited_flags_flagged(web_pentest_roe: RoeScope):
    cmd = parse_cli_command("sqlmap -u http://10.10.20.15 --os-shell")
    viols, mods = check_tool_and_flags(cmd, web_pentest_roe)
    assert any("Prohibited Parameter or Action Flag" in v.rule for v in viols)
    assert any("Stripped prohibited parameter" in m for m in mods)
