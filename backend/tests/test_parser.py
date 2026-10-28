"""Unit tests for command parsing, shlex tokenization, and target extraction."""

from app.engine.parser import (
    extract_and_parse_all_commands,
    extract_command_blocks,
    parse_cli_command,
    split_chained_commands,
)
from app.models.audit import TargetKind


def test_parse_single_nmap_command():
    cmd = "nmap -sV -sC -T4 192.168.1.105"
    parsed = parse_cli_command(cmd)
    assert parsed.tool == "nmap"
    assert "-sV" in parsed.flags
    assert "-T4" in parsed.flags
    assert len(parsed.targets) == 1
    assert parsed.targets[0].canonical == "192.168.1.105"


def test_parse_gobuster_with_url_flag():
    cmd = "gobuster dir -u http://10.10.20.15:8080/app -w /usr/share/wordlists/dirb/common.txt"
    parsed = parse_cli_command(cmd)
    assert parsed.tool == "gobuster"
    assert len(parsed.targets) == 1
    assert parsed.targets[0].canonical == "10.10.20.15"
    # Verify wordlist.txt was not treated as a target domain
    assert not any(t.canonical.endswith(".txt") for t in parsed.targets)


def test_split_chained_commands():
    chained = "nmap -sP 192.168.1.0/24 && curl http://192.168.1.105; nikto -h 192.168.1.105"
    sub_cmds = split_chained_commands(chained)
    assert len(sub_cmds) == 3
    assert sub_cmds[0] == "nmap -sP 192.168.1.0/24"
    assert sub_cmds[1] == "curl http://192.168.1.105"
    assert sub_cmds[2] == "nikto -h 192.168.1.105"


def test_split_chained_commands_ignores_quotes():
    chained = 'echo "hello && world" && nmap 192.168.1.105'
    sub_cmds = split_chained_commands(chained)
    assert len(sub_cmds) == 2
    assert sub_cmds[0] == 'echo "hello && world"'
    assert sub_cmds[1] == "nmap 192.168.1.105"


def test_extract_command_blocks_markdown():
    markdown = """Here is the reconnaissance command:
```bash
# Ping scan the subnet
nmap -sn 192.168.1.0/24
```
Follow up with enumeration:
```sh
gobuster dir -u http://192.168.1.105 -w /tmp/wordlist.txt
```
"""
    commands = extract_command_blocks(markdown)
    assert len(commands) == 2
    assert commands[0] == "nmap -sn 192.168.1.0/24"
    assert commands[1] == "gobuster dir -u http://192.168.1.105 -w /tmp/wordlist.txt"


def test_extract_and_parse_all_pipeline():
    text = """Execute this test:
```bash
nmap -T4 192.168.1.105 && nikto -h http://192.168.1.105
```"""
    parsed = extract_and_parse_all_commands(text)
    assert len(parsed) == 2
    assert parsed[0].tool == "nmap"
    assert parsed[1].tool == "nikto"


def test_multiline_backslash_continuation():
    text = """```bash
omp \\
  --target-add 192.168.1.105 \\
  --task-create "Full Scan" \\
  --scanner "OpenVAS"
```"""
    parsed = extract_and_parse_all_commands(text)
    assert len(parsed) == 1
    assert parsed[0].tool == "omp"
    assert "--target-add" in parsed[0].flags
    assert "--task-create" in parsed[0].flags
    assert "--scanner" in parsed[0].flags
    assert len(parsed[0].targets) == 1
    assert parsed[0].targets[0].canonical == "192.168.1.105"


def test_variable_assignment_blocks():
    text = """```bash
product="Apache"
version="2.4.54"
TARGET=192.168.1.105
nmap -sV $TARGET
```"""
    parsed = extract_and_parse_all_commands(text)
    assert parsed[0].tool == ""
    assert parsed[1].tool == ""
    assert parsed[2].tool == ""
    assert len(parsed[2].targets) == 1
    assert parsed[2].targets[0].canonical == "192.168.1.105"
    assert parsed[3].tool == "nmap"


def test_pipeline_and_redirection_no_smash():
    text = """```bash
echo "Possible command injection" | tee web_rce_scan.txt
echo "Vulnerability found" > web_rce_scan.txt
```"""
    parsed = extract_and_parse_all_commands(text)
    assert len(parsed) == 2
    assert parsed[0].tool == "echo"
    assert "|" in parsed[0].tokens
    assert "tee" in parsed[0].tokens
    assert parsed[1].tool == "echo"
    assert ">" in parsed[1].tokens


def test_phase2_1_command_substitution_ast():
    """Verify bashlex AST extracts nested command substitutions ($(cmd) and `cmd`)."""
    cmd = "nmap -sV $(cat /tmp/targets.txt)"
    parsed = parse_cli_command(cmd)
    assert parsed.tool == "nmap"
    assert parsed.has_substitution is True
    assert len(parsed.pipeline_stages) == 1
    nested = parsed.pipeline_stages[0]
    assert nested.tool == "cat"
    assert nested.source == "substitution"

    # Backtick substitution
    cmd_backtick = "nmap -sV `cat /tmp/hosts.txt`"
    parsed_bt = parse_cli_command(cmd_backtick)
    assert parsed_bt.tool == "nmap"
    assert parsed_bt.has_substitution is True
    assert any(st.tool == "cat" for st in parsed_bt.pipeline_stages)


def test_phase2_1_nested_banned_tool_in_substitution():
    """Verify offensive tools nested inside command substitutions are captured."""
    cmd = "nmap $(cat wordlist.txt | hydra -l admin -P - 192.168.1.10 ssh)"
    parsed = parse_cli_command(cmd)
    assert parsed.tool == "nmap"
    # Find nested hydra stage
    hydra_stages = [st for st in parsed.pipeline_stages if st.tool == "hydra"]
    assert len(hydra_stages) >= 1
    assert any(t.canonical == "192.168.1.10" for t in hydra_stages[0].targets)


def test_phase2_2_per_tool_flag_specs():
    """Verify ToolFlagSpec correctly distinguishes target flags from non-target arguments."""
    from app.engine.parser import TOOL_FLAG_SPECS

    assert "nmap" in TOOL_FLAG_SPECS
    assert "gobuster" in TOOL_FLAG_SPECS
    assert "ffuf" in TOOL_FLAG_SPECS
    assert "sqlmap" in TOOL_FLAG_SPECS

    # Gobuster: -w is wordlist (non-target), -u is target, 'dir' is mode (not target)
    gb_cmd = parse_cli_command("gobuster dir -u http://10.10.20.15:8080/app -w common.txt")
    assert gb_cmd.tool == "gobuster"
    assert len(gb_cmd.targets) == 1
    assert gb_cmd.targets[0].canonical == "10.10.20.15"
    assert not any(t.canonical == "dir" for t in gb_cmd.targets)
    assert not any("common.txt" in t.canonical for t in gb_cmd.targets)

    # SQLMap: -u is target, -p and --dbms are non-target option values
    sql_cmd = parse_cli_command("sqlmap -u http://10.10.20.15/item?id=1 --dbms=mysql -p id")
    assert sql_cmd.tool == "sqlmap"
    assert len(sql_cmd.targets) == 1
    assert sql_cmd.targets[0].canonical == "10.10.20.15"

    # FFuf: -w is wordlist, -u is target
    ffuf_cmd = parse_cli_command("ffuf -u http://10.10.20.15/FUZZ -w /usr/share/wordlists/dirb/big.txt")
    assert ffuf_cmd.tool == "ffuf"
    assert len(ffuf_cmd.targets) == 1
    assert ffuf_cmd.targets[0].canonical == "10.10.20.15"

