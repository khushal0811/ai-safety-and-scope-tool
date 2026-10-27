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
