"""Unit tests for destructive payload and Denial-of-Service detection."""

from app.engine.destructive_rules import (
    _has_dd_to_block_device,
    _has_rm_recursive_force,
    check_destructive_commands,
)
from app.models.audit import Severity, ViolationCategory


def test_destructive_rm_rf():
    viols = check_destructive_commands("rm -rf /var/www/html")
    assert len(viols) == 1
    assert viols[0].severity == Severity.CRITICAL
    assert viols[0].category == ViolationCategory.DESTRUCTIVE
    assert "Recursive Forced Deletion" in viols[0].rule


def test_destructive_rm_separate_flags_and_long_options():
    """Verify separate flags (-r -f) and GNU long options (--recursive --force) are caught."""
    variants = [
        ("rm -r -f /important_data", ["rm", "-r", "-f", "/important_data"]),
        ("rm --recursive --force /data", ["rm", "--recursive", "--force", "/data"]),
        ("rm -r --force /data", ["rm", "-r", "--force", "/data"]),
        ("rm -f -R /var/log", ["rm", "-f", "-R", "/var/log"]),
    ]
    for cmd_str, tokens in variants:
        assert _has_rm_recursive_force(tokens) is True
        viols_with_tokens = check_destructive_commands(cmd_str, tokens=tokens)
        assert any("Recursive Forced Deletion" in v.rule for v in viols_with_tokens), f"Missed {cmd_str} with tokens"
        viols_raw = check_destructive_commands(cmd_str)
        assert any("Recursive Forced Deletion" in v.rule for v in viols_raw), f"Missed {cmd_str} raw"


def test_destructive_mkfs():
    viols = check_destructive_commands("mkfs.ext4 /dev/sdb1")
    assert len(viols) >= 1
    assert any("Filesystem Formatting" in v.rule for v in viols)


def test_destructive_dd_to_disk():
    viols = check_destructive_commands("dd if=/dev/zero of=/dev/sda bs=1M count=100")
    assert len(viols) >= 1
    assert any("Raw Block Device Write" in v.rule for v in viols)


def test_destructive_dd_reversed_arg_order():
    """Verify dd with of=/dev/... appearing before if=... is caught."""
    cmd = "dd of=/dev/sda if=/dev/zero bs=1M"
    tokens = ["dd", "of=/dev/sda", "if=/dev/zero", "bs=1M"]
    assert _has_dd_to_block_device(tokens) == "/dev/sda"

    viols_tokens = check_destructive_commands(cmd, tokens=tokens)
    assert any("Raw Block Device Write" in v.rule for v in viols_tokens)

    viols_raw = check_destructive_commands(cmd)
    assert any("Raw Block Device Write" in v.rule for v in viols_raw)


def test_destructive_fork_bomb():
    viols = check_destructive_commands(":(){ :|:& };:")
    assert len(viols) >= 1
    assert any("Fork Bomb" in v.rule for v in viols)


def test_destructive_sql_drop():
    viols = check_destructive_commands("sqlmap -u 'http://10.10.20.15' --sql-query='DROP TABLE customers;'")
    assert len(viols) >= 1
    assert any("DROP TABLE" in v.rule for v in viols)


def test_destructive_sql_truncate():
    viols = check_destructive_commands("TRUNCATE TABLE audit_logs")
    assert len(viols) >= 1
    assert any("TRUNCATE" in v.rule for v in viols)


def test_destructive_dos_ping_flood():
    viols = check_destructive_commands("ping -f 192.168.1.105")
    assert len(viols) >= 1
    assert any("ICMP Flood" in v.rule for v in viols)


def test_destructive_dos_packet_flood():
    viols = check_destructive_commands("hping3 --flood -S -p 80 192.168.1.105")
    assert len(viols) >= 1
    assert any("Packet Flood" in v.rule for v in viols)


def test_safe_sql_no_violations():
    viols = check_destructive_commands("sqlmap -u 'http://10.10.20.15' --dbs")
    assert len(viols) == 0
