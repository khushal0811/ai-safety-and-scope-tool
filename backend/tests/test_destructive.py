"""Unit tests for destructive payload and Denial-of-Service detection."""

from app.engine.destructive_rules import check_destructive_commands
from app.models.audit import Severity, ViolationCategory


def test_destructive_rm_rf():
    viols = check_destructive_commands("rm -rf /var/www/html")
    assert len(viols) == 1
    assert viols[0].severity == Severity.CRITICAL
    assert viols[0].category == ViolationCategory.DESTRUCTIVE
    assert "Recursive Forced Deletion" in viols[0].rule


def test_destructive_mkfs():
    viols = check_destructive_commands("mkfs.ext4 /dev/sdb1")
    assert len(viols) >= 1
    assert any("Filesystem Formatting" in v.rule for v in viols)


def test_destructive_dd_to_disk():
    viols = check_destructive_commands("dd if=/dev/zero of=/dev/sda bs=1M count=100")
    assert len(viols) >= 1
    assert any("Raw Block Device Write" in v.rule for v in viols)


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
