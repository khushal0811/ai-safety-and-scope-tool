"""Destructive payload and Denial-of-Service detection engine.

Zero Host Execution: Inspects command strings using strict regex and pattern
classifiers to prevent destructive execution or infrastructure disruption.
"""

from dataclasses import dataclass
import re
from typing import List, Optional
from app.models.audit import Severity, Violation, ViolationCategory


@dataclass
class DestructivePattern:
    pattern: re.Pattern
    label: str
    category: ViolationCategory
    severity: Severity
    remediation_note: str


DESTRUCTIVE_PATTERNS: List[DestructivePattern] = [
    # System and Disk Destruction
    DestructivePattern(
        pattern=re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b", re.IGNORECASE),
        label="Recursive Forced Deletion (rm -rf)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed dangerous recursive deletion command.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\bmkfs(\.[a-zA-Z0-9]+)?\b", re.IGNORECASE),
        label="Filesystem Formatting (mkfs)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed filesystem formatting command.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\bdd\s+if=.*of=(/dev/[a-zA-Z0-9]+)", re.IGNORECASE),
        label="Raw Block Device Write (dd to block device)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed raw block device write command.",
    ),
    DestructivePattern(
        pattern=re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:", re.IGNORECASE),
        label="Bash Fork Bomb",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed bash fork bomb denial-of-service payload.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b", re.IGNORECASE),
        label="Arbitrary Piped Shell Execution (| bash/sh)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed dangerous piped shell execution.",
    ),

    # SQL Destruction
    DestructivePattern(
        pattern=re.compile(r"\bdrop\s+(table|database|schema|view)\b", re.IGNORECASE),
        label="Destructive SQL (DROP TABLE/DATABASE)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed destructive SQL DROP command.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\btruncate\s+(table\s+)?\w+", re.IGNORECASE),
        label="Destructive SQL (TRUNCATE TABLE)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed destructive SQL TRUNCATE command.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\bdelete\s+from\s+\w+\s*(;|--|$|'|\")(?!.*\bwhere\b)", re.IGNORECASE),
        label="Unbounded SQL Deletion (DELETE without WHERE)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed unbounded SQL DELETE statement.",
    ),

    # Denial of Service / Network Flooding
    DestructivePattern(
        pattern=re.compile(r"\bping\b.*\s-f\b|\bping\s+-f\b", re.IGNORECASE),
        label="ICMP Flood (ping -f)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed ICMP flood option.",
    ),
    DestructivePattern(
        pattern=re.compile(r"(?:^|\s)--flood(?:\s|$)", re.IGNORECASE),
        label="Packet Flood (--flood)",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed packet flood flag.",
    ),
    DestructivePattern(
        pattern=re.compile(r"(?:^|\s)--min-rate\s+([1-9][0-9]{4,})(?:\s|$)", re.IGNORECASE),
        label="Excessive Scanning Packet Rate (min-rate >= 10000)",
        category=ViolationCategory.POLICY,
        severity=Severity.WARNING,
        remediation_note="Throttled excessive min-rate to prevent network congestion.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\bslowloris\b", re.IGNORECASE),
        label="Slowloris DoS Attack Tool",
        category=ViolationCategory.DESTRUCTIVE,
        severity=Severity.CRITICAL,
        remediation_note="Removed Slowloris denial-of-service tool.",
    ),
    DestructivePattern(
        pattern=re.compile(r"\b(arpspoof|bettercap|ettercap)\b", re.IGNORECASE),
        label="ARP Spoofing / Network Poisoning Tool",
        category=ViolationCategory.POLICY,
        severity=Severity.CRITICAL,
        remediation_note="Removed unauthorized network poisoning tool.",
    ),
]


def check_destructive_commands(command_str: str) -> List[Violation]:
    """Inspect a raw command string for destructive or DoS patterns."""
    violations: List[Violation] = []

    for pattern in DESTRUCTIVE_PATTERNS:
        if pattern.pattern.search(command_str):
            violations.append(
                Violation(
                    rule=pattern.label,
                    category=pattern.category,
                    severity=pattern.severity,
                    detail=f"{pattern.label} detected. Prohibited under standard RoE stability guidelines.",
                    command=command_str,
                )
            )

    return violations
