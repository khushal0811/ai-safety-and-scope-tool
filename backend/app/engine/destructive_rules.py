"""Destructive payload and Denial-of-Service detection engine.

Zero Host Execution: Inspects command strings and AST token lists using strict
token-set and pattern classifiers to prevent destructive execution or
infrastructure disruption.
"""

from dataclasses import dataclass
import re
import shlex
from typing import List, Optional, Set
from app.models.audit import Severity, Violation, ViolationCategory


@dataclass
class DestructivePattern:
    pattern: re.Pattern
    label: str
    category: ViolationCategory
    severity: Severity
    remediation_note: str


RM_RECURSIVE_FORCE_LABEL = "Recursive Forced Deletion (rm -rf)"
DD_BLOCK_DEVICE_LABEL = "Raw Block Device Write (dd to block device)"


def _has_rm_recursive_force(tokens: List[str]) -> bool:
    """True if `rm` is invoked with recursive+force semantics in ANY flag arrangement."""
    if not tokens:
        return False
    idx = 0
    while idx < len(tokens) and tokens[idx].lower() in ("sudo", "env", "command", "nohup"):
        idx += 1
    if idx >= len(tokens):
        return False
    cmd_name = tokens[idx].lower().rsplit("/", 1)[-1]
    if cmd_name != "rm":
        return False

    flag_chars: Set[str] = set()
    long_opts: Set[str] = set()
    for t in tokens[idx + 1 :]:
        if t == "--":
            break
        if t.startswith("--"):
            long_opts.add(t.split("=", 1)[0].lower())
        elif t.startswith("-") and len(t) > 1:
            flag_chars.update(t[1:])  # combined short flags: -rf -> {'r','f'}
    has_recursive = (
        "r" in flag_chars
        or "R" in flag_chars
        or "--recursive" in long_opts
        or "-r" in long_opts
    )
    has_force = "f" in flag_chars or "--force" in long_opts
    return has_recursive and has_force


def _has_dd_to_block_device(tokens: List[str]) -> Optional[str]:
    """True if `dd` targets a /dev/ block device via of=, regardless of arg order."""
    if not tokens:
        return None
    idx = 0
    while idx < len(tokens) and tokens[idx].lower() in ("sudo", "env", "command", "nohup"):
        idx += 1
    if idx >= len(tokens):
        return None
    cmd_name = tokens[idx].lower().rsplit("/", 1)[-1]
    if cmd_name != "dd":
        return None

    for t in tokens[idx + 1 :]:
        if t.lower().startswith("of="):
            dev_path = t[3:].strip("'\"")
            if dev_path.startswith("/dev/") and dev_path.lower() not in (
                "/dev/null",
                "/dev/stdout",
                "/dev/stderr",
            ):
                return dev_path
    return None


DESTRUCTIVE_PATTERNS: List[DestructivePattern] = [
    # System and Disk Destruction
    DestructivePattern(
        pattern=re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b", re.IGNORECASE),
        label=RM_RECURSIVE_FORCE_LABEL,
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
        label=DD_BLOCK_DEVICE_LABEL,
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


def _extract_token_segments(command_str: str, tokens: Optional[List[str]] = None) -> List[List[str]]:
    """Return one or more token lists for AST-backed or fallback flag inspection."""
    if tokens:
        return [list(tokens)]

    segments: List[List[str]] = []
    for sub in re.split(r"(?:\|\||&&|[;|&\n])", command_str):
        sub_stripped = sub.strip()
        if not sub_stripped:
            continue
        try:
            toks = shlex.split(sub_stripped)
        except ValueError:
            toks = sub_stripped.split()
        if toks:
            segments.append(toks)
    return segments


def check_destructive_commands(
    command_str: str,
    tokens: Optional[List[str]] = None,
) -> List[Violation]:
    """Inspect a command string and its parsed token list for destructive or DoS patterns."""
    violations: List[Violation] = []
    seen_rules: Set[str] = set()

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
            seen_rules.add(pattern.label)

    for seg_tokens in _extract_token_segments(command_str, tokens):
        if RM_RECURSIVE_FORCE_LABEL not in seen_rules and _has_rm_recursive_force(seg_tokens):
            violations.append(
                Violation(
                    rule=RM_RECURSIVE_FORCE_LABEL,
                    category=ViolationCategory.DESTRUCTIVE,
                    severity=Severity.CRITICAL,
                    detail=f"{RM_RECURSIVE_FORCE_LABEL} detected. Prohibited under standard RoE stability guidelines.",
                    command=command_str,
                )
            )
            seen_rules.add(RM_RECURSIVE_FORCE_LABEL)

        dd_dev = _has_dd_to_block_device(seg_tokens)
        if DD_BLOCK_DEVICE_LABEL not in seen_rules and dd_dev:
            violations.append(
                Violation(
                    rule=DD_BLOCK_DEVICE_LABEL,
                    category=ViolationCategory.DESTRUCTIVE,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"{DD_BLOCK_DEVICE_LABEL} targeting '{dd_dev}' detected. "
                        "Prohibited under standard RoE stability guidelines."
                    ),
                    command=command_str,
                )
            )
            seen_rules.add(DD_BLOCK_DEVICE_LABEL)

    return violations
