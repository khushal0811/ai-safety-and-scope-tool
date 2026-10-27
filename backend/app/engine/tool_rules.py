"""Offensive tool whitelist, prohibited flags, and parameter validation engine.

Strict Zero Host Execution: Validates tools and flags against contract terms.
"""

import re
from typing import List, Tuple
from app.engine.parser import ParsedCommand
from app.models.audit import Severity, Violation, ViolationCategory
from app.models.roe import RoeScope


def check_tool_and_flags(parsed_cmd: ParsedCommand, roe: RoeScope) -> Tuple[List[Violation], List[str]]:
    """Validate tool permissions, prohibited flags, and rate constraints."""
    violations: List[Violation] = []
    modifications: List[str] = []
    tool = parsed_cmd.tool.lower()

    # 1. Prohibited Tools Check
    if tool in [t.lower() for t in roe.prohibited_tools]:
        violations.append(
            Violation(
                rule="Prohibited Offensive Tool",
                category=ViolationCategory.POLICY,
                severity=Severity.CRITICAL,
                detail=f'"{tool}" is explicitly banned under this engagement\'s Rules of Engagement.',
                command=parsed_cmd.raw,
            )
        )
        modifications.append(f'Removed banned tool "{tool}".')
        return violations, modifications

    # 2. Tool Whitelist Check (if whitelist is explicitly provided)
    if roe.allowed_tools and tool:
        allowed_lower = [t.lower() for t in roe.allowed_tools]
        if tool not in allowed_lower:
            violations.append(
                Violation(
                    rule="Tool Outside Authorized Whitelist",
                    category=ViolationCategory.POLICY,
                    severity=Severity.WARNING,
                    detail=f'"{tool}" is not listed in the authorized tools whitelist for this engagement.',
                    command=parsed_cmd.raw,
                )
            )

    # 3. Prohibited Flags Check
    for banned_flag in roe.prohibited_flags:
        bf_clean = banned_flag.strip()
        if not bf_clean:
            continue
        # Search for exact substring or regex boundary
        pattern = re.compile(rf"(?:\s|^){re.escape(bf_clean)}(?:\s|=|:|$)", re.IGNORECASE)
        if pattern.search(parsed_cmd.raw) or bf_clean.lower() in parsed_cmd.raw.lower():
            violations.append(
                Violation(
                    rule="Prohibited Parameter or Action Flag",
                    category=ViolationCategory.POLICY,
                    severity=Severity.CRITICAL,
                    detail=f'Prohibited flag/action "{bf_clean}" detected in command arguments.',
                    command=parsed_cmd.raw,
                )
            )
            modifications.append(f'Stripped prohibited parameter "{bf_clean}".')

    # 4. Tool-Specific Parameters: Nmap Timing Template
    if tool == "nmap":
        timing_match = re.search(r"(?:^|\s)-T([0-5])\b", parsed_cmd.raw)
        if timing_match:
            timing_val = int(timing_match.group(1))
            if timing_val > roe.max_nmap_timing:
                violations.append(
                    Violation(
                        rule="Aggressive Scan Timing Template",
                        category=ViolationCategory.POLICY,
                        severity=Severity.WARNING,
                        detail=(
                            f"Nmap timing -T{timing_val} exceeds authorized maximum timing template "
                            f"-T{roe.max_nmap_timing}. Aggressive timing templates risk service disruption."
                        ),
                        command=parsed_cmd.raw,
                    )
                )
                modifications.append(f"Throttled nmap timing from -T{timing_val} to -T{roe.max_nmap_timing}.")

        # Check for --min-rate
        min_rate_match = re.search(r"--min-rate[=\s]+(\d+)", parsed_cmd.raw)
        if min_rate_match:
            rate = int(min_rate_match.group(1))
            if rate >= 1000:
                violations.append(
                    Violation(
                        rule="Excessive Scanning Packet Rate",
                        category=ViolationCategory.POLICY,
                        severity=Severity.WARNING,
                        detail=f"--min-rate {rate} may saturate bandwidth or trigger client firewall bans.",
                        command=parsed_cmd.raw,
                    )
                )
                modifications.append(f"Removed aggressive --min-rate {rate} flag.")

    return violations, modifications
