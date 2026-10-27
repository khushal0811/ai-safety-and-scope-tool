"""Offensive tool whitelist, prohibited flags, and parameter validation engine.

Strict Zero Host Execution: Validates tools and flags against contract terms.
"""

import re
from typing import List, Set, Tuple
from app.engine.parser import ParsedCommand
from app.models.audit import Severity, Violation, ViolationCategory
from app.models.roe import RoeScope

# Standard local POSIX stream and string processing utilities (not offensive attack tools)
WHITELISTED_SYSTEM_UTILITIES: Set[str] = {
    "sh", "bash", "zsh", "cat", "grep", "egrep", "fgrep", "awk", "sed",
    "tee", "head", "tail", "sort", "uniq", "cut", "tr", "wc", "echo",
    "printf", "xargs", "column", "base64", "strings", "hexdump", "xxd",
    "od", "fold", "find", "diff", "less", "more", "sleep", "true", "false",
}

# Local package managers prohibited from modifying execution environment at runtime
PACKAGE_MANAGERS: Set[str] = {
    "apt", "apt-get", "dpkg", "yum", "dnf", "pacman", "rpm", "brew",
    "pip", "pip3", "npm", "yarn", "gem", "apk", "snap", "flatpak",
}

# Interactive remote session tools (prohibited unless explicitly in authorized tools)
INTERACTIVE_SESSION_TOOLS: Set[str] = {
    "ssh", "telnet", "rlogin", "nc", "netcat", "socat",
}


def check_tool_and_flags(parsed_cmd: ParsedCommand, roe: RoeScope) -> Tuple[List[Violation], List[str]]:
    """Validate tool permissions, prohibited flags, and rate constraints."""
    violations: List[Violation] = []
    modifications: List[str] = []
    tool = parsed_cmd.tool.lower()

    # 1. Sudo Check: Local privilege escalation check
    has_sudo = (
        "sudo" in [tok.lower() for tok in parsed_cmd.tokens]
        or re.search(r"(?:^|[;&|]\s*)sudo\b", parsed_cmd.raw, re.IGNORECASE) is not None
    )
    if has_sudo:
        violations.append(
            Violation(
                rule="Prohibited Sudo Privilege Escalation",
                category=ViolationCategory.POLICY,
                severity=Severity.WARNING,
                detail="Local privilege escalation via 'sudo' is prohibited under Rules of Engagement.",
                command=parsed_cmd.raw,
            )
        )
        modifications.append("Stripped unauthorized 'sudo' prefix.")

    # 2. Package Manager Check
    if tool in PACKAGE_MANAGERS:
        violations.append(
            Violation(
                rule="Prohibited Local Package Installation",
                category=ViolationCategory.POLICY,
                severity=Severity.CRITICAL,
                detail=(
                    f"Runtime package manager '{tool}' is prohibited. Assessment must utilize pre-installed utilities."
                ),
                command=parsed_cmd.raw,
            )
        )
        modifications.append(f"Dropped unauthorized runtime package installation '{tool}'.")
        return violations, modifications

    # 3. Interactive Remote Session Tool Check
    allowed_lower = [t.lower() for t in roe.allowed_tools]
    if tool in INTERACTIVE_SESSION_TOOLS and tool not in allowed_lower:
        violations.append(
            Violation(
                rule="Prohibited Interactive Session Utility",
                category=ViolationCategory.POLICY,
                severity=Severity.WARNING,
                detail=(
                    f"Interactive remote utility '{tool}' is prohibited. Use non-interactive banner grab "
                    "or port scan instead (e.g., nmap -sV -p 22)."
                ),
                command=parsed_cmd.raw,
            )
        )
        modifications.append(f"Replaced interactive session '{tool}' with non-interactive scanner.")
        return violations, modifications

    # 4. Prohibited Offensive Tools Check
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

    # 5. Tool Whitelist Check (Permits both allowed attack tools and standard system utilities)
    sys_utils = set(WHITELISTED_SYSTEM_UTILITIES)
    if hasattr(roe, "whitelisted_system_utilities") and roe.whitelisted_system_utilities:
        sys_utils.update(u.lower() for u in roe.whitelisted_system_utilities)

    if roe.allowed_tools and tool:
        is_allowed_attack_tool = tool in allowed_lower
        is_system_util = tool in sys_utils

        if not is_allowed_attack_tool and not is_system_util:
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
