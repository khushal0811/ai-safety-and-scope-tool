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

    allowed_lower = [t.lower() for t in roe.allowed_tools]
    sys_utils = set(WHITELISTED_SYSTEM_UTILITIES)
    if hasattr(roe, "whitelisted_system_utilities") and roe.whitelisted_system_utilities:
        sys_utils.update(u.lower() for u in roe.whitelisted_system_utilities)

    # 2. Pipeline-aware Tool Verification across all stages
    all_stages = [parsed_cmd] + parsed_cmd.pipeline_stages
    for idx, stage in enumerate(all_stages):
        stage_tool = stage.tool.lower()
        if not stage_tool:
            continue

        # Package manager check
        if stage_tool in PACKAGE_MANAGERS:
            violations.append(
                Violation(
                    rule="Prohibited Local Package Installation",
                    category=ViolationCategory.POLICY,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"Runtime package manager '{stage_tool}' is prohibited. Assessment must utilize pre-installed utilities."
                    ),
                    command=parsed_cmd.raw,
                )
            )
            modifications.append(f"Dropped unauthorized runtime package installation '{stage_tool}'.")

        # Prohibited offensive tool check
        is_prohibited_tool = False
        if stage_tool in [t.lower() for t in roe.prohibited_tools]:
            is_prohibited_tool = True
            violations.append(
                Violation(
                    rule="Prohibited Offensive Tool",
                    category=ViolationCategory.POLICY,
                    severity=Severity.CRITICAL,
                    detail=f'"{stage_tool}" is explicitly banned under this engagement\'s Rules of Engagement.',
                    command=parsed_cmd.raw,
                )
            )
            modifications.append(f'Removed banned tool "{stage_tool}".')

        # Interactive remote session tool check
        if stage_tool in INTERACTIVE_SESSION_TOOLS and stage_tool not in allowed_lower:
            violations.append(
                Violation(
                    rule="Prohibited Interactive Session Utility",
                    category=ViolationCategory.POLICY,
                    severity=Severity.WARNING,
                    detail=(
                        f"Interactive remote utility '{stage_tool}' is prohibited. Use non-interactive banner grab "
                        "or port scan instead (e.g., nmap -sV -p 22)."
                    ),
                    command=parsed_cmd.raw,
                )
            )
            modifications.append(f"Replaced interactive session '{stage_tool}' with non-interactive scanner.")

        # Piped shell interpreter execution check (e.g. echo ... | bash)
        if idx > 0 and stage_tool in {"sh", "bash", "zsh"}:
            violations.append(
                Violation(
                    rule="Arbitrary Piped Shell Execution",
                    category=ViolationCategory.DESTRUCTIVE,
                    severity=Severity.CRITICAL,
                    detail=f"Piping stream into shell interpreter '{stage_tool}' constitutes arbitrary code execution risk.",
                    command=parsed_cmd.raw,
                )
            )
            modifications.append(f"Dropped piped execution into interpreter '{stage_tool}'.")

        # Whitelist check (only evaluate if not already flagged as an explicitly banned offensive tool)
        if not is_prohibited_tool and roe.allowed_tools and stage_tool:
            is_allowed = stage_tool in allowed_lower
            is_sys = stage_tool in sys_utils
            if not is_allowed and not is_sys:
                violations.append(
                    Violation(
                        rule="Tool Outside Authorized Whitelist",
                        category=ViolationCategory.POLICY,
                        severity=Severity.WARNING,
                        detail=f'"{stage_tool}" is not listed in the authorized tools whitelist for this engagement.',
                        command=parsed_cmd.raw,
                    )
                )

    # 3. Prohibited Flags & Action Sequences Check (Tokenized & phrase-matched)
    raw_flag_tokens = {f.split("=", 1)[0].lower() for stage in all_stages for f in stage.flags}
    toks_lower = [t.lower() for stage in all_stages for t in stage.tokens]

    for banned_flag in roe.prohibited_flags:
        bf_clean = banned_flag.strip()
        if not bf_clean:
            continue
        bf_lower = bf_clean.lower()
        if bf_lower.startswith("-"):
            # Match flag tokens (e.g. --script-args or -T5) exactly
            hit = bf_lower in raw_flag_tokens
        else:
            # Action-shaped prohibitions (e.g. "s3 rm", "kerberos::golden"):
            # require the phrase to appear as whole, adjacent tokens
            phrase_tokens = bf_lower.split()
            if not phrase_tokens:
                continue
            hit = any(
                toks_lower[i : i + len(phrase_tokens)] == phrase_tokens
                for i in range(len(toks_lower) - len(phrase_tokens) + 1)
            )
        if hit:
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
