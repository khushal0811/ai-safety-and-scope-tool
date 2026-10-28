"""Phase 4.5: Ephemeral Micro-Sandbox Dry-Run Environment.

Provides isolated syntax and parameter validation for proposed and synthesized
offensive commands without releasing any network packets to external systems.

Strict Invariants:
- Zero Host Execution: Operates via AST inspection and in-memory virtual simulation.
  Never calls host shell binaries, subprocesses, or unconfined evaluators.
- Permanent Egress Isolation: 0 network packets transmitted (interfaces disabled).
- Diagnostic Clarity: Delivers actionable syntax errors and CLI grammar feedback.
"""

from dataclasses import dataclass
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import bashlex
import bashlex.errors

from app.engine.parser import (
    KNOWN_SECURITY_TOOLS,
    TOOL_FLAG_SPECS,
    DEFAULT_TOOL_FLAG_SPEC,
)
from app.models.roe import RoeScope
from app.models.sandbox import (
    SandboxDryRunRequest,
    SandboxDryRunResponse,
    SandboxIsolationMetadata,
    SandboxStatusResponse,
)

logger = logging.getLogger(__name__)


# Supported security tools for detailed simulation
SIMULATED_TOOL_BANNERS = {
    "nmap": "Starting Nmap 7.94 ( https://nmap.org ) at {timestamp}\n[VALLUM MICRO-SANDBOX] Mode: TCP/IP Packet Trace Dry-Run (Egress: DISABLED)",
    "gobuster": "Gobuster v3.6 - Rapid Directory/DNS Brute-Forcer\n[VALLUM MICRO-SANDBOX] Mode: Grammar & Wordlist Pre-Flight (Egress: DISABLED)",
    "nikto": "- Nikto v2.5.0\n[VALLUM MICRO-SANDBOX] Mode: HTTP Configuration Pre-Check (Egress: DISABLED)",
    "sqlmap": "sqlmap/1.8#stable - Automatic SQL Injection Engine\n[VALLUM MICRO-SANDBOX] Mode: Injection Parameter Dry-Run (Egress: DISABLED)",
    "curl": "curl 8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0\n[VALLUM MICRO-SANDBOX] Mode: HTTP Request Simulator (Egress: DISABLED)",
    "hydra": "Hydra v9.5 (c) 2023 by van Hauser / THC - https://www.thc.org\n[VALLUM MICRO-SANDBOX] Mode: Protocol Credential Dry-Run (Egress: DISABLED)",
    "masscan": "Masscan 1.3.2 ( https://github.com/robertdavidgraham/masscan )\n[VALLUM MICRO-SANDBOX] Mode: Asynchronous Probe Pre-Flight (Egress: DISABLED)",
}


class IsolatedVirtualSandbox:
    """In-memory ephemeral micro-sandbox performing AST syntax and flag validation."""

    @classmethod
    def dry_run(
        cls,
        command_str: str,
        roe: Optional[RoeScope] = None,
        strict_syntax: bool = True,
    ) -> SandboxDryRunResponse:
        """Execute a deterministic, network-egress disabled dry-run of a command string."""
        t0 = time.perf_counter()
        raw_cmd = command_str.strip()
        diagnostics: List[str] = []

        if not raw_cmd:
            elapsed = int((time.perf_counter() - t0) * 1000)
            return SandboxDryRunResponse(
                command=command_str,
                tool="none",
                syntax_valid=False,
                exit_code=2,
                diagnostics=["Empty command input: no executable tokens provided."],
                simulated_stdout="",
                simulated_stderr="vallum-sandbox: syntax error: empty command input\n",
                elapsed_ms=elapsed,
            )

        # 1. POSIX AST Syntax Parsing via bashlex
        try:
            ast_nodes = bashlex.parse(raw_cmd)
            diagnostics.append("POSIX Shell AST: Syntax structure valid (no unclosed quotes or unbalanced operators).")
        except bashlex.errors.ParsingError as pe:
            elapsed = int((time.perf_counter() - t0) * 1000)
            err_msg = str(pe)
            diagnostics.append(f"POSIX Syntax Error: {err_msg}")
            return SandboxDryRunResponse(
                command=command_str,
                tool="syntax_error",
                syntax_valid=False,
                exit_code=2,
                diagnostics=diagnostics,
                simulated_stdout="",
                simulated_stderr=f"vallum-sandbox: shell syntax error: {err_msg}\n",
                elapsed_ms=elapsed,
            )
        except Exception as ex:
            elapsed = int((time.perf_counter() - t0) * 1000)
            diagnostics.append(f"Parsing Failure: {ex}")
            return SandboxDryRunResponse(
                command=command_str,
                tool="syntax_error",
                syntax_valid=False,
                exit_code=2,
                diagnostics=diagnostics,
                simulated_stdout="",
                simulated_stderr=f"vallum-sandbox: parse failure: {ex}\n",
                elapsed_ms=elapsed,
            )

        # 2. Extract atomic command words
        tokens = cls._tokenize_command_line(raw_cmd)
        if not tokens:
            elapsed = int((time.perf_counter() - t0) * 1000)
            return SandboxDryRunResponse(
                command=command_str,
                tool="none",
                syntax_valid=False,
                exit_code=2,
                diagnostics=["No executable command tokens parsed."],
                simulated_stdout="",
                simulated_stderr="vallum-sandbox: no executable tokens found\n",
                elapsed_ms=elapsed,
            )

        tool_binary = tokens[0].lower()
        args = tokens[1:]

        # 3. Tool-Specific Flag Grammar Validation
        syntax_valid, flag_errors, validated_flags, targets = cls._validate_tool_flags(tool_binary, args)
        diagnostics.extend(flag_errors)

        if not syntax_valid and strict_syntax:
            elapsed = int((time.perf_counter() - t0) * 1000)
            stderr_out = "\n".join(f"{tool_binary}: option error: {e}" for e in flag_errors) + "\n"
            return SandboxDryRunResponse(
                command=command_str,
                tool=tool_binary,
                syntax_valid=False,
                exit_code=1,
                diagnostics=diagnostics,
                simulated_stdout="",
                simulated_stderr=stderr_out,
                elapsed_ms=elapsed,
            )

        # 4. Scope Cross-Check Diagnostic
        if roe:
            cls._append_scope_diagnostics(tool_binary, validated_flags, targets, roe, diagnostics)

        # 5. Synthesize Execution Output (stdout/stderr)
        stdout_sim, stderr_sim, exit_code = cls._simulate_tool_execution(tool_binary, args, validated_flags, targets)

        elapsed = int((time.perf_counter() - t0) * 1000)
        return SandboxDryRunResponse(
            command=command_str,
            tool=tool_binary,
            syntax_valid=True,
            exit_code=exit_code,
            isolation=SandboxIsolationMetadata(
                network_isolated=True,
                network_egress="DISABLED",
                packets_transmitted=0,
                zero_host_execution=True,
                filesystem_mode="ephemeral-vfs-readonly",
            ),
            diagnostics=diagnostics,
            simulated_stdout=stdout_sim,
            simulated_stderr=stderr_sim,
            elapsed_ms=elapsed,
        )

    @classmethod
    def _tokenize_command_line(cls, cmd_line: str) -> List[str]:
        """Split a command line into arguments respecting quotes and escapes."""
        # Simple regex tokenizer respecting double and single quotes
        token_pattern = re.compile(r"""(?:[^\s"']+|"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*')+""")
        raw_tokens = token_pattern.findall(cmd_line)
        cleaned: List[str] = []
        for t in raw_tokens:
            if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
                cleaned.append(t[1:-1])
            else:
                cleaned.append(t)
        return cleaned

    @classmethod
    def _validate_tool_flags(
        cls,
        tool: str,
        args: List[str],
    ) -> Tuple[bool, List[str], Dict[str, str], List[str]]:
        """Verify tool-specific CLI options and flags against specs."""
        errors: List[str] = []
        validated_flags: Dict[str, str] = {}
        targets: List[str] = []

        spec = TOOL_FLAG_SPECS.get(tool, DEFAULT_TOOL_FLAG_SPEC)
        idx = 0
        total_args = len(args)

        while idx < total_args:
            token = args[idx]

            # Flag with equals sign (e.g. --timing=3, --url=http://...)
            if "=" in token and token.startswith("-"):
                opt, val = token.split("=", 1)
                validated_flags[opt] = val
                idx += 1
                continue

            # Flag that expects an argument
            if token in spec.non_target_value_flags or token in spec.target_flags:
                if idx + 1 >= total_args:
                    errors.append(f"Option '{token}' requires an argument operand.")
                    return False, errors, validated_flags, targets
                val = args[idx + 1]
                validated_flags[token] = val

                # Specific parameter sanity checks
                if token in {"-p", "--ports"}:
                    # Port specification grammar check
                    if not re.match(r"^[0-9TU:, \-]+$", val, re.IGNORECASE):
                        errors.append(f"Invalid port specification for '{token}': '{val}' (expected e.g. 80,443 or 1-1000).")
                elif token in {"-T", "--timing"}:
                    # Nmap timing must be 0-5
                    if not val.isdigit() or int(val) < 0 or int(val) > 5:
                        errors.append(f"Invalid timing value for '{token}': '{val}' (expected 0-5).")

                if token in spec.target_flags:
                    targets.append(val)

                idx += 2
                continue

            # Attached short flags (e.g. -T3, -sS, -p80)
            if token.startswith("-T") and len(token) > 2 and token[2:].isdigit():
                timing_val = int(token[2:])
                if timing_val < 0 or timing_val > 5:
                    errors.append(f"Invalid timing template '{token}' (must be -T0 to -T5).")
                validated_flags["-T"] = str(timing_val)
                idx += 1
                continue

            if token.startswith("-p") and len(token) > 2:
                port_val = token[2:]
                if not re.match(r"^[0-9TU:, \-]+$", port_val, re.IGNORECASE):
                    errors.append(f"Invalid attached port specification: '{token}'.")
                validated_flags["-p"] = port_val
                idx += 1
                continue

            # Regular flag without argument
            if token.startswith("-"):
                validated_flags[token] = "true"
                idx += 1
                continue

            # Positional operand / Target
            targets.append(token)
            idx += 1

        # Check required options for specific tools
        if tool == "gobuster":
            if not any(sub in args for sub in ["dir", "dns", "vhost", "fuzz"]):
                errors.append("gobuster requires a mode operand (e.g. 'gobuster dir' or 'gobuster dns').")
            if "-u" not in validated_flags and "--url" not in validated_flags and "dir" in args:
                errors.append("gobuster dir requires a target URL flag ('-u' or '--url').")
            if "-w" not in validated_flags and "--wordlist" not in validated_flags:
                errors.append("gobuster requires a wordlist flag ('-w' or '--wordlist').")

        if tool == "sqlmap":
            has_target = (
                "-u" in validated_flags
                or "--url" in validated_flags
                or "-r" in validated_flags
                or any(t.startswith("http") for t in targets)
            )
            if not has_target:
                errors.append("sqlmap requires a target URL ('-u', '--url') or request file ('-r').")

        if tool == "nikto":
            has_host = "-h" in validated_flags or "-host" in validated_flags or len(targets) > 0
            if not has_host:
                errors.append("nikto requires a target host flag ('-h' or '-host').")

        syntax_ok = len(errors) == 0
        return syntax_ok, errors, validated_flags, targets

    @classmethod
    def _append_scope_diagnostics(
        cls,
        tool: str,
        flags: Dict[str, str],
        targets: List[str],
        roe: RoeScope,
        diagnostics: List[str],
    ) -> None:
        """Add engagement boundary cross-reference diagnostics."""
        # Check tool allowance
        if roe.prohibited_tools and tool in roe.prohibited_tools:
            diagnostics.append(f"RoE Policy Warning: Tool '{tool}' is explicitly prohibited by active engagement rules.")
        elif roe.allowed_tools and tool not in roe.allowed_tools:
            diagnostics.append(f"RoE Policy Notice: Tool '{tool}' is not in authorized tools whitelist.")

        # Check prohibited flags
        for f in flags:
            if roe.prohibited_flags and f in roe.prohibited_flags:
                diagnostics.append(f"RoE Policy Warning: Flag '{f}' is prohibited by active engagement rules.")

        # Check nmap timing template
        if "-T" in flags and roe.max_nmap_timing:
            try:
                timing_val = int(flags["-T"])
                if timing_val > roe.max_nmap_timing:
                    diagnostics.append(
                        f"RoE Timing Warning: Timing -T{timing_val} exceeds maximum allowable -T{roe.max_nmap_timing}."
                    )
            except ValueError:
                pass

    @classmethod
    def _simulate_tool_execution(
        cls,
        tool: str,
        args: List[str],
        flags: Dict[str, str],
        targets: List[str],
    ) -> Tuple[str, str, int]:
        """Generate realistic dry-run terminal output in network-isolated state."""
        cur_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        banner = SIMULATED_TOOL_BANNERS.get(
            tool,
            f"Executing {tool} in Vallum Ephemeral Micro-Sandbox\n[VALLUM MICRO-SANDBOX] Mode: Isolated Dry-Run (Egress: DISABLED)",
        ).format(timestamp=cur_ts)

        lines: List[str] = [banner, ""]

        if tool == "nmap":
            target_str = ", ".join(targets) if targets else "127.0.0.1"
            ports_str = flags.get("-p", "1-1000 (standard top ports)")
            timing_str = f"-T{flags.get('-T', '3')}"
            lines.append(f"Nmap scan report for {target_str}")
            lines.append(f"Host is up (0.00012s latency).")
            lines.append(f"Scanned at {cur_ts}")
            lines.append(f"Parameters: ports={ports_str}, timing={timing_str}")
            lines.append(f"Scan Technique: SYN Stealth Scan (simulated)")
            lines.append("")
            lines.append("PORT     STATE SERVICE")
            lines.append("80/tcp   open  http")
            lines.append("443/tcp  open  https")
            lines.append("")
            lines.append(f"Nmap done: 1 IP address (1 host up) scanned in 0.02 seconds")
            lines.append("[VALLUM-EGRESS-GUARD] 0 real packets released onto physical/virtual interfaces.")

        elif tool == "gobuster":
            url = flags.get("-u") or flags.get("--url") or (targets[0] if targets else "http://localhost")
            wordlist = flags.get("-w") or flags.get("--wordlist") or "wordlist.txt"
            lines.append(f"===============================================================")
            lines.append(f"Gobuster v3.6")
            lines.append(f"by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)")
            lines.append(f"===============================================================")
            lines.append(f"[+] Url:                     {url}")
            lines.append(f"[+] Method:                  GET")
            lines.append(f"[+] Threads:                 {flags.get('-t', '10')}")
            lines.append(f"[+] Wordlist:                {wordlist}")
            lines.append(f"[+] Status codes:            {flags.get('-s', '200,204,301,302,307,401,403')}")
            lines.append(f"===============================================================")
            lines.append(f"[VALLUM-EGRESS-GUARD] Dry-run pre-flight verified; network egress halted.")

        elif tool == "nikto":
            host = flags.get("-h") or flags.get("-host") or (targets[0] if targets else "localhost")
            lines.append(f"+ Target IP:          {host}")
            lines.append(f"+ Target Hostname:    {host}")
            lines.append(f"+ Target Port:        {flags.get('-p', '80')}")
            lines.append(f"+ Start Time:         {cur_ts}")
            lines.append(f"---------------------------------------------------------------------------")
            lines.append(f"+ Server: Apache/2.4 (Virtual Simulation)")
            lines.append(f"+ [VALLUM-EGRESS-GUARD] Syntax check passed. No HTTP requests transmitted.")

        elif tool == "sqlmap":
            target = flags.get("-u") or flags.get("--url") or (targets[0] if targets else "http://localhost")
            lines.append(f"[*] starting @ {cur_ts}")
            lines.append(f"[INFO] testing connection to the target URL: {target}")
            lines.append(f"[INFO] checking if the target is protected by some kind of WAF/IPS")
            lines.append(f"[INFO] testing if the target URL content is stable")
            lines.append(f"[VALLUM-EGRESS-GUARD] Injection vectors parsed. Network egress blocked.")

        elif tool == "curl":
            url = targets[0] if targets else flags.get("-u", "http://localhost")
            lines.append(f"* Connecting to {url} (simulated)...")
            lines.append(f"* Connected to micro-sandbox virtual interface")
            lines.append(f"> GET / HTTP/1.1")
            lines.append(f"> Host: {url}")
            lines.append(f"> User-Agent: curl/8.4.0")
            lines.append(f"> Accept: */*")
            lines.append(f"* [VALLUM-EGRESS-GUARD] Loopback socket disconnected: 0 bytes sent.")

        else:
            lines.append(f"[Dry-Run Execution] Tool: {tool}")
            lines.append(f"Tokens recognized: {len(args)} arguments")
            lines.append(f"Flag bindings: {flags}")
            lines.append(f"Positional operands: {targets}")
            lines.append(f"[VALLUM-EGRESS-GUARD] Strict network isolation active. Zero packets egressed.")

        stdout_sim = "\n".join(lines) + "\n"
        stderr_sim = ""
        exit_code = 0
        return stdout_sim, stderr_sim, exit_code

    @classmethod
    def get_status(cls) -> SandboxStatusResponse:
        """Provide capabilities and state metadata for the micro-sandbox."""
        return SandboxStatusResponse(
            status="operational",
            sandbox_tier="ephemeral-micro-sandbox (vfs-isolated)",
            network_egress="DISABLED",
            zero_host_execution=True,
            supported_tools=list(TOOL_FLAG_SPECS.keys()),
        )
