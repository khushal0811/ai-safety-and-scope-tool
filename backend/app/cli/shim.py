"""Vallum CLI & Real-Time Terminal Interceptor Shim.

Enforces Zero Host Execution by statically pre-screening every shell command
against active Rules of Engagement (RoE) boundaries before execution.

Usage:
    vallum-cli check "<command>"
    vallum-cli run "<command>"
    vallum-cli roe [list | show | set <id>]
    vallum-cli daemon [status | start]
    vallum-cli init [bash | zsh | fish] [--install]
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

# --- ANSI Color Codes for Dark Desk Terminal UI ---
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[38;2;16;185;129m"
    RED = "\033[38;2;239;68;68m"
    YELLOW = "\033[38;2;245;158;11m"
    CYAN = "\033[38;2;6;182;212m"
    PURPLE = "\033[38;2;168;85;247m"
    GRAY = "\033[38;2;107;114;128m"
    BG_DARK = "\033[48;2;15;23;42m"
    WHITE = "\033[38;2;248;250;252m"

    @classmethod
    def disable(cls):
        """Disable all color formatting for plain text / pipes."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.GREEN = ""
        cls.RED = ""
        cls.YELLOW = ""
        cls.CYAN = ""
        cls.PURPLE = ""
        cls.GRAY = ""
        cls.BG_DARK = ""
        cls.WHITE = ""


# Default paths and daemon configuration
CONFIG_DIR = Path.home() / ".vallum"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_DAEMON_URL = os.environ.get("VALLUM_DAEMON_URL", "http://127.0.0.1:8000")
DEFAULT_ROE_ID = "ROE-PRESET-NET-001"


def get_config() -> Dict[str, Any]:
    """Load persistent CLI configuration or return sensible defaults."""
    default_config = {
        "daemon_url": DEFAULT_DAEMON_URL,
        "active_roe_id": DEFAULT_ROE_ID,
        "active_roe_file": None,
        "mode": "deterministic",
        "strict": False,
    }
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                default_config.update(data)
        except Exception:
            pass
    return default_config


def save_config(config: Dict[str, Any]) -> None:
    """Save persistent CLI configuration to ~/.vallum/config.json."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def is_daemon_alive(daemon_url: str, timeout: float = 1.0) -> bool:
    """Check if the local Vallum FastAPI daemon is running."""
    try:
        url = f"{daemon_url.rstrip('/')}/api/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def load_local_engine():
    """Dynamically import the local Vallum Python verification engine."""
    # Ensure backend path is on sys.path if running in dev environment
    current_dir = Path(__file__).resolve().parent
    backend_dir = current_dir.parent.parent
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    from app.data.presets import ROE_PRESETS, get_roe_preset_by_id
    from app.engine.verifier import evaluate_deterministic_command
    from app.models.audit import DeterministicAuditRequest
    from app.models.roe import RoeScope

    return {
        "ROE_PRESETS": ROE_PRESETS,
        "get_roe_preset_by_id": get_roe_preset_by_id,
        "evaluate_deterministic_command": evaluate_deterministic_command,
        "DeterministicAuditRequest": DeterministicAuditRequest,
        "RoeScope": RoeScope,
    }


def resolve_roe_locally(roe_id_or_file: Optional[str]) -> Any:
    """Resolve an RoE scope object from a preset ID or custom file."""
    engine = load_local_engine()
    preset_lookup = engine["get_roe_preset_by_id"]
    RoeScope = engine["RoeScope"]
    ROE_PRESETS = engine["ROE_PRESETS"]

    if not roe_id_or_file:
        return ROE_PRESETS[0]

    # Check if path to file exists
    file_path = Path(roe_id_or_file).expanduser().resolve()
    if file_path.exists() and file_path.is_file():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                if file_path.suffix.lower() == ".json":
                    data = json.loads(content)
                    return RoeScope(**data)
                else:
                    # Markdown or text RoE
                    from app.engine.roe_parser import parse_unstructured_roe_sync
                    # If synchronous parser exists or simple fallback:
                    try:
                        import asyncio
                        from app.engine.roe_parser import parse_unstructured_roe
                        return asyncio.run(parse_unstructured_roe(content, filename=file_path.name))
                    except Exception:
                        pass
        except Exception as e:
            sys.stderr.write(f"{Colors.YELLOW}[!] Could not parse custom RoE file: {e}. Falling back to preset.{Colors.RESET}\n")

    preset = preset_lookup(roe_id_or_file)
    if preset:
        return preset

    return ROE_PRESETS[0]


def query_daemon_audit(
    command: str,
    roe_id: Optional[str] = None,
    custom_roe: Optional[Dict[str, Any]] = None,
    daemon_url: str = DEFAULT_DAEMON_URL,
    timeout: float = 3.0,
) -> Optional[Dict[str, Any]]:
    """Submit command for verification to the running Vallum FastAPI daemon."""
    url = f"{daemon_url.rstrip('/')}/api/audit/deterministic"
    payload: Dict[str, Any] = {
        "command": command,
        "model_id": "vallum-cli-shim",
    }
    if custom_roe:
        payload["roe"] = custom_roe
    elif roe_id:
        payload["roe_id"] = roe_id

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Vallum-CLI-Shim/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read().decode("utf-8")
                return json.loads(body)
    except Exception:
        return None
    return None


def evaluate_command_audit(
    command: str,
    roe_spec: Optional[str] = None,
    daemon_url: str = DEFAULT_DAEMON_URL,
    force_offline: bool = False,
) -> Tuple[Dict[str, Any], str]:
    """Evaluate command either via the daemon or local in-process fallback."""
    config = get_config()
    active_roe = roe_spec or config.get("active_roe_id") or DEFAULT_ROE_ID

    # 1. Try daemon first unless force_offline is requested
    if not force_offline:
        res = query_daemon_audit(command, roe_id=active_roe, daemon_url=daemon_url)
        if res:
            return res, "daemon"

    # 2. Fallback to in-process deterministic engine
    engine = load_local_engine()
    roe = resolve_roe_locally(active_roe)
    req = engine["DeterministicAuditRequest"](
        command=command,
        roe=roe,
        model_id="vallum-cli-local",
    )
    result = engine["evaluate_deterministic_command"](req)
    return result.model_dump(mode="json"), "local"


def render_audit_report(result: Dict[str, Any], engine_source: str, quiet: bool = False) -> None:
    """Print Dark Desk styled security report to terminal."""
    if quiet:
        return

    raw_verdict = str(result.get("verdict", "Unsafe")).strip().capitalize()
    targets = result.get("targets", [])
    violations = result.get("violation_details", [])
    sanitized = result.get("safe_sanitized_command")
    extracted_cmds = result.get("extracted_commands", [])

    print()
    if raw_verdict == "Correct":
        status_badge = f"{Colors.GREEN}{Colors.BOLD}[✓] VALLUM: PASS{Colors.RESET}"
        print(f"{status_badge}  {Colors.WHITE}Command authorized by Rules of Engagement.{Colors.RESET}")
    elif raw_verdict == "Incorrect":
        status_badge = f"{Colors.YELLOW}{Colors.BOLD}[!] VALLUM: REVIEW REQUIRED{Colors.RESET}"
        print(f"{status_badge}  {Colors.YELLOW}Command requires review (non-blocking findings detected).{Colors.RESET}")
    else:
        status_badge = f"{Colors.RED}{Colors.BOLD}[✗] VALLUM: BLOCKED{Colors.RESET}"
        print(f"{status_badge}  {Colors.RED}{Colors.BOLD}Command breaches active Rules of Engagement!{Colors.RESET}")

    # Targets breakdown
    if targets:
        print(f"\n{Colors.CYAN}{Colors.BOLD}Target Assets:{Colors.RESET}")
        for t in targets:
            token = t.get("token") or t.get("raw_token") or t.get("target") or "unknown"
            status = str(t.get("status", "")).lower()
            normalized = t.get("normalized", "")
            norm_str = f" ({normalized})" if normalized and normalized != token else ""
            override_reason = t.get("override_reason") or ""
            
            if status == "in_scope":
                status_str = f"{Colors.GREEN}IN_SCOPE{Colors.RESET}"
            elif status == "out_of_scope":
                status_str = f"{Colors.RED}{Colors.BOLD}OUT_OF_SCOPE{Colors.RESET}"
            elif status == "prohibited":
                status_str = f"{Colors.RED}{Colors.BOLD}PROHIBITED{Colors.RESET}"
            else:
                status_str = f"{Colors.YELLOW}{status.upper()}{Colors.RESET}"

            extra = f" {Colors.DIM}[{override_reason}]{Colors.RESET}" if override_reason else ""
            print(f"  • {Colors.WHITE}{token}{norm_str}{Colors.RESET} [{status_str}]{extra}")

    # Violations breakdown
    if violations:
        print(f"\n{Colors.RED}{Colors.BOLD}Scope & Policy Violations:{Colors.RESET}")
        for v in violations:
            rule = v.get("rule", "Unknown Rule")
            sev = str(v.get("severity", "WARNING")).upper()
            cat = str(v.get("category", "POLICY")).upper()
            detail = v.get("detail", "")
            culprit = v.get("command") or ""

            sev_color = Colors.RED if sev == "CRITICAL" else Colors.YELLOW
            print(f"  • {sev_color}[{sev} | {cat}]{Colors.RESET} {Colors.BOLD}{rule}{Colors.RESET}")
            print(f"    {Colors.DIM}{detail}{Colors.RESET}")
            if culprit:
                print(f"    {Colors.DIM}Culprit token: {Colors.WHITE}`{culprit}`{Colors.RESET}")

    # Remediation
    if sanitized and raw_verdict != "Correct":
        print(f"\n{Colors.PURPLE}{Colors.BOLD}Compliant Remediation (Synthesized by Vallum):{Colors.RESET}")
        print(f"  {Colors.GREEN}{Colors.BOLD}{sanitized}{Colors.RESET}")

    # Engine footer
    src_tag = f"{Colors.DIM}(Engine: {engine_source}){Colors.RESET}"
    print(f"\n{Colors.GRAY}─────────────────────────────────────────────────────────────{Colors.RESET} {src_tag}\n")


# ============================================================================
# CLI Commands Implementation
# ============================================================================

def cmd_check(args: argparse.Namespace) -> int:
    """Audit command and exit with 0 (safe), 1 (blocked), or 2 (review)."""
    command = " ".join(args.command)
    if not command.strip():
        sys.stderr.write(f"{Colors.RED}[!] No command provided to check.{Colors.RESET}\n")
        return 1

    result, source = evaluate_command_audit(
        command=command,
        roe_spec=args.roe,
        daemon_url=args.daemon_url or DEFAULT_DAEMON_URL,
        force_offline=args.offline,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        render_audit_report(result, source, quiet=args.quiet)

    verdict = str(result.get("verdict", "Unsafe")).strip().capitalize()
    if verdict == "Correct":
        return 0
    elif verdict == "Incorrect":
        return 2 if args.strict else 0
    else:
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Pre-screen command with Vallum, then return authorization exit code for the shell wrapper."""
    command = " ".join(args.command)
    if not command.strip():
        sys.stderr.write(f"{Colors.RED}[!] No command provided to run.{Colors.RESET}\n")
        return 1

    result, source = evaluate_command_audit(
        command=command,
        roe_spec=args.roe,
        daemon_url=args.daemon_url or DEFAULT_DAEMON_URL,
        force_offline=args.offline,
    )

    verdict = str(result.get("verdict", "Unsafe")).strip().capitalize()
    sanitized = result.get("safe_sanitized_command")

    if verdict == "Correct" or (verdict == "Incorrect" and not args.strict):
        render_audit_report(result, source, quiet=args.quiet)
        if args.dry_run:
            print(f"{Colors.CYAN}[DRY-RUN] Command passed inspection. Execution skipped.{Colors.RESET}")
        return 0
    else:
        render_audit_report(result, source, quiet=False)
        return 1


def cmd_intercept(args: argparse.Namespace) -> int:
    """Shell alias target: intercepts command invocation, checks it, then runs."""
    command = " ".join([args.tool] + args.tool_args)
    return cmd_run(
        argparse.Namespace(
            command=[command],
            roe=args.roe,
            daemon_url=args.daemon_url,
            offline=args.offline,
            quiet=args.quiet,
            strict=args.strict,
            dry_run=False,
            fix=False,
        )
    )


def cmd_roe(args: argparse.Namespace) -> int:
    """Manage active Rules of Engagement."""
    engine = load_local_engine()
    presets = engine["ROE_PRESETS"]
    config = get_config()

    action = args.action or "show"

    if action == "list":
        print(f"\n{Colors.BOLD}{Colors.WHITE}Available Rules of Engagement Presets:{Colors.RESET}\n")
        active_id = config.get("active_roe_id")
        for p in presets:
            is_active = p.roe_id == active_id
            marker = f"{Colors.GREEN}* [ACTIVE]{Colors.RESET}" if is_active else "         "
            print(f"{marker} {Colors.CYAN}{Colors.BOLD}{p.roe_id}{Colors.RESET} — {Colors.WHITE}{p.name}{Colors.RESET}")
            print(f"           Type: {p.engagement_type} | CIDRs: {', '.join(p.allowed_cidrs) or 'None'}")
            print(f"           Summary: {Colors.DIM}{p.summary}{Colors.RESET}\n")
        return 0

    elif action == "set":
        target = args.target
        if not target:
            sys.stderr.write(f"{Colors.RED}[!] Please specify a preset ID or RoE file path.{Colors.RESET}\n")
            return 1
        # Test resolution
        scope = resolve_roe_locally(target)
        config["active_roe_id"] = scope.roe_id
        save_config(config)
        print(f"{Colors.GREEN}[✓] Active Scope updated to: {Colors.BOLD}{scope.name} [{scope.roe_id}]{Colors.RESET}")
        return 0

    else:  # show
        active_id = config.get("active_roe_id", DEFAULT_ROE_ID)
        scope = resolve_roe_locally(active_id)
        print(f"\n{Colors.BOLD}{Colors.WHITE}Active Scope Configuration:{Colors.RESET}")
        print(f"  ID:               {Colors.CYAN}{scope.roe_id}{Colors.RESET}")
        print(f"  Name:             {Colors.WHITE}{scope.name}{Colors.RESET}")
        print(f"  Engagement Type:  {scope.engagement_type}")
        print(f"  Allowed CIDRs:    {Colors.GREEN}{', '.join(scope.allowed_cidrs) or 'None'}{Colors.RESET}")
        print(f"  Allowed Domains:  {Colors.GREEN}{', '.join(scope.allowed_domains) or 'None'}{Colors.RESET}")
        print(f"  Prohibited Tools: {Colors.RED}{', '.join(scope.prohibited_tools) or 'None'}{Colors.RESET}")
        print(f"  Prohibited Flags: {Colors.RED}{', '.join(scope.prohibited_flags) or 'None'}{Colors.RESET}")
        print(f"  Summary:          {Colors.DIM}{scope.summary}{Colors.RESET}\n")
        return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    """Inspect or manage the local Vallum daemon."""
    daemon_url = args.daemon_url or DEFAULT_DAEMON_URL
    action = args.action or "status"

    if action == "status":
        alive = is_daemon_alive(daemon_url)
        if alive:
            print(f"{Colors.GREEN}[✓] Vallum Daemon is ONLINE at {daemon_url}{Colors.RESET}")
            return 0
        else:
            print(f"{Colors.YELLOW}[!] Vallum Daemon is OFFLINE at {daemon_url} (Local fallback is active){Colors.RESET}")
            return 1

    elif action == "start":
        if is_daemon_alive(daemon_url):
            print(f"{Colors.GREEN}[✓] Vallum Daemon is already running at {daemon_url}{Colors.RESET}")
            return 0

        print(f"{Colors.CYAN}[+] To start the Vallum Daemon in the background, run:{Colors.RESET}")
        print(f"    nohup uvicorn app.main:app --host 127.0.0.1 --port 8000 > /tmp/vallum-daemon.log 2>&1 &")
        print(f"{Colors.DIM}    (Or run: ./bin/vallum-cli daemon start){Colors.RESET}")
        return 0
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Generate or install shell integration wrapper function."""
    shell_type = args.shell.lower() if args.shell else "zsh"

    script = """# ─────────────────────────────────────────────────────────────
# Vallum Real-Time Scope & Safety Shell Shim
# Automatically screens offensive commands before host execution.
# ─────────────────────────────────────────────────────────────
vallum() {
    if [ $# -eq 0 ]; then
        vallum-cli --help
        return 0
    fi
    local cmd="$*"
    if vallum-cli check "$cmd"; then
        eval "$cmd"
    else
        local rc=$?
        return $rc
    fi
}
"""

    if args.install:
        home = Path.home()
        target_rc = home / (".zshrc" if "zsh" in os.environ.get("SHELL", "zsh") else ".bashrc")
        if target_rc.exists():
            content = target_rc.read_text(encoding="utf-8")
            if "vallum()" in content:
                print(f"{Colors.YELLOW}[!] Vallum shell hook is already present in {target_rc}{Colors.RESET}")
                return 0
            # Append hook
            with open(target_rc, "a", encoding="utf-8") as f:
                f.write("\n" + script + "\n")
            print(f"{Colors.GREEN}[✓] Vallum shell wrapper installed to {target_rc}{Colors.RESET}")
            print(f"{Colors.CYAN}    Run `source {target_rc}` or open a new terminal to activate.{Colors.RESET}")
            return 0
        else:
            print(f"{Colors.RED}[!] Could not locate shell RC file: {target_rc}{Colors.RESET}")
            return 1

    print(script)
    return 0


# ============================================================================
# Main Entry Point
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="vallum-cli",
        description="Vallum — Real-Time Scope & Safety CLI Interceptor for Penetration Testers",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    parser.add_argument("--daemon-url", default=None, help="Vallum API daemon URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--offline", action="store_true", help="Force local offline verification (bypass daemon)")

    subparsers = parser.add_subparsers(dest="subcommand", help="Vallum command modes")

    # 1. check
    p_check = subparsers.add_parser("check", help="Pre-screen a command string against active RoE")
    p_check.add_argument("command", nargs="+", help="CLI command to audit")
    p_check.add_argument("--roe", default=None, help="Preset ID or path to custom RoE file")
    p_check.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (exit code only)")
    p_check.add_argument("--json", action="store_true", help="Output raw JSON evaluation result")
    p_check.add_argument("--strict", action="store_true", help="Fail on warning findings (Verdict.INCORRECT)")

    # 2. run
    p_run = subparsers.add_parser("run", help="Audit command and execute only if compliant")
    p_run.add_argument("command", nargs="+", help="CLI command to audit and run")
    p_run.add_argument("--roe", default=None, help="Preset ID or path to custom RoE file")
    p_run.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    p_run.add_argument("--strict", action="store_true", help="Fail on warning findings")
    p_run.add_argument("--dry-run", action="store_true", help="Audit only; do not execute even if safe")
    p_run.add_argument("--fix", action="store_true", help="Prompt to execute synthesized remediation if blocked")

    # 3. intercept
    p_intercept = subparsers.add_parser("intercept", help="Interceptor wrapper for individual tool aliases")
    p_intercept.add_argument("tool", help="Offensive tool name (e.g. nmap, gobuster)")
    p_intercept.add_argument("tool_args", nargs="*", help="Arguments passed to tool")
    p_intercept.add_argument("--roe", default=None, help="Preset ID or custom RoE file")
    p_intercept.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    p_intercept.add_argument("--strict", action="store_true", help="Strict mode")

    # 4. roe
    p_roe = subparsers.add_parser("roe", help="Manage active Rules of Engagement scope")
    p_roe.add_argument("action", nargs="?", choices=["list", "show", "set"], default="show")
    p_roe.add_argument("target", nargs="?", help="Preset ID or path to RoE file (for set)")

    # 5. daemon
    p_daemon = subparsers.add_parser("daemon", help="Inspect or launch local Vallum daemon")
    p_daemon.add_argument("action", nargs="?", choices=["status", "start"], default="status")

    # 6. init
    p_init = subparsers.add_parser("init", help="Generate shell wrapper script for .bashrc / .zshrc")
    p_init.add_argument("shell", nargs="?", choices=["bash", "zsh", "fish"], default="zsh")
    p_init.add_argument("--install", action="store_true", help="Automatically append wrapper to user's shell rc file")

    return parser


def main() -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    if args.subcommand == "check":
        return cmd_check(args)
    elif args.subcommand == "run":
        return cmd_run(args)
    elif args.subcommand == "intercept":
        return cmd_intercept(args)
    elif args.subcommand == "roe":
        return cmd_roe(args)
    elif args.subcommand == "daemon":
        return cmd_daemon(args)
    elif args.subcommand == "init":
        return cmd_init(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
