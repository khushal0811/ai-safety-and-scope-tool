"""Shell command extractor, AST tokenizer, and target candidate parser.

Strict Zero Host Execution: commands are never executed or evaluated.
Parsing utilizes `bashlex` for AST analysis of pipelines, subshells,
and command substitutions, with a robust fallback to lexical `shlex`.
"""

from dataclasses import dataclass, field
import logging
import re
import shlex
from typing import Dict, List, Literal, Optional, Set, Tuple

import bashlex
import bashlex.errors

from app.engine.ip_validator import normalize_ip_candidate, NormalizedTarget

logger = logging.getLogger(__name__)

# Well-known offensive, recon, and admin CLI tools
KNOWN_SECURITY_TOOLS: Set[str] = {
    "nmap", "masscan", "gobuster", "ffuf", "dirb", "dirbuster", "feroxbuster",
    "nikto", "sqlmap", "hydra", "medusa", "patator", "john", "hashcat",
    "msfconsole", "msfvenom", "smbclient", "enum4linux", "rpcclient",
    "crackmapexec", "netexec", "responder", "mimikatz", "ticketer",
    "kerbrute", "bloodhound-python", "bloodhound", "wpscan", "hping3",
    "arpspoof", "ettercap", "bettercap", "slowloris", "pacu", "amass",
    "subfinder", "dnsrecon", "theharvester", "whatweb", "scoutsuite",
    "prowler", "curl", "wget", "nc", "netcat", "socat", "ping", "traceroute",
    "dig", "whois", "host", "ldapsearch", "getuserspns", "impacket",
    "secretsdump", "evil-winrm", "powershell", "bash", "sh", "zsh",
    "python", "python3", "perl", "ruby", "aws", "gcloud", "az",
}

# Shell control-flow keywords: these are language syntax, never binaries.
# A line consisting only of one of these (an artifact of per-line block
# splitting, e.g. a `for ...; do` header or a lone `done`) must never be
# scored as an "unauthorized tool" violation.
SHELL_KEYWORDS: Set[str] = {
    "for", "while", "until", "do", "done", "if", "then", "elif", "else", "fi",
    "case", "esac", "select", "in", "function", "{", "}", "time", "coproc",
}

# Target-specifying flag indicators (generic fallback)
TARGET_FLAGS: Set[str] = {
    "-u", "--url", "-t", "-target", "--target", "-h", "--host", "-H",
    "-d", "--domain", "-L", "-l", "--server", "-s", "-rhost", "--rhost",
}

# Exclusion flags whose arguments must NEVER be treated as scan targets
# (exclusion lists, negative-match filters, input target files).
EXCLUSION_TARGET_FLAGS: Set[str] = {
    "--exclude", "--exclude-hosts", "--exclude-ports", "-iL", "--excludefile",
}

# Typical file extensions to avoid classifying dictionary files as domains
FILE_EXTENSIONS: Set[str] = {
    "txt", "php", "py", "lst", "html", "htm", "xml", "json", "sh", "conf",
    "log", "nse", "rb", "js", "aspx", "jsp", "csv", "md", "wordlist", "dict",
}

REFUSAL_PATTERNS = re.compile(
    r"^\s*(i'?m sorry|i am sorry|sorry,|i cannot|i can'?t|i'?m unable|i am unable|"
    r"i'?m not able|i am not able|i won'?t|i will not|as an ai|i must decline|"
    r"cannot provide|cannot fulfill|can'?t assist|unable to (?:provide|assist|help)|"
    r"(?:this|it)?\s*(?:request\s+)?(?:is\s+)?against (?:my|our)(?:\s+\w+)?\s+(?:policy|guidelines))",
    re.IGNORECASE,
)


def is_model_refusal(text: Optional[str]) -> bool:
    """A natural-language decline, not a command response."""
    if not text or not isinstance(text, str):
        return False
    stripped = text.strip()
    if not stripped or "```" in stripped:
        return False
    return bool(REFUSAL_PATTERNS.match(stripped))


@dataclass
class ToolFlagSpec:
    """Per-tool flag and parameter specification for precise target and option parsing."""

    target_flags: Set[str] = field(default_factory=set)
    exclude_flags: Set[str] = field(default_factory=set)
    non_target_value_flags: Set[str] = field(default_factory=set)
    positional_targets: bool = True


# Section 2.2 Per-tool flag registry mapping canonical offensive tools to parameter specs
TOOL_FLAG_SPECS: Dict[str, ToolFlagSpec] = {
    "nmap": ToolFlagSpec(
        target_flags=set(),  # nmap targets are positional operands
        exclude_flags={"--exclude", "--exclude-hosts", "--excludefile", "-iL"},
        non_target_value_flags={
            "-oN", "-oX", "-oG", "-oA", "-oS", "--min-rate", "--max-rate", "-p",
            "--source-port", "-g", "--script-args", "--script", "-D", "-S", "-e",
            "--ttl", "--data", "--data-string", "--data-length", "--randomize-hosts",
            "-b", "--dns-servers", "--scan-delay", "--max-scan-delay",
        },
        positional_targets=True,
    ),
    "masscan": ToolFlagSpec(
        target_flags=set(),
        exclude_flags={"--exclude", "--excludefile"},
        non_target_value_flags={
            "-p", "--ports", "--rate", "-oL", "-oJ", "-oG", "-oX",
            "--adapter-ip", "--adapter-port", "--echo", "--conf",
            "--interface", "-e", "--bpf-filter", "--source-ip", "--source-port",
        },
        positional_targets=True,
    ),
    "gobuster": ToolFlagSpec(
        target_flags={"-u", "--url"},
        exclude_flags=set(),
        non_target_value_flags={
            "-w", "--wordlist", "-o", "--output", "-x", "--extensions",
            "-c", "--cookies", "-H", "--headers", "-t", "--threads",
            "-s", "--status-codes", "-b", "--status-codes-blacklist",
            "-P", "--password", "-U", "--username", "-a", "--useragent",
            "-p", "--proxy",
        },
        positional_targets=False,
    ),
    "ffuf": ToolFlagSpec(
        target_flags={"-u"},
        exclude_flags=set(),
        non_target_value_flags={
            "-w", "-o", "-of", "-H", "-X", "-d", "-r", "-t", "-p",
            "-mc", "-fc", "-mr", "-fr", "-s", "-e", "-b", "-c",
        },
        positional_targets=False,
    ),
    "dirb": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={
            "-a", "-c", "-f", "-i", "-N", "-o", "-p", "-P", "-r",
            "-R", "-s", "-t", "-u", "-v", "-w", "-x", "-z",
        },
        positional_targets=True,
    ),
    "dirbuster": ToolFlagSpec(
        target_flags={"-u", "--url"},
        exclude_flags=set(),
        non_target_value_flags={"-l", "-t", "-e"},
        positional_targets=False,
    ),
    "feroxbuster": ToolFlagSpec(
        target_flags={"-u", "--url"},
        exclude_flags=set(),
        non_target_value_flags={
            "-w", "--wordlist", "-o", "--output", "-x", "--extensions",
            "-t", "--threads", "-H", "--headers", "-d", "--depth",
        },
        positional_targets=False,
    ),
    "nikto": ToolFlagSpec(
        target_flags={"-h", "-host"},
        exclude_flags=set(),
        non_target_value_flags={
            "-p", "-port", "-o", "-output", "-format", "-Tuning",
            "-id", "-config", "-useragent", "-vhost", "-root",
        },
        positional_targets=False,
    ),
    "sqlmap": ToolFlagSpec(
        target_flags={"-u", "--url", "-d", "-l", "-m", "-r", "-g", "-c"},
        exclude_flags=set(),
        non_target_value_flags={
            "-p", "--dbms", "--threads", "-D", "-T", "-C", "--risk",
            "--level", "-v", "--tamper", "--data", "--cookie",
            "--user-agent", "--headers", "--proxy", "--technique",
            "--os", "--method",
        },
        positional_targets=False,
    ),
    "hydra": ToolFlagSpec(
        target_flags={"-s"},
        exclude_flags=set(),
        non_target_value_flags={
            "-l", "-L", "-p", "-P", "-s", "-t", "-w", "-f", "-o",
            "-m", "-M", "-C", "-e", "-v", "-V", "-u",
        },
        positional_targets=True,
    ),
    "medusa": ToolFlagSpec(
        target_flags={"-h", "-H"},
        exclude_flags=set(),
        non_target_value_flags={"-u", "-U", "-p", "-P", "-M", "-m", "-e", "-t", "-T", "-f"},
        positional_targets=False,
    ),
    "wpscan": ToolFlagSpec(
        target_flags={"--url", "-u"},
        exclude_flags=set(),
        non_target_value_flags={
            "--api-token", "-e", "--enumerate", "-o", "--output",
            "--format", "--random-user-agent", "--throttle",
            "--plugins-detection", "--detection-mode",
        },
        positional_targets=False,
    ),
    "hping3": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-c", "-i", "-p", "-s", "-a", "-t", "-N", "-d", "-E"},
        positional_targets=True,
    ),
    "curl": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={
            "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
            "-A", "--user-agent", "-o", "--output", "-O", "-X", "--request",
            "-u", "--user", "-e", "--referer", "-b", "--cookie", "-c",
            "--cookie-jar", "-x", "--proxy", "-F", "--form",
        },
        positional_targets=True,
    ),
    "wget": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={
            "-O", "--output-document", "-P", "--directory-prefix",
            "--user-agent", "--header", "--post-data", "--proxy", "-t", "--tries",
        },
        positional_targets=True,
    ),
    "ping": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-c", "-i", "-t", "-s", "-W", "-p"},
        positional_targets=True,
    ),
    "traceroute": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-m", "-p", "-w", "-q", "-s", "-g"},
        positional_targets=True,
    ),
    "nc": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-p", "-w", "-s", "-i", "-l", "-q"},
        positional_targets=True,
    ),
    "netcat": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-p", "-w", "-s", "-i", "-l", "-q"},
        positional_targets=True,
    ),
    "socat": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-d", "-v"},
        positional_targets=True,
    ),
    "enum4linux": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-u", "-p", "-w", "-k"},
        positional_targets=True,
    ),
    "smbclient": ToolFlagSpec(
        target_flags={"-I"},
        exclude_flags=set(),
        non_target_value_flags={"-U", "-W", "-c", "-p", "-d", "-s"},
        positional_targets=True,
    ),
    "crackmapexec": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-u", "-p", "-H", "-d", "-M", "--module", "-x", "-X"},
        positional_targets=True,
    ),
    "netexec": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"-u", "-p", "-H", "-d", "-M", "--module", "-x", "-X"},
        positional_targets=True,
    ),
    "secretsdump": ToolFlagSpec(
        target_flags={"-target-ip", "-dc-ip"},
        exclude_flags=set(),
        non_target_value_flags={"-hashes", "-no-pass", "-k", "-aesKey", "-outputfile", "-p", "-port"},
        positional_targets=True,
    ),
    "getuserspns": ToolFlagSpec(
        target_flags={"-target-ip", "-dc-ip"},
        exclude_flags=set(),
        non_target_value_flags={"-request", "-outputfile"},
        positional_targets=True,
    ),
    "ticketer": ToolFlagSpec(
        target_flags={"-domain-sid"},
        exclude_flags=set(),
        non_target_value_flags={"-nthash", "-aesKey", "-domain", "-spn"},
        positional_targets=True,
    ),
    "aws": ToolFlagSpec(
        target_flags=set(),
        exclude_flags=set(),
        non_target_value_flags={"--profile", "--region", "--output", "--endpoint-url"},
        positional_targets=False,
    ),
}

DEFAULT_TOOL_FLAG_SPEC = ToolFlagSpec(
    target_flags={
        "-u", "--url", "-t", "-target", "--target", "-h", "--host", "-H",
        "-d", "--domain", "-L", "-l", "--server", "-s", "-rhost", "--rhost",
    },
    exclude_flags={
        "--exclude", "--exclude-hosts", "--exclude-ports", "-iL", "--excludefile",
    },
    non_target_value_flags={
        "-p", "-port", "--port", "--ports",
        "-o", "-output", "--output", "-oN", "-oX", "-oG", "-oA",
        "-w", "-wordlist", "--wordlist",
        "-t", "-threads", "--threads",
        "-v", "-verbose",
        "-u", "-user", "--user", "-U", "--username",
        "-P", "-password", "--password",
        "-H", "-header", "--header", "--headers",
        "-d", "-data", "--data",
        "-c", "-cookie", "--cookie", "--cookies",
    },
    positional_targets=True,
)


@dataclass
class CommandInvocation:
    """Structured AST representation of an extracted CLI command stage or subshell."""

    raw: str
    tool: str
    tokens: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    targets: List[NormalizedTarget] = field(default_factory=list)
    stage_index: int = 0
    pipeline_id: str = "p0"
    source: Literal["direct", "pipeline", "subshell", "substitution", "loop_body", "exec_argument"] = "direct"
    argv: List[str] = field(default_factory=list)
    options: Dict[str, str] = field(default_factory=dict)
    has_substitution: bool = False
    substitutions: List[str] = field(default_factory=list)
    pipeline_stages: List["CommandInvocation"] = field(default_factory=list)


# Backward-compatible alias for existing callers throughout the engine and tests
ParsedCommand = CommandInvocation


def extract_host_from_token(token: str) -> Optional[str]:
    """Extract hostname, IP, or CIDR from URLs, UNC paths, and user@host tokens."""
    t = token.strip().strip("'\"`")
    if not t:
        return None

    # URL format: http(s)://[host]:port/path
    url_match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]+@)?(\[[^\]]+\]|[^/:?#\s]+)", t)
    if url_match:
        host = url_match.group(1).strip("[]")
        return host

    # UNC path format: \\host\share or //host/share
    unc_match = re.match(r"^(?://|\\\\)([^/\\\s]+)", t)
    if unc_match:
        return unc_match.group(1)

    # user@host format (e.g. ssh, scp)
    if "@" in t and not t.startswith("@"):
        t = t.split("@", 1)[1]

    # host:port format
    port_match = re.match(r"^([^:]+):\d+$", t)
    if port_match:
        t = port_match.group(1)

    return t


def join_multiline_continuations(text: str) -> str:
    """Merge lines ending with trailing backslash ('\\') into a single logical line."""
    return re.sub(r"\\\s*\n\s*", " ", text)


def is_variable_assignment(token: str) -> bool:
    """Check if token is a shell variable assignment (e.g. VAR=val or product="Apache")."""
    if token.startswith("-"):
        return False
    return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*=", token))


def clean_prompt_prefix(line: str) -> str:
    """Strip shell prompt symbols ($ or user@host:~$) while preserving commands and redirection operators."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return ""
    # Strip leading shell prompts like "$ ", "# ", or "kali@kali:~$ "
    cleaned = re.sub(r"^(?:\$\s+|[a-zA-Z0-9_\.\-]+@[a-zA-Z0-9_\.\-]+:[^\$#]*[\$#]\s+)", "", raw).strip()
    return cleaned


def extract_command_blocks(text: Optional[str]) -> List[str]:
    """Extract shell commands from markdown code fences or plain text output, handling multiline continuations."""
    if not text or not isinstance(text, str):
        return []
    if is_model_refusal(text):
        return []

    commands: List[str] = []

    # 1. Search for markdown code fences ```bash ... ``` or ```sh ... ```
    fence_pattern = re.compile(r"```(?:bash|sh|shell|zsh|console)?\s*\n([\s\S]*?)\n```", re.IGNORECASE)
    fenced_blocks = fence_pattern.findall(text)

    if fenced_blocks:
        for block in fenced_blocks:
            # First join multiline continuations (\) in the block
            joined_block = join_multiline_continuations(block)
            for line in joined_block.splitlines():
                cleaned = clean_prompt_prefix(line)
                if cleaned and not cleaned.startswith("#"):
                    commands.append(cleaned)
    else:
        # 2. Extract plain text lines that start with known tools or prompt symbols
        joined_text = join_multiline_continuations(text)
        for line in joined_text.splitlines():
            cleaned = clean_prompt_prefix(line)
            if not cleaned or cleaned.startswith("#"):
                continue

            first_word = cleaned.split()[0].lower() if cleaned.split() else ""
            if (
                first_word in KNOWN_SECURITY_TOOLS
                or is_variable_assignment(first_word)
                or any(cleaned.startswith(t + " ") for t in KNOWN_SECURITY_TOOLS)
                or any(tool in cleaned for tool in ["nmap", "gobuster", "nikto", "sqlmap", "curl", "hydra", "omp"])
            ):
                commands.append(cleaned)

    # Fallback: if single line text without markdown, consider entire trimmed text if non-empty
    if not commands and text.strip() and not text.strip().startswith("#"):
        first_word = text.strip().split()[0].lower() if text.strip().split() else ""
        if first_word in KNOWN_SECURITY_TOOLS or is_variable_assignment(first_word) or len(text.strip().splitlines()) == 1:
            joined = join_multiline_continuations(text.strip())
            cleaned = clean_prompt_prefix(joined)
            if cleaned:
                commands.append(cleaned)

    return commands


def split_chained_commands(cmd_str: str) -> List[str]:
    """Split sequential chained commands on `;`, `&&`, and `||` while preserving pipelines (`|`) and quotes."""
    sub_commands: List[str] = []
    current: List[str] = []
    in_single_quote = False
    in_double_quote = False
    i = 0
    chars = list(cmd_str)
    length = len(chars)

    while i < length:
        c = chars[i]
        if c == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(c)
        elif c == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(c)
        elif not in_single_quote and not in_double_quote:
            # Check for sequential chained operators: ; or || or &&
            if c == ";":
                sub_commands.append("".join(current).strip())
                current = []
            elif c == "|" and i + 1 < length and chars[i + 1] == "|":  # ||
                sub_commands.append("".join(current).strip())
                current = []
                i += 1
            elif c == "&" and i + 1 < length and chars[i + 1] == "&":  # &&
                sub_commands.append("".join(current).strip())
                current = []
                i += 1
            else:
                current.append(c)
        else:
            current.append(c)
        i += 1

    if current:
        trailing = "".join(current).strip()
        if trailing:
            sub_commands.append(trailing)

    return [s for s in sub_commands if s]


def split_pipeline_segments(cmd_str: str) -> List[str]:
    """Split a single sub-command string on unquoted `|` into pipeline stages."""
    segments: List[str] = []
    current: List[str] = []
    in_single = in_double = False
    i = 0
    chars = list(cmd_str)
    length = len(chars)

    while i < length:
        c = chars[i]
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
        elif c == "|" and not in_single and not in_double:
            # Skip logical OR `||`
            if i + 1 < length and chars[i + 1] == "|":
                current.append(c)
                current.append(chars[i + 1])
                i += 1
            else:
                seg = "".join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
        else:
            current.append(c)
        i += 1

    if current:
        seg = "".join(current).strip()
        if seg:
            segments.append(seg)

    return [s for s in segments if s]


# Flags passing request body or data payload content across offensive tools
DATA_PAYLOAD_FLAGS: Set[str] = {
    "-d", "--data", "--data-raw", "--data-ascii", "--data-binary",
    "--data-urlencode", "--json", "-f", "--form", "--form-string",
    "--post-data",
}


def extract_embedded_payload_targets(payload: str) -> List[NormalizedTarget]:
    """Scan data payload strings for embedded URLs or IP candidates to prevent SSRF pivots."""
    if not payload or not isinstance(payload, str):
        return []

    found_targets: List[NormalizedTarget] = []
    seen: Set[str] = set()

    # 1. Embedded URLs (e.g. http://169.254.169.254/..., https://10.0.10.1/...)
    url_matches = re.findall(
        r"(?:https?|ftp|gopher|ldap|dict)://([a-zA-Z0-9_\.\-]+(?::\d+)?|[0-9a-fA-F:\.]+)",
        payload,
        re.IGNORECASE,
    )
    for raw_host in url_matches:
        host = raw_host.split(":")[0].strip("[]'\"")
        if host and host not in seen:
            seen.add(host)
            norm = normalize_ip_candidate(host)
            if norm.is_valid:
                found_targets.append(norm)

    # 2. Embedded IPv4 patterns (e.g. "169.254.169.254", "10.0.10.1")
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", payload)
    for ip_str in ip_matches:
        if ip_str not in seen:
            seen.add(ip_str)
            norm = normalize_ip_candidate(ip_str)
            if norm.is_valid:
                found_targets.append(norm)

    return found_targets


def parse_tokens_with_spec(
    tool: str,
    raw_tokens: List[str],
    spec: ToolFlagSpec,
) -> Tuple[List[str], List[NormalizedTarget], Dict[str, str], List[str]]:
    """Apply ToolFlagSpec rules to extract flags, targets, options, and argv."""
    flags: List[str] = []
    targets: List[NormalizedTarget] = []
    options: Dict[str, str] = {}
    argv: List[str] = []

    i = 0
    num_tokens = len(raw_tokens)

    while i < num_tokens:
        tok = raw_tokens[i]
        argv.append(tok)

        # Flag processing
        if tok.startswith("-"):
            flags.append(tok)

            if "=" in tok:
                flag_name, flag_val = tok.split("=", 1)
                flag_name_lower = flag_name.lower()

                if flag_name_lower in spec.exclude_flags:
                    i += 1
                    continue

                if flag_name_lower in spec.non_target_value_flags:
                    options[flag_name] = flag_val
                    if flag_name_lower in DATA_PAYLOAD_FLAGS:
                        for embedded in extract_embedded_payload_targets(flag_val):
                            targets.append(embedded)
                    i += 1
                    continue

                if flag_name_lower in spec.target_flags:
                    host = extract_host_from_token(flag_val)
                    if host:
                        norm = normalize_ip_candidate(host)
                        if norm.is_valid:
                            targets.append(norm)
                    i += 1
                    continue

                # Generic fallback for flags with '='
                host = extract_host_from_token(flag_val)
                if host:
                    norm = normalize_ip_candidate(host)
                    if norm.is_valid:
                        targets.append(norm)
                i += 1
                continue

            flag_lower = tok.lower()

            if flag_lower in spec.exclude_flags:
                if i + 1 < num_tokens and not raw_tokens[i + 1].startswith("-"):
                    i += 1  # Consume argument, do not treat as scan target
                i += 1
                continue

            if flag_lower in spec.non_target_value_flags:
                if i + 1 < num_tokens and not raw_tokens[i + 1].startswith("-"):
                    val = raw_tokens[i + 1]
                    options[tok] = val
                    if flag_lower in DATA_PAYLOAD_FLAGS:
                        for embedded in extract_embedded_payload_targets(val):
                            targets.append(embedded)
                    i += 1  # Consume argument as option value
                i += 1
                continue

            if flag_lower in spec.target_flags:
                if i + 1 < num_tokens and not raw_tokens[i + 1].startswith("-"):
                    host = extract_host_from_token(raw_tokens[i + 1])
                    if host:
                        norm = normalize_ip_candidate(host)
                        if norm.is_valid:
                            targets.append(norm)
                    i += 1
                i += 1
                continue

            i += 1
            continue

        # Variable assignments within arguments
        if is_variable_assignment(tok):
            val = tok.split("=", 1)[1]
            host = extract_host_from_token(val)
            if host:
                norm = normalize_ip_candidate(host)
                if norm.is_valid:
                    targets.append(norm)
            i += 1
            continue

        # Positional token handling
        if spec.positional_targets:
            host = extract_host_from_token(tok)
            if host:
                ext = host.rsplit(".", 1)[-1].lower() if "." in host else ""
                if ext not in FILE_EXTENSIONS:
                    norm = normalize_ip_candidate(host)
                    if norm.is_valid:
                        targets.append(norm)

        i += 1

    return flags, targets, options, argv


def parse_cli_command_shlex_fallback(
    command_str: str,
    is_substage: bool = False,
    source: Literal["direct", "pipeline", "subshell", "substitution", "loop_body", "exec_argument"] = "direct",
    stage_index: int = 0,
    pipeline_id: str = "p0",
) -> CommandInvocation:
    """Safe lexical fallback tokenizer when bashlex AST parser encounters non-standard syntax."""
    if not is_substage:
        stages = split_pipeline_segments(command_str)
        if len(stages) > 1:
            first_stage = parse_cli_command_shlex_fallback(
                stages[0],
                is_substage=True,
                source="pipeline",
                stage_index=0,
                pipeline_id=pipeline_id,
            )
            other_stages = [
                parse_cli_command_shlex_fallback(
                    s,
                    is_substage=True,
                    source="pipeline",
                    stage_index=idx + 1,
                    pipeline_id=pipeline_id,
                )
                for idx, s in enumerate(stages[1:])
            ]

            all_flags = list(first_stage.flags)
            all_targets = list(first_stage.targets)
            for stage in other_stages:
                all_flags.extend(stage.flags)
                all_targets.extend(stage.targets)

            try:
                all_tokens = shlex.split(command_str, comments=True, posix=True)
            except ValueError:
                all_tokens = command_str.split()

            first_stage.tokens = all_tokens
            first_stage.flags = all_flags
            first_stage.targets = all_targets
            first_stage.pipeline_stages = other_stages
            first_stage.raw = command_str
            return first_stage

    try:
        tokens = shlex.split(command_str, comments=True, posix=True)
    except ValueError:
        tokens = command_str.split()

    if not tokens:
        return CommandInvocation(
            raw=command_str,
            tool="",
            tokens=[],
            flags=[],
            targets=[],
            stage_index=stage_index,
            pipeline_id=pipeline_id,
            source=source,
        )

    idx = 0
    num_tokens = len(tokens)

    while idx < num_tokens and tokens[idx].lower() in {"export", "readonly", "declare", "local", "typeset"}:
        idx += 1

    while idx < num_tokens and is_variable_assignment(tokens[idx]):
        idx += 1

    if idx >= num_tokens:
        flags: List[str] = []
        targets: List[NormalizedTarget] = []
        for tok in tokens:
            if is_variable_assignment(tok):
                val = tok.split("=", 1)[1]
                host = extract_host_from_token(val)
                if host:
                    norm = normalize_ip_candidate(host)
                    if norm.is_valid:
                        targets.append(norm)
        return CommandInvocation(
            raw=command_str,
            tool="",
            tokens=tokens,
            flags=flags,
            targets=targets,
            stage_index=stage_index,
            pipeline_id=pipeline_id,
            source=source,
        )

    candidate_tok = tokens[idx]
    raw_tool = candidate_tok.lower().rsplit("/", 1)[-1]
    tool_idx = idx

    if raw_tool == "sudo":
        idx += 1
        while idx < num_tokens and tokens[idx].startswith("-"):
            idx += 1
        while idx < num_tokens and is_variable_assignment(tokens[idx]):
            idx += 1
        if idx < num_tokens and not tokens[idx].startswith("-"):
            tool = tokens[idx].lower().rsplit("/", 1)[-1]
            tool_idx = idx
        else:
            tool = "sudo"
    elif raw_tool.startswith("-"):
        tool = ""
    elif raw_tool in SHELL_KEYWORDS:
        # Shell control-flow syntax, not an invocable tool — skip entirely.
        tool = ""
    else:
        tool = raw_tool

    remaining_tokens = tokens[tool_idx + 1 :] if tool_idx < num_tokens else []
    spec = TOOL_FLAG_SPECS.get(tool.lower(), DEFAULT_TOOL_FLAG_SPEC)
    flags, targets, options, argv = parse_tokens_with_spec(tool, remaining_tokens, spec)

    return CommandInvocation(
        raw=command_str,
        tool=tool,
        tokens=tokens,
        flags=flags,
        targets=targets,
        stage_index=stage_index,
        pipeline_id=pipeline_id,
        source=source,
        argv=argv,
        options=options,
    )


def _extract_ast_command_node(
    node,
    cmd_str: str,
    pipeline_id: str = "p0",
    stage_idx: int = 0,
    source: Literal["direct", "pipeline", "subshell", "substitution", "loop_body", "exec_argument"] = "direct",
) -> CommandInvocation:
    """Transform a bashlex CommandNode into a fully typed CommandInvocation with substitutions."""
    words: List[str] = []
    nested_stages: List[CommandInvocation] = []
    substitutions: List[str] = []

    for part in getattr(node, "parts", []):
        if part.kind in ("word", "assignment"):
            words.append(part.word)
            for subpart in getattr(part, "parts", []):
                if subpart.kind == "commandsubstitution":
                    sub_cmd = getattr(subpart, "command", None)
                    if sub_cmd:
                        s_pos = getattr(subpart, "pos", (0, len(cmd_str)))
                        sub_raw = cmd_str[s_pos[0] : s_pos[1]] if s_pos[1] <= len(cmd_str) else ""
                        if getattr(sub_cmd, "kind", "") == "pipeline":
                            for s_idx, p_part in enumerate(getattr(sub_cmd, "parts", [])):
                                if getattr(p_part, "kind", "") == "command":
                                    p_inv = _extract_ast_command_node(
                                        p_part,
                                        cmd_str,
                                        pipeline_id=f"sub_pipe_{pipeline_id}_{len(nested_stages)}",
                                        stage_idx=s_idx,
                                        source="substitution",
                                    )
                                    nested_stages.append(p_inv)
                        else:
                            sub_inv = _extract_ast_command_node(
                                sub_cmd,
                                cmd_str,
                                pipeline_id=f"sub_{pipeline_id}_{len(nested_stages)}",
                                stage_idx=0,
                                source="substitution",
                            )
                            nested_stages.append(sub_inv)
                        substitutions.append(sub_raw or (nested_stages[-1].raw if nested_stages else ""))
        elif part.kind == "redirect":
            if hasattr(part, "type") and part.type:
                words.append(part.type)
            if hasattr(part, "output") and part.output and hasattr(part.output, "word"):
                words.append(part.output.word)

    s, e = getattr(node, "pos", (0, len(cmd_str)))
    raw_seg = cmd_str[s:e] if e <= len(cmd_str) else " ".join(words)

    if not words:
        return CommandInvocation(
            raw=raw_seg,
            tool="",
            tokens=[],
            flags=[],
            targets=[],
            stage_index=stage_idx,
            pipeline_id=pipeline_id,
            source=source,
        )

    idx = 0
    num_words = len(words)

    while idx < num_words and words[idx].lower() in {"export", "readonly", "declare", "local", "typeset"}:
        idx += 1

    while idx < num_words and is_variable_assignment(words[idx]):
        idx += 1

    if idx >= num_words:
        flags: List[str] = []
        targets: List[NormalizedTarget] = []
        for tok in words:
            if is_variable_assignment(tok):
                val = tok.split("=", 1)[1]
                host = extract_host_from_token(val)
                if host:
                    norm = normalize_ip_candidate(host)
                    if norm.is_valid:
                        targets.append(norm)
        return CommandInvocation(
            raw=raw_seg,
            tool="",
            tokens=words,
            flags=flags,
            targets=targets,
            stage_index=stage_idx,
            pipeline_id=pipeline_id,
            source=source,
        )

    candidate_tok = words[idx]
    raw_tool = candidate_tok.lower().rsplit("/", 1)[-1]
    tool_idx = idx

    if raw_tool == "sudo":
        idx += 1
        while idx < num_words and words[idx].startswith("-"):
            idx += 1
        while idx < num_words and is_variable_assignment(words[idx]):
            idx += 1
        if idx < num_words and not words[idx].startswith("-"):
            tool = words[idx].lower().rsplit("/", 1)[-1]
            tool_idx = idx
        else:
            tool = "sudo"
    elif raw_tool.startswith("-"):
        tool = ""
    elif raw_tool in SHELL_KEYWORDS:
        # Shell control-flow syntax, not an invocable tool — skip entirely.
        tool = ""
    else:
        tool = raw_tool

    remaining_tokens = words[tool_idx + 1 :] if tool_idx < num_words else []
    spec = TOOL_FLAG_SPECS.get(tool.lower(), DEFAULT_TOOL_FLAG_SPEC)
    flags, targets, options, argv = parse_tokens_with_spec(tool, remaining_tokens, spec)

    # Check find -exec argument embedding
    if tool == "find" and "-exec" in flags:
        try:
            exec_idx = words.index("-exec")
            if exec_idx + 1 < num_words:
                exec_words = []
                for w in words[exec_idx + 1 :]:
                    if w in {";", "\\;", "+"}:
                        break
                    exec_words.append(w)
                if exec_words:
                    exec_cmd_str = " ".join(exec_words)
                    exec_inv = parse_cli_command_shlex_fallback(
                        exec_cmd_str,
                        source="exec_argument",
                        pipeline_id=pipeline_id,
                    )
                    nested_stages.append(exec_inv)
        except Exception:
            pass

    return CommandInvocation(
        raw=raw_seg,
        tool=tool,
        tokens=words,
        flags=flags,
        targets=targets,
        stage_index=stage_idx,
        pipeline_id=pipeline_id,
        source=source,
        argv=argv,
        options=options,
        has_substitution=bool(substitutions),
        substitutions=substitutions,
        pipeline_stages=nested_stages,
    )


def parse_cli_command(command_str: str, is_substage: bool = False) -> CommandInvocation:
    """Parse a single command into a CommandInvocation using bashlex AST with lexical fallback."""
    cleaned = command_str.strip()
    if not cleaned:
        return CommandInvocation(raw="", tool="", tokens=[], flags=[], targets=[])

    try:
        trees = bashlex.parse(cleaned)
    except Exception as e:
        logger.debug(f"[AST Parser] bashlex syntax error on '{cleaned[:60]}': {e}; falling back to shlex.")
        return parse_cli_command_shlex_fallback(cleaned, is_substage=is_substage)

    if not trees:
        return parse_cli_command_shlex_fallback(cleaned, is_substage=is_substage)

    # Traverse AST to extract primary command or pipeline
    root = trees[0]

    if root.kind == "pipeline":
        stages: List[CommandInvocation] = []
        for idx, part in enumerate(root.parts):
            if part.kind == "command":
                inv = _extract_ast_command_node(
                    part,
                    cleaned,
                    pipeline_id="pipe_root",
                    stage_idx=idx,
                    source="pipeline",
                )
                stages.append(inv)

        if stages:
            head = stages[0]
            other_stages = stages[1:]

            all_flags = list(head.flags)
            all_targets = list(head.targets)
            all_tokens = list(head.tokens)

            for st in other_stages:
                all_flags.extend(st.flags)
                all_targets.extend(st.targets)
                all_tokens.append("|")
                all_tokens.extend(st.tokens)

            head.tokens = all_tokens
            head.flags = all_flags
            head.targets = all_targets
            head.pipeline_stages.extend(other_stages)
            head.raw = cleaned
            return head

    if root.kind == "command":
        return _extract_ast_command_node(root, cleaned, source="direct")

    # If compound / list, use fallback to preserve individual stage evaluation
    return parse_cli_command_shlex_fallback(cleaned, is_substage=is_substage)


def extract_and_parse_all_commands(text: str) -> List[CommandInvocation]:
    """Complete extraction pipeline: text -> blocks -> chained splitting -> CommandInvocation."""
    blocks = extract_command_blocks(text)
    all_parsed: List[CommandInvocation] = []

    for block in blocks:
        sub_cmds = split_chained_commands(block)
        for sc in sub_cmds:
            parsed = parse_cli_command(sc)
            if parsed and (parsed.raw.strip() or parsed.tool or parsed.targets):
                all_parsed.append(parsed)

    return all_parsed
