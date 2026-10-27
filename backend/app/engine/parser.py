"""Shell command extractor, tokenizer, and target candidate parser.

Strict Zero Host Execution: commands are never executed or evaluated.
Parsing utilizes `shlex` and lexical analysis to extract tools, flags,
and target operands safely.
"""

from dataclasses import dataclass, field
import re
import shlex
from typing import List, Optional, Set
from app.engine.ip_validator import normalize_ip_candidate, NormalizedTarget

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

# Target-specifying flag indicators
TARGET_FLAGS: Set[str] = {
    "-u", "--url", "-t", "-target", "--target", "-h", "--host", "-H",
    "-d", "--domain", "-L", "-l", "--server", "-s",
}

# Typical file extensions to avoid classifying dictionary files as domains
FILE_EXTENSIONS: Set[str] = {
    "txt", "php", "py", "lst", "html", "htm", "xml", "json", "sh", "conf",
    "log", "nse", "rb", "js", "aspx", "jsp", "csv", "md", "wordlist", "dict",
}


@dataclass
class ParsedCommand:
    """Structured representation of an extracted CLI command."""

    raw: str
    tool: str
    tokens: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    targets: List[NormalizedTarget] = field(default_factory=list)


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


def extract_command_blocks(text: str) -> List[str]:
    """Extract shell commands from markdown code fences or plain text output."""
    commands: List[str] = []

    # 1. Search for markdown code fences ```bash ... ``` or ```sh ... ```
    fence_pattern = re.compile(r"```(?:bash|sh|shell|zsh|console)?\s*\n([\s\S]*?)\n```", re.IGNORECASE)
    fenced_blocks = fence_pattern.findall(text)

    if fenced_blocks:
        for block in fenced_blocks:
            for line in block.splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                # Strip leading prompt symbols ($ >) but preserve commands
                cleaned = re.sub(r"^[\$>\s]+", "", raw).strip()
                if cleaned and not cleaned.startswith("#"):
                    commands.append(cleaned)
    else:
        # 2. Extract plain text lines that start with known tools or prompt symbols
        for line in text.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            cleaned = re.sub(r"^[\$>\s]+", "", raw).strip()
            if not cleaned or cleaned.startswith("#"):
                continue

            first_word = cleaned.split()[0].lower() if cleaned.split() else ""
            if first_word in KNOWN_SECURITY_TOOLS or any(cleaned.startswith(t + " ") for t in KNOWN_SECURITY_TOOLS):
                commands.append(cleaned)
            elif any(tool in cleaned for tool in ["nmap", "gobuster", "nikto", "sqlmap", "curl", "hydra"]):
                commands.append(cleaned)

    # Fallback: if single line text without markdown, consider entire trimmed text if non-empty
    if not commands and text.strip() and not text.strip().startswith("#"):
        first_word = text.strip().split()[0].lower() if text.strip().split() else ""
        if first_word in KNOWN_SECURITY_TOOLS or len(text.strip().splitlines()) == 1:
            commands.append(text.strip())

    return commands


def split_chained_commands(cmd_str: str) -> List[str]:
    """Split chained commands on `;`, `&&`, `||`, and `|` while respecting quotes."""
    # Custom stateful splitter that ignores operators inside quotes
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
            # Check for chained operators
            if c == ";" or c == "|":
                if i + 1 < length and chars[i + 1] == "|":  # ||
                    sub_commands.append("".join(current).strip())
                    current = []
                    i += 1
                elif c == ";":
                    sub_commands.append("".join(current).strip())
                    current = []
                elif c == "|":
                    sub_commands.append("".join(current).strip())
                    current = []
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


def parse_cli_command(command_str: str) -> ParsedCommand:
    """Parse a single command into tool, tokens, flags, and targets."""
    # Tokenize using shlex safely
    try:
        tokens = shlex.split(command_str, comments=True, posix=True)
    except ValueError:
        # Fallback to regex splitting if quotes are unclosed
        tokens = command_str.split()

    if not tokens:
        return ParsedCommand(raw=command_str, tool="", tokens=[], flags=[], targets=[])

    tool = tokens[0].lower().rsplit("/", 1)[-1]  # Strip path if /usr/bin/nmap
    flags: List[str] = []
    targets: List[NormalizedTarget] = []

    i = 0
    num_tokens = len(tokens)
    while i < num_tokens:
        tok = tokens[i]

        # Collect flags
        if tok.startswith("-"):
            flags.append(tok)
            # Check if this flag takes an argument e.g. -u http://target.com or --url=http://target.com
            if "=" in tok:
                flag_name, flag_val = tok.split("=", 1)
                host = extract_host_from_token(flag_val)
                if host:
                    norm = normalize_ip_candidate(host)
                    if norm.is_valid:
                        targets.append(norm)
            elif tok in TARGET_FLAGS and i + 1 < num_tokens:
                next_tok = tokens[i + 1]
                host = extract_host_from_token(next_tok)
                if host:
                    norm = normalize_ip_candidate(host)
                    if norm.is_valid:
                        targets.append(norm)
                i += 1
            i += 1
            continue

        # Positional token: check if it's a target IP, CIDR, or domain
        host = extract_host_from_token(tok)
        if host and i > 0:  # Skip the tool name itself
            # Check if this is a file with known extension (e.g. wordlist.txt)
            ext = host.rsplit(".", 1)[-1].lower() if "." in host else ""
            if ext not in FILE_EXTENSIONS:
                norm = normalize_ip_candidate(host)
                if norm.is_valid:
                    targets.append(norm)

        i += 1

    return ParsedCommand(
        raw=command_str,
        tool=tool,
        tokens=tokens,
        flags=flags,
        targets=targets,
    )


def extract_and_parse_all_commands(text: str) -> List[ParsedCommand]:
    """Complete extraction pipeline: text -> blocks -> chained splitting -> ParsedCommand."""
    blocks = extract_command_blocks(text)
    all_parsed: List[ParsedCommand] = []

    for block in blocks:
        sub_cmds = split_chained_commands(block)
        for sc in sub_cmds:
            parsed = parse_cli_command(sc)
            if parsed.tool:
                all_parsed.append(parsed)

    return all_parsed
