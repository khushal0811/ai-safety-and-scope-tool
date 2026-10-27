"""IP address normalization and Scope/CIDR validation engine.

Strict Zero Host Execution: All checks perform pure static math and AST
inspection using Python's standard library `ipaddress` module.
"""

from dataclasses import dataclass
import ipaddress
import re
from typing import List, Optional, Tuple
from app.models.audit import TargetFinding, TargetKind, TargetStatus
from app.models.roe import RoeScope

# Hardcoded absolute prohibitions enforced across all engagements
HARD_PROHIBITED_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),  # Cloud Instance Metadata (AWS/GCP/Azure)
    ipaddress.ip_network("169.254.0.0/16"),      # IPv4 Link-Local / APIPA
    ipaddress.ip_network("0.0.0.0/32"),          # Unspecified / Default route target
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved / Class E
]

# Standard public DNS servers frequently targeted by hallucinating models
PUBLIC_DNS_SERVERS = {
    ipaddress.ip_address("8.8.8.8"),
    ipaddress.ip_address("8.8.4.4"),
    ipaddress.ip_address("1.1.1.1"),
    ipaddress.ip_address("1.0.0.1"),
    ipaddress.ip_address("9.9.9.9"),
}

LOOPBACK_NET_V4 = ipaddress.ip_network("127.0.0.0/8")
LOOPBACK_NET_V6 = ipaddress.ip_network("::1/128")


@dataclass
class NormalizedTarget:
    """Result of normalizing an extracted host or IP string."""

    raw_token: str
    canonical: str
    kind: TargetKind
    is_valid: bool
    is_obfuscated: bool
    format_type: str
    ip_obj: Optional[ipaddress._BaseAddress] = None
    net_obj: Optional[ipaddress._BaseNetwork] = None


def parse_octal_or_hex_part(part: str) -> Optional[int]:
    """Parse a single byte/part allowing hex (0x..), octal (0..), or decimal."""
    try:
        p = part.strip()
        if not p:
            return None
        if p.lower().startswith("0x"):
            val = int(p, 16)
        elif p.startswith("0") and len(p) > 1 and all(c in "01234567" for c in p):
            val = int(p, 8)
        else:
            val = int(p, 10)
        return val
    except ValueError:
        return None


def normalize_ip_candidate(token: str) -> NormalizedTarget:
    """Normalize any IPv4, IPv6, Hex, Octal, Decimal, or Mapped notation.

    Returns canonical string representation and obfuscation detection flag.
    """
    clean = token.strip().strip("[]\"'")

    # Check for CIDR notation first (e.g. 192.168.1.0/24)
    if "/" in clean:
        try:
            net = ipaddress.ip_network(clean, strict=False)
            is_obf = str(net) != clean
            return NormalizedTarget(
                raw_token=token,
                canonical=str(net),
                kind=TargetKind.CIDR,
                is_valid=True,
                is_obfuscated=is_obf,
                format_type="cidr",
                net_obj=net,
            )
        except ValueError:
            pass

    # IPv6-mapped IPv4 e.g. ::ffff:192.168.1.1 or ::ffff:7f00:1
    if "::ffff:" in clean.lower():
        try:
            v6 = ipaddress.ip_address(clean)
            if isinstance(v6, ipaddress.IPv6Address) and v6.ipv4_mapped:
                v4_str = str(v6.ipv4_mapped)
                return NormalizedTarget(
                    raw_token=token,
                    canonical=v4_str,
                    kind=TargetKind.IP,
                    is_valid=True,
                    is_obfuscated=True,
                    format_type="ipv6_mapped_ipv4",
                    ip_obj=v6.ipv4_mapped,
                )
        except ValueError:
            pass

    # Standard IPv6 (e.g. ::1 or 2001:db8::1)
    if ":" in clean:
        try:
            v6 = ipaddress.ip_address(clean)
            return NormalizedTarget(
                raw_token=token,
                canonical=str(v6),
                kind=TargetKind.IP,
                is_valid=True,
                is_obfuscated=False,
                format_type="ipv6",
                ip_obj=v6,
            )
        except ValueError:
            pass

    # Single integer (Decimal dword like 2130706433 or Hex dword 0x7f000001)
    if re.match(r"^0x[0-9a-fA-F]{1,8}$", clean):
        try:
            dword = int(clean, 16)
            if 0 <= dword <= 0xFFFFFFFF:
                v4 = ipaddress.IPv4Address(dword)
                return NormalizedTarget(
                    raw_token=token,
                    canonical=str(v4),
                    kind=TargetKind.IP,
                    is_valid=True,
                    is_obfuscated=True,
                    format_type="hex_dword",
                    ip_obj=v4,
                )
        except ValueError:
            pass

    # Pure decimal integer (e.g. 2130706433 or 3232235777)
    if clean.isdigit() and len(clean) >= 8:
        try:
            dword = int(clean, 10)
            if 0 <= dword <= 0xFFFFFFFF:
                v4 = ipaddress.IPv4Address(dword)
                return NormalizedTarget(
                    raw_token=token,
                    canonical=str(v4),
                    kind=TargetKind.IP,
                    is_valid=True,
                    is_obfuscated=True,
                    format_type="decimal_dword",
                    ip_obj=v4,
                )
        except ValueError:
            pass

    # Dotted notation: allows mixed octal (0177.0.0.1), hex (0x7f.0.0.1), or decimal
    if "." in clean:
        parts = clean.split(".")
        if 2 <= len(parts) <= 4:
            parsed_parts = [parse_octal_or_hex_part(p) for p in parts]
            if all(p is not None for p in parsed_parts):
                is_obf = False
                for raw_part in parts:
                    if raw_part.lower().startswith("0x"):
                        is_obf = True
                    elif raw_part.startswith("0") and len(raw_part) > 1 and raw_part != "0":
                        is_obf = True

                # Assemble according to standard BSD inet_aton logic
                try:
                    if len(parts) == 4:
                        if all(0 <= p <= 255 for p in parsed_parts):
                            dword = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | (parsed_parts[2] << 8) | parsed_parts[3]
                            v4 = ipaddress.IPv4Address(dword)
                            return NormalizedTarget(
                                raw_token=token,
                                canonical=str(v4),
                                kind=TargetKind.IP,
                                is_valid=True,
                                is_obfuscated=is_obf or str(v4) != clean,
                                format_type="dotted_hex_or_octal" if is_obf else "dot_decimal",
                                ip_obj=v4,
                            )
                    elif len(parts) == 3:  # a.b.c -> a.b as 8-bit, c as 16-bit
                        if 0 <= parsed_parts[0] <= 255 and 0 <= parsed_parts[1] <= 255 and 0 <= parsed_parts[2] <= 0xFFFF:
                            dword = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | parsed_parts[2]
                            v4 = ipaddress.IPv4Address(dword)
                            return NormalizedTarget(
                                raw_token=token,
                                canonical=str(v4),
                                kind=TargetKind.IP,
                                is_valid=True,
                                is_obfuscated=True,
                                format_type="three_part_ip",
                                ip_obj=v4,
                            )
                    elif len(parts) == 2:  # a.b -> a as 8-bit, b as 24-bit
                        if 0 <= parsed_parts[0] <= 255 and 0 <= parsed_parts[1] <= 0xFFFFFF:
                            dword = (parsed_parts[0] << 24) | parsed_parts[1]
                            v4 = ipaddress.IPv4Address(dword)
                            return NormalizedTarget(
                                raw_token=token,
                                canonical=str(v4),
                                kind=TargetKind.IP,
                                is_valid=True,
                                is_obfuscated=True,
                                format_type="two_part_ip",
                                ip_obj=v4,
                            )
                except ValueError:
                    pass

    # Domain name candidate
    domain_re = r"^(?=.{4,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    if re.match(domain_re, clean):
        return NormalizedTarget(
            raw_token=token,
            canonical=clean.lower(),
            kind=TargetKind.DOMAIN,
            is_valid=True,
            is_obfuscated=False,
            format_type="domain",
        )

    return NormalizedTarget(
        raw_token=token,
        canonical=token,
        kind=TargetKind.IP,
        is_valid=False,
        is_obfuscated=False,
        format_type="unknown",
    )


class ScopeValidator:
    """Evaluates normalized targets against active RoE constraints."""

    def __init__(self, roe: RoeScope):
        self.roe = roe
        self.allowed_networks: List[ipaddress._BaseNetwork] = []
        for c in roe.allowed_cidrs:
            try:
                self.allowed_networks.append(ipaddress.ip_network(c.strip(), strict=False))
            except ValueError:
                pass

        self.prohibited_networks: List[ipaddress._BaseNetwork] = []
        for p in roe.prohibited_ips:
            try:
                p_clean = p.strip()
                if "/" in p_clean:
                    self.prohibited_networks.append(ipaddress.ip_network(p_clean, strict=False))
                else:
                    self.prohibited_networks.append(ipaddress.ip_network(f"{p_clean}/32", strict=False))
            except ValueError:
                pass

        # Determine if loopback is intentionally authorized in allowed_cidrs
        self.allows_loopback = any(
            (isinstance(n, ipaddress.IPv4Network) and n.overlaps(LOOPBACK_NET_V4))
            or (isinstance(n, ipaddress.IPv6Network) and n.overlaps(LOOPBACK_NET_V6))
            for n in self.allowed_networks
        )

    def is_gateway(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if an IP is the default gateway (.1) of any allowed subnet."""
        for net in self.allowed_networks:
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
                if ip == net.network_address + 1:
                    return True
        return False

    def is_broadcast(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if an IP is the subnet broadcast address of any allowed network."""
        for net in self.allowed_networks:
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
                if ip == net.broadcast_address:
                    return True
        return False

    def classify_target(self, target: NormalizedTarget) -> TargetFinding:
        """Classify a normalized target candidate against RoE rules."""
        if not target.is_valid:
            return TargetFinding(
                token=target.raw_token,
                normalized=target.canonical,
                kind=target.kind,
                status=TargetStatus.OUT_OF_SCOPE,
                obfuscated=target.is_obfuscated,
            )

        # Domain classification
        if target.kind == TargetKind.DOMAIN:
            domain = target.canonical.lower()
            in_scope = False
            for allowed in self.roe.allowed_domains:
                allowed_clean = allowed.lower().strip()
                if domain == allowed_clean or domain.endswith(f".{allowed_clean}"):
                    in_scope = True
                    break

            status = TargetStatus.IN_SCOPE if in_scope else TargetStatus.OUT_OF_SCOPE
            return TargetFinding(
                token=target.raw_token,
                normalized=domain,
                kind=TargetKind.DOMAIN,
                status=status,
                obfuscated=False,
            )

        # CIDR classification
        if target.kind == TargetKind.CIDR and target.net_obj:
            net = target.net_obj
            # Check hard prohibitions
            for hard_net in HARD_PROHIBITED_NETWORKS:
                if net.overlaps(hard_net):
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.CIDR,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # Check loopback
            if (isinstance(net, ipaddress.IPv4Network) and net.overlaps(LOOPBACK_NET_V4)) or (
                isinstance(net, ipaddress.IPv6Network) and net.overlaps(LOOPBACK_NET_V6)
            ):
                if not self.allows_loopback:
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.CIDR,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # Check RoE explicit prohibited IPs/subnets
            for p_net in self.prohibited_networks:
                if net.overlaps(p_net):
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.CIDR,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # Check if contained in any allowed subnet
            in_scope = any(net.subnet_of(a_net) for a_net in self.allowed_networks)
            return TargetFinding(
                token=target.raw_token,
                normalized=target.canonical,
                kind=TargetKind.CIDR,
                status=TargetStatus.IN_SCOPE if in_scope else TargetStatus.OUT_OF_SCOPE,
                obfuscated=target.is_obfuscated,
            )

        # Single IP classification
        if target.kind == TargetKind.IP and target.ip_obj:
            ip = target.ip_obj

            # 1. Hard Prohibited networks (Cloud Metadata, Link-Local, Multicast, Reserved)
            for hard_net in HARD_PROHIBITED_NETWORKS:
                if ip in hard_net:
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.IP,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # 2. Public DNS servers (e.g. 8.8.8.8) unless explicitly whitelisted in target_hosts or allowed_cidrs
            is_explicit_host = any(str(ip) == t.strip() for t in self.roe.target_hosts)
            if ip in PUBLIC_DNS_SERVERS and not is_explicit_host:
                return TargetFinding(
                    token=target.raw_token,
                    normalized=target.canonical,
                    kind=TargetKind.IP,
                    status=TargetStatus.PROHIBITED,
                    obfuscated=target.is_obfuscated,
                )

            # 3. Loopback
            if (isinstance(ip, ipaddress.IPv4Address) and ip in LOOPBACK_NET_V4) or (
                isinstance(ip, ipaddress.IPv6Address) and ip in LOOPBACK_NET_V6
            ):
                if not self.allows_loopback:
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.IP,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # 4. RoE Explicit Prohibited IPs
            for p_net in self.prohibited_networks:
                if ip in p_net:
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.IP,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # 5. Gateway (.1) and Broadcast (.255) checks for IPv4
            if isinstance(ip, ipaddress.IPv4Address):
                if self.is_gateway(ip) and not is_explicit_host:
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.IP,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )
                if self.is_broadcast(ip):
                    return TargetFinding(
                        token=target.raw_token,
                        normalized=target.canonical,
                        kind=TargetKind.IP,
                        status=TargetStatus.PROHIBITED,
                        obfuscated=target.is_obfuscated,
                    )

            # 6. Check Allowed Subnets & Target Hosts
            in_scope = is_explicit_host or any(ip in a_net for a_net in self.allowed_networks)
            return TargetFinding(
                token=target.raw_token,
                normalized=target.canonical,
                kind=TargetKind.IP,
                status=TargetStatus.IN_SCOPE if in_scope else TargetStatus.OUT_OF_SCOPE,
                obfuscated=target.is_obfuscated,
            )

        return TargetFinding(
            token=target.raw_token,
            normalized=target.canonical,
            kind=TargetKind.IP,
            status=TargetStatus.OUT_OF_SCOPE,
            obfuscated=target.is_obfuscated,
        )
