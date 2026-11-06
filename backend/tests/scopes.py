"""Test-only scope fixtures.

The product no longer ships pre-built presets; scope definitions are custom
(text or uploaded document). Unit tests still need stable scopes, so the five
former preset definitions are kept here, in the test package only.
"""

from typing import Dict, List, Optional

from app.models.roe import RoeScope


TEST_SCOPES: List[RoeScope] = [
    RoeScope(
        roe_id="ROE-PRESET-NET-001",
        name="Internal Network Recon",
        engagement_type="Network Penetration Test",
        summary="Single internal /24. Gateway, broadcast and cloud metadata are off-limits. No DoS or ARP spoofing.",
        allowed_cidrs=["192.168.1.0/24"],
        allowed_domains=[],
        target_hosts=["192.168.1.105"],
        prohibited_ips=["192.168.1.1", "192.168.1.255", "169.254.169.254", "8.8.8.8"],
        allowed_tools=["nmap", "gobuster", "nikto", "smbclient", "enum4linux", "rpcclient", "curl", "whatweb"],
        prohibited_tools=["hping3", "loic", "arpspoof", "ettercap", "bettercap", "slowloris"],
        prohibited_flags=["--flood"],
        prohibited_actions=["denial_of_service", "arp_spoofing", "password_spraying"],
        max_nmap_timing=3,
    ),
    RoeScope(
        roe_id="ROE-PRESET-WEB-002",
        name="Web Application Pentest",
        engagement_type="Web Application Assessment",
        summary="One staging web host only. No destructive SQL, no OS shells, no brute force that could lock accounts.",
        allowed_cidrs=["10.10.20.15/32"],
        allowed_domains=["staging.acme-target.internal"],
        target_hosts=["10.10.20.15"],
        prohibited_ips=["10.10.20.1", "169.254.169.254"],
        allowed_tools=["nmap", "nikto", "gobuster", "ffuf", "sqlmap", "curl", "whatweb", "wpscan"],
        prohibited_tools=["hydra", "medusa", "patator"],
        prohibited_flags=["--os-shell", "--os-pwn", "--sql-shell", "--file-write"],
        prohibited_actions=["destructive_sql", "account_lockout", "remote_code_execution"],
        max_nmap_timing=3,
    ),
    RoeScope(
        roe_id="ROE-PRESET-AD-003",
        name="Active Directory Audit",
        engagement_type="Internal AD Assessment",
        summary="Staging domain controller subnet in scope. Production servers excluded. No persistence or password resets.",
        allowed_cidrs=["10.0.50.0/24"],
        allowed_domains=["staging.corp.local"],
        target_hosts=["10.0.50.10"],
        prohibited_ips=["10.0.10.0/24", "10.0.50.1", "169.254.169.254"],
        allowed_tools=["nmap", "ldapsearch", "bloodhound-python", "netexec", "crackmapexec", "kerbrute", "getuserspns", "smbclient", "enum4linux"],
        prohibited_tools=["ticketer", "mimikatz", "responder"],
        prohibited_flags=["kerberos::golden", "--reset-password", "lsadump::dcsync"],
        prohibited_actions=["golden_ticket", "domain_password_reset", "production_access"],
        max_nmap_timing=3,
    ),
    RoeScope(
        roe_id="ROE-PRESET-CLOUD-004",
        name="Cloud Environment (AWS/GCP)",
        engagement_type="Cloud Security Review",
        summary="Assigned staging elastic IPs only. Instance metadata service, IAM changes and bucket deletion are banned.",
        allowed_cidrs=["203.0.113.0/28"],
        allowed_domains=[],
        target_hosts=["203.0.113.10"],
        prohibited_ips=["169.254.169.254", "203.0.113.1"],
        allowed_tools=["nmap", "aws", "gcloud", "scoutsuite", "prowler", "curl", "nikto"],
        prohibited_tools=["pacu"],
        prohibited_flags=["attach-role-policy", "put-user-policy", "s3 rb", "s3 rm", "delete-bucket", "create-access-key"],
        prohibited_actions=["cloud_metadata_access", "iam_modification", "bucket_deletion"],
        max_nmap_timing=3,
    ),
    RoeScope(
        roe_id="ROE-PRESET-EXT-005",
        name="External Perimeter Recon",
        engagement_type="External Reconnaissance",
        summary="Passive OSINT, non-intrusive port discovery and targeted HTTP endpoint checks only. No exploitation, fuzzing or vulnerability scripts.",
        allowed_cidrs=["198.51.100.0/24"],
        allowed_domains=["example-corp.com"],
        target_hosts=["198.51.100.20"],
        prohibited_ips=["169.254.169.254", "198.51.100.1"],
        allowed_tools=["nmap", "amass", "subfinder", "dig", "whois", "dnsrecon", "theharvester", "host", "curl"],
        prohibited_tools=["sqlmap", "msfconsole", "hydra", "ffuf", "gobuster", "nikto", "wpscan"],
        prohibited_flags=["--script vuln", "--script=vuln", "--script exploit"],
        prohibited_actions=["active_exploitation", "web_fuzzing", "vulnerability_exploitation"],
        max_nmap_timing=3,
    ),
]

TEST_SCOPES_BY_ID: Dict[str, RoeScope] = {scope.roe_id: scope for scope in TEST_SCOPES}


def get_test_scope(identifier: Optional[str]) -> Optional[RoeScope]:
    """Resolve a test scope by exact id or a short alias."""
    if not identifier:
        return None
    key = str(identifier).strip().upper()
    if key in TEST_SCOPES_BY_ID:
        return TEST_SCOPES_BY_ID[key]
    for scope in TEST_SCOPES:
        if scope.roe_id.upper().endswith(key) or scope.name.upper().startswith(key):
            return scope
    return None
