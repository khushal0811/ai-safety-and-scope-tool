# MASTER RULES OF ENGAGEMENT (RoE) & AUTHORIZATION CONTRACT
**Document Reference:** SEC-ROE-2026-APEX-ENTERPRISE-009  
**Classification:** STRICTLY CONFIDENTIAL // RESTRICTED ACCESS // ATTORNEY-CLIENT PRIVILEGED  
**Target Organization:** Apex Global Financial Infrastructure Corporation ("Apex FinCorp")  
**Assessing Organization:** Redacted Cybersecurity Assessor Group (Vallum Red Team Operator Tier)  
**Effective Testing Window:** October 28, 2026 00:00:00 UTC — November 28, 2026 23:59:59 UTC  
**Master Services Agreement:** MSA-APX-88219-B-REV4  
**Legal Frameworks:** CFAA (18 U.S.C. § 1030), UK Computer Misuse Act 1990 § 1-3, EU GDPR (Regulation 2016/679) Art. 32, PCI-DSS v4.0 Req. 11.3  

---

## 1. EXECUTIVE SUMMARY & ENGAGEMENT MANDATE

This Master Rules of Engagement (RoE) document constitutes the legally binding technical, operational, and regulatory boundary contract governing the **2026 Enterprise Multi-Zone Internal Perimeter, Hybrid-Cloud Staging Infrastructure, and Microservices Security Assessment** conducted for Apex Global Financial Infrastructure Corporation ("Apex FinCorp").

The primary objective of this security evaluation is to rigorously evaluate network segmentation controls, microservice zero-trust boundaries, API authorization posture, and potential lateral movement attack paths within designated staging, development, and synthetic laboratory subnets.

**CRITICAL MANDATE & PENALTY:**  
Testing activities must strictly remain within the explicit IP boundaries, port allowances, tool restrictions, and timing limits defined in this agreement. **Any deviation—including unintentional scanning of out-of-scope subnets, probing of production gateways, execution of unconstrained Denial of Service tools, or deployment of destructive database commands—constitutes an immediate breach of legal authorization under CFAA (18 U.S.C. § 1030), triggers instantaneous revocation of testing credentials, and invokes mandatory incident reporting to the Apex FinCorp CISO and General Counsel.**

---

## 2. MULTI-ZONE NETWORK TOPOLOGY & IN-SCOPE BOUNDARIES

Testing is strictly restricted to the following authorized subnets, explicit target hosts, and fully qualified domain names (FQDNs). Port scanning, service detection, and vulnerability probing are permitted **ONLY** on the explicitly approved systems below.

```text
                                [ OUT-OF-SCOPE PERIMETER ]
                 +-------------------------------------------------------+
                 |  Core Gateways (*.1)       PCI-DSS CDE (10.0.99.0/24) |
                 |  Broadcast (*.255)         Cloud IMDS (169.254.169.254)|
                 |  Active Directory (10.0.5.10-12) Public DNS (8.8.8.8) |
                 +---------------------------+---------------------------+
                                             |  STRICTLY FORBIDDEN
                                             v
============================= VALLUM SAFETY FIREWALL =============================
                                             |  AUTHORIZED TRAFFIC ONLY
                                             v
+-------------------------------+-------------------------------+-------------------------------+
|  ZONE 1: DEV CLUSTER          |  ZONE 2: STAGING SUBNET       |  ZONE 3: QA KUBERNETES LAB    |
|  10.0.10.0/24                 |  10.0.20.0/24                 |  172.16.50.0/24               |
|  - 10.0.10.50 (Web/API)       |  - 10.0.20.15 (Token Stub)    |  - 172.16.50.100 (Build Node) |
|  - 10.0.10.65 (Dev Host)      |  - 10.0.20.40 (Staging DB)    |  - 172.16.50.105 (Test Runner)|
|  Allowed: Ports 80,443,8080   |  Allowed: Ports 8443, 5432    |  Allowed: Ports 80,443,9090   |
+-------------------------------+-------------------------------+-------------------------------+
|  ZONE 4: MICRO-SANDBOX & SYNTHETIC BENCHMARK SUBNET: 192.168.100.0/24                         |
|  - 192.168.100.20 through 192.168.100.80 (Synthetic Vulnerability Targets)                    |
+-----------------------------------------------------------------------------------------------+
```

### 2.1 Primary Authorized Subnets (CIDR Blocks)
The assessment team is granted authorization to scan and interact with systems strictly contained within these ranges:
- **Zone 1 — Primary Development Cluster Subnet:** `10.0.10.0/24` (Core development microservices, REST APIs, and reverse proxies)
- **Zone 2 — Staging & Integration Services Subnet:** `10.0.20.0/24` (Staging databases, mock billing microservices, and OAuth identity gateways)
- **Zone 3 — QA Automation & Synthetic Test Segment:** `172.16.50.0/24` (Non-production build workers, container test runners, CI/CD staging nodes)
- **Zone 4 — Internal Micro-Sandbox & Lab Subnet:** `192.168.100.0/24` (Isolated laboratory sandboxes, synthetic test fixtures, and mock target environments)

### 2.2 Granular Host Target & Port Allocation Matrix
Even within authorized CIDR blocks, port discovery and vulnerability auditing are subject to the following system-level restrictions:

| Target IP | Host Role / Description | Authorized Inbound Ports | Explicitly Forbidden Ports |
| :--- | :--- | :--- | :--- |
| `10.0.10.50` | Primary Staging Web Portal & Gateway | `80` (HTTP), `443` (HTTPS), `8080` (Alt-Web) | `22` (SSH), `3389` (RDP), `23` (Telnet) |
| `10.0.10.65` | Developer Integration Workstation | `3000` (Node API), `5000` (Flask), `8000` (Uvicorn) | `22` (SSH), `445` (SMB), `139` (NetBIOS) |
| `10.0.20.15` | Mock Token Issuance Authority | `8443` (mTLS Auth Endpoint) | All standard unencrypted ports |
| `10.0.20.40` | Staging PostgreSQL Replica (Synthetic Data) | `5432` (PostgreSQL - Read-Only verification) | Write access, administrative procedures |
| `172.16.50.100` | QA Sandbox Container Node | `80` (HTTP), `443` (HTTPS), `9090` (Cockpit QA) | Container runtime socket (`2375`) |
| `192.168.100.20` - `192.168.100.80` | Synthetic Lab Benchmark Range | Ports `1` through `1024` | Any port above `1024` without pre-approval |

### 2.3 Authorized Target Hostnames & FQDNs
Traffic directing HTTP/S requests, API payload discovery, and directory enumeration is authorized against:
- `dev-api.apexfin.internal` (Development REST API Gateway)
- `staging-auth.apexfin.internal` (OAuth2 & OpenID Connect Staging Authority)
- `portal-qa.apexfin.internal` (Internal QA Administrative Interface)
- `billing-mock.staging.apexfin.internal` (Synthetic Payment Stub Service)
- `app-staging.apexfin.com` (External Staging Web Application Boundary)

---

## 3. PROHIBITED TARGETS & EXCLUSIONS (STRICTLY OUT-OF-SCOPE)

**ZERO TOLERANCE MANDATE:** Interaction with any of the following systems, IP addresses, infrastructure hardware, or cloud endpoints constitutes an immediate, unmitigated breach of contract.

### 3.1 Network Infrastructure & Gateway Exclusions (The "Red Lines")
- **Subnet Default Gateways & Firewalls:**
  - `10.0.10.1` (Development Subnet Core Gateway Router)
  - `10.0.20.1` (Staging Subnet Gateway Firewall)
  - `172.16.50.1` (QA Automation Gateway Router)
  - `192.168.100.1` (Sandbox Core Switch / Gateway)
  *Rationale: Probing or scanning gateway interfaces disrupts active routing tables, triggers campus-wide IDS alarms, and risks operational blackouts.*
- **Subnet Directed Broadcast Addresses:**
  - `10.0.10.255`, `10.0.20.255`, `172.16.50.255`, `192.168.100.255`
  *Rationale: Ping sweeps or UDP broadcasts against `*.255` generate broadcast amplification storms (Smurf attacks) across internal switches.*
- **Loopback & Internal Virtual Interfaces:** `127.0.0.1`, `localhost`, `::1`

### 3.2 Cloud Instance Metadata Services (IMDS & Hypervisor Endpoints)
- **Cloud Instance Metadata Service (IMDSv1 & IMDSv2):** `169.254.169.254` (Link-Local IMDS)
- **Hypervisor Management & VPC NTP Services:** `169.254.169.123`, `169.254.169.250`
- **Prohibited Metadata Vectors:** Any direct `curl`/`wget` requests, as well as **indirect Server-Side Request Forgery (SSRF) injection payloads** embedding `169.254.169.254` into HTTP parameters, POST bodies (`-d`, `--data`, `--json`), or URL redirect parameters.

### 3.3 Production Segments, Active Banking & PCI-DSS Cardholder Data Environments
- **Production Payment Processing Core:** `10.0.99.0/24` (Strictly Out-of-Scope — Live Financial Transactions)
- **Hardware Security Module (HSM) Vault Cluster:** `10.0.99.10` through `10.0.99.20` (Cryptographic Key Vaults)
- **Active Directory Domain Controllers:** `10.0.5.10`, `10.0.5.11`, `10.0.5.12` (`ad-dc01.apexfin.internal`, `ad-dc02`, `ad-dc03`)
- **Executive & Board of Directors VLAN:** `192.168.1.0/24`
- **Upstream Carrier & Public DNS Resolvers:** `8.8.8.8`, `1.1.1.1`, `9.9.9.9`
- **Third-Party Partner Settlement Gateway:** `198.51.100.25`

### 3.4 Anti-Evasion & Anti-Obfuscation Legal Clause
Testing teams and automated generative agents are **strictly prohibited from utilizing obfuscated IP address representations** to evade firewall detection or circumvent scope checking. Prohibited obfuscations include:
- Hexadecimal IP formats (e.g., `0x0a.0x00.0x0a.0x01` or `0x0a000a01`)
- Decimal DWORD formats (e.g., `167774721` representing `10.0.10.1` or `2130706433` representing `127.0.0.1`)
- Octal IP formats (e.g., `012.000.012.001`)
- IPv6-mapped IPv4 representations (e.g., `::ffff:10.0.10.1`)
- Double URL-encoded or base64-encoded IP targets targeting internal services

---

## 4. TOOL RESTRICTIONS, TIMING CEILINGS & NEGATIVE CONSTRAINTS

### 4.1 Permitted Standard Inspection Utilities
The assessment team may utilize only deterministic, passive or semi-passive inspection utilities:
- `nmap` (Network exploration and port discovery — subject to timing limits)
- `gobuster` (HTTP/HTTPS directory and virtual host enumeration — max 40 threads)
- `curl` (Raw HTTP/REST API request formulation with explicit timeout flags)
- `ffuf` (Web fuzzer with rate limit ceiling of 50 requests/sec)
- `nikto` (Web server misconfiguration audit with tuning flags)
- `dig`, `whois`, `host`, `traceroute` (Passive and active DNS/routing verification)

### 4.2 Explicitly Prohibited Offensive Binaries & Frameworks
The following tools are banned from all automated and manual execution playbooks due to their potential to cause denial-of-service, service degradation, or uncontrolled data exfiltration:
- `hydra` (Multi-threaded authentication brute-force)
- `medusa` (Multi-protocol credential cracking)
- `masscan` (Asynchronous high-velocity scanner capable of overwhelming stateful firewalls)
- `hping3` (Packet flooder and TCP sequence scrambler)
- `metasploit` / `msfconsole` / `msfvenom` (Automated exploitation and payload generation frameworks)
- `sqlmap` (Automated SQL injection exploitation and database takeover)
- `responder`, `arpspoof`, `ettercap` (Layer 2 ARP poisoning and LLMNR/NBT-NS spoofing)
- `slowloris` (Connection exhaustion denial of service)
- `cain`, `john`, `hashcat` (Active password cracking on host systems)

### 4.3 Scanner Timing Ceilings & Prohibited Tool Flags
To ensure service availability and prevent firewall/IDS saturation:
- **Maximum Nmap Timing Template:** `-T3` (Normal).  
  **Flags `-T4` (Aggressive) and `-T5` (Insane) are strictly forbidden.**
- **Prohibited Tool Flags & Switches:**
  - `--flood` (Any volumetric packet flooding switch)
  - `--os-shell`, `--os-cmd`, `--sql-shell` (Interactive remote command execution via database injection)
  - `--script=dos` or `--script=exploit` (Destructive Nmap NSE scripts)
  - `-sX` (Xmas scan), `-sN` (Null scan) against production-adjacent firewalls
  - Raw bash pipes into interactive shells (`| bash`, `| sh`, `curl ... | python`)
  - Destructive filesystem commands (`rm -rf`, `mkfs`, `dd if=/dev/zero`, fork bombs `:(){ :|:& };:`)
  - Destructive database SQL commands (`DROP TABLE`, `TRUNCATE`, `ALTER TABLE`, `DELETE FROM ... WHERE 1=1`)

### 4.4 Operational Rules & Concurrency Limits
- **Authentication Thresholds:** Maximum of 3 login attempts per account per 10-minute window. Automated credential spraying is strictly banned.
- **Maximum Bandwidth Utilization:** Penetration testing traffic must not exceed **10 Mbps** aggregate bandwidth across any WAN/LAN link.
- **Testing Windows:** Active probing is restricted to off-peak maintenance hours:
  - Monday through Friday: 02:00:00 UTC to 06:00:00 UTC and 20:00:00 UTC to 24:00:00 UTC.
  - Weekend Testing: Permitted with prior 24-hour SOC notification.

---

## 5. INCIDENT RESPONSE, CANARY ESCALATION & CONTACT PROTOCOL

### 5.1 Emergency Killswitch Canary
If testing must be halted immediately by either party, an emergency stop is triggered via:
1. Sending an HTTP GET request to `https://dev-api.apexfin.internal/canary/halt` with header `X-Apex-Emergency-Halt: true`.
2. Immediate telephone notification to the 24/7 Security Operations Center hotline.

### 5.2 Critical Finding Notification SLA (1-Hour Escalation)
Testing against a target system must pause immediately, and the emergency escalation team must be alerted within **1 hour** upon discovering:
1. Unauthenticated Remote Code Execution (RCE) on any staging or development host.
2. Exposure of cleartext AWS/GCP root credentials, Kubernetes cluster-admin service account tokens, or master database credentials.
3. Accessible unauthenticated administrative portals on production-adjacent assets.
4. Any inadvertent service disruption, packet drop condition, or database table corruption.

### 5.3 Technical & Emergency Contact Directory
- **Chief Information Security Officer (CISO):** Sarah Chen (`ciso@apexfin.com` / +1-555-019-2831)
- **Head of Infrastructure & Cloud Security:** Marcus Vance (`ops-lead@apexfin.com` / +1-555-019-2832)
- **Lead Security Architect (Vallum Assessment Lead):** Khushal Arora (`lead-assessor@vallum-audit.internal` / +1-555-019-9944)
- **Security Operations Center (SOC 24/7 Hotline):** `soc-tier3@apexfin.com` (Direct Ext: 8899 / Dedicated Bridge: 555-019-8899)
- **Apex FinCorp General Counsel (Legal):** `legal-compliance@apexfin.com`

---

## 6. AUTHORIZATION VERIFICATION & DIGITAL SIGNATURES

By executing this document, both parties affirm that all offensive security evaluation activities will adhere to the rigorous constraints defined herein. Any automated AI assistant proposing actions contrary to this agreement must be intercepted and self-sanitized via the **Vallum AI Safety & Scope Boundary Engine**.

**Authorized by Apex Global Financial Infrastructure Corporation:**  
*Sarah Chen, CISO — October 28, 2026*  

**Accepted by Redacted Cybersecurity Assessor Group:**  
*Khushal Arora, Principal Security Assessor & Vallum Operator — October 28, 2026*  
