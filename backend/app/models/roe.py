"""Pydantic schemas for Rules of Engagement (RoE) scopes."""

import ipaddress
from typing import List
from pydantic import BaseModel, Field, field_validator


class RoeScope(BaseModel):
    """Rules of Engagement Scope Definition."""

    roe_id: str = Field(..., description="Unique identifier for the RoE scope.")
    name: str = Field(..., description="Human-readable engagement name.")
    engagement_type: str = Field(..., description="Assessment type (e.g. Network, Web, Cloud).")
    summary: str = Field(default="", description="High-level description of scope boundaries.")
    allowed_cidrs: List[str] = Field(default_factory=list, description="Subnets authorized for testing.")

    @field_validator("allowed_cidrs")
    @classmethod
    def _validate_allowed_cidrs(cls, values: List[str]) -> List[str]:
        """Enforce the wildcard and minimum-prefix policy at the model boundary, not only in the parser."""
        for value in values:
            try:
                net = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError:
                continue  # Malformed entries are ignored by the scope engine, not treated as wildcards
            if net.prefixlen == 0:
                raise ValueError("wildcard scope is not allowed")
            min_prefix = 8 if net.version == 4 else 48
            if net.prefixlen < min_prefix:
                raise ValueError(f"scope {value} is too broad")
        return values

    allowed_domains: List[str] = Field(default_factory=list, description="Fully qualified domain names authorized.")
    target_hosts: List[str] = Field(default_factory=list, description="Primary authorized target IP addresses.")
    prohibited_ips: List[str] = Field(default_factory=list, description="IPs/subnets explicitly excluded from testing.")
    allowed_tools: List[str] = Field(default_factory=list, description="Permitted offensive tools.")
    whitelisted_system_utilities: List[str] = Field(
        default_factory=lambda: ["sh", "bash", "cat", "grep", "awk", "sed", "tee", "head", "tail", "sort", "uniq", "cut", "tr", "echo", "printf", "xargs"],
        description="Authorized local POSIX stream and string processing utilities.",
    )
    prohibited_tools: List[str] = Field(default_factory=list, description="Banned offensive tools.")
    prohibited_flags: List[str] = Field(default_factory=list, description="Specific tool flags prohibited by contract.")
    prohibited_actions: List[str] = Field(default_factory=list, description="High-level banned attack techniques.")
    max_nmap_timing: int = Field(default=3, ge=0, le=5, description="Maximum permitted nmap timing template (-T0..-T5).")

