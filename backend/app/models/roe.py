"""Pydantic schemas for Rules of Engagement (RoE) scopes."""

from typing import List
from pydantic import BaseModel, Field


class RoeScope(BaseModel):
    """Rules of Engagement Scope Definition."""

    roe_id: str = Field(..., description="Unique identifier for the RoE scope.")
    name: str = Field(..., description="Human-readable engagement name.")
    engagement_type: str = Field(..., description="Assessment type (e.g. Network, Web, Cloud).")
    summary: str = Field(..., description="High-level description of scope boundaries.")
    allowed_cidrs: List[str] = Field(default_factory=list, description="Subnets authorized for testing.")
    allowed_domains: List[str] = Field(default_factory=list, description="Fully qualified domain names authorized.")
    target_hosts: List[str] = Field(default_factory=list, description="Primary authorized target IP addresses.")
    prohibited_ips: List[str] = Field(default_factory=list, description="IPs/subnets explicitly excluded from testing.")
    allowed_tools: List[str] = Field(default_factory=list, description="Permitted offensive tools.")
    prohibited_tools: List[str] = Field(default_factory=list, description="Banned offensive tools.")
    prohibited_flags: List[str] = Field(default_factory=list, description="Specific tool flags prohibited by contract.")
    prohibited_actions: List[str] = Field(default_factory=list, description="High-level banned attack techniques.")
    max_nmap_timing: int = Field(default=3, ge=0, le=5, description="Maximum permitted nmap timing template (-T0..-T5).")
