"""Pydantic schemas for Phase 4.5: Ephemeral Micro-Sandbox Dry-Run Environment.

Provides structured models for syntax checking, tool flag grammar validation,
and network-egress disabled execution simulation.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class SandboxDryRunRequest(BaseModel):
    """Request payload for dry-running a command in the micro-sandbox."""

    command: str = Field(..., description="Offensive CLI command or synthesized remediation to dry-run")
    roe_id: Optional[str] = Field(default="ROE-PRESET-NET-001", description="Active RoE identifier for scope cross-referencing")
    strict_syntax: bool = Field(default=True, description="Enforce strict POSIX and tool-specific flag grammar")
    timeout_ms: int = Field(default=5000, ge=500, le=30000, description="Virtual execution timeout in milliseconds")


class SandboxIsolationMetadata(BaseModel):
    """Security isolation parameters enforced during micro-sandbox dry-run."""

    network_isolated: bool = Field(default=True, description="Network interfaces permanently disabled")
    network_egress: str = Field(default="DISABLED", description="Egress state: DISABLED or BLOCKED")
    packets_transmitted: int = Field(default=0, description="Network packets released to host/external networks")
    zero_host_execution: bool = Field(default=True, description="Strict Zero Host Execution principle adhered to")
    filesystem_mode: str = Field(default="ephemeral-vfs-readonly", description="Virtual filesystem isolation mode")


class SandboxDryRunResponse(BaseModel):
    """Comprehensive dry-run execution results and diagnostic report."""

    command: str = Field(..., description="The command evaluated in the micro-sandbox")
    tool: str = Field(default="generic", description="Identified offensive security binary or shell builtin")
    syntax_valid: bool = Field(..., description="Whether command conforms to POSIX and tool-specific CLI grammar")
    exit_code: int = Field(default=0, description="Simulated exit code (0 = success, non-zero = syntax/grammar error)")
    sandbox_tier: str = Field(default="ephemeral-micro-sandbox (vfs-isolated)", description="Sandbox execution tier")
    isolation: SandboxIsolationMetadata = Field(default_factory=SandboxIsolationMetadata)
    diagnostics: List[str] = Field(default_factory=list, description="Parser and flag validator findings")
    simulated_stdout: str = Field(default="", description="Simulated standard output stream")
    simulated_stderr: str = Field(default="", description="Simulated standard error stream")
    elapsed_ms: int = Field(default=0, description="Execution and parsing duration in milliseconds")


class SandboxStatusResponse(BaseModel):
    """Health and isolation capability telemetry for the micro-sandbox."""

    status: str = Field(default="operational")
    sandbox_tier: str = Field(default="ephemeral-micro-sandbox")
    network_egress: str = Field(default="DISABLED")
    zero_host_execution: bool = Field(default=True)
    supported_tools: List[str] = Field(default_factory=list)
