"""Pydantic schemas for audit requests, findings, and evaluation results."""

from enum import Enum
from typing import Any, List, Literal, Optional
from pydantic import BaseModel, Field
from app.models.roe import RoeScope


class Verdict(str, Enum):
    CORRECT = "Correct"
    INCORRECT = "Incorrect"
    UNSAFE = "Unsafe"
    REFUSED = "Refused"  # Model declined — never scored as a compliance failure


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class ViolationCategory(str, Enum):
    SCOPE = "scope"
    DESTRUCTIVE = "destructive"
    POLICY = "policy"
    ACCURACY = "accuracy"


class TargetStatus(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    PROHIBITED = "prohibited"


class TargetKind(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"


class TargetFinding(BaseModel):
    """Classification of an extracted target candidate."""

    token: str = Field(..., description="Raw string token extracted from command or output.")
    normalized: str = Field(..., description="Canonical dot-decimal IP, CIDR, or domain.")
    kind: TargetKind = Field(..., description="Type of target (ip, cidr, domain).")
    status: TargetStatus = Field(..., description="Authorization status against the active RoE.")
    obfuscated: bool = Field(default=False, description="True if target used evasion notation (hex, octal, decimal).")
    override_reason: Optional[str] = Field(
        default=None,
        description="Set when the AI Judge reclassified this target's status away from the deterministic Pass 1 result.",
    )


class Violation(BaseModel):
    """Specific rule violation flagged during inspection."""

    rule: str = Field(..., description="Rule name or identifier.")
    category: ViolationCategory = Field(..., description="Violation category.")
    severity: Severity = Field(..., description="Severity level of the violation.")
    detail: str = Field(..., description="Technical explanation of the infraction.")
    command: Optional[str] = Field(default=None, description="The specific command that triggered the rule.")


class ViolationCandidate(BaseModel):
    """Pre-parsed candidate violation emitted by Pass 1 for adjudication."""

    id: str = Field(..., description="Stable candidate identifier, e.g. c1, c2.")
    rule: str = Field(..., description="Flagged rule name.")
    category: ViolationCategory = Field(..., description="Candidate violation category.")
    severity: Severity = Field(..., description="Candidate severity level.")
    detail: str = Field(..., description="Technical explanation of the infraction.")
    culprit_token: str = Field(default="", description="Token or argument that triggered the rule.")
    target_token: Optional[str] = Field(default=None, description="Related target token if applicable.")

    def to_violation(self) -> Violation:
        return Violation(
            rule=self.rule,
            category=self.category,
            severity=self.severity,
            detail=self.detail,
            command=self.culprit_token,
        )


class JudgeDisposition(BaseModel):
    """AI Judge disposition for a single candidate."""

    id: str = Field(..., description="Candidate ID being adjudicated.")
    disposition: Literal["confirmed", "false_positive"] = Field(
        ..., description="Confirmed violation vs false positive."
    )
    reason: str = Field(default="", description="Technical rationale for the disposition.")
    evidence: str = Field(
        default="",
        description="Verbatim quote from the candidate output proving a false-positive disposition.",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this disposition.",
    )


class JudgeOverride(BaseModel):
    """Explicit field-level override emitted by the AI Judge.

    Candidate-level false positives are handled through ``dispositions``. This
    model covers the remaining result fields the Judge may correct directly.
    """

    field: Literal[
        "verdict",
        "targets",
        "safe_sanitized_command",
        "explanation",
        "modifications_made",
    ] = Field(..., description="Result field being overridden.")
    action: Literal["set", "clear"] = Field(default="set", description="Override action.")
    value: Optional[Any] = Field(default=None, description="New value for the field.")
    evidence: str = Field(
        default="",
        description="Verbatim quote from the candidate output proving the override.",
    )
    reason: str = Field(default="", description="Technical rationale for the override.")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this override.",
    )


class JudgeResponse(BaseModel):
    """Strict AI Judge JSON output contract (no summary verdicts or metrics)."""

    dispositions: List[JudgeDisposition] = Field(
        default_factory=list, description="Itemized candidate dispositions."
    )
    overrides: List[JudgeOverride] = Field(
        default_factory=list, description="Field-level result corrections."
    )
    sanitized_script: Optional[str] = Field(default=None, description="Compliant rewritten script.")
    modifications_made: List[str] = Field(default_factory=list, description="List of surgical modifications.")
    technical_rationale: Optional[str] = Field(default=None, description="Technical explanation.")


class AuditRequest(BaseModel):
    """Payload for auditing model output against an RoE."""

    roe: RoeScope = Field(..., description="Active Rules of Engagement scope.")
    model_id: str = Field(..., max_length=200, description="Identifier of the target LLM.")
    user_prompt: str = Field(..., max_length=20_000, description="User prompt presented to the model.")
    model_output: str = Field(..., max_length=200_000, description="Raw output generated by the model.")


class DeterministicAuditRequest(BaseModel):
    """Fast-path inspection for a raw command string."""

    roe: Optional[RoeScope] = Field(default=None, description="Active Rules of Engagement scope (defaults to active preset if omitted).")
    roe_id: Optional[str] = Field(default=None, description="Preset RoE ID if roe scope object is omitted.")
    command: str = Field(..., max_length=20_000, description="CLI command string to evaluate.")
    model_id: str = Field(default="cli-direct", description="Identifier of the model or source.")
    user_prompt: str = Field(default="", max_length=20_000, description="Original user prompt if available.")


class OverrideRecord(BaseModel):
    """Audit-trail entry for a single AI Judge override."""

    field: str = Field(..., description="Field or candidate id that was overridden.")
    action: str = Field(..., description="clear, set, relabel, or replace.")
    from_value: Optional[Any] = Field(default=None, description="Value before the override.")
    to_value: Optional[Any] = Field(default=None, description="Value after the override.")
    evidence: str = Field(default="", description="Verbatim quote used to justify the override.")
    reason: str = Field(default="", description="Reason for the override.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_pass: str = Field(default="", description="First-pass disposition or action.")
    second_pass: Optional[dict] = Field(default=None, description="Second-pass confirmation result.")
    prompt_version: str = Field(default="audit-judge-v3")


class AuditResult(BaseModel):
    """Complete audit verdict and remediation report."""

    audit_id: str = Field(..., description="Unique audit identifier.")
    timestamp: str = Field(..., description="ISO 8601 evaluation timestamp.")
    mode: Literal["demo", "live"] = Field(default="live", description="Engine mode (live vs demo).")
    selected_model: str = Field(..., description="Audited model identifier.")
    user_prompt: str = Field(..., description="User prompt audited.")
    raw_model_output: str = Field(..., description="Raw model response.")
    extracted_commands: List[str] = Field(default_factory=list, description="Parsed CLI commands.")
    targets: List[TargetFinding] = Field(default_factory=list, description="Extracted targets with scope findings.")
    verdict: Verdict = Field(..., description="Final compliance verdict.")
    violation_details: List[Violation] = Field(default_factory=list, description="Itemized rule violations.")
    safe_sanitized_command: Optional[str] = Field(default=None, description="Compliant rewritten command or None.")
    modifications_made: List[str] = Field(default_factory=list, description="Remediation steps applied.")
    explanation: str = Field(..., description="Summary of evaluation results and rationale.")
    trust_tier: Literal["hybrid", "deterministic"] = Field(
        default="hybrid",
        description="Evaluation trust tier (hybrid: AST + AI Judge; deterministic: Pass 1 AST engine authoritative).",
    )
    ai_judge_notes: List[str] = Field(
        default_factory=list,
        description="Advisory observations and contextual notes emitted by the AI Judge without altering deterministic verdicts.",
    )
    override_log: List[OverrideRecord] = Field(
        default_factory=list,
        description="Audit trail of AI Judge overrides, including second-pass confirmations.",
    )
    needs_review: bool = Field(
        default=False,
        description="True when an override was rejected or a critical override could not be confirmed.",
    )


class NormalizeIpRequest(BaseModel):
    """Request to normalize an obfuscated IP address."""

    target: str = Field(..., description="Raw IP string (hex, octal, decimal, dot-decimal, or IPv6).")


class NormalizeIpResponse(BaseModel):
    """Response containing canonical IP and obfuscation metadata."""

    raw_token: str
    normalized: Optional[str]
    is_valid: bool
    is_obfuscated: bool
    format_detected: str
    is_loopback: bool
    is_private: bool
    is_multicast: bool
    is_reserved: bool
