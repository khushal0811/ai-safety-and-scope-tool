"""Pydantic schemas for multi-model frontier benchmarking.

Strict Zero Host Execution: Benchmark outputs are purely analyzed for scope adherence
and compliance with deterministic rules.
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.audit import AuditResult
from app.models.roe import RoeScope


class FrontierModelInfo(BaseModel):
    """Metadata describing a frontier LLM available for benchmarking."""

    id: str = Field(..., description="OpenRouter model identifier slug.")
    name: str = Field(..., description="Human-friendly model name.")
    provider: str = Field(..., description="Provider / Organization (OpenAI, Anthropic, Google, Meta).")
    context_length: int = Field(default=128000, description="Context window length in tokens.")
    description: str = Field(..., description="Capabilities and architectural notes.")
    tier: str = Field(default="frontier", description="Model capability tier.")
    recommended: bool = Field(default=True, description="Whether recommended for cybersecurity benchmarking.")


class BenchmarkQueryRequest(BaseModel):
    """Request to query frontier model(s) via OpenRouter."""

    prompt: str = Field(..., description="Offensive cybersecurity prompt or pentesting task.")
    model_id: Optional[str] = Field(
        default=None,
        description="Target model slug, or None/'all' to benchmark all frontier models.",
    )
    system_prompt: Optional[str] = Field(
        default=None,
        description="Optional system prompt framing the assistant's persona.",
    )
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature.")
    max_tokens: int = Field(default=1024, ge=64, le=4096, description="Maximum token generation budget.")


class ModelBenchmarkResult(BaseModel):
    """Raw response and benchmark telemetry for a single model."""

    model_id: str
    model_name: str
    provider: str
    latency_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    raw_output: str = ""
    extracted_commands: List[str] = Field(default_factory=list)
    status: str = Field(default="success", description="Status: 'success', 'rate_limited', 'unauthorized', 'error'")
    error_message: Optional[str] = None


class BenchmarkQueryResponse(BaseModel):
    """Response containing outputs from all queried models."""

    timestamp: str
    prompt: str
    results: List[ModelBenchmarkResult]


class BenchmarkEvaluateRequest(BaseModel):
    """Request to query frontier models and simultaneously evaluate outputs against RoE."""

    roe: RoeScope = Field(..., description="Active Rules of Engagement scope to evaluate against.")
    prompt: str = Field(..., description="Pentest prompt provided to the frontier models.")
    models: Optional[List[str]] = Field(
        default=None,
        description="List of model slugs to benchmark, or None for all 4 frontier models.",
    )
    scenario_title: Optional[str] = Field(
        default="Custom Benchmark",
        description="Optional human-readable title of the benchmark scenario.",
    )
    temperature: float = Field(default=0.0, description="Sampling temperature.")


class BenchmarkEvaluateItem(BaseModel):
    """Comparative evaluation item for a single frontier model."""

    model: ModelBenchmarkResult
    audit: AuditResult


class BenchmarkSummary(BaseModel):
    """Aggregated quantitative comparison metrics."""

    total_models: int
    correct_count: int
    unsafe_count: int
    incorrect_count: int
    compliance_rate: float = Field(..., description="Percentage of models producing verified safe recommendations.")
    scope_violation_rate: float = Field(..., description="Percentage of models violating network target/boundary constraints.")
    policy_violation_rate: float = Field(default=0.0, description="Percentage of models violating tool or environment policies.")
    hallucination_rate: float = Field(..., description="Percentage of models inventing CVEs or fictional commands.")
    average_latency_ms: float
    fastest_model: Optional[str] = None


class BenchmarkEvaluateResponse(BaseModel):
    """Full comparative benchmark report."""

    benchmark_id: Optional[str] = Field(default=None, description="Unique identifier for persisted benchmark run.")
    timestamp: str
    roe_id: str
    scenario_title: Optional[str] = "Custom Benchmark"
    prompt: str
    items: List[BenchmarkEvaluateItem]
    summary: BenchmarkSummary


class BenchmarkRunRecord(BaseModel):
    """Persisted benchmark evaluation record stored in PostgreSQL."""

    id: Optional[str] = None
    benchmark_id: str
    user_id: Optional[str] = None
    roe_id: str
    scenario_title: str = "Custom Benchmark"
    prompt: str
    total_models: int
    compliance_rate: float
    scope_violation_rate: float
    policy_violation_rate: float = 0.0
    hallucination_rate: float
    average_latency_ms: float
    fastest_model: Optional[str] = None
    summary: dict
    items: list
    created_at: str


class BenchmarkDeleteRequest(BaseModel):
    """Request payload to delete historical benchmark runs."""

    benchmark_ids: List[str] = Field(..., description="List of benchmark_id strings to permanently delete.")

