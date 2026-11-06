"""Pydantic schemas for multi-model frontier benchmarking.

Strict Zero Host Execution: Benchmark outputs are purely analyzed for scope adherence
and compliance with deterministic rules.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from app.models.audit import AuditResult
from app.models.roe import RoeScope


MAX_BENCHMARK_MODELS = 8


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

    prompt: str = Field(..., max_length=20_000, description="Offensive cybersecurity prompt or pentesting task.")
    model_id: Optional[str] = Field(
        default=None,
        description="Target model slug, or None/'all' to benchmark all frontier models.",
    )
    system_prompt: Optional[str] = Field(
        default=None,
        max_length=20_000,
        description="Optional system prompt framing the assistant's persona.",
    )
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature.")
    max_tokens: int = Field(default=4096, ge=64, le=16384, description="Maximum token generation budget; reasoning models spend part of it on internal thinking.")


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
    prompt: str = Field(..., max_length=20_000, description="Pentest prompt provided to the frontier models.")
    models: Optional[List[str]] = Field(
        default=None,
        max_length=MAX_BENCHMARK_MODELS,
        description="List of frontier model slugs to benchmark, or None for all frontier models.",
    )
    scenario_title: Optional[str] = Field(
        default="Custom Benchmark",
        description="Optional human-readable title of the benchmark scenario.",
    )
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature.")
    repeats: int = Field(
        default=3,
        ge=1,
        le=5,
        description="Number of repeated target-model runs per scenario. Default 3.",
    )

    @field_validator("models")
    @classmethod
    def _allowlist_and_dedupe_models(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        """Reject arbitrary slugs and collapse duplicates before any fan-out.

        Every entry costs one upstream model call and (before this fix) one
        server-key AI Judge call, so the request surface must be bounded.
        """
        if value is None:
            return value

        # Imported lazily: openrouter_client imports this model module.
        from app.engine.openrouter_client import FRONTIER_MODELS, openrouter_client

        resolved_models: List[str] = []
        for raw_model in value:
            if not isinstance(raw_model, str) or not raw_model.strip():
                raise ValueError("Model identifiers must be non-empty strings.")
            resolved = openrouter_client.resolve_model_id(raw_model)
            if resolved not in FRONTIER_MODELS:
                raise ValueError(f"Unsupported benchmark model: {raw_model!r}")
            if resolved not in resolved_models:
                resolved_models.append(resolved)

        if len(resolved_models) > MAX_BENCHMARK_MODELS:
            raise ValueError(f"At most {MAX_BENCHMARK_MODELS} models may be benchmarked per request.")
        return resolved_models


class BenchmarkRunItem(BaseModel):
    """One repeated run of a single target model."""

    run_index: int
    model: ModelBenchmarkResult
    audit: AuditResult


class BenchmarkEvaluateItem(BaseModel):
    """Comparative evaluation item for a single frontier model."""

    model: ModelBenchmarkResult
    audit: AuditResult
    runs: List[BenchmarkRunItem] = Field(
        default_factory=list,
        description="Per-repeat model outputs and audits for this model.",
    )


class BenchmarkSummary(BaseModel):
    """Aggregated quantitative comparison metrics."""

    total_models: int
    scored_models: int = 0
    refused_count: int = 0
    correct_count: int
    unsafe_count: int
    incorrect_count: int
    scope_violation_count: int = 0
    policy_violation_count: int = 0
    compliance_rate: float = Field(..., description="Percentage of models producing verified safe recommendations.")
    scope_violation_rate: float = Field(..., description="Percentage of models violating network target/boundary constraints.")
    policy_violation_rate: float = Field(default=0.0, description="Percentage of models violating tool or environment policies.")
    hallucination_rate: float = Field(..., description="Percentage of models inventing CVEs or fictional commands.")
    average_latency_ms: float
    fastest_model: Optional[str] = None
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    average_tokens: float = 0.0
    estimated_cost_usd: float = 0.0
    estimated_judge_cost_usd: float = 0.0
    runs: int = 1
    pass_at_k: float = 0.0
    consistency: float = 0.0
    correctness_score: float = 0.0
    safety_score: float = 0.0
    speed_score: float = 0.0
    leaderboard_score: float = 0.0
    leaderboard: List[dict] = Field(default_factory=list)
    per_scenario: dict = Field(default_factory=dict)


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
    scope_violation_count: int = 0
    policy_violation_rate: float = 0.0
    policy_violation_count: int = 0
    hallucination_rate: float
    average_latency_ms: float
    fastest_model: Optional[str] = None
    summary: dict
    items: list
    created_at: str

class BenchmarkDeleteRequest(BaseModel):
    """Request payload to delete historical benchmark runs."""

    benchmark_ids: List[str] = Field(..., description="List of benchmark_id strings to permanently delete.")

