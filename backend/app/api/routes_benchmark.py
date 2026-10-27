"""FastAPI routes for frontier LLM benchmarking via OpenRouter.

Endpoints:
- GET  /api/benchmark/models    : List canonical frontier models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro, Llama 3.1)
- POST /api/benchmark/query     : Query single or all models and return outputs with latency telemetry
- POST /api/benchmark/evaluate  : Query models and simultaneously verify outputs against active RoE
"""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from fastapi import APIRouter, Header

from app.engine.openrouter_client import openrouter_client
from app.engine.verifier import evaluate_audit
from app.models.audit import AuditRequest, AuditResult, Verdict, ViolationCategory
from app.models.benchmark import (
    BenchmarkEvaluateItem,
    BenchmarkEvaluateRequest,
    BenchmarkEvaluateResponse,
    BenchmarkQueryRequest,
    BenchmarkQueryResponse,
    BenchmarkSummary,
    FrontierModelInfo,
    ModelBenchmarkResult,
)

logger = logging.getLogger(__name__)

benchmark_router = APIRouter(prefix="/api/benchmark", tags=["Benchmark Runner"])


@benchmark_router.get("/models", response_model=List[FrontierModelInfo])
async def list_benchmark_models():
    """List canonical frontier models supported for scope adherence benchmarking."""
    return openrouter_client.list_frontier_models()


@benchmark_router.post("/query", response_model=BenchmarkQueryResponse)
async def query_benchmark_models(
    request: BenchmarkQueryRequest,
    x_openrouter_key: Optional[str] = Header(None, alias="X-OpenRouter-Key"),
    x_groq_key: Optional[str] = Header(None, alias="X-Groq-Key"),
):
    """Query one or all frontier models via OpenRouter or system Groq key.

    Zero Host Storage: Keys passed in headers are purely used for transit
    inference and are never logged or stored.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    if request.model_id and request.model_id.lower() != "all":
        single_res = await openrouter_client.query_model(
            model_id=request.model_id,
            prompt=request.prompt,
            system_prompt=request.system_prompt,
            api_key=x_openrouter_key,
            groq_key=x_groq_key,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        results = [single_res]
    else:
        results = await openrouter_client.benchmark_frontier_models(
            prompt=request.prompt,
            system_prompt=request.system_prompt,
            api_key=x_openrouter_key,
            groq_key=x_groq_key,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )

    return BenchmarkQueryResponse(
        timestamp=timestamp,
        prompt=request.prompt,
        results=results,
    )


@benchmark_router.post("/evaluate", response_model=BenchmarkEvaluateResponse)
async def evaluate_benchmark_models(
    request: BenchmarkEvaluateRequest,
    x_openrouter_key: Optional[str] = Header(None, alias="X-OpenRouter-Key"),
    x_groq_key: Optional[str] = Header(None, alias="X-Groq-Key"),
):
    """Query frontier models and evaluate each response against the active RoE scope."""
    timestamp = datetime.now(timezone.utc).isoformat()

    # 1. Dispatch queries across target models
    results = await openrouter_client.benchmark_frontier_models(
        prompt=request.prompt,
        models=request.models,
        api_key=x_openrouter_key,
        groq_key=x_groq_key,
        temperature=request.temperature,
    )

    items: List[BenchmarkEvaluateItem] = []
    correct_count = 0
    unsafe_count = 0
    incorrect_count = 0
    hallucination_count = 0
    valid_latencies: List[float] = []
    fastest_model: Optional[str] = None
    min_latency = float("inf")

    # 2. Evaluate each model output through the deterministic verification engine
    for res in results:
        # Construct audit request
        output_text = res.raw_output
        if not output_text.strip() and res.extracted_commands:
            output_text = "\n".join(f"```bash\n{c}\n```" for c in res.extracted_commands)

        audit_req = AuditRequest(
            roe=request.roe,
            model_id=res.model_id,
            user_prompt=request.prompt,
            model_output=output_text or f"// Model returned status: {res.status}. {res.error_message or ''}",
        )

        audit_res: AuditResult = evaluate_audit(audit_req)

        # Tabulate verdicts
        if audit_res.verdict == Verdict.CORRECT:
            correct_count += 1
        elif audit_res.verdict == Verdict.UNSAFE:
            unsafe_count += 1
        else:
            incorrect_count += 1

        # Check for hallucinations (accuracy violations or unverified CVEs)
        has_hallucination = any(
            v.category == ViolationCategory.ACCURACY or "CVE" in v.rule
            for v in audit_res.violation_details
        )
        if has_hallucination:
            hallucination_count += 1

        # Track latency metrics for successful inference calls
        if res.status == "success" and res.latency_ms > 0:
            valid_latencies.append(res.latency_ms)
            if res.latency_ms < min_latency:
                min_latency = res.latency_ms
                fastest_model = res.model_name

        items.append(BenchmarkEvaluateItem(model=res, audit=audit_res))

    total = len(items)
    avg_latency = round(sum(valid_latencies) / len(valid_latencies), 2) if valid_latencies else 0.0
    cr = round((correct_count / total) * 100, 1) if total > 0 else 0.0
    svr = round((unsafe_count / total) * 100, 1) if total > 0 else 0.0
    hr = round((hallucination_count / total) * 100, 1) if total > 0 else 0.0

    summary = BenchmarkSummary(
        total_models=total,
        correct_count=correct_count,
        unsafe_count=unsafe_count,
        incorrect_count=incorrect_count,
        compliance_rate=cr,
        scope_violation_rate=svr,
        hallucination_rate=hr,
        average_latency_ms=avg_latency,
        fastest_model=fastest_model,
    )

    return BenchmarkEvaluateResponse(
        timestamp=timestamp,
        roe_id=request.roe.roe_id,
        prompt=request.prompt,
        items=items,
        summary=summary,
    )
