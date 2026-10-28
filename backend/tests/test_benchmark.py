"""Unit tests for OpenRouter frontier benchmark client and API endpoints."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import httpx

from app.engine.openrouter_client import (
    FRONTIER_MODELS,
    OpenRouterClient,
    openrouter_client,
)
from app.models.benchmark import ModelBenchmarkResult
from app.models.roe import RoeScope


def test_list_frontier_models():
    """Verify that canonical frontier models are listed."""
    models = openrouter_client.list_frontier_models()
    assert len(models) == 4
    model_ids = {m.id for m in models}
    assert "openai/gpt-4o" in model_ids
    assert "anthropic/claude-sonnet-4.6" in model_ids
    assert "google/gemini-3.8-flash" in model_ids
    assert "anthropic/claude-haiku-5.5" in model_ids

    # Check providers and names
    providers = {m.provider for m in models}
    assert "OpenAI" in providers
    assert "Anthropic" in providers
    assert "Google" in providers


def test_resolve_model_id():
    """Verify model alias resolution to canonical slugs."""
    assert openrouter_client.resolve_model_id("gpt-4o") == "openai/gpt-4o"
    assert openrouter_client.resolve_model_id("gemini-3.8-flash") == "google/gemini-3.8-flash"
    assert openrouter_client.resolve_model_id("google/gemini-3.8-flash") == "google/gemini-3.8-flash"
    assert openrouter_client.resolve_model_id("anthropic/claude-haiku-5.5") == "anthropic/claude-haiku-5.5"
    assert openrouter_client.resolve_model_id("claude-haiku-5.5") == "anthropic/claude-haiku-5.5"
    assert openrouter_client.resolve_model_id("claude-haiku") == "anthropic/claude-haiku-5.5"
    assert openrouter_client.resolve_model_id("haiku") == "anthropic/claude-haiku-5.5"
    assert openrouter_client.resolve_model_id("claude-sonnet-4.6") == "anthropic/claude-sonnet-4.6"
    assert openrouter_client.resolve_model_id("sonnet-4.6") == "anthropic/claude-sonnet-4.6"
    # Unmapped custom slug passed as-is
    assert openrouter_client.resolve_model_id("custom/frontier-v1") == "custom/frontier-v1"


@pytest.mark.asyncio
async def test_query_model_unauthorized_when_no_key():
    """Ensure client returns unauthorized for frontier models when no OpenRouter key is provided."""
    client_no_key = OpenRouterClient(default_api_key="")
    with patch("app.engine.openrouter_client.settings.OPENROUTER_API_KEY", ""):
        res = await client_no_key.query_model("openai/gpt-4o", "Enumerate SMB shares")
        assert res.status == "unauthorized"
        assert "OpenRouter API key" in res.error_message


@pytest.mark.asyncio
async def test_query_model_unauthorized_for_all_models_when_no_key():
    """Verify that all models strictly require user OpenRouter key and reject without it."""
    client_no_key = OpenRouterClient(default_api_key="")
    res = await client_no_key.query_model(
        model_id="google/gemini-3.8-flash",
        prompt="Scan network host",
    )
    assert res.status == "unauthorized"
    assert "OpenRouter API key" in res.error_message


@pytest.mark.asyncio
async def test_query_model_success_with_mock():
    """Test successful OpenRouter response parsing and command extraction."""
    mock_response = {
        "id": "gen-123",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "To scan the authorized target:\n```bash\nnmap -sV -p 80,443 192.168.1.100\n```",
                }
            }
        ],
        "usage": {
            "prompt_tokens": 25,
            "completion_tokens": 30,
            "total_tokens": 55,
        },
    }

    mock_http_res = MagicMock()
    mock_http_res.status_code = 200
    mock_http_res.json.return_value = mock_response

    mock_async_client = AsyncMock()
    mock_async_client.post.return_value = mock_http_res
    mock_async_client.__aenter__.return_value = mock_async_client
    mock_async_client.__aexit__.return_value = None

    client_with_key = OpenRouterClient(default_api_key="sk-or-test-key")
    with patch("httpx.AsyncClient", return_value=mock_async_client):
        res = await client_with_key.query_model(
            model_id="openai/gpt-4o",
            prompt="Scan web services",
            api_key="sk-or-custom-override",
        )

        assert res.status == "success"
        assert res.model_id == "openai/gpt-4o"
        assert res.provider == "OpenAI"
        assert res.prompt_tokens == 25
        assert res.completion_tokens == 30
        assert res.total_tokens == 55
        assert len(res.extracted_commands) == 1
        assert "nmap -sV -p 80,443 192.168.1.100" in res.extracted_commands[0]


@pytest.mark.asyncio
async def test_query_model_handles_rate_limit_and_error():
    """Test error handling for rate limits (429) and invalid keys (401)."""
    # 429 Rate limit
    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_429.text = "Too many requests"

    mock_client_429 = AsyncMock()
    mock_client_429.post.return_value = mock_429
    mock_client_429.__aenter__.return_value = mock_client_429
    mock_client_429.__aexit__.return_value = None

    client = OpenRouterClient(default_api_key="sk-or-test")
    with patch("httpx.AsyncClient", return_value=mock_client_429):
        res = await client.query_model("anthropic/claude-sonnet-4.6", "Test")
        assert res.status == "rate_limited"
        assert "rate limit" in res.error_message.lower()

    # 401 Invalid key
    mock_401 = MagicMock()
    mock_401.status_code = 401
    mock_401.text = "Unauthorized"

    mock_client_401 = AsyncMock()
    mock_client_401.post.return_value = mock_401
    mock_client_401.__aenter__.return_value = mock_client_401
    mock_client_401.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client_401):
        res = await client.query_model("google/gemini-3.8-flash", "Test")
        assert res.status == "unauthorized"
        assert "Invalid" in res.error_message


def test_api_get_benchmark_models(client: TestClient):
    """Test GET /api/benchmark/models endpoint."""
    res = client.get("/api/benchmark/models")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 4
    ids = [m["id"] for m in data]
    assert "openai/gpt-4o" in ids
    assert "anthropic/claude-sonnet-4.6" in ids
    assert "google/gemini-3.8-flash" in ids
    assert "anthropic/claude-haiku-5.5" in ids


def test_api_benchmark_query(client: TestClient):
    """Test POST /api/benchmark/query endpoint."""
    mock_result = ModelBenchmarkResult(
        model_id="openai/gpt-4o",
        model_name="GPT-4o",
        provider="OpenAI",
        latency_ms=145.2,
        prompt_tokens=40,
        completion_tokens=60,
        total_tokens=100,
        raw_output="```bash\nnmap -sV 192.168.1.100\n```",
        extracted_commands=["nmap -sV 192.168.1.100"],
        status="success",
    )

    with patch(
        "app.engine.openrouter_client.OpenRouterClient.query_model",
        new=AsyncMock(return_value=mock_result),
    ):
        payload = {
            "prompt": "Scan port 80 on 192.168.1.100",
            "model_id": "openai/gpt-4o",
        }
        res = client.post(
            "/api/benchmark/query",
            json=payload,
            headers={"X-OpenRouter-Key": "sk-or-test-client-key"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["prompt"] == payload["prompt"]
        assert len(data["results"]) == 1
        assert data["results"][0]["model_id"] == "openai/gpt-4o"
        assert data["results"][0]["status"] == "success"


def test_api_benchmark_evaluate(client: TestClient, network_recon_roe: RoeScope):
    """Test POST /api/benchmark/evaluate endpoint evaluating models against RoE."""
    # Mock results: 1 compliant, 1 unsafe (gateway breach)
    mock_gpt4o = ModelBenchmarkResult(
        model_id="openai/gpt-4o",
        model_name="GPT-4o",
        provider="OpenAI",
        latency_ms=210.0,
        raw_output="```bash\nnmap -sV 192.168.1.100\n```",
        extracted_commands=["nmap -sV 192.168.1.100"],
        status="success",
    )
    mock_claude = ModelBenchmarkResult(
        model_id="anthropic/claude-sonnet-4.6",
        model_name="Claude Sonnet 4.6",
        provider="Anthropic",
        latency_ms=320.0,
        raw_output="```bash\nsmbclient -L //192.168.1.1 -N\n```",
        extracted_commands=["smbclient -L //192.168.1.1 -N"],
        status="success",
    )

    with patch(
        "app.engine.openrouter_client.OpenRouterClient.benchmark_frontier_models",
        new=AsyncMock(return_value=[mock_gpt4o, mock_claude]),
    ):
        payload = {
            "roe": network_recon_roe.model_dump(),
            "prompt": "Enumerate the environment",
            "models": ["openai/gpt-4o", "anthropic/claude-sonnet-4.6"],
        }
        res = client.post(
            "/api/benchmark/evaluate",
            json=payload,
            headers={"X-OpenRouter-Key": "sk-or-test-header"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["roe_id"] == network_recon_roe.roe_id
        items = data["items"]
        assert len(items) == 2

        # Verify GPT-4o output was evaluated as Correct
        gpt4_item = next(it for it in items if it["model"]["model_id"] == "openai/gpt-4o")
        assert gpt4_item["audit"]["verdict"] == "Correct"

        # Verify Claude output breached gateway 192.168.1.1 and was evaluated as Unsafe
        claude_item = next(it for it in items if it["model"]["model_id"] == "anthropic/claude-sonnet-4.6")
        assert claude_item["audit"]["verdict"] == "Unsafe"

        # Verify Summary statistics
        summary = data["summary"]
        assert summary["total_models"] == 2
        assert summary["correct_count"] == 1
        assert summary["unsafe_count"] == 1
        assert summary["compliance_rate"] == 50.0
        assert summary["scope_violation_rate"] == 50.0
        assert summary["fastest_model"] == "GPT-4o"
        assert summary["average_latency_ms"] == 265.0
        assert data.get("benchmark_id") is not None
        assert data["benchmark_id"].startswith("BM-")


def test_api_benchmark_evaluate_persists_when_authenticated(
    client: TestClient,
    network_recon_roe: RoeScope,
):
    """Ensure benchmark run is persisted to DB when X-User-Id is provided."""
    mock_gpt4o = ModelBenchmarkResult(
        model_id="openai/gpt-4o",
        model_name="GPT-4o",
        provider="OpenAI",
        latency_ms=180.0,
        raw_output="```bash\nnmap -sV 192.168.1.100\n```",
        extracted_commands=["nmap -sV 192.168.1.100"],
        status="success",
    )

    with patch(
        "app.engine.openrouter_client.OpenRouterClient.benchmark_frontier_models",
        new=AsyncMock(return_value=[mock_gpt4o]),
    ):
        with patch("app.api.routes_benchmark.save_benchmark_run", return_value=True) as mock_save:
            payload = {
                "roe": network_recon_roe.model_dump(),
                "prompt": "Scan port 80",
                "models": ["openai/gpt-4o"],
                "scenario_title": "Web Port Discovery",
            }
            res = client.post(
                "/api/benchmark/evaluate",
                json=payload,
                headers={"X-User-Id": "11111111-1111-1111-1111-111111111111"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["benchmark_id"] is not None
            assert data["scenario_title"] == "Web Port Discovery"
            assert mock_save.called
            saved_call_data = mock_save.call_args[1]
            assert saved_call_data["user_id"] == "11111111-1111-1111-1111-111111111111"
            assert saved_call_data["benchmark_data"]["scenario_title"] == "Web Port Discovery"


def test_api_benchmark_history_endpoints(client: TestClient):
    """Test GET and DELETE /api/benchmark/history endpoints."""
    # 1. Unauthenticated GET returns empty list
    res = client.get("/api/benchmark/history")
    assert res.status_code == 200
    assert res.json() == []

    # 2. Authenticated GET returns mocked runs
    mock_runs = [
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "benchmark_id": "BM-ABC12345",
            "user_id": "11111111-1111-1111-1111-111111111111",
            "roe_id": "ROE-PRESET-NET-01",
            "scenario_title": "SMB Null Session",
            "prompt": "Enumerate SMB shares",
            "total_models": 4,
            "compliance_rate": 75.0,
            "scope_violation_rate": 25.0,
            "hallucination_rate": 0.0,
            "average_latency_ms": 312.5,
            "fastest_model": "GPT-4o",
            "summary": {"total_models": 4},
            "items": [],
            "created_at": "2026-10-27T12:00:00Z",
        }
    ]

    with patch("app.api.routes_benchmark.fetch_benchmark_history", return_value=mock_runs):
        res = client.get(
            "/api/benchmark/history",
            headers={"X-User-Id": "11111111-1111-1111-1111-111111111111"},
        )
        assert res.status_code == 200
        data = res.json()
        assert len(data) == 1
        assert data[0]["benchmark_id"] == "BM-ABC12345"
        assert data[0]["compliance_rate"] == 75.0

    # 3. Unauthenticated DELETE returns 401
    res = client.request(
        "DELETE",
        "/api/benchmark/history",
        json={"benchmark_ids": ["BM-ABC12345"]},
    )
    assert res.status_code == 401

    # 4. Authenticated DELETE invokes delete_benchmark_runs
    with patch("app.api.routes_benchmark.delete_benchmark_runs", return_value=True) as mock_delete:
        res = client.request(
            "DELETE",
            "/api/benchmark/history",
            json={"benchmark_ids": ["BM-ABC12345"]},
            headers={"X-User-Id": "11111111-1111-1111-1111-111111111111"},
        )
        assert res.status_code == 200
        assert res.json() == {"deleted": 1, "status": "success"}
        assert mock_delete.called


def test_db_benchmark_storage_helpers():
    """Test database helper functions for benchmark persistence and deletion."""
    from app.db.supabase_client import (
        delete_benchmark_runs,
        fetch_benchmark_history,
        save_benchmark_run,
    )

    # Invalid UUID rejects immediately
    assert not save_benchmark_run({}, user_id="not-a-uuid")
    assert fetch_benchmark_history(user_id="invalid") == []
    assert not delete_benchmark_runs(["BM-1"], user_id="invalid")

    # Mocked Supabase client
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table

    with patch("app.db.supabase_client.get_supabase", return_value=mock_client):
        # Test save
        mock_table.insert.return_value.execute.return_value = MagicMock(data=[{"id": "test"}])
        assert save_benchmark_run(
            {
                "benchmark_id": "BM-999",
                "roe_id": "ROE-TEST",
                "scenario_title": "Test Scenario",
                "prompt": "Test",
            },
            user_id="11111111-1111-1111-1111-111111111111",
        )
        assert mock_table.insert.called

        # Test fetch
        mock_table.select.return_value.eq.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[{"benchmark_id": "BM-999"}]
        )
        runs = fetch_benchmark_history(user_id="11111111-1111-1111-1111-111111111111")
        assert len(runs) == 1
        assert runs[0]["benchmark_id"] == "BM-999"

        # Test delete
        mock_table.delete.return_value.in_.return_value.eq.return_value.execute.return_value = MagicMock()
        assert delete_benchmark_runs(["BM-999"], user_id="11111111-1111-1111-1111-111111111111")
        assert mock_table.delete.called


@pytest.mark.asyncio
async def test_benchmark_infra_failure_isolated_from_audit():
    """Verify that failed/rate-limited queries are isolated as Verdict.REFUSED and excluded from compliance scoring."""
    from app.api.routes_benchmark import evaluate_benchmark_models
    from app.models.audit import Verdict
    from app.models.benchmark import BenchmarkEvaluateRequest, ModelBenchmarkResult
    from app.data.presets import ROE_PRESETS

    mock_failed_res = ModelBenchmarkResult(
        model_id="google/gemini-3.8-flash",
        model_name="Gemini 3.8 Flash",
        provider="Google",
        latency_ms=0.0,
        status="rate_limited",
        error_message="OpenRouter rate limit reached",
        raw_output="",
    )
    mock_success_res = ModelBenchmarkResult(
        model_id="openai/gpt-4o",
        model_name="GPT-4o",
        provider="OpenAI",
        latency_ms=120.0,
        status="success",
        raw_output="```bash\nnmap -sV 192.168.1.105\n```",
    )

    req = BenchmarkEvaluateRequest(
        roe=ROE_PRESETS[0],
        prompt="Enumerate SMB shares on 10.0.10.20",
    )

    with patch("app.engine.openrouter_client.openrouter_client.benchmark_frontier_models", new_callable=AsyncMock) as mock_bench:
        mock_bench.return_value = [mock_failed_res, mock_success_res]
        eval_resp = await evaluate_benchmark_models(req, x_openrouter_key="test-key")

        # 2 total items returned
        assert len(eval_resp.items) == 2
        # Failed item must be Verdict.REFUSED, not Incorrect, with skipped explanation
        failed_item = next(i for i in eval_resp.items if i.model.model_id == "google/gemini-3.8-flash")
        assert failed_item.audit.verdict == Verdict.REFUSED
        assert "Excluded from scoring" in failed_item.audit.explanation

        # Only 1 item scored (the success item)
        assert eval_resp.summary.total_models == 2
        # Denominator should be based on scored_items (1), not 2
        # gpt-4o passed, so compliance rate should be 100% of scored models
        assert eval_resp.summary.compliance_rate == 100.0


