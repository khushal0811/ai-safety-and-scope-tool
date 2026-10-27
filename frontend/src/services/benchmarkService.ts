import type { RoeScope, AuditResult } from '../types/audit';
import { API_BASE_URL } from './auditService';
import { getOpenRouterKey, getGroqKey } from '../lib/keyStore';

export interface FrontierModelInfo {
  id: string;
  name: string;
  provider: string;
  context_length: number;
  description: string;
  tier: string;
  recommended: boolean;
}

export interface ModelBenchmarkResult {
  model_id: string;
  model_name: string;
  provider: string;
  latency_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  raw_output: string;
  extracted_commands: string[];
  status: 'success' | 'rate_limited' | 'unauthorized' | 'error';
  error_message?: string | null;
}

export interface BenchmarkQueryResponse {
  timestamp: string;
  prompt: string;
  results: ModelBenchmarkResult[];
}

export interface BenchmarkEvaluateItem {
  model: ModelBenchmarkResult;
  audit: AuditResult;
}

export interface BenchmarkSummary {
  total_models: number;
  correct_count: number;
  unsafe_count: number;
  incorrect_count: number;
  compliance_rate: number;
  scope_violation_rate: number;
  hallucination_rate: number;
  average_latency_ms: number;
  fastest_model?: string | null;
}

export interface BenchmarkEvaluateResponse {
  timestamp: string;
  roe_id: string;
  prompt: string;
  items: BenchmarkEvaluateItem[];
  summary: BenchmarkSummary;
}

function getBenchmarkHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  const openRouter = getOpenRouterKey();
  if (openRouter) {
    headers['X-OpenRouter-Key'] = openRouter;
  }
  const groq = getGroqKey();
  if (groq) {
    headers['X-Groq-Key'] = groq;
  }
  return headers;
}

/**
 * Fetch supported frontier models for benchmarking.
 */
export async function fetchBenchmarkModels(): Promise<FrontierModelInfo[]> {
  const res = await fetch(`${API_BASE_URL}/api/benchmark/models`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) {
    throw new Error('Failed to load benchmark models');
  }
  return (await res.json()) as FrontierModelInfo[];
}

/**
 * Query one or all frontier models via OpenRouter.
 */
export async function queryBenchmark(
  prompt: string,
  modelId?: string,
  systemPrompt?: string
): Promise<BenchmarkQueryResponse> {
  const res = await fetch(`${API_BASE_URL}/api/benchmark/query`, {
    method: 'POST',
    headers: getBenchmarkHeaders(),
    body: JSON.stringify({
      prompt,
      model_id: modelId,
      system_prompt: systemPrompt,
    }),
    signal: AbortSignal.timeout(60000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Benchmark query failed' }));
    throw new Error(err.detail || 'Benchmark query failed');
  }

  return (await res.json()) as BenchmarkQueryResponse;
}

/**
 * Benchmark frontier models and simultaneously evaluate outputs against RoE.
 */
export async function evaluateBenchmark(
  roe: RoeScope,
  prompt: string,
  models?: string[]
): Promise<BenchmarkEvaluateResponse> {
  const res = await fetch(`${API_BASE_URL}/api/benchmark/evaluate`, {
    method: 'POST',
    headers: getBenchmarkHeaders(),
    body: JSON.stringify({
      roe,
      prompt,
      models,
    }),
    signal: AbortSignal.timeout(90000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Benchmark evaluation failed' }));
    throw new Error(err.detail || 'Benchmark evaluation failed');
  }

  return (await res.json()) as BenchmarkEvaluateResponse;
}
