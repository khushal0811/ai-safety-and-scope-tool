import type { RoeScope } from '../types/audit';
import type {
  BenchmarkEvaluateResponse,
  BenchmarkRunRecord,
  FrontierModelInfo,
} from '../types/benchmark';
import { getOpenRouterKey, getGroqKey } from '../lib/keyStore';
import { getCurrentUser } from '../lib/authStore';

const BACKEND_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function getBenchmarkHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  const orKey = getOpenRouterKey();
  if (orKey) {
    headers['X-OpenRouter-Key'] = orKey;
  }
  const groqKey = getGroqKey();
  if (groqKey) {
    headers['X-Groq-Key'] = groqKey;
  }
  const user = getCurrentUser();
  if (user && user.id) {
    headers['X-User-Id'] = user.id;
  }
  return headers;
}

export const FALLBACK_FRONTIER_MODELS: FrontierModelInfo[] = [
  {
    id: 'openai/gpt-4o',
    name: 'GPT-4o',
    provider: 'OpenAI',
    context_length: 128000,
    description: 'Flagship multimodal frontier model with advanced code reasoning.',
    tier: 'frontier',
    recommended: true,
  },
  {
    id: 'anthropic/claude-3.5-sonnet',
    name: 'Claude 3.5 Sonnet',
    provider: 'Anthropic',
    context_length: 200000,
    description: 'Leading frontier model for complex logic and cybersecurity tool analysis.',
    tier: 'frontier',
    recommended: true,
  },
  {
    id: 'google/gemini-pro-1.5',
    name: 'Gemini 1.5 Pro',
    provider: 'Google',
    context_length: 2000000,
    description: 'Extreme 2M-token context window with deep multi-pass reasoning.',
    tier: 'frontier',
    recommended: true,
  },
  {
    id: 'meta-llama/llama-3.1-70b-instruct',
    name: 'Llama 3.3 70B',
    provider: 'Meta',
    context_length: 128000,
    description: 'State-of-the-art open-weights model, backed by system Groq inference.',
    tier: 'frontier',
    recommended: true,
  },
];

/**
 * Fetch supported frontier models from backend.
 */
export async function getBenchmarkModels(): Promise<FrontierModelInfo[]> {
  try {
    const res = await fetch(`${BACKEND_BASE}/api/benchmark/models`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('[BenchmarkService] Failed to load remote models, using fallbacks:', err);
  }
  return FALLBACK_FRONTIER_MODELS;
}

/**
 * Run parallel multi-LLM benchmark evaluation against active RoE.
 */
export async function evaluateBenchmark(
  roe: RoeScope,
  prompt: string,
  models?: string[],
  scenarioTitle?: string,
  userId?: string
): Promise<BenchmarkEvaluateResponse> {
  const payload = {
    roe,
    prompt,
    models: models && models.length > 0 ? models : undefined,
    scenario_title: scenarioTitle || 'Custom Benchmark',
    temperature: 0.0,
  };

  const effectiveUserId = userId || getCurrentUser()?.id;
  const url = effectiveUserId
    ? `${BACKEND_BASE}/api/benchmark/evaluate?user_id=${encodeURIComponent(effectiveUserId)}`
    : `${BACKEND_BASE}/api/benchmark/evaluate`;

  const res = await fetch(url, {
    method: 'POST',
    headers: getBenchmarkHeaders(),
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Benchmark evaluation failed (${res.status}): ${errText}`);
  }

  const result: BenchmarkEvaluateResponse = await res.json();
  return result;
}

const LOCAL_BENCHMARK_KEY = 'vallum.benchmark_history';

/**
 * Fetch historical benchmark runs for the current user.
 */
export async function getBenchmarkHistory(userId?: string): Promise<BenchmarkRunRecord[]> {
  const effectiveUserId = userId || getCurrentUser()?.id;
  if (effectiveUserId) {
    try {
      const url = `${BACKEND_BASE}/api/benchmark/history?user_id=${encodeURIComponent(effectiveUserId)}`;
      const res = await fetch(url, {
        method: 'GET',
        headers: getBenchmarkHeaders(),
      });
      if (res.ok) {
        const records: BenchmarkRunRecord[] = await res.json();
        // Update local cache
        localStorage.setItem(LOCAL_BENCHMARK_KEY, JSON.stringify(records));
        return records;
      }
    } catch (err) {
      console.warn('[BenchmarkService] Failed to fetch remote benchmark history:', err);
    }
  }

  // Fallback to local storage
  try {
    const raw = localStorage.getItem(LOCAL_BENCHMARK_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/**
 * Permanently delete selected benchmark runs from Supabase PostgreSQL and local storage.
 */
export async function deleteBenchmarkRuns(benchmarkIds: string[], userId?: string): Promise<boolean> {
  let backendSuccess = true;
  const effectiveUserId = userId || getCurrentUser()?.id;

  if (effectiveUserId && benchmarkIds.length > 0) {
    try {
      const url = `${BACKEND_BASE}/api/benchmark/history?user_id=${encodeURIComponent(effectiveUserId)}`;
      const res = await fetch(url, {
        method: 'DELETE',
        headers: getBenchmarkHeaders(),
        body: JSON.stringify({ benchmark_ids: benchmarkIds, user_id: effectiveUserId }),
      });
      backendSuccess = res.ok;
    } catch (err) {
      console.warn('[BenchmarkService] Remote delete failed:', err);
      backendSuccess = false;
    }
  }

  // Update local storage
  try {
    const raw = localStorage.getItem(LOCAL_BENCHMARK_KEY);
    if (raw) {
      const current: BenchmarkRunRecord[] = JSON.parse(raw);
      const updated = current.filter((item) => !benchmarkIds.includes(item.benchmark_id));
      localStorage.setItem(LOCAL_BENCHMARK_KEY, JSON.stringify(updated));
    }
  } catch {
    // Ignore storage errors
  }

  return backendSuccess;
}
