import type { RoeScope } from '../types/audit';
import type {
  BenchmarkEvaluateResponse,
  BenchmarkRunRecord,
  FrontierModelInfo,
} from '../types/benchmark';
import { getOpenRouterKey, getGroqKey } from '../lib/keyStore';
import { isBenchmarkRunRecord } from '../lib/benchmarkStore';
import { getStoredAuthToken } from '../lib/supabaseClient';

const BACKEND_BASE = (
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_API_BASE_URL ||
  ''
).replace(/\/+$/, '');

function requireBackend(): string {
  if (!BACKEND_BASE) {
    throw new Error('Backend API URL is not configured. Set VITE_API_URL for this deployment.');
  }
  return BACKEND_BASE;
}

function keyTransportIsSecure(): boolean {
  if (BACKEND_BASE.startsWith('https://')) return true;
  if (!import.meta.env.DEV) return false;
  try {
    const host = new URL(BACKEND_BASE, window.location.origin).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch {
    return false;
  }
}

function getBenchmarkHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  const token = getStoredAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  const orKey = getOpenRouterKey();
  const groqKey = getGroqKey();
  if (orKey || groqKey) {
    if (!keyTransportIsSecure()) {
      throw new Error('Refusing to send a provider API key over a non-HTTPS connection.');
    }
    if (orKey) headers['X-OpenRouter-Key'] = orKey;
    if (groqKey) headers['X-Groq-Key'] = groqKey;
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
    id: 'anthropic/claude-sonnet-4.6',
    name: 'Claude Sonnet 4.6',
    provider: 'Anthropic',
    context_length: 1000000,
    description: 'Flagship frontier model for complex reasoning and cybersecurity tool analysis.',
    tier: 'frontier',
    recommended: true,
  },
  {
    id: 'google/gemini-3.8-flash',
    name: 'Gemini 3.8 Flash',
    provider: 'Google',
    context_length: 1000000,
    description: 'High-speed multimodal frontier model by Google with low latency and high reasoning fidelity.',
    tier: 'frontier',
    recommended: true,
  },
  {
    id: 'anthropic/claude-haiku-5.5',
    name: 'Claude Haiku 5.5',
    provider: 'Anthropic',
    context_length: 200000,
    description: 'Fast, highly efficient Anthropic frontier model with cutting-edge reasoning and tool capabilities.',
    tier: 'frontier',
    recommended: true,
  },
  {
    id: 'deepseek/deepseek-v4.1-flash',
    name: 'DeepSeek V4.1 Flash',
    provider: 'DeepSeek',
    context_length: 1000000,
    description: 'Cost-efficient frontier reasoning model; pinned to max-effort thinking for methodical pentest command synthesis.',
    tier: 'frontier',
    recommended: true,
  },
];

/**
 * Fetch supported frontier models from backend.
 */
export async function getBenchmarkModels(): Promise<FrontierModelInfo[]> {
  if (!BACKEND_BASE) return FALLBACK_FRONTIER_MODELS;
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
  _userId?: string
): Promise<BenchmarkEvaluateResponse> {
  const payload = {
    roe,
    prompt,
    models: models && models.length > 0 ? models : undefined,
    scenario_title: scenarioTitle || 'Custom Benchmark',
    temperature: 0.0,
  };

  const res = await fetch(`${requireBackend()}/api/benchmark/evaluate`, {
    method: 'POST',
    headers: getBenchmarkHeaders(),
    body: JSON.stringify(payload),
    // Bound the wait so a stalled backend cannot leave the run spinning forever
    signal: AbortSignal.timeout(180_000),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Benchmark evaluation failed (${res.status}): ${errText}`);
  }

  const result: BenchmarkEvaluateResponse = await res.json();
  return result;
}

const LOCAL_BENCHMARK_PREFIX = 'vallum.benchmark_history';

function localBenchmarkKey(userId?: string): string | null {
  return userId ? `${LOCAL_BENCHMARK_PREFIX}.${userId}` : null;
}

function readLocalBenchmarkHistory(userId?: string): BenchmarkRunRecord[] {
  const key = localBenchmarkKey(userId);
  if (!key) return [];
  try {
    const raw = localStorage.getItem(key);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed)
      ? parsed.filter(isBenchmarkRunRecord)
      : [];
  } catch {
    return [];
  }
}

/**
 * Fetch historical benchmark runs for the current user.
 */
export async function getBenchmarkHistory(userId?: string): Promise<BenchmarkRunRecord[]> {
  if (!userId) return [];

  if (BACKEND_BASE) {
    try {
      const res = await fetch(`${BACKEND_BASE}/api/benchmark/history?limit=100`, {
        method: 'GET',
        headers: getBenchmarkHeaders(),
      });
      if (res.ok) {
        const parsed: unknown = await res.json();
        const records = Array.isArray(parsed)
          ? parsed.filter(isBenchmarkRunRecord)
          : [];
        const key = localBenchmarkKey(userId);
        if (key) localStorage.setItem(key, JSON.stringify(records));
        return records;
      }
    } catch (err) {
      console.warn('[BenchmarkService] Failed to fetch remote benchmark history:', err);
    }
  }

  return readLocalBenchmarkHistory(userId);
}

/**
 * Permanently delete selected benchmark runs from Supabase PostgreSQL and local storage.
 */
export async function deleteBenchmarkRuns(benchmarkIds: string[], userId?: string): Promise<boolean> {
  if (!userId || benchmarkIds.length === 0) return false;

  let backendSuccess = true;
  if (BACKEND_BASE) {
    try {
      const res = await fetch(`${BACKEND_BASE}/api/benchmark/history`, {
        method: 'DELETE',
        headers: getBenchmarkHeaders(),
        body: JSON.stringify({ benchmark_ids: benchmarkIds }),
      });
      backendSuccess = res.ok;
    } catch (err) {
      console.warn('[BenchmarkService] Remote delete failed:', err);
      backendSuccess = false;
    }
  }

  // Update only this user's local cache
  const key = localBenchmarkKey(userId);
  if (key) {
    try {
      const current = readLocalBenchmarkHistory(userId);
      const updated = current.filter((item) => !benchmarkIds.includes(item.benchmark_id));
      localStorage.setItem(key, JSON.stringify(updated));
    } catch {
      // Ignore storage errors
    }
  }

  return backendSuccess;
}
