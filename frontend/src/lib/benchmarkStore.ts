import type { BenchmarkRunRecord } from '../types/benchmark';
import { supabase, getAuthHeaders } from './supabaseClient';

const STORAGE_PREFIX = 'sst.history.benchmarks';
const API_BASE = (
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_API_BASE_URL ||
  ''
).replace(/\/+$/, '');

function apiUrl(path: string): string | null {
  return API_BASE ? `${API_BASE}${path}` : null;
}

async function getScopedAuthHeaders(): Promise<Record<string, string>> {
  if (!API_BASE) return {};
  return getAuthHeaders();
}

function getUserStorageKey(userId?: string): string | null {
  if (!userId) return null;
  return `${STORAGE_PREFIX}.${userId}`;
}

export function isBenchmarkRunRecord(value: unknown): value is BenchmarkRunRecord {
  if (!value || typeof value !== 'object') return false;
  const v = value as Partial<BenchmarkRunRecord>;
  return (
    typeof v.benchmark_id === 'string' &&
    typeof v.created_at === 'string' &&
    typeof v.scenario_title === 'string' &&
    !!v.summary &&
    typeof v.summary === 'object' &&
    Array.isArray(v.items)
  );
}

function parseStoredBenchmarks(raw: string | null): BenchmarkRunRecord[] {
  if (!raw) return [];
  const parsed: unknown = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed.filter(isBenchmarkRunRecord) : [];
}

/**
 * Retrieve past benchmark runs for an authenticated user from local storage cache.
 * STRICT PRIVACY RULE: Guests have no saved benchmarks.
 */
export function getPastBenchmarks(userId?: string): BenchmarkRunRecord[] {
  const key = getUserStorageKey(userId);
  if (!key) {
    return [];
  }
  try {
    const raw = localStorage.getItem(key);
    return parseStoredBenchmarks(raw);
  } catch {
    return [];
  }
}

/**
 * Save a benchmark record under the authenticated user's ID.
 */
export function savePastBenchmark(run: BenchmarkRunRecord, userId?: string): BenchmarkRunRecord[] {
  const key = getUserStorageKey(userId);
  if (!key) {
    return [];
  }
  const current = getPastBenchmarks(userId);
  const updated = [run, ...current.filter((r) => r.benchmark_id !== run.benchmark_id)];
  try {
    localStorage.setItem(key, JSON.stringify(updated));
  } catch (err) {
    console.error('[BenchmarkStore] Failed to save benchmark to cache:', err);
  }
  return updated;
}

/**
 * Clear benchmark history for an authenticated user.
 */
export function clearPastBenchmarks(userId?: string): void {
  const key = getUserStorageKey(userId);
  if (key) {
    localStorage.removeItem(key);
  }
  localStorage.removeItem(STORAGE_PREFIX);
  localStorage.removeItem('vallum.benchmark_history');
}

/**
 * Permanently delete selected benchmark runs from database and local cache.
 */
export async function deletePastBenchmarks(benchmarkIds: string[], userId?: string): Promise<BenchmarkRunRecord[]> {
  if (!userId || benchmarkIds.length === 0) {
    return [];
  }

  // 1. Delete from FastAPI backend (only for a configured origin)
  try {
    const url = apiUrl('/api/benchmark/history');
    if (url) {
      const authHeaders = await getScopedAuthHeaders();
      await fetch(url, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders,
        },
        body: JSON.stringify({
          benchmark_ids: benchmarkIds,
        }),
      });
    }
  } catch (err) {
    console.warn('[BenchmarkStore] FastAPI delete failed:', err);
  }

  // 2. Direct Supabase delete if table exists
  if (supabase) {
    try {
      await supabase
        .from('benchmark_runs')
        .delete()
        .eq('user_id', userId)
        .in('benchmark_id', benchmarkIds);
    } catch (err) {
      console.warn('[BenchmarkStore] Direct Supabase delete failed:', err);
    }
  }

  // 3. Update local cache
  const key = getUserStorageKey(userId);
  const current = getPastBenchmarks(userId);
  const toDeleteSet = new Set(benchmarkIds);
  const updated = current.filter((r) => !toDeleteSet.has(r.benchmark_id));
  if (key) {
    try {
      localStorage.setItem(key, JSON.stringify(updated));
    } catch {
      // ignore
    }
  }

  return updated;
}

/**
 * Synchronize benchmark history with PostgreSQL cloud database / backend repository.
 */
export async function syncPastBenchmarksFromCloud(userId?: string): Promise<BenchmarkRunRecord[]> {
  if (!userId) {
    return [];
  }

  const key = getUserStorageKey(userId);

  // Attempt 1: Fetch via FastAPI backend endpoint
  try {
    const url = apiUrl('/api/benchmark/history?limit=100');
    if (url) {
      const authHeaders = await getScopedAuthHeaders();
      const res = await fetch(url, {
        headers: {
          Accept: 'application/json',
          ...authHeaders,
        },
      });
      if (res.ok) {
        const rows: unknown = await res.json();
        const records = Array.isArray(rows) ? rows.filter(isBenchmarkRunRecord) : [];
        if (records.length > 0) {
          if (key) {
            localStorage.setItem(key, JSON.stringify(records));
          }
          return records;
        }
      }
    }
  } catch (err) {
    console.warn('[BenchmarkStore] Backend fetch failed, checking Supabase direct:', err);
  }

  // Attempt 2: Direct Supabase query
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('benchmark_runs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(100);

      if (!error && Array.isArray(data) && data.length > 0) {
        const records = data.filter(isBenchmarkRunRecord);
        if (key) {
          localStorage.setItem(key, JSON.stringify(records));
        }
        return records;
      }
    } catch (err) {
      console.warn('[BenchmarkStore] Direct Supabase query failed:', err);
    }
  }

  // Fallback to local storage
  return getPastBenchmarks(userId);
}
