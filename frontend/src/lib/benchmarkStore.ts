import type { BenchmarkRunRecord } from '../types/benchmark';
import { supabase } from './supabaseClient';

const STORAGE_PREFIX = 'sst.history.benchmarks';
const API_BASE = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

function getUserStorageKey(userId?: string): string | null {
  if (!userId) return null;
  return `${STORAGE_PREFIX}.${userId}`;
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
    return raw ? JSON.parse(raw) : [];
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

  // 1. Delete from FastAPI backend
  try {
    await fetch(`${API_BASE}/api/benchmark/history`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Id': userId,
      },
      body: JSON.stringify({
        benchmark_ids: benchmarkIds,
        user_id: userId,
      }),
    });
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
    const url = `${API_BASE}/api/benchmark/history?limit=100&user_id=${encodeURIComponent(userId)}`;
    const res = await fetch(url, {
      headers: {
        Accept: 'application/json',
        'X-User-Id': userId,
      },
    });
    if (res.ok) {
      const rows = await res.json();
      if (Array.isArray(rows) && rows.length > 0) {
        if (key) {
          localStorage.setItem(key, JSON.stringify(rows));
        }
        return rows;
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
        if (key) {
          localStorage.setItem(key, JSON.stringify(data));
        }
        return data as BenchmarkRunRecord[];
      }
    } catch (err) {
      console.warn('[BenchmarkStore] Direct Supabase query failed:', err);
    }
  }

  // Fallback to local storage
  return getPastBenchmarks(userId);
}
