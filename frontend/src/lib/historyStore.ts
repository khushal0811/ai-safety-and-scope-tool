import type { PastAudit } from '../types/history';
import { supabase, getAuthHeaders } from './supabaseClient';

const STORAGE_PREFIX = 'sst.history.audits';
// Deployment config sets VITE_API_URL; VITE_API_BASE_URL remains a legacy alias.
// An empty base means "no backend configured" and must never fall back to localhost,
// because that would leak the Supabase bearer token to a local process (AUDIT_004 H2).
const API_BASE = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');

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

export function isPastAudit(value: unknown): value is PastAudit {
  if (!value || typeof value !== 'object') return false;
  const v = value as Partial<PastAudit>;
  return (
    typeof v.id === 'string' &&
    typeof v.timestamp === 'string' &&
    typeof v.roeId === 'string' &&
    typeof v.modelId === 'string' &&
    typeof v.prompt === 'string' &&
    !!v.result &&
    typeof v.result === 'object' &&
    Array.isArray(v.result.targets) &&
    Array.isArray(v.result.violation_details)
  );
}

function parseStoredAudits(raw: string | null): PastAudit[] {
  if (!raw) return [];
  const parsed: unknown = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed.filter(isPastAudit) : [];
}

/**
 * Convert a Supabase audit_logs PostgreSQL row into a frontend PastAudit object
 */
export function dbRecordToPastAudit(row: any): PastAudit {
  const modelName = row.selected_model
    ? row.selected_model.replace('openai/', '').replace('meta-llama/', '')
    : 'Language Model';

  return {
    id: row.audit_id || row.id,
    timestamp: row.created_at || new Date().toISOString(),
    roeId: row.roe_id || 'UNKNOWN',
    roeName: row.roe_id || 'Canonical Scope',
    modelId: row.selected_model || 'unknown',
    modelName,
    prompt: row.user_prompt || '',
    proposedCommand:
      Array.isArray(row.extracted_commands) && row.extracted_commands[0]
        ? row.extracted_commands[0]
        : row.raw_model_output || '',
    executionTimeMs: row.execution_time_ms || 0,
    result: {
      audit_id: row.audit_id || row.id,
      timestamp: row.created_at || new Date().toISOString(),
      mode: row.mode || 'live',
      selected_model: row.selected_model || 'unknown',
      user_prompt: row.user_prompt || '',
      raw_model_output: row.raw_model_output || '',
      extracted_commands: row.extracted_commands || [],
      targets: row.targets || [],
      verdict: row.verdict || 'Unsafe',
      violation_details: row.violation_details || [],
      safe_sanitized_command: row.safe_sanitized_command || null,
      modifications_made: row.modifications_made || [],
      explanation: row.explanation || '',
    },
  };
}

/**
 * Retrieve past audits for an authenticated user.
 * STRICT PRIVACY RULE: Guests have no saved audits. Returns [] for guests with 0 storage or cookie usage.
 */
export function getPastAudits(userId?: string): PastAudit[] {
  const key = getUserStorageKey(userId);
  if (!key) {
    return [];
  }
  try {
    const raw = localStorage.getItem(key);
    return parseStoredAudits(raw);
  } catch {
    return [];
  }
}

/**
 * Save an audit record strictly under the authenticated user's ID.
 * STRICT PRIVACY RULE: Does not save anything for guests.
 */
export function savePastAudit(audit: PastAudit, userId?: string): PastAudit[] {
  const key = getUserStorageKey(userId);
  if (!key) {
    return [];
  }
  const current = getPastAudits(userId);
  const updated = [audit, ...current.filter((a) => a.id !== audit.id)];
  try {
    localStorage.setItem(key, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to save audit history:', err);
  }
  return updated;
}

/**
 * Clear audit history for an authenticated user.
 */
export function clearPastAudits(userId?: string): void {
  const key = getUserStorageKey(userId);
  if (key) {
    localStorage.removeItem(key);
  }
  // Clear any legacy global storage keys
  localStorage.removeItem(STORAGE_PREFIX);
}

/**
 * Permanently delete selected audits from the cloud database and local cache.
 */
export async function deletePastAudits(auditIds: string[], userId?: string): Promise<PastAudit[]> {
  if (!userId || auditIds.length === 0) {
    return [];
  }

  // 1. Delete from Backend FastAPI endpoint (only for a configured origin)
  try {
    const url = apiUrl('/api/audit/history');
    if (url) {
      const authHeaders = await getScopedAuthHeaders();
      await fetch(url, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({
          audit_ids: auditIds,
          user_id: userId,
        }),
      });
    }
  } catch (err) {
    console.warn('[HistoryStore] FastAPI delete failed:', err);
  }

  // 2. Direct Supabase delete as immediate guarantee
  if (supabase) {
    try {
      await supabase
        .from('audit_logs')
        .delete()
        .eq('user_id', userId)
        .in('audit_id', auditIds);
    } catch (err) {
      console.warn('[HistoryStore] Direct Supabase delete failed:', err);
    }
  }

  // 3. Update local cache / storage
  const key = getUserStorageKey(userId);
  const current = getPastAudits(userId);
  const toDeleteSet = new Set(auditIds);
  const updated = current.filter((a) => !toDeleteSet.has(a.id));
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
 * Synchronize audit history with Supabase PostgreSQL cloud database.
 * STRICT PRIVACY RULE: Returns [] immediately if not authenticated as a registered user.
 */
export async function syncPastAuditsFromCloud(userId?: string): Promise<PastAudit[]> {
  if (!userId) {
    // Guest mode: zero audits, zero memory/cookies/cloud queries
    return [];
  }

  const key = getUserStorageKey(userId);

  try {
    // Attempt 1: Fetch via FastAPI backend endpoint filtered by user_id
    const url = apiUrl(`/api/audit/history?limit=100&user_id=${encodeURIComponent(userId)}`);
    if (url) {
      const authHeaders = await getScopedAuthHeaders();
      const res = await fetch(url, {
        headers: { ...authHeaders },
      });
      if (res.ok) {
        const rows = await res.json();
        if (Array.isArray(rows)) {
          const cloudAudits = rows.map(dbRecordToPastAudit).filter(isPastAudit);
          if (key) {
            localStorage.setItem(key, JSON.stringify(cloudAudits));
          }
          return cloudAudits;
        }
      }
    }
  } catch (err) {
    console.warn('[Sync] FastAPI audit history fetch failed, trying direct Supabase:', err);
  }

  // Attempt 2: Direct Supabase query strictly filtered by user_id
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(100);

      if (!error && Array.isArray(data)) {
        const cloudAudits = data.map(dbRecordToPastAudit).filter(isPastAudit);
        if (key) {
          localStorage.setItem(key, JSON.stringify(cloudAudits));
        }
        return cloudAudits;
      }
    } catch (err) {
      console.warn('[Sync] Supabase direct query failed:', err);
    }
  }

  // Fallback to authenticated user's local cache
  return getPastAudits(userId);
}

/**
 * Fetch aggregated audit metrics for an authenticated user from cloud database.
 * STRICT PRIVACY RULE: Returns zeroed metrics for guests.
 */
export async function fetchCloudMetrics(userId?: string): Promise<{
  total: number;
  unsafe: number;
  correct: number;
  incorrect: number;
  pass_rate: number;
  avg_latency_ms: number;
} | null> {
  if (!userId) {
    return { total: 0, unsafe: 0, correct: 0, incorrect: 0, pass_rate: 0, avg_latency_ms: 0 };
  }

  try {
    const url = apiUrl(`/api/audit/metrics?user_id=${encodeURIComponent(userId)}`);
    if (url) {
      const authHeaders = await getScopedAuthHeaders();
      const res = await fetch(url, {
        headers: { ...authHeaders },
      });
      if (res.ok) {
        return await res.json();
      }
    }
  } catch (err) {
    console.warn('[Metrics] Failed to fetch cloud metrics:', err);
  }
  return null;
}
