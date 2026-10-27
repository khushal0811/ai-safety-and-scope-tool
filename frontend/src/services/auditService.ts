import type { AuditRequest, AuditResult, RoeScope } from '../types/audit';
import { runDemoAudit } from './demoEngine';
import { ROE_PRESETS } from '../data/presets';

/**
 * Single entry point the UI uses for safety and scope audits.
 *
 * Phase 2+: Automatically connects to the FastAPI verification engine
 * at VITE_API_BASE_URL (defaults to http://localhost:8000).
 * Gracefully falls back to the client-side demo engine if the backend is offline.
 */
export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

let _liveBackendAvailable: boolean | null = null;
const _listeners: Set<(live: boolean) => void> = new Set();

export function subscribeLiveStatus(callback: (live: boolean) => void): () => void {
  _listeners.add(callback);
  if (_liveBackendAvailable !== null) {
    callback(_liveBackendAvailable);
  }
  return () => _listeners.delete(callback);
}

function notifyStatus(isLive: boolean) {
  if (_liveBackendAvailable !== isLive) {
    _liveBackendAvailable = isLive;
    _listeners.forEach((cb) => cb(isLive));
  }
}

export function isLiveMode(): boolean {
  return _liveBackendAvailable ?? false;
}

/**
 * Perform health probe against the backend verification service.
 */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(2500),
    });
    if (res.ok) {
      notifyStatus(true);
      return true;
    }
  } catch {
    // Backend unreachable
  }
  notifyStatus(false);
  return false;
}

// Initial eager probe on module initialization
if (typeof window !== 'undefined') {
  checkBackendHealth().catch(() => {});
}

/**
 * Fetch authoritative RoE presets from backend, falling back to local presets.
 */
export async function fetchRoePresets(): Promise<RoeScope[]> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/roe/presets`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      return (await res.json()) as RoeScope[];
    }
  } catch {
    // Fallback to local
  }
  return ROE_PRESETS;
}

/**
 * Audit model output against RoE rules.
 */
export async function runAudit(req: AuditRequest): Promise<AuditResult> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/audit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(10000),
    });

    if (res.ok) {
      const data = (await res.json()) as AuditResult;
      notifyStatus(true);
      return data;
    }
  } catch (err) {
    console.warn('[SST] Live backend audit request failed, falling back to demo engine:', err);
    notifyStatus(false);
  }

  // Graceful fallback to client-side deterministic demo engine
  await new Promise((r) => setTimeout(r, 450));
  return runDemoAudit(req);
}

/**
 * Parse raw pasted RoE text using backend LLM extraction.
 */
export async function parseRoeText(content: string, filename?: string): Promise<RoeScope> {
  const res = await fetch(`${API_BASE_URL}/api/roe/parse-text`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ content, filename: filename || 'custom_roe.md' }),
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to parse RoE document' }));
    throw new Error(err.detail || 'Failed to parse RoE document');
  }

  notifyStatus(true);
  return (await res.json()) as RoeScope;
}

/**
 * Upload and parse an RoE file (.md or .txt) using backend LLM extraction.
 */
export async function parseRoeFile(file: File): Promise<RoeScope> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE_URL}/api/roe/parse-document`, {
    method: 'POST',
    body: formData,
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to parse RoE file' }));
    throw new Error(err.detail || 'Failed to parse RoE file');
  }

  notifyStatus(true);
  return (await res.json()) as RoeScope;
}

