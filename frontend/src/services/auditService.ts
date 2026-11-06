import type { AuditRequest, AuditResult, RoeScope, TargetFinding, Violation } from '../types/audit';
import type { SandboxDryRunResult } from '../types/sandbox';
import { getOpenRouterKey, getGroqKey } from '../lib/keyStore';
import { getStoredAuthToken } from '../lib/supabaseClient';

export const API_BASE_URL: string = (
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_API_BASE_URL ||
  ''
).replace(/\/+$/, '');

function requireApiBase(): string {
  if (!API_BASE_URL) {
    throw new Error('Backend API URL is not configured. Set VITE_API_URL for this deployment.');
  }
  return API_BASE_URL;
}

function keyTransportIsSecure(): boolean {
  if (API_BASE_URL.startsWith('https://')) return true;
  if (!import.meta.env.DEV) return false;
  try {
    const host = new URL(API_BASE_URL, window.location.origin).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

export function isRoeScope(value: unknown): value is RoeScope {
  if (!isRecord(value)) return false;
  return (
    typeof value.roe_id === 'string' &&
    typeof value.name === 'string' &&
    typeof value.engagement_type === 'string' &&
    typeof value.summary === 'string' &&
    isStringArray(value.allowed_cidrs) &&
    isStringArray(value.allowed_domains) &&
    isStringArray(value.target_hosts) &&
    isStringArray(value.prohibited_ips) &&
    isStringArray(value.allowed_tools) &&
    isStringArray(value.prohibited_tools) &&
    isStringArray(value.prohibited_flags) &&
    isStringArray(value.prohibited_actions) &&
    typeof value.max_nmap_timing === 'number' &&
    Number.isFinite(value.max_nmap_timing)
  );
}

function isTargetFinding(value: unknown): value is TargetFinding {
  if (!isRecord(value)) return false;
  return (
    typeof value.token === 'string' &&
    typeof value.normalized === 'string' &&
    isOneOf(value.kind, ['ip', 'cidr', 'domain'] as const) &&
    isOneOf(value.status, ['in_scope', 'out_of_scope', 'prohibited'] as const) &&
    typeof value.obfuscated === 'boolean'
  );
}

function isViolation(value: unknown): value is Violation {
  if (!isRecord(value)) return false;
  return (
    typeof value.rule === 'string' &&
    isOneOf(value.category, ['scope', 'destructive', 'policy', 'accuracy'] as const) &&
    isOneOf(value.severity, ['CRITICAL', 'WARNING', 'INFO'] as const) &&
    typeof value.detail === 'string' &&
    (value.command === undefined || typeof value.command === 'string')
  );
}

export function isAuditResult(value: unknown): value is AuditResult {
  if (!isRecord(value)) return false;
  return (
    typeof value.audit_id === 'string' &&
    typeof value.timestamp === 'string' &&
    isOneOf(value.mode, ['demo', 'live'] as const) &&
    typeof value.selected_model === 'string' &&
    typeof value.user_prompt === 'string' &&
    typeof value.raw_model_output === 'string' &&
    isStringArray(value.extracted_commands) &&
    Array.isArray(value.targets) &&
    value.targets.every(isTargetFinding) &&
    isOneOf(value.verdict, ['Correct', 'Incorrect', 'Unsafe', 'Refused'] as const) &&
    Array.isArray(value.violation_details) &&
    value.violation_details.every(isViolation) &&
    (value.safe_sanitized_command === null || typeof value.safe_sanitized_command === 'string') &&
    isStringArray(value.modifications_made) &&
    typeof value.explanation === 'string' &&
    (value.trust_tier === undefined ||
      isOneOf(value.trust_tier, ['hybrid', 'deterministic'] as const)) &&
    (value.ai_judge_notes === undefined || isStringArray(value.ai_judge_notes))
  );
}

export function isSandboxDryRunResult(value: unknown): value is SandboxDryRunResult {
  if (!isRecord(value)) return false;
  const isolation = value.isolation;
  return (
    typeof value.command === 'string' &&
    typeof value.tool === 'string' &&
    typeof value.syntax_valid === 'boolean' &&
    typeof value.exit_code === 'number' &&
    typeof value.sandbox_tier === 'string' &&
    isRecord(isolation) &&
    typeof isolation.network_isolated === 'boolean' &&
    typeof isolation.network_egress === 'string' &&
    typeof isolation.packets_transmitted === 'number' &&
    typeof isolation.zero_host_execution === 'boolean' &&
    typeof isolation.filesystem_mode === 'string' &&
    isStringArray(value.diagnostics) &&
    typeof value.simulated_stdout === 'string' &&
    typeof value.simulated_stderr === 'string' &&
    typeof value.elapsed_ms === 'number'
  );
}

/**
 * Signed-in callers authenticate with the JWT only; the backend resolves the
 * provider key from the encrypted vault. Guest BYOK is the only path that sends
 * a provider key, and never over plaintext (AUDIT_004 M1).
 */
function getApiHeaders(json = true): Record<string, string> {
  const headers: Record<string, string> = json
    ? { 'Content-Type': 'application/json', Accept: 'application/json' }
    : { Accept: 'application/json' };

  const token = getStoredAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  const openRouter = getOpenRouterKey();
  const groq = getGroqKey();
  if (openRouter || groq) {
    if (!keyTransportIsSecure()) {
      throw new Error('Refusing to send a provider API key over a non-HTTPS connection.');
    }
    if (openRouter) headers['X-OpenRouter-Key'] = openRouter;
    if (groq) headers['X-Groq-Key'] = groq;
  }
  return headers;
}

/**
 * Single entry point the UI uses for safety and scope audits.
 *
 * Connects to the FastAPI verification engine at VITE_API_URL. No implicit
 * localhost fallback: an unconfigured build fails closed instead of sending
 * credentials to whatever happens to listen on the developer port.
 */

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
  if (!API_BASE_URL) {
    notifyStatus(false);
    return false;
  }
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
 * Fetch one saved custom RoE so a historical audit can restore its scope.
 * Presets were removed; scope definitions are custom-only.
 */
export async function fetchCustomRoeById(roeId: string): Promise<RoeScope | null> {
  if (!API_BASE_URL || !roeId) return null;
  try {
    const res = await fetch(`${API_BASE_URL}/api/roe/custom/${encodeURIComponent(roeId)}`, {
      headers: getApiHeaders(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data: unknown = await res.json();
    return isRoeScope(data) ? data : null;
  } catch {
    return null;
  }
}

/**
 * Audit model output against RoE rules.
 */
export async function runAudit(req: AuditRequest, _userId?: string): Promise<AuditResult> {
  const url = `${requireApiBase()}/api/audit`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: getApiHeaders(),
      body: JSON.stringify(req),
      // Full AI override can take longer than a minute on long outputs.
      signal: AbortSignal.timeout(180000),
    });

    if (res.ok) {
      const data: unknown = await res.json();
      if (!isAuditResult(data)) {
        throw new Error('Backend returned a malformed audit result.');
      }
      notifyStatus(true);
      return data;
    }

    const errText = await res.text().catch(() => '');
    notifyStatus(false);
    throw new Error(`Audit backend returned HTTP ${res.status}: ${errText.slice(0, 300)}`);
  } catch (err) {
    notifyStatus(false);
    throw err instanceof Error ? err : new Error('Failed to reach the audit backend.');
  }
}

/**
 * Parse raw pasted RoE text using backend LLM extraction.
 */
export async function parseRoeText(content: string, filename?: string, _userId?: string): Promise<RoeScope> {
  const url = `${requireApiBase()}/api/roe/parse-text`;
  const res = await fetch(url, {
    method: 'POST',
    headers: getApiHeaders(),
    body: JSON.stringify({ content, filename: filename || 'custom_roe.md' }),
    signal: AbortSignal.timeout(180000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to parse RoE document' }));
    throw new Error(err.detail || 'Failed to parse RoE document');
  }

  const data: unknown = await res.json();
  if (!isRoeScope(data)) {
    throw new Error('Backend returned a malformed RoE scope.');
  }
  notifyStatus(true);
  return data;
}

/**
 * Query a selected model live via the backend benchmark endpoint.
 * Frontier models (GPT-4o, Claude Sonnet 4.6, Gemini 3.8 Flash, Claude Haiku 5.5,
 * DeepSeek V4.1 Flash) run on the user's OpenRouter key; server keys are disabled
 * for user tasks.
 */
export async function queryLiveModel(
  prompt: string,
  modelId: string,
  _userId?: string
): Promise<{ text: string; latencyMs: number; error?: string }> {
  if (!API_BASE_URL) {
    return { text: '', latencyMs: 0, error: 'Backend API URL is not configured for this deployment.' };
  }
  const headers = getApiHeaders();

  try {
    const res = await fetch(`${API_BASE_URL}/api/benchmark/query`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        prompt,
        model_id: modelId,
        temperature: 0.2,
      }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return {
        text: '',
        latencyMs: 0,
        error: errData.detail || `Query failed with HTTP status ${res.status}`,
      };
    }

    const data = await res.json();
    const result = data.results?.[0];
    if (!result) {
      return { text: '', latencyMs: 0, error: 'No model result returned' };
    }

    if (result.status === 'unauthorized') {
      return {
        text: '',
        latencyMs: 0,
        error: result.error_message || 'Model requires an OpenRouter API key. Configure your key in Settings.',
      };
    }

    return {
      text: result.raw_output || (result.extracted_commands?.join('\n') ?? ''),
      latencyMs: result.latency_ms || 0,
      error: result.error_message || undefined,
    };
  } catch (err: any) {
    return {
      text: '',
      latencyMs: 0,
      error: err?.message || 'Failed to connect to backend model query endpoint',
    };
  }
}

/**
 * Phase 4.4: Download formal, client-ready RoE compliance attestation report
 * with cryptographic SHA-256 hash chains (PDF, Markdown, or JSON).
 */
export async function downloadComplianceReport(
  roeId: string,
  format: 'pdf' | 'markdown' | 'json' = 'pdf',
  _userId?: string,
  auditId?: string
): Promise<void> {
  const params = new URLSearchParams({
    roe_id: roeId,
    format: format,
  });
  if (auditId) {
    params.set('audit_id', auditId);
  }

  const url = `${requireApiBase()}/api/audit/report?${params.toString()}`;
  const token = getStoredAuthToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Failed to generate compliance report: HTTP ${res.status} ${errText.slice(0, 200)}`);
  }

  const blob = await res.blob();
  const disposition = res.headers.get('content-disposition');
  let filename = `vallum_attestation_${roeId.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}.${format === 'markdown' ? 'md' : format}`;
  if (disposition) {
    const match = disposition.match(/filename="?([^";]+)"?/i);
    if (match && match[1]) {
      filename = match[1];
    }
  }

  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(blobUrl);
}

/**
 * Phase 4.5: Execute pre-flight syntax and parameter dry-run in the
 * network-egress disabled ephemeral micro-sandbox.
 */
export async function executeSandboxDryRun(
  command: string,
  roeId?: string,
  strictSyntax: boolean = true
): Promise<SandboxDryRunResult> {
  if (!roeId) {
    throw new Error('A parsed custom scope is required for a sandbox dry-run.');
  }
  const url = `${requireApiBase()}/api/sandbox/dry-run`;
  const res = await fetch(url, {
    method: 'POST',
    headers: getApiHeaders(),
    body: JSON.stringify({
      command,
      roe_id: roeId,
      strict_syntax: strictSyntax,
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Micro-sandbox evaluation failed: HTTP ${res.status} ${errText.slice(0, 200)}`);
  }

  const data: unknown = await res.json();
  if (!isSandboxDryRunResult(data)) {
    throw new Error('Backend returned a malformed sandbox result.');
  }
  notifyStatus(true);
  return data;
}


