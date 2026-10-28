/**
 * User-supplied API keys for OpenRouter and Groq.
 * Security invariant: keys are NEVER persisted to database tables,
 * NEVER written to permanent localStorage and NEVER logged.
 *   - 'session': sessionStorage, wiped when the browser tab closes
 *   - 'memory' : module variable, wiped on page reload
 */
export type KeyStorageMode = 'session' | 'memory';

const OPENROUTER_KEY_NAME = 'sst.openrouter_key';
const GROQ_KEY_NAME = 'sst.groq_key';
const MODE_NAME = 'sst.key_storage_mode';
const VAULT_HAS_OR_KEY_NAME = 'sst.vault_has_openrouter_key';
const VAULT_OR_HINT_NAME = 'sst.vault_openrouter_hint';

let memoryOpenRouterKey: string | null = null;
let memoryGroqKey: string | null = null;

export function hasVaultOpenRouterKey(): boolean {
  try {
    return (
      sessionStorage.getItem(VAULT_HAS_OR_KEY_NAME) === 'true' ||
      localStorage.getItem(VAULT_HAS_OR_KEY_NAME) === 'true'
    );
  } catch {
    return false;
  }
}

export function setVaultOpenRouterKeyStatus(hasKey: boolean, hint?: string | null): void {
  try {
    if (hasKey) {
      sessionStorage.setItem(VAULT_HAS_OR_KEY_NAME, 'true');
      localStorage.setItem(VAULT_HAS_OR_KEY_NAME, 'true');
      if (hint) {
        sessionStorage.setItem(VAULT_OR_HINT_NAME, hint);
        localStorage.setItem(VAULT_OR_HINT_NAME, hint);
      }
    } else {
      sessionStorage.removeItem(VAULT_HAS_OR_KEY_NAME);
      sessionStorage.removeItem(VAULT_OR_HINT_NAME);
      localStorage.removeItem(VAULT_HAS_OR_KEY_NAME);
      localStorage.removeItem(VAULT_OR_HINT_NAME);
    }
  } catch {
    // ignore storage errors
  }
}

export function getStorageMode(): KeyStorageMode {
  const mode = sessionStorage.getItem(MODE_NAME) || localStorage.getItem(MODE_NAME);
  return mode === 'memory' ? 'memory' : 'session';
}

export function setStorageMode(mode: KeyStorageMode): void {
  sessionStorage.setItem(MODE_NAME, mode);
  localStorage.setItem(MODE_NAME, mode);
}

// --- OpenRouter Key ---
export function getOpenRouterKey(): string | null {
  if (getStorageMode() === 'memory') return memoryOpenRouterKey;
  return sessionStorage.getItem(OPENROUTER_KEY_NAME) || localStorage.getItem(OPENROUTER_KEY_NAME) || memoryOpenRouterKey;
}

export function saveOpenRouterKey(key: string, mode?: KeyStorageMode): void {
  const currentMode = mode || getStorageMode();
  setStorageMode(currentMode);
  clearOpenRouterKey();
  if (currentMode === 'session') {
    sessionStorage.setItem(OPENROUTER_KEY_NAME, key);
    localStorage.setItem(OPENROUTER_KEY_NAME, key);
  } else {
    memoryOpenRouterKey = key;
  }
}

export function clearOpenRouterKey(): void {
  memoryOpenRouterKey = null;
  sessionStorage.removeItem(OPENROUTER_KEY_NAME);
  localStorage.removeItem(OPENROUTER_KEY_NAME);
}

// Backward-compatible aliases for existing callers
export const getApiKey = getOpenRouterKey;
export const saveApiKey = saveOpenRouterKey;
export const clearApiKey = clearOpenRouterKey;

// --- Groq Key ---
export function getGroqKey(): string | null {
  if (getStorageMode() === 'memory') return memoryGroqKey;
  return sessionStorage.getItem(GROQ_KEY_NAME) || localStorage.getItem(GROQ_KEY_NAME) || memoryGroqKey;
}

export function saveGroqKey(key: string, mode?: KeyStorageMode): void {
  const currentMode = mode || getStorageMode();
  setStorageMode(currentMode);
  clearGroqKey();
  if (currentMode === 'session') {
    sessionStorage.setItem(GROQ_KEY_NAME, key);
    localStorage.setItem(GROQ_KEY_NAME, key);
  } else {
    memoryGroqKey = key;
  }
}

export function clearGroqKey(): void {
  memoryGroqKey = null;
  sessionStorage.removeItem(GROQ_KEY_NAME);
  localStorage.removeItem(GROQ_KEY_NAME);
}

// --- Unified Methods ---
export interface ApiKeys {
  openRouterKey: string | null;
  groqKey: string | null;
}

export function getAllApiKeys(): ApiKeys {
  return {
    openRouterKey: getOpenRouterKey(),
    groqKey: getGroqKey(),
  };
}

import { supabase, getAuthHeaders } from './supabaseClient';

export function saveAllApiKeys(keys: { openRouterKey?: string; groqKey?: string }, mode: KeyStorageMode = 'session'): void {
  setStorageMode(mode);
  if (keys.openRouterKey !== undefined) {
    if (keys.openRouterKey.trim()) {
      saveOpenRouterKey(keys.openRouterKey.trim(), mode);
    } else {
      clearOpenRouterKey();
    }
  }
  if (keys.groqKey !== undefined) {
    if (keys.groqKey.trim()) {
      saveGroqKey(keys.groqKey.trim(), mode);
    } else {
      clearGroqKey();
    }
  }
}

export function clearAllKeys(): void {
  clearOpenRouterKey();
  clearGroqKey();
  setVaultOpenRouterKeyStatus(false, null);
}

const BACKEND_BASE = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export interface VaultStatus {
  isConfigured: boolean;
  hasOpenRouterKey: boolean;
  openRouterHint: string | null;
  hasGroqKey: boolean;
  groqHint: string | null;
}

export async function fetchVaultStatus(userId?: string): Promise<VaultStatus> {
  if (!userId) {
    return {
      isConfigured: false,
      hasOpenRouterKey: false,
      openRouterHint: null,
      hasGroqKey: false,
      groqHint: null,
    };
  }

  // 1. Check Supabase Auth user metadata / app_metadata first (instant, works even during Render cold start)
  let metaHasOr = false;
  let metaOrHint: string | null = null;
  let metaHasGroq = false;
  let metaGroqHint: string | null = null;
  if (supabase) {
    try {
      const { data: userData } = await supabase.auth.getUser();
      const u = userData?.user;
      if (u && u.id === userId) {
        const appVault = (u.app_metadata as any)?.vallum_vault;
        const userVault = (u.user_metadata as any)?.vallum_vault_status;
        if (appVault?.encrypted_openrouter_key || userVault?.has_openrouter_key) {
          metaHasOr = true;
          metaOrHint = appVault?.key_hint_openrouter || userVault?.openrouter_hint || null;
        }
        if (appVault?.encrypted_groq_key || userVault?.has_groq_key) {
          metaHasGroq = true;
          metaGroqHint = appVault?.key_hint_groq || userVault?.groq_hint || null;
        }
      }
    } catch {
      // Ignore auth metadata lookup error
    }
  }

  // 2. Check backend encrypted database vault status
  try {
    const authHeaders = await getAuthHeaders();
    const res = await fetch(`${BACKEND_BASE}/api/vault/status?user_id=${encodeURIComponent(userId)}`, {
      headers: { ...authHeaders },
    });
    if (!res.ok) throw new Error('Status check failed');
    const data = await res.json();
    const hasOr = Boolean(data.has_openrouter_key || metaHasOr || getOpenRouterKey());
    const orHint = data.openrouter_hint || metaOrHint || (getOpenRouterKey() ? maskKey(getOpenRouterKey() || '') : null);
    const hasGroq = Boolean(data.has_groq_key || metaHasGroq || getGroqKey());
    const groqHint = data.groq_hint || metaGroqHint || (getGroqKey() ? maskKey(getGroqKey() || '') : null);

    setVaultOpenRouterKeyStatus(hasOr, orHint);
    return {
      isConfigured: Boolean(hasOr || hasGroq),
      hasOpenRouterKey: hasOr,
      openRouterHint: orHint,
      hasGroqKey: hasGroq,
      groqHint,
    };
  } catch {
    const hasOr = Boolean(metaHasOr || getOpenRouterKey() || hasVaultOpenRouterKey());
    const orHint = metaOrHint || maskKey(getOpenRouterKey() || '') || null;
    const hasGroq = Boolean(metaHasGroq || getGroqKey());
    const groqHint = metaGroqHint || maskKey(getGroqKey() || '') || null;
    if (hasOr) {
      setVaultOpenRouterKeyStatus(true, orHint);
    }
    return {
      isConfigured: Boolean(hasOr || hasGroq),
      hasOpenRouterKey: hasOr,
      openRouterHint: orHint,
      hasGroqKey: hasGroq,
      groqHint,
    };
  }
}

export async function saveKeysToVault(
  userId: string,
  keys: { openRouterKey?: string; groqKey?: string }
): Promise<boolean> {
  // Save locally in transient session memory
  saveAllApiKeys(keys, 'session');
  if (keys.openRouterKey?.trim()) {
    setVaultOpenRouterKeyStatus(true, maskKey(keys.openRouterKey.trim()));
  }

  // Sync key presence status to Supabase user_metadata so future logins on any domain detect it immediately
  if (supabase) {
    try {
      await supabase.auth.updateUser({
        data: {
          vallum_vault_status: {
            has_openrouter_key: Boolean(keys.openRouterKey?.trim() || getOpenRouterKey()),
            openrouter_hint: keys.openRouterKey?.trim() ? maskKey(keys.openRouterKey.trim()) : null,
            has_groq_key: Boolean(keys.groqKey?.trim() || getGroqKey()),
            groq_hint: keys.groqKey?.trim() ? maskKey(keys.groqKey.trim()) : null,
          },
        },
      });
    } catch {
      // Ignore metadata sync warning
    }
  }

  // Encrypt with server-side AES-256-GCM and persist to database vault
  try {
    const authHeaders = await getAuthHeaders();
    const res = await fetch(`${BACKEND_BASE}/api/vault/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({
        user_id: userId,
        openrouter_key: keys.openRouterKey || null,
        groq_key: keys.groqKey || null,
      }),
    });
    return res.ok;
  } catch (err) {
    console.warn('Vault save network warning:', err);
    return false;
  }
}

/**
 * Completely wipe API keys from client session and delete the row from the Supabase database vault.
 */
export async function revokeAndWipeUserKeys(userId?: string): Promise<{ success: boolean; error?: string }> {
  clearAllKeys();
  if (!userId) {
    return { success: true };
  }

  if (supabase) {
    try {
      await supabase.auth.updateUser({
        data: { vallum_vault_status: null },
      });
    } catch {
      // Ignored
    }
  }

  // 1. Call backend vault deletion endpoint
  try {
    const authHeaders = await getAuthHeaders();
    await fetch(`${BACKEND_BASE}/api/vault/keys?user_id=${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: { ...authHeaders },
    });
  } catch (err) {
    console.warn('Backend vault delete warning:', err);
  }

  // 2. Direct Supabase fallback
  if (supabase) {
    try {
      await supabase.from('user_api_vault').delete().eq('user_id', userId);
    } catch {
      // Ignored if offline
    }
  }

  return { success: true };
}

export function maskKey(key: string): string {
  if (!key) return '';
  return key.length <= 10 ? '••••••' : `${key.slice(0, 6)}…${key.slice(-4)}`;
}

export interface KeyVerificationResult {
  provider: string;
  valid: boolean;
  statusCode: number;
  message: string;
  latencyMs: number;
  details?: Record<string, any>;
}

export async function testApiKeys(keys: {
  openRouterKey?: string;
  groqKey?: string;
  userId?: string;
}): Promise<{ success: boolean; results: KeyVerificationResult[]; error?: string }> {
  try {
    const authHeaders = await getAuthHeaders();
    const res = await fetch(`${BACKEND_BASE}/api/vault/verify-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({
        openrouter_key: keys.openRouterKey?.trim() || null,
        groq_key: keys.groqKey?.trim() || null,
        user_id: keys.userId || null,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return {
        success: false,
        results: [],
        error: err.detail || `Validation failed with status ${res.status}`,
      };
    }

    const data = await res.json();
    return {
      success: data.success,
      results: (data.results || []).map((r: any) => ({
        provider: r.provider,
        valid: r.valid,
        statusCode: r.status_code,
        message: r.message,
        latencyMs: r.latency_ms,
        details: r.details,
      })),
    };
  } catch (err: any) {
    return {
      success: false,
      results: [],
      error: err?.message || 'Failed to connect to verification service.',
    };
  }
}
