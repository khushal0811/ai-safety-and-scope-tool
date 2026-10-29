/**
 * User-supplied API keys for OpenRouter and Groq.
 * Security invariant: Raw API keys are NEVER written to localStorage or sessionStorage,
 * and NEVER logged. Client-side keys live strictly in volatile in-memory variables
 * for the active tab lifecycle; durable storage goes strictly through the FastAPI
 * backend's AES-256-GCM encrypted vault (`POST /api/vault/keys`).
 */
import { supabase, getAuthHeaders } from './supabaseClient';

export type KeyStorageMode = 'memory' | 'session';

const OPENROUTER_KEY_NAME = 'sst.openrouter_key';
const GROQ_KEY_NAME = 'sst.groq_key';
const MODE_NAME = 'sst.key_storage_mode';
const VAULT_HAS_OR_KEY_NAME = 'sst.vault_has_openrouter_key';
const VAULT_OR_HINT_NAME = 'sst.vault_openrouter_hint';

let memoryOpenRouterKey: string | null = null;
let memoryGroqKey: string | null = null;

// One-time migration cleanup: purge any legacy plaintext keys that earlier builds
// may have written to browser storage.
try {
  if (typeof window !== 'undefined') {
    sessionStorage.removeItem(OPENROUTER_KEY_NAME);
    localStorage.removeItem(OPENROUTER_KEY_NAME);
    sessionStorage.removeItem(GROQ_KEY_NAME);
    localStorage.removeItem(GROQ_KEY_NAME);
    sessionStorage.removeItem(MODE_NAME);
    localStorage.removeItem(MODE_NAME);
  }
} catch {
  // ignore storage errors in restricted environments
}

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
  return 'memory';
}

export function setStorageMode(_mode: KeyStorageMode): void {
  // No-op: raw key storage is strictly memory-only on the client.
}

// --- OpenRouter Key ---
export function getOpenRouterKey(): string | null {
  return memoryOpenRouterKey;
}

export function saveOpenRouterKey(key: string, _mode?: KeyStorageMode): void {
  const trimmed = key.trim();
  memoryOpenRouterKey = trimmed || null;
}

export function clearOpenRouterKey(): void {
  memoryOpenRouterKey = null;
  try {
    sessionStorage.removeItem(OPENROUTER_KEY_NAME);
    localStorage.removeItem(OPENROUTER_KEY_NAME);
  } catch {
    // ignore
  }
}

// Backward-compatible aliases for existing callers
export const getApiKey = getOpenRouterKey;
export const saveApiKey = saveOpenRouterKey;
export const clearApiKey = clearOpenRouterKey;

// --- Groq Key ---
export function getGroqKey(): string | null {
  return memoryGroqKey;
}

export function saveGroqKey(key: string, _mode?: KeyStorageMode): void {
  const trimmed = key.trim();
  memoryGroqKey = trimmed || null;
}

export function clearGroqKey(): void {
  memoryGroqKey = null;
  try {
    sessionStorage.removeItem(GROQ_KEY_NAME);
    localStorage.removeItem(GROQ_KEY_NAME);
  } catch {
    // ignore
  }
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

export function saveAllApiKeys(
  keys: { openRouterKey?: string; groqKey?: string },
  _mode?: KeyStorageMode
): void {
  if (keys.openRouterKey !== undefined) {
    if (keys.openRouterKey.trim()) {
      saveOpenRouterKey(keys.openRouterKey.trim());
    } else {
      clearOpenRouterKey();
    }
  }
  if (keys.groqKey !== undefined) {
    if (keys.groqKey.trim()) {
      saveGroqKey(keys.groqKey.trim());
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

  // 1. Check Supabase Auth user metadata / app_metadata first (non-sensitive presence & masked hint only)
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

  // 2. Check backend encrypted database vault status (authenticated via Bearer JWT)
  try {
    const authHeaders = await getAuthHeaders();
    const res = await fetch(`${BACKEND_BASE}/api/vault/status`, {
      headers: { ...authHeaders },
    });
    if (!res.ok) throw new Error('Status check failed');
    const data = await res.json();
    const hasOr = Boolean(data.has_openrouter_key || metaHasOr);
    const orHint = data.openrouter_hint || metaOrHint || null;
    const hasGroq = Boolean(data.has_groq_key || metaHasGroq);
    const groqHint = data.groq_hint || metaGroqHint || null;

    setVaultOpenRouterKeyStatus(hasOr, orHint);
    return {
      isConfigured: Boolean(hasOr || hasGroq),
      hasOpenRouterKey: hasOr,
      openRouterHint: orHint,
      hasGroqKey: hasGroq,
      groqHint,
    };
  } catch {
    const hasOr = Boolean(metaHasOr || hasVaultOpenRouterKey());
    const orHint = metaOrHint || null;
    const hasGroq = Boolean(metaHasGroq);
    const groqHint = metaGroqHint || null;
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
  _userId: string,
  keys: { openRouterKey?: string; groqKey?: string }
): Promise<boolean> {
  // Hold in volatile in-memory variable for immediate session requests
  saveAllApiKeys(keys);
  if (keys.openRouterKey?.trim()) {
    setVaultOpenRouterKeyStatus(true, maskKey(keys.openRouterKey.trim()));
  }

  // Sync non-sensitive key presence hint to Supabase Auth user_metadata
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

  // Encrypt with server-side AES-256-GCM and persist to database vault via backend
  try {
    const authHeaders = await getAuthHeaders();
    const res = await fetch(`${BACKEND_BASE}/api/vault/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({
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
 * Completely wipe API keys from client memory and delete the row from the backend database vault.
 */
export async function revokeAndWipeUserKeys(_userId?: string): Promise<{ success: boolean; error?: string }> {
  clearAllKeys();

  if (supabase) {
    try {
      await supabase.auth.updateUser({
        data: { vallum_vault_status: null },
      });
    } catch {
      // Ignored
    }
  }

  try {
    const authHeaders = await getAuthHeaders();
    if (Object.keys(authHeaders).length === 0) {
      return { success: true };
    }
    const res = await fetch(`${BACKEND_BASE}/api/vault/keys`, {
      method: 'DELETE',
      headers: { ...authHeaders },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return {
        success: false,
        error: err.detail || `Failed to revoke keys (HTTP ${res.status})`,
      };
    }
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Failed to reach backend to revoke keys.',
    };
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
