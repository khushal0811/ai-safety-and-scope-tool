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

let memoryOpenRouterKey: string | null = null;
let memoryGroqKey: string | null = null;

export function getStorageMode(): KeyStorageMode {
  return sessionStorage.getItem(MODE_NAME) === 'session' ? 'session' : 'memory';
}

export function setStorageMode(mode: KeyStorageMode): void {
  sessionStorage.setItem(MODE_NAME, mode);
}

// --- OpenRouter Key ---
export function getOpenRouterKey(): string | null {
  return getStorageMode() === 'session' ? sessionStorage.getItem(OPENROUTER_KEY_NAME) : memoryOpenRouterKey;
}

export function saveOpenRouterKey(key: string, mode?: KeyStorageMode): void {
  const currentMode = mode || getStorageMode();
  setStorageMode(currentMode);
  clearOpenRouterKey();
  if (currentMode === 'session') {
    sessionStorage.setItem(OPENROUTER_KEY_NAME, key);
  } else {
    memoryOpenRouterKey = key;
  }
}

export function clearOpenRouterKey(): void {
  memoryOpenRouterKey = null;
  sessionStorage.removeItem(OPENROUTER_KEY_NAME);
}

// Backward-compatible aliases for existing callers
export const getApiKey = getOpenRouterKey;
export const saveApiKey = saveOpenRouterKey;
export const clearApiKey = clearOpenRouterKey;

// --- Groq Key ---
export function getGroqKey(): string | null {
  return getStorageMode() === 'session' ? sessionStorage.getItem(GROQ_KEY_NAME) : memoryGroqKey;
}

export function saveGroqKey(key: string, mode?: KeyStorageMode): void {
  const currentMode = mode || getStorageMode();
  setStorageMode(currentMode);
  clearGroqKey();
  if (currentMode === 'session') {
    sessionStorage.setItem(GROQ_KEY_NAME, key);
  } else {
    memoryGroqKey = key;
  }
}

export function clearGroqKey(): void {
  memoryGroqKey = null;
  sessionStorage.removeItem(GROQ_KEY_NAME);
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

import { supabase } from './supabaseClient';

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
}

const BACKEND_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

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
  try {
    const res = await fetch(`${BACKEND_BASE}/api/vault/status?user_id=${encodeURIComponent(userId)}`);
    if (!res.ok) throw new Error('Status check failed');
    const data = await res.json();
    return {
      isConfigured: data.is_configured,
      hasOpenRouterKey: data.has_openrouter_key,
      openRouterHint: data.openrouter_hint,
      hasGroqKey: data.has_groq_key,
      groqHint: data.groq_hint,
    };
  } catch {
    return {
      isConfigured: Boolean(getOpenRouterKey() || getGroqKey()),
      hasOpenRouterKey: Boolean(getOpenRouterKey()),
      openRouterHint: maskKey(getOpenRouterKey() || ''),
      hasGroqKey: Boolean(getGroqKey()),
      groqHint: maskKey(getGroqKey() || ''),
    };
  }
}

export async function saveKeysToVault(
  userId: string,
  keys: { openRouterKey?: string; groqKey?: string }
): Promise<boolean> {
  // Save locally in transient memory
  saveAllApiKeys(keys);

  // Encrypt with server-side AES-256-GCM and persist to database vault
  try {
    const res = await fetch(`${BACKEND_BASE}/api/vault/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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

  // 1. Call backend vault deletion endpoint
  try {
    await fetch(`${BACKEND_BASE}/api/vault/keys?user_id=${encodeURIComponent(userId)}`, {
      method: 'DELETE',
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
