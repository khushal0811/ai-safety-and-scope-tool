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

/**
 * Completely wipe API keys from client session and delete the row from the Supabase database vault.
 */
export async function revokeAndWipeUserKeys(userId?: string): Promise<{ success: boolean; error?: string }> {
  clearAllKeys();
  if (!userId || !supabase) {
    return { success: true };
  }
  try {
    const { error } = await supabase.from('user_api_vault').delete().eq('user_id', userId);
    if (error) {
      // In offline mode or table not yet migrated, log warning but local keys are still wiped
      console.warn('Database key vault delete notice:', error.message);
      return { success: true, error: error.message };
    }
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Failed to revoke keys' };
  }
}

export function maskKey(key: string): string {
  if (!key) return '';
  return key.length <= 10 ? '••••••' : `${key.slice(0, 6)}…${key.slice(-4)}`;
}
