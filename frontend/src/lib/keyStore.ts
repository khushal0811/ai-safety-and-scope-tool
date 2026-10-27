/**
 * User-supplied API keys. Security invariant: keys are NEVER sent to the SST
 * backend for storage, NEVER written to localStorage and NEVER logged.
 *   - 'session': sessionStorage, wiped when the tab closes
 *   - 'memory' : module variable, wiped on page reload
 */
export type KeyStorageMode = 'session' | 'memory';

const KEY_NAME = 'sst.openrouter_key';
const MODE_NAME = 'sst.key_storage_mode';
let memoryKey: string | null = null;

export function getStorageMode(): KeyStorageMode {
  return sessionStorage.getItem(MODE_NAME) === 'session' ? 'session' : 'memory';
}

export function getApiKey(): string | null {
  return getStorageMode() === 'session' ? sessionStorage.getItem(KEY_NAME) : memoryKey;
}

export function saveApiKey(key: string, mode: KeyStorageMode): void {
  clearApiKey();
  sessionStorage.setItem(MODE_NAME, mode);
  if (mode === 'session') sessionStorage.setItem(KEY_NAME, key);
  else memoryKey = key;
}

export function clearApiKey(): void {
  memoryKey = null;
  sessionStorage.removeItem(KEY_NAME);
}

export function maskKey(key: string): string {
  return key.length <= 10 ? '••••••' : `${key.slice(0, 6)}…${key.slice(-4)}`;
}
