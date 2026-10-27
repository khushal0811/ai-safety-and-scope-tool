import { useEffect, useState } from 'react';
import {
  clearAllKeys,
  getOpenRouterKey,
  getGroqKey,
  saveAllApiKeys,
  getStorageMode,
  maskKey,
  type KeyStorageMode,
} from '../lib/keyStore';
import { KeyIcon, XIcon } from './Icons';

export function SettingsModal({ onClose }: { onClose: () => void }) {
  const [mode, setMode] = useState<KeyStorageMode>(getStorageMode());
  const [draftOpenRouter, setDraftOpenRouter] = useState('');
  const [draftGroq, setDraftGroq] = useState('');
  const [storedOpenRouter, setStoredOpenRouter] = useState<string | null>(getOpenRouterKey());
  const [storedGroq, setStoredGroq] = useState<string | null>(getGroqKey());

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  function save() {
    saveAllApiKeys(
      {
        openRouterKey: draftOpenRouter ? draftOpenRouter.trim() : (storedOpenRouter || undefined),
        groqKey: draftGroq ? draftGroq.trim() : (storedGroq || undefined),
      },
      mode
    );
    if (draftOpenRouter.trim()) setStoredOpenRouter(draftOpenRouter.trim());
    if (draftGroq.trim()) setStoredGroq(draftGroq.trim());
    setDraftOpenRouter('');
    setDraftGroq('');
  }

  function clear() {
    clearAllKeys();
    setStoredOpenRouter(null);
    setStoredGroq(null);
    setDraftOpenRouter('');
    setDraftGroq('');
  }

  const hasAnyKey = Boolean(storedOpenRouter || storedGroq || draftOpenRouter.trim() || draftGroq.trim());
  const canSave = Boolean(draftOpenRouter.trim() || draftGroq.trim());

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
        <div className="modal__head">
          <h2 className="card__title row" id="settings-title">
            <KeyIcon /> API Keys Vault
          </h2>
          <button className="btn btn--ghost btn--icon" aria-label="Close settings" onClick={onClose}>
            <XIcon />
          </button>
        </div>

        <div className="modal__body">
          <p className="muted" style={{ fontSize: 13, marginBottom: 14 }}>
            Bring your own OpenRouter and Groq keys to power frontier model benchmarking and instant extraction. Keys stay in this browser and are never logged or stored by SST.
          </p>

          <div className="field">
            <label className="field__label" htmlFor="openrouter-key-input">
              <span>OpenRouter API Key</span>
              {storedOpenRouter ? <span className="mono font-xs tag tag--ok">saved: {maskKey(storedOpenRouter)}</span> : <span className="mono font-xs text-muted">sk-or-v1-...</span>}
            </label>
            <input
              id="openrouter-key-input"
              className="input mono"
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder={storedOpenRouter ? '••••••••••••••••' : 'sk-or-v1-...'}
              value={draftOpenRouter}
              onChange={(e) => setDraftOpenRouter(e.target.value)}
            />
          </div>

          <div className="field">
            <label className="field__label" htmlFor="groq-key-input">
              <span>Groq API Key</span>
              {storedGroq ? <span className="mono font-xs tag tag--ok">saved: {maskKey(storedGroq)}</span> : <span className="mono font-xs text-muted">gsk_...</span>}
            </label>
            <input
              id="groq-key-input"
              className="input mono"
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder={storedGroq ? '••••••••••••••••' : 'gsk_...'}
              value={draftGroq}
              onChange={(e) => setDraftGroq(e.target.value)}
            />
          </div>

          <p className="section-label">Storage Isolation</p>
          <div className="radio-row">
            <label className="radio-card">
              <input type="radio" name="key-mode" checked={mode === 'memory'} onChange={() => setMode('memory')} />
              <span>
                <strong>Memory only</strong>
                Cleared on reload
              </span>
            </label>
            <label className="radio-card">
              <input type="radio" name="key-mode" checked={mode === 'session'} onChange={() => setMode('session')} />
              <span>
                <strong>Session</strong>
                Cleared when tab closes
              </span>
            </label>
          </div>
        </div>

        <div className="modal__foot">
          <button id="clear-keys" className="btn btn--danger" onClick={clear} disabled={!hasAnyKey}>
            Clear keys
          </button>
          <div className="row">
            <button className="btn" onClick={onClose}>Close</button>
            <button id="save-key" className="btn btn--primary" onClick={save} disabled={!canSave}>
              Save keys
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
