import { useEffect, useState } from 'react';
import { clearApiKey, getApiKey, getStorageMode, maskKey, saveApiKey, type KeyStorageMode } from '../lib/keyStore';
import { KeyIcon, XIcon } from './Icons';

export function SettingsModal({ onClose }: { onClose: () => void }) {
  const [mode, setMode] = useState<KeyStorageMode>(getStorageMode());
  const [draft, setDraft] = useState('');
  const [stored, setStored] = useState<string | null>(getApiKey());

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  function save() {
    const key = draft.trim();
    if (!key) return;
    saveApiKey(key, mode);
    setStored(key);
    setDraft('');
  }

  function clear() {
    clearApiKey();
    setStored(null);
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
        <div className="modal__head">
          <h2 className="card__title row" id="settings-title">
            <KeyIcon /> API keys
          </h2>
          <button className="btn btn--ghost btn--icon" aria-label="Close settings" onClick={onClose}>
            <XIcon />
          </button>
        </div>

        <div className="modal__body">
          <p className="muted" style={{ fontSize: 13, marginBottom: 14 }}>
            Bring your own OpenRouter key to compare models. Keys stay in this browser and are never stored or logged by SST.
          </p>

          <div className="field">
            <label className="field__label" htmlFor="api-key-input">
              <span>OpenRouter API key</span>
              {stored ? <span className="mono">saved: {maskKey(stored)}</span> : null}
            </label>
            <input
              id="api-key-input"
              className="input mono"
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder="sk-or-v1-…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
          </div>

          <p className="section-label">Storage</p>
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
          <button id="clear-keys" className="btn btn--danger" onClick={clear} disabled={!stored}>
            Clear keys
          </button>
          <div className="row">
            <button className="btn" onClick={onClose}>Close</button>
            <button id="save-key" className="btn btn--primary" onClick={save} disabled={!draft.trim()}>
              Save key
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
