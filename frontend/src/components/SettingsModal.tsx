import { useEffect, useState } from 'react';
import {
  clearAllKeys,
  getOpenRouterKey,
  getGroqKey,
  saveAllApiKeys,
  revokeAndWipeUserKeys,
  maskKey,
} from '../lib/keyStore';
import { getStoredAuthToken } from '../lib/supabaseClient';
import { KeyIcon, XIcon } from './Icons';

export function SettingsModal({ onClose }: { onClose: () => void }) {
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
    saveAllApiKeys({
      openRouterKey: draftOpenRouter ? draftOpenRouter.trim() : (storedOpenRouter || undefined),
      groqKey: draftGroq ? draftGroq.trim() : (storedGroq || undefined),
    });
    if (draftOpenRouter.trim()) setStoredOpenRouter(draftOpenRouter.trim());
    if (draftGroq.trim()) setStoredGroq(draftGroq.trim());
    setDraftOpenRouter('');
    setDraftGroq('');
  }

  async function clear() {
    if (getStoredAuthToken()) {
      const res = await revokeAndWipeUserKeys();
      if (!res.success) {
        window.alert(res.error || 'Could not delete the vault key.');
        return;
      }
    } else {
      clearAllKeys();
    }
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
          {/* Option 1: System Key */}
          <div
            style={{
              padding: '10px 12px',
              borderRadius: 'var(--radius)',
              background: 'var(--surface-sunken)',
              border: '1px solid var(--border)',
              marginBottom: 14,
            }}
          >
            <div className="row between" style={{ marginBottom: 4 }}>
              <strong style={{ fontSize: 13 }}>Option 1: Built-in System Key</strong>
              <span className="tag tag--ok">● Ready</span>
            </div>
            <p className="font-xs muted" style={{ margin: 0, lineHeight: 1.4 }}>
              Vallum provides a backend-managed Groq key by default. Basic audits, RoE parsing, and remediation work without entering any key.
            </p>
          </div>

          {/* Option 2: Personal OpenRouter Key */}
          <div className="field">
            <label className="field__label" htmlFor="openrouter-key-input">
              <span className="row" style={{ gap: 6 }}>
                <span>Option 2: OpenRouter Key (BYOK)</span>
                {storedOpenRouter ? <span className="mono font-xs tag tag--ok">saved: {maskKey(storedOpenRouter)}</span> : null}
              </span>
              <span className="mono font-xs text-muted">sk-or-v1-...</span>
            </label>
            <input
              id="openrouter-key-input"
              className="input mono"
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder={storedOpenRouter ? '••••••••••••••••' : 'Paste sk-or-v1-... to benchmark frontier models'}
              value={draftOpenRouter}
              onChange={(e) => setDraftOpenRouter(e.target.value)}
            />
            <p className="font-xs muted" style={{ marginTop: 4 }}>
              Unlocks real-time benchmarking across GPT-4o, Claude Sonnet 4.6, Gemini 3.8 Flash, Claude Haiku 5.5, and DeepSeek V4.1 Flash.
            </p>
          </div>

          <details style={{ marginBottom: 14, fontSize: 12 }}>
            <summary style={{ cursor: 'pointer', color: 'var(--text-muted)' }}>
              ▸ Optional: Custom Groq Key Override
            </summary>
            <div style={{ marginTop: 8 }}>
              <input
                id="groq-key-input"
                className="input mono"
                type="password"
                autoComplete="off"
                spellCheck={false}
                placeholder={storedGroq ? '••••••••••••••••' : 'gsk_... (override backend system key)'}
                value={draftGroq}
                onChange={(e) => setDraftGroq(e.target.value)}
              />
            </div>
          </details>

          <p className="section-label">Storage Isolation</p>
          <div
            className="note"
            style={{ fontSize: 12, color: 'var(--text-subtle)', lineHeight: 1.5 }}
          >
            <strong>Memory only.</strong> Raw keys live in this tab's memory and are cleared on
            reload. Signed-in keys are persisted exclusively in the encrypted server-side vault.
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
