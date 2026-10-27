import { useState } from 'react';
import type { UserProfile } from '../types/user';
import {
  getOpenRouterKey,
  getGroqKey,
  getStorageMode,
  saveAllApiKeys,
  type KeyStorageMode,
} from '../lib/keyStore';
import { SparkIcon, ShieldIcon, CheckIcon, KeyIcon } from './Icons';

interface Props {
  user: UserProfile;
  isOpen: boolean;
  onClose: () => void;
}

export function InitialSetupModal({ user, isOpen, onClose }: Props) {
  const [choice, setChoice] = useState<'system' | 'custom'>('system');
  const [openRouterKey, setOpenRouterKey] = useState(getOpenRouterKey() || '');
  const [groqKey, setGroqKey] = useState(getGroqKey() || '');
  const [storageMode, setStorageMode] = useState<KeyStorageMode>(getStorageMode());
  const [showGroqOverride, setShowGroqOverride] = useState(false);

  if (!isOpen) return null;

  function markCompleted() {
    try {
      localStorage.setItem(`sst.initial_setup_completed_${user.id}`, 'true');
    } catch {
      // Ignored if storage full/blocked
    }
  }

  function handleSaveAndContinue() {
    markCompleted();
    if (choice === 'custom') {
      saveAllApiKeys({ openRouterKey, groqKey }, storageMode);
    }
    onClose();
  }

  function handleSkip() {
    markCompleted();
    onClose();
  }

  return (
    <div className="modal-backdrop" style={{ zIndex: 60 }}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="initial-setup-title"
        style={{ maxWidth: 560, padding: 0 }}
      >
        <div className="modal__head" style={{ padding: '20px 24px 16px' }}>
          <div>
            <div className="hero__eyebrow" style={{ marginBottom: 4 }}>
              // WELCOME, {user.name.toUpperCase()}
            </div>
            <h2 className="card__title row" id="initial-setup-title" style={{ fontSize: 18, gap: 10 }}>
              <SparkIcon style={{ color: 'var(--accent)' }} /> Choose Your Inference Setup
            </h2>
            <p className="card__desc" style={{ marginTop: 4, fontSize: 13 }}>
              Select how SST should evaluate security recommendations and run model benchmarks.
            </p>
          </div>
        </div>

        <div className="modal__body" style={{ padding: '20px 24px', display: 'grid', gap: 16 }}>
          {/* Option 1: Built-in System Key */}
          <div
            onClick={() => setChoice('system')}
            style={{
              border: choice === 'system' ? '1.5px solid var(--accent)' : '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '16px 18px',
              background: choice === 'system' ? 'rgba(98, 114, 240, 0.05)' : 'var(--surface-sunken)',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: choice === 'system' ? '0 0 0 1px var(--accent-glow)' : 'none',
            }}
          >
            <div className="row between" style={{ marginBottom: 6 }}>
              <div className="row" style={{ gap: 10 }}>
                <input
                  type="radio"
                  name="inferenceChoice"
                  checked={choice === 'system'}
                  onChange={() => setChoice('system')}
                  style={{ accentColor: 'var(--accent)' }}
                />
                <strong style={{ fontSize: 14 }}>Option 1: Built-in System Provider</strong>
              </div>
              <span className="tag tag--ok">● Recommended · Free</span>
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, paddingLeft: 24, lineHeight: 1.5 }}>
              Use SST's backend server infrastructure (Groq Llama 3.3). Zero setup needed — RoE document extraction, scope analysis, and safe command rewriting work immediately without any personal API key.
            </p>
          </div>

          {/* Option 2: Bring Your Own OpenRouter Key */}
          <div
            onClick={() => setChoice('custom')}
            style={{
              border: choice === 'custom' ? '1.5px solid var(--accent)' : '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '16px 18px',
              background: choice === 'custom' ? 'rgba(98, 114, 240, 0.05)' : 'var(--surface-sunken)',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: choice === 'custom' ? '0 0 0 1px var(--accent-glow)' : 'none',
            }}
          >
            <div className="row between" style={{ marginBottom: 6 }}>
              <div className="row" style={{ gap: 10 }}>
                <input
                  type="radio"
                  name="inferenceChoice"
                  checked={choice === 'custom'}
                  onChange={() => setChoice('custom')}
                  style={{ accentColor: 'var(--accent)' }}
                />
                <strong style={{ fontSize: 14 }}>Option 2: Bring Your Own OpenRouter Key</strong>
              </div>
              <span className="tag">Frontier Benchmarking</span>
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, paddingLeft: 24, lineHeight: 1.5 }}>
              Compare frontier models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro, Llama 3.1) in real-time. Keys stay strictly in your browser transient memory and are never saved on the server.
            </p>

            {choice === 'custom' && (
              <div
                style={{ marginTop: 16, paddingLeft: 24, display: 'grid', gap: 12 }}
                onClick={(e) => e.stopPropagation()}
              >
                <div className="field" style={{ margin: 0 }}>
                  <label className="field__label">
                    <span>OpenRouter API Key</span>
                    <span className="mono font-xs text-muted">sk-or-v1-...</span>
                  </label>
                  <input
                    type="password"
                    className="input mono"
                    placeholder="Paste sk-or-v1-..."
                    value={openRouterKey}
                    onChange={(e) => setOpenRouterKey(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    autoFocus
                  />
                </div>

                <div className="field" style={{ margin: 0 }}>
                  <label className="field__label">
                    <span>Key Storage Isolation</span>
                  </label>
                  <div className="radio-row">
                    <label className="radio-card" style={{ padding: '8px 12px' }}>
                      <input
                        type="radio"
                        name="initStorageMode"
                        checked={storageMode === 'session'}
                        onChange={() => setStorageMode('session')}
                      />
                      <span>
                        <strong>Session Storage</strong>
                        <span className="muted font-xs">Cleared on tab close</span>
                      </span>
                    </label>
                    <label className="radio-card" style={{ padding: '8px 12px' }}>
                      <input
                        type="radio"
                        name="initStorageMode"
                        checked={storageMode === 'memory'}
                        onChange={() => setStorageMode('memory')}
                      />
                      <span>
                        <strong>In-Memory</strong>
                        <span className="muted font-xs">Cleared on reload</span>
                      </span>
                    </label>
                  </div>
                </div>

                <details style={{ fontSize: 12 }}>
                  <summary
                    style={{ cursor: 'pointer', color: 'var(--text-muted)' }}
                    onClick={() => setShowGroqOverride(!showGroqOverride)}
                  >
                    ▸ Optional: Custom Groq Key Override
                  </summary>
                  <div style={{ marginTop: 8 }}>
                    <input
                      type="password"
                      className="input mono"
                      placeholder="gsk_... (optional custom quota override)"
                      value={groqKey}
                      onChange={(e) => setGroqKey(e.target.value)}
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </div>
                </details>
              </div>
            )}
          </div>

          {/* Reassurance Notice */}
          <div
            className="note"
            style={{
              padding: '10px 14px',
              fontSize: 12.5,
              background: 'var(--surface-sunken)',
              border: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <ShieldIcon width={16} height={16} style={{ flexShrink: 0, color: 'var(--accent)' }} />
            <span>
              <strong>Note:</strong> You can change this selection, add or delete API keys, and update verification engine rules anytime on the <strong>Settings</strong> page.
            </span>
          </div>
        </div>

        <div className="modal__foot" style={{ padding: '16px 24px', background: 'var(--surface-sunken)' }}>
          <button className="btn btn--ghost" onClick={handleSkip}>
            Skip for now
          </button>
          <button
            className="btn btn--primary"
            onClick={handleSaveAndContinue}
            style={{ minWidth: 180 }}
          >
            {choice === 'system' ? (
              <>
                <CheckIcon width={15} height={15} /> Continue with System Key
              </>
            ) : (
              <>
                <KeyIcon width={15} height={15} /> Save &amp; Launch Studio
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
