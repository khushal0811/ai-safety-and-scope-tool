import { useState } from 'react';
import type { UserProfile } from '../types/user';
import {
  getOpenRouterKey,
  getGroqKey,
  saveAllApiKeys,
  saveKeysToVault,
} from '../lib/keyStore';
import { SparkIcon, ShieldIcon, CheckIcon, KeyIcon } from './Icons';
import { KeyProtectionNotice } from './KeyProtectionNotice';

interface Props {
  user: UserProfile | null;
  isOpen: boolean;
  onClose: () => void;
}

export function InitialSetupModal({ user, isOpen, onClose }: Props) {
  const [choice, setChoice] = useState<'system' | 'custom'>('system');
  const [openRouterKey, setOpenRouterKey] = useState(getOpenRouterKey() || '');
  const [groqKey, setGroqKey] = useState(getGroqKey() || '');

  if (!isOpen) return null;

  function markCompleted() {
    try {
      const key = user ? `sst.initial_setup_completed_${user.id}` : 'sst.initial_setup_completed_guest';
      localStorage.setItem(key, 'true');
    } catch {
      // Ignored if storage full/blocked
    }
  }

  async function handleSaveAndContinue() {
    markCompleted();
    if (choice === 'custom') {
      if (user) {
        await saveKeysToVault(user.id, { openRouterKey, groqKey });
      } else {
        saveAllApiKeys({ openRouterKey, groqKey });
      }
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
        style={{ maxWidth: 580, padding: 0 }}
      >
        <div className="modal__head" style={{ padding: '22px 24px 16px' }}>
          <div>
            <div className="hero__eyebrow" style={{ marginBottom: 4 }}>
              // INITIAL CONFIGURATION {user ? `· WELCOME, ${user.name.toUpperCase()}` : '· INFERENCE SETUP'}
            </div>
            <h2 className="card__title row" id="initial-setup-title" style={{ fontSize: 18, gap: 10 }}>
              <SparkIcon style={{ color: 'var(--accent)' }} /> Choose Your Inference Setup
            </h2>
            <p className="card__desc" style={{ marginTop: 4, fontSize: 13 }}>
              Select how Vallum should evaluate pentest commands and run frontier model benchmarks.
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
                <strong style={{ fontSize: 14 }}>Option 1: Use System Key (Claude Sonnet 4.6)</strong>
              </div>
              <span className="tag tag--ok">● Recommended · Active</span>
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, paddingLeft: 24, lineHeight: 1.5 }}>
              Use Vallum's pre-configured backend infrastructure (Claude Sonnet 4.6 via OpenRouter). Zero setup needed — RoE extraction, scope analysis, and safe command remediation work immediately without any personal API key.
            </p>
          </div>

          {/* Option 2: Enter Custom API Keys (Registered Users Only) */}
          {user ? (
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
                  <strong style={{ fontSize: 14 }}>Option 2: Enter Your Own API Key (BYOK)</strong>
                </div>
                <span className="tag">Frontier Benchmarking</span>
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, paddingLeft: 24, lineHeight: 1.5 }}>
                Supply your own OpenRouter key to benchmark frontier models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro) or enter a custom Groq key. Keys are encrypted with AES-256-GCM before reaching your database.
              </p>

              {choice === 'custom' && (
                <div
                  style={{ marginTop: 16, paddingLeft: 24, display: 'grid', gap: 12 }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="field" style={{ margin: 0 }}>
                    <label className="field__label">
                      <span>OpenRouter API Key</span>
                      <span className="mono font-xs text-muted">sk-or-v1-... (Frontier Models)</span>
                    </label>
                    <input
                      type="password"
                      className="input mono"
                      placeholder="Paste sk-or-v1-... for GPT-4o, Claude 3.5, Gemini"
                      value={openRouterKey}
                      onChange={(e) => setOpenRouterKey(e.target.value)}
                      autoComplete="off"
                      spellCheck={false}
                      autoFocus
                    />
                  </div>

                  <div className="field" style={{ margin: 0 }}>
                    <label className="field__label">
                      <span>Custom Groq API Key</span>
                      <span className="mono font-xs text-muted">gsk_... (Optional Override)</span>
                    </label>
                    <input
                      type="password"
                      className="input mono"
                      placeholder="Paste gsk_... (optional custom quota override)"
                      value={groqKey}
                      onChange={(e) => setGroqKey(e.target.value)}
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <span className="font-xs muted" style={{ marginTop: 3 }}>
                      Leave blank to use the backend's default OpenRouter key for Claude Sonnet 4.6.
                    </span>
                  </div>

                  <div style={{ marginTop: 4 }}>
                    <KeyProtectionNotice compact />
                  </div>
                </div>
              )}
            </div>
          ) : (
            /* Locked Option 2 for Guest Mode */
            <div
              style={{
                border: '1px dashed var(--border)',
                borderRadius: 'var(--radius)',
                padding: '16px 18px',
                background: 'var(--surface-sunken)',
                opacity: 0.75,
              }}
            >
              <div className="row between" style={{ marginBottom: 6 }}>
                <div className="row" style={{ gap: 10 }}>
                  <input
                    type="radio"
                    name="inferenceChoice"
                    checked={false}
                    disabled
                  />
                  <strong style={{ fontSize: 14, color: 'var(--text-muted)' }}>
                    Option 2: Enter Your Own API Key (BYOK)
                  </strong>
                </div>
                <span className="tag tag--warn">🔒 Account Required</span>
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, paddingLeft: 24, lineHeight: 1.5 }}>
                Guest users only use the system's own Groq key. Because guest sessions do not have a database vault to store and encrypt API keys, custom keys are disabled. Sign in with Google or Email to unlock custom API keys.
              </p>
            </div>
          )}

          {/* Reassurance Notice that initial settings can be changed later */}
          <div
            className="note"
            style={{
              padding: '12px 14px',
              fontSize: 12.5,
              background: 'rgba(98, 114, 240, 0.08)',
              border: '1px solid rgba(98, 114, 240, 0.25)',
              borderRadius: 'var(--radius)',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <ShieldIcon width={18} height={18} style={{ flexShrink: 0, color: 'var(--accent)' }} />
            <span style={{ lineHeight: 1.45 }}>
              <strong>Initial Settings Note:</strong> These initial preferences can be changed anytime in the <strong>Settings</strong> page, where you can add, remove, or update your API keys whenever you want.
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
            style={{ minWidth: 200 }}
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
