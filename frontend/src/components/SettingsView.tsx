import { useState } from 'react';
import type { UserProfile } from '../types/user';
import {
  getOpenRouterKey,
  getGroqKey,
  saveAllApiKeys,
  clearAllKeys,
  getStorageMode,
  type KeyStorageMode,
} from '../lib/keyStore';
import { GoogleIcon, ShieldIcon, CheckIcon } from './Icons';

interface Props {
  currentUser: UserProfile | null;
  onOpenLogin: () => void;
  onLogout: () => void;
  onClearHistory: () => void;
}

export function SettingsView({ currentUser, onOpenLogin, onLogout, onClearHistory }: Props) {
  const [openRouterKey, setOpenRouterKey] = useState(getOpenRouterKey() || '');
  const [groqKey, setGroqKey] = useState(getGroqKey() || '');
  const [storageMode, setStorageMode] = useState<KeyStorageMode>(getStorageMode());
  const [savedNotice, setSavedNotice] = useState(false);

  // Verification rule toggles
  const [strictNormalization, setStrictNormalization] = useState(true);
  const [blockGateway, setBlockGateway] = useState(true);
  const [blockCloudMetadata, setBlockCloudMetadata] = useState(true);
  const [filterDestructiveArgs, setFilterDestructiveArgs] = useState(true);

  function handleSaveKeys() {
    saveAllApiKeys({ openRouterKey, groqKey }, storageMode);
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  }

  function handleClearKeys() {
    clearAllKeys();
    setOpenRouterKey('');
    setGroqKey('');
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  }

  return (
    <div className="container" style={{ paddingBottom: 80, maxWidth: 920 }}>
      {/* Header */}
      <div className="hero" style={{ padding: '32px 0 24px' }}>
        <div className="hero__eyebrow">// 003 — CONFIGURATION &amp; VAULT</div>
        <h1>Settings</h1>
        <p>
          Configure user identity, LLM provider credentials, verification engine policies, and storage preferences.
        </p>
      </div>

      <div style={{ display: 'grid', gap: 24 }}>
        {/* Section 1: User Identity & Google Account */}
        <div className="card">
          <div className="card__header">
            <span className="step-index">01</span>
            <div>
              <h3 className="card__title">User Account &amp; Authentication</h3>
              <p className="card__desc">Manage your identity and PostgreSQL sync session.</p>
            </div>
          </div>
          <div className="card__body">
            {currentUser ? (
              <div className="settings-user-card">
                <img
                  src={currentUser.avatarUrl}
                  alt={currentUser.name}
                  className="settings-user-card__avatar"
                />
                <div style={{ flex: 1 }}>
                  <div className="row" style={{ gap: 10 }}>
                    <h3 style={{ fontSize: 16 }}>{currentUser.name}</h3>
                    <span className="tag tag--ok">● Google OAuth Active</span>
                  </div>
                  <span className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {currentUser.email}
                  </span>
                  <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', marginTop: 4 }}>
                    Audit history and custom scope definitions are synchronized under this account.
                  </p>
                </div>
                <button className="btn btn--danger btn--sm" onClick={onLogout}>
                  Sign Out
                </button>
              </div>
            ) : (
              <div className="settings-login-banner">
                <div>
                  <h4 style={{ fontSize: 14, marginBottom: 4 }}>Guest Mode Active</h4>
                  <p className="card__desc">
                    Connect your Google account to enable cloud audit synchronization and custom RoE profiles.
                  </p>
                </div>
                <button className="btn btn--primary" onClick={onOpenLogin}>
                  <GoogleIcon width={16} height={16} /> Sign In with Google
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Section 2: LLM API Keys Vault */}
        <div className="card">
          <div className="card__header">
            <span className="step-index">02</span>
            <div>
              <h3 className="card__title">LLM Provider API Keys</h3>
              <p className="card__desc">
                Optional keys for real-time model queries via OpenRouter (Llama 3.3, Claude, GPT-4o).
              </p>
            </div>
          </div>
          <div className="card__body">
            <div className="field">
              <label className="field__label">
                <span className="row" style={{ gap: 8 }}>
                  <span>OpenRouter API Key</span>
                  {getOpenRouterKey() ? (
                    <span className="tag tag--ok">Active</span>
                  ) : (
                    <span className="tag">Optional</span>
                  )}
                </span>
                <span className="mono font-xs text-muted">sk-or-v1-...</span>
              </label>
              <input
                type="password"
                className="input mono"
                placeholder="sk-or-v1-..."
                value={openRouterKey}
                onChange={(e) => setOpenRouterKey(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <p className="font-xs muted" style={{ marginTop: 4 }}>
                Powers real-time benchmarking across frontier models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro, Llama 3.1).
              </p>
            </div>

            <div className="field">
              <label className="field__label">
                <span className="row" style={{ gap: 8 }}>
                  <span>Groq API Key</span>
                  {getGroqKey() ? (
                    <span className="tag tag--ok">Active</span>
                  ) : (
                    <span className="tag">Optional</span>
                  )}
                </span>
                <span className="mono font-xs text-muted">gsk_...</span>
              </label>
              <input
                type="password"
                className="input mono"
                placeholder="gsk_..."
                value={groqKey}
                onChange={(e) => setGroqKey(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <p className="font-xs muted" style={{ marginTop: 4 }}>
                Powers ultra-low latency Llama-3.3 inference for RoE document extraction and command rewriting.
              </p>
            </div>

            <div className="field">
              <label className="field__label">
                <span>Key Storage Mode</span>
                <span className="mono font-xs text-muted">Client-side isolation</span>
              </label>
              <div className="radio-row">
                <label className="radio-card">
                  <input
                    type="radio"
                    name="storageMode"
                    checked={storageMode === 'session'}
                    onChange={() => setStorageMode('session')}
                  />
                  <div>
                    <strong>Session Storage</strong>
                    <span className="muted font-xs">Persists across reloads, wiped on tab close</span>
                  </div>
                </label>
                <label className="radio-card">
                  <input
                    type="radio"
                    name="storageMode"
                    checked={storageMode === 'memory'}
                    onChange={() => setStorageMode('memory')}
                  />
                  <div>
                    <strong>In-Memory Only</strong>
                    <span className="muted font-xs">Highest paranoia: wiped on browser refresh</span>
                  </div>
                </label>
              </div>
            </div>

            <div className="note" style={{ marginTop: 16 }}>
              <ShieldIcon width={16} height={16} style={{ flexShrink: 0, color: 'var(--accent)' }} />
              <div>
                <strong>Zero-Host-Storage Guarantee:</strong> Keys are stored in your browser's transient memory and are never persisted to database tables, server logs, or telemetry.
              </div>
            </div>

            <div className="card__actions">
              {savedNotice && (
                <span className="row" style={{ color: 'var(--healthy)', fontSize: 13, fontWeight: 500 }}>
                  <CheckIcon width={16} height={16} /> API keys saved to browser vault
                </span>
              )}
              <div className="row" style={{ marginLeft: 'auto', gap: 8 }}>
                <button
                  className="btn btn--danger btn--sm"
                  onClick={handleClearKeys}
                  disabled={!openRouterKey && !groqKey && !getOpenRouterKey() && !getGroqKey()}
                >
                  Clear Keys
                </button>
                <button className="btn btn--primary" onClick={handleSaveKeys}>
                  Save Keys
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: Audit Engine Policy Rules */}
        <div className="card">
          <div className="card__header">
            <span className="step-index">03</span>
            <div>
              <h3 className="card__title">Verification Engine Policies</h3>
              <p className="card__desc">
                Configure deterministic AST safety checks applied before and after LLM inference.
              </p>
            </div>
          </div>
          <div className="card__body" style={{ display: 'grid', gap: 14 }}>
            <label className="settings-toggle-row">
              <div>
                <strong>Strict IP Obfuscation Normalization</strong>
                <p className="card__desc">
                  Normalize hex (`0x7f000001`), octal (`0177.0.0.1`), decimal (`2130706433`), and IPv6-mapped addresses.
                </p>
              </div>
              <input
                type="checkbox"
                checked={strictNormalization}
                onChange={(e) => setStrictNormalization(e.target.checked)}
                style={{ width: 18, height: 18, accentColor: 'var(--accent)' }}
              />
            </label>

            <label className="settings-toggle-row">
              <div>
                <strong>Infrastructure &amp; Default Gateway Defense</strong>
                <p className="card__desc">
                  Automatically flag and drop targets matching `.1` default gateway or broadcast addresses.
                </p>
              </div>
              <input
                type="checkbox"
                checked={blockGateway}
                onChange={(e) => setBlockGateway(e.target.checked)}
                style={{ width: 18, height: 18, accentColor: 'var(--accent)' }}
              />
            </label>

            <label className="settings-toggle-row">
              <div>
                <strong>Cloud Metadata Endpoint Interception</strong>
                <p className="card__desc">
                  Prohibit instance metadata exfiltration on `169.254.169.254` across AWS and GCP scopes.
                </p>
              </div>
              <input
                type="checkbox"
                checked={blockCloudMetadata}
                onChange={(e) => setBlockCloudMetadata(e.target.checked)}
                style={{ width: 18, height: 18, accentColor: 'var(--accent)' }}
              />
            </label>

            <label className="settings-toggle-row">
              <div>
                <strong>Destructive Shell Command Filter</strong>
                <p className="card__desc">
                  Block dangerous bash patterns (fork bombs, disk erasures, raw block writes).
                </p>
              </div>
              <input
                type="checkbox"
                checked={filterDestructiveArgs}
                onChange={(e) => setFilterDestructiveArgs(e.target.checked)}
                style={{ width: 18, height: 18, accentColor: 'var(--accent)' }}
              />
            </label>
          </div>
        </div>

        {/* Section 4: Data & Cache Maintenance */}
        <div className="card">
          <div className="card__header">
            <span className="step-index">04</span>
            <div>
              <h3 className="card__title">Data &amp; Cache Management</h3>
              <p className="card__desc">Manage local audit cache and session state.</p>
            </div>
          </div>
          <div className="card__body">
            <div className="row between" style={{ flexWrap: 'wrap', gap: 12 }}>
              <div>
                <strong>Clear Local Audit History</strong>
                <p className="card__desc">Purges locally cached audit records from this browser.</p>
              </div>
              <button
                className="btn btn--danger btn--sm"
                onClick={() => {
                  if (confirm('Clear all local audit history?')) {
                    onClearHistory();
                    alert('Local audit history cleared.');
                  }
                }}
              >
                Clear History
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
