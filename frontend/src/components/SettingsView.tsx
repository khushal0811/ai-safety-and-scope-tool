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
  onOpenInitialSetup?: () => void;
}

export function SettingsView({ currentUser, onOpenLogin, onLogout, onClearHistory, onOpenInitialSetup }: Props) {
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

        {/* Section 2: LLM Provider & Inference Options */}
        <div className="card">
          <div className="card__header">
            <span className="step-index">02</span>
            <div>
              <h3 className="card__title">LLM Provider &amp; Inference Modes</h3>
              <p className="card__desc">
                Use SST's built-in backend system key by default, or bring your own OpenRouter key for frontier benchmarking.
              </p>
            </div>
          </div>
          <div className="card__body">
            {/* Option 1: Built-in System Key (Default) */}
            <div
              style={{
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '16px 18px',
                marginBottom: 16,
                background: 'var(--surface-sunken)',
              }}
            >
              <div className="row between" style={{ marginBottom: 6 }}>
                <span className="row" style={{ gap: 8 }}>
                  <strong style={{ fontSize: 13.5 }}>Option 1: Built-in System Provider (Default)</strong>
                  <span className="tag tag--ok">● Active &amp; Ready</span>
                </span>
                <span className="mono font-xs text-muted">Backend Managed · Groq Llama 3.3</span>
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, lineHeight: 1.5 }}>
                Zero setup required. Powered by SST's server-side Groq infrastructure for RoE document extraction, intelligent scope violation analysis, and safe command rewriting. No personal API key needed.
              </p>
            </div>

            {/* Option 2: Personal OpenRouter Key (BYOK) */}
            <div
              style={{
                border: openRouterKey ? '1px solid var(--accent)' : '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '16px 18px',
                marginBottom: 16,
                background: 'var(--surface-sunken)',
              }}
            >
              <div className="row between" style={{ marginBottom: 8 }}>
                <span className="row" style={{ gap: 8 }}>
                  <strong style={{ fontSize: 13.5 }}>Option 2: Personal OpenRouter Key (BYOK)</strong>
                  {getOpenRouterKey() ? (
                    <span className="tag tag--ok">● Active (User Key)</span>
                  ) : (
                    <span className="tag">Optional · Frontier Models</span>
                  )}
                </span>
                <span className="mono font-xs text-muted">sk-or-v1-...</span>
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', marginBottom: 12, lineHeight: 1.5 }}>
                Bring your own OpenRouter API key to benchmark frontier models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro, Llama 3.1) in real-time. Keys stay in this browser session and are never logged or stored.
              </p>
              <input
                type="password"
                className="input mono"
                placeholder="Paste OpenRouter API key (sk-or-v1-...)"
                value={openRouterKey}
                onChange={(e) => setOpenRouterKey(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>

            {/* Advanced: Optional Custom Groq Key Override */}
            <details style={{ marginBottom: 18, fontSize: 13 }}>
              <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', userSelect: 'none', padding: '4px 0' }}>
                ▸ Advanced: Custom Groq Key Override (Optional)
              </summary>
              <div style={{ marginTop: 10, padding: 12, border: '1px dashed var(--border)', borderRadius: 'var(--radius)', background: 'var(--surface-sunken)' }}>
                <label className="field__label" style={{ marginBottom: 6 }}>
                  <span>Custom Groq API Key</span>
                  <span className="mono font-xs text-muted">gsk_...</span>
                </label>
                <input
                  type="password"
                  className="input mono"
                  placeholder="Paste custom Groq key if overriding backend system quota"
                  value={groqKey}
                  onChange={(e) => setGroqKey(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
                <p className="font-xs muted" style={{ marginTop: 4 }}>
                  Only needed if you wish to use your own private Groq API tier instead of SST's shared server quota.
                </p>
              </div>
            </details>

            <div className="field">
              <label className="field__label">
                <span>Key Storage Isolation</span>
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
                {onOpenInitialSetup && (
                  <button className="btn btn--ghost btn--sm" onClick={onOpenInitialSetup}>
                    Setup Wizard
                  </button>
                )}
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
