import { useEffect, useState } from 'react';
import type { UserProfile } from '../types/user';
import {
  getOpenRouterKey,
  getGroqKey,
  saveAllApiKeys,
  saveKeysToVault,
  revokeAndWipeUserKeys,
  fetchVaultStatus,
  testApiKeys,
  type KeyVerificationResult,
  type VaultStatus,
} from '../lib/keyStore';
import { GoogleIcon, CheckIcon, TrashIcon, UserIcon, SparkIcon, AlertIcon } from './Icons';
import { KeyProtectionNotice } from './KeyProtectionNotice';

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
  const [savedNotice, setSavedNotice] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [revokedNotice, setRevokedNotice] = useState(false);

  // Key testing state
  const [testing, setTesting] = useState(false);
  const [testFeedback, setTestFeedback] = useState<{
    success: boolean;
    results: KeyVerificationResult[];
    error?: string;
  } | null>(null);
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);

  useEffect(() => {
    if (currentUser?.id) {
      fetchVaultStatus(currentUser.id).then(setVaultStatus).catch(() => {});
    }
  }, [currentUser?.id]);

  // Verification rule toggles
  const [strictNormalization, setStrictNormalization] = useState(true);
  const [blockGateway, setBlockGateway] = useState(true);
  const [blockCloudMetadata, setBlockCloudMetadata] = useState(true);
  const [filterDestructiveArgs, setFilterDestructiveArgs] = useState(true);

  async function handleSaveKeys() {
    if (currentUser) {
      await saveKeysToVault(currentUser.id, { openRouterKey, groqKey });
      fetchVaultStatus(currentUser.id).then(setVaultStatus).catch(() => {});
    } else {
      saveAllApiKeys({ openRouterKey, groqKey });
    }
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  }

  async function handleRevokeKeys() {
    setRevoking(true);
    setTestFeedback(null);
    try {
      await revokeAndWipeUserKeys(currentUser?.id);
      setOpenRouterKey('');
      setGroqKey('');
      setVaultStatus(null);
      setRevokedNotice(true);
      setTimeout(() => setRevokedNotice(false), 3000);
    } finally {
      setRevoking(false);
    }
  }

  async function handleTestKeys() {
    setTesting(true);
    setTestFeedback(null);
    try {
      const res = await testApiKeys({
        openRouterKey: openRouterKey.trim() || undefined,
        groqKey: groqKey.trim() || undefined,
        userId: currentUser?.id,
      });
      setTestFeedback(res);
    } catch (err: any) {
      setTestFeedback({
        success: false,
        results: [],
        error: err?.message || 'Failed to verify API key connection.',
      });
    } finally {
      setTesting(false);
    }
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
                    <span className="tag tag--ok">
                      {currentUser.provider === 'google'
                        ? '● Google OAuth Active'
                        : currentUser.provider === 'github'
                        ? '● GitHub OAuth Active'
                        : '● Email Account Active'}
                    </span>
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
                Use Vallum's built-in backend system key by default, or bring your own OpenRouter key for frontier benchmarking.
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
                <span className="mono font-xs text-muted">Backend Managed · Claude Haiku</span>
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', margin: 0, lineHeight: 1.5 }}>
                Zero setup required. Powered by Vallum's server-side OpenRouter infrastructure (Claude Haiku Latest) for RoE document extraction, intelligent scope violation analysis, and safe command rewriting. No personal API key needed.
              </p>
            </div>

            {/* Option 2: Personal OpenRouter Key (BYOK) */}
            {currentUser ? (
              <>
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
                    Bring your own OpenRouter API key to benchmark frontier models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro, Llama 3.3) in real-time. Keys are encrypted with AES-256-GCM before saving to your database vault.
                  </p>
                  <div className="row" style={{ gap: 8, marginTop: 4 }}>
                    <input
                      type="password"
                      className="input mono"
                      style={{ flex: 1 }}
                      placeholder={
                        vaultStatus?.hasOpenRouterKey && !openRouterKey
                          ? `Vault configured (${vaultStatus.openRouterHint || '••••••'}) — paste new key to update`
                          : 'Paste OpenRouter API key (sk-or-v1-...)'
                      }
                      value={openRouterKey}
                      onChange={(e) => {
                        setOpenRouterKey(e.target.value);
                        setTestFeedback(null);
                      }}
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <button
                      type="button"
                      id="test-key-inline-btn"
                      className="btn btn--secondary btn--sm row"
                      style={{ gap: 6, flexShrink: 0 }}
                      disabled={testing || (!openRouterKey.trim() && !vaultStatus?.hasOpenRouterKey && !getOpenRouterKey())}
                      onClick={handleTestKeys}
                      title="Test connection and check if this API key is valid and working"
                    >
                      {testing ? (
                        <>
                          <span className="spinner" style={{ width: 12, height: 12 }} /> Testing…
                        </>
                      ) : (
                        <>
                          <SparkIcon width={13} height={13} /> Test Key
                        </>
                      )}
                    </button>
                  </div>

                  {testFeedback && (
                    <div style={{ marginTop: 12 }}>
                      {testFeedback.error ? (
                        <div className="key-test-banner key-test-banner--error">
                          <AlertIcon width={16} height={16} style={{ flexShrink: 0, marginTop: 1 }} />
                          <div style={{ flex: 1 }}>
                            <strong>Connection Test Failed:</strong> {testFeedback.error}
                          </div>
                        </div>
                      ) : (
                        testFeedback.results.map((r, idx) => (
                          <div
                            key={idx}
                            className={`key-test-banner ${r.valid ? 'key-test-banner--success' : 'key-test-banner--error'}`}
                          >
                            {r.valid ? (
                              <CheckIcon width={16} height={16} style={{ flexShrink: 0, marginTop: 1 }} />
                            ) : (
                              <AlertIcon width={16} height={16} style={{ flexShrink: 0, marginTop: 1 }} />
                            )}
                            <div style={{ flex: 1 }}>
                              <strong>{r.provider} Test:</strong> {r.message}
                              {r.latencyMs > 0 && (
                                <span className="mono font-xs" style={{ marginLeft: 8, opacity: 0.85 }}>
                                  ({r.latencyMs}ms response)
                                </span>
                              )}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}
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
                      Only needed if you wish to use your own private Groq API tier instead of Vallum's shared server quota.
                    </p>
                  </div>
                </details>
              </>
            ) : (
              /* Locked Option 2 for Guests */
              <div
                style={{
                  border: '1px dashed var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '16px 18px',
                  marginBottom: 16,
                  background: 'var(--surface-sunken)',
                }}
              >
                <div className="row between" style={{ marginBottom: 8 }}>
                  <span className="row" style={{ gap: 8 }}>
                    <strong style={{ fontSize: 13.5 }}>Option 2: Personal OpenRouter Key (BYOK)</strong>
                    <span className="tag tag--warn">🔒 Account Required</span>
                  </span>
                  <span className="mono font-xs text-muted">No Database For Guests</span>
                </div>
                <p style={{ fontSize: 12.5, color: 'var(--text-subtle)', marginBottom: 12, lineHeight: 1.5 }}>
                  Guest users only have one option: using Vallum's backend system key. Because guest sessions do not have a private database to store and encrypt API keys, custom keys are disabled. Sign in with Google, GitHub, or Email to unlock custom keys.
                </p>
                <button className="btn btn--primary btn--sm" onClick={onOpenLogin}>
                  <UserIcon width={14} height={14} /> Sign In to Enable Custom Keys
                </button>
              </div>
            )}

            <div style={{ marginTop: 18 }}>
              <KeyProtectionNotice />
            </div>

            <div className="card__actions">
              {savedNotice && (
                <span className="row" style={{ color: 'var(--healthy)', fontSize: 13, fontWeight: 500, gap: 6 }}>
                  <CheckIcon width={16} height={16} /> API keys encrypted &amp; saved to vault
                </span>
              )}
              {revokedNotice && (
                <span className="row" style={{ color: 'var(--unsafe)', fontSize: 13, fontWeight: 500, gap: 6 }}>
                  <CheckIcon width={16} height={16} /> API keys permanently revoked &amp; wiped from database
                </span>
              )}
              <div className="row" style={{ marginLeft: 'auto', gap: 8 }}>
                {onOpenInitialSetup && (
                  <button className="btn btn--ghost btn--sm" onClick={onOpenInitialSetup}>
                    Setup Wizard
                  </button>
                )}
                {currentUser && (
                  <>
                    <button
                      className="btn btn--danger btn--sm row"
                      onClick={handleRevokeKeys}
                      disabled={revoking || (!openRouterKey && !groqKey && !getOpenRouterKey() && !getGroqKey() && !vaultStatus?.isConfigured)}
                      title="Revoke and completely wipe API keys from the database and session"
                      style={{ gap: 6 }}
                    >
                      <TrashIcon width={14} height={14} />
                      {revoking ? 'Revoking...' : 'Revoke / Delete Key'}
                    </button>
                    <button
                      type="button"
                      id="test-keys-btn"
                      className="btn btn--secondary btn--sm row"
                      onClick={handleTestKeys}
                      disabled={testing || (!openRouterKey.trim() && !groqKey.trim() && !vaultStatus?.hasOpenRouterKey && !getOpenRouterKey())}
                      title="Test connection and verify that entered API keys are valid and working"
                      style={{ gap: 6 }}
                    >
                      {testing ? (
                        <>
                          <span className="spinner" style={{ width: 13, height: 13 }} />
                          Testing Connection…
                        </>
                      ) : (
                        <>
                          <SparkIcon width={14} height={14} />
                          Test Connection
                        </>
                      )}
                    </button>
                    <button className="btn btn--primary" onClick={handleSaveKeys}>
                      Save Keys
                    </button>
                  </>
                )}
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
