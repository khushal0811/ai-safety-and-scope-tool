import { useEffect, useState } from 'react';
import type { UserProfile } from '../types/user';
import {
  fetchVaultStatus,
  getOpenRouterKey,
  hasVaultOpenRouterKey,
  saveAllApiKeys,
  saveKeysToVault,
} from '../lib/keyStore';
import { ShieldIcon, KeyIcon } from './Icons';
import { KeyProtectionNotice } from './KeyProtectionNotice';

interface Props {
  user: UserProfile | null;
  isOpen: boolean;
  onClose: () => void;
  onKeySaved?: () => void;
}

export function InitialSetupModal({ user, isOpen, onClose, onKeySaved }: Props) {
  const [openRouterKey, setOpenRouterKey] = useState(getOpenRouterKey() || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function markCompleted() {
    try {
      const key = user ? `sst.initial_setup_completed_${user.id}` : 'sst.initial_setup_completed_guest';
      localStorage.setItem(key, 'true');
    } catch {
      // Ignored if storage full/blocked
    }
  }

  function handleSkipBypass() {
    markCompleted();
    onClose();
  }

  // If the user already has a key stored in the database vault, automatically skip and close the popup
  useEffect(() => {
    if (!isOpen) return;
    if (getOpenRouterKey() || hasVaultOpenRouterKey()) {
      markCompleted();
      onKeySaved?.();
      onClose();
      return;
    }
    if (user?.id) {
      fetchVaultStatus(user.id)
        .then((st) => {
          if (st.hasOpenRouterKey) {
            markCompleted();
            onKeySaved?.();
            onClose();
          }
        })
        .catch(() => {});
    }
  }, [isOpen, user?.id]);

  if (!isOpen) return null;

  async function handleSaveAndContinue() {
    const trimmed = openRouterKey.trim();
    if (!trimmed) {
      setError('An OpenRouter API key is required to use Vallum.');
      return;
    }
    if (!trimmed.startsWith('sk-or-') && trimmed.length < 20) {
      setError('Please enter a valid OpenRouter API key (starts with sk-or-...).');
      return;
    }

    setSaving(true);
    setError(null);
    try {
      if (user) {
        await saveKeysToVault(user.id, { openRouterKey: trimmed });
      } else {
        saveAllApiKeys({ openRouterKey: trimmed });
      }
      markCompleted();
      onKeySaved?.();
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to save OpenRouter API key.');
    } finally {
      setSaving(false);
    }
  }

  const isValidFormat = openRouterKey.trim().length >= 15;

  return (
    <div className="modal-backdrop" style={{ zIndex: 60 }}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="initial-setup-title"
        style={{ maxWidth: 540, padding: 0 }}
      >
        <div className="modal__head" style={{ padding: '22px 24px 16px' }}>
          <div>
            <div className="hero__eyebrow" style={{ marginBottom: 4 }}>
              // MANDATORY SETUP · BRING YOUR OWN KEY (BYOK)
            </div>
            <h2 className="card__title row" id="initial-setup-title" style={{ fontSize: 18, gap: 10 }}>
              <KeyIcon style={{ color: 'var(--accent)' }} /> OpenRouter API Key Required
            </h2>
            <p className="card__desc" style={{ marginTop: 6, fontSize: 13, lineHeight: 1.5 }}>
              To audit pentest commands, evaluate scope boundaries, or run comparative benchmarks, you must supply your personal OpenRouter API key. Server system keys are disabled for user tasks.
            </p>
          </div>
        </div>

        <div className="modal__body" style={{ padding: '16px 24px 20px', display: 'grid', gap: 16 }}>
          <div className="field" style={{ margin: 0 }}>
            <label className="field__label" htmlFor="initial-openrouter-key">
              <span>OpenRouter API Key</span>
              <span className="mono font-xs text-muted">Required (sk-or-v1-...)</span>
            </label>
            <input
              id="initial-openrouter-key"
              type="password"
              className="input mono"
              placeholder="Paste sk-or-v1-..."
              value={openRouterKey}
              onChange={(e) => {
                setOpenRouterKey(e.target.value);
                if (error) setError(null);
              }}
              autoComplete="off"
              spellCheck={false}
              autoFocus
            />
            {error && (
              <p style={{ color: 'var(--unsafe)', fontSize: 12, marginTop: 4, marginBottom: 0 }}>
                {error}
              </p>
            )}
          </div>

          <div
            style={{
              fontSize: 12,
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0 2px',
            }}
          >
            <span>Don't have an OpenRouter key yet?</span>
            <a
              href="https://openrouter.ai/keys"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--accent)', textDecoration: 'underline' }}
            >
              Get one at openrouter.ai/keys →
            </a>
          </div>

          <div style={{ marginTop: 2 }}>
            <KeyProtectionNotice compact />
          </div>

          <div
            className="note"
            style={{
              padding: '10px 14px',
              fontSize: 12,
              background: 'rgba(98, 114, 240, 0.06)',
              border: '1px solid rgba(98, 114, 240, 0.2)',
              borderRadius: 'var(--radius)',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <ShieldIcon width={16} height={16} style={{ flexShrink: 0, color: 'var(--accent)' }} />
            <span style={{ lineHeight: 1.45, color: 'var(--text-subtle)' }}>
              Your key is strictly stored client-side in session memory (or encrypted via AES-256-GCM in your vault if signed in) and is never logged or exposed.
            </span>
          </div>
        </div>

        <div className="modal__foot" style={{ padding: '16px 24px', background: 'var(--surface-sunken)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <button
            type="button"
            className="btn btn--ghost"
            onClick={handleSkipBypass}
            disabled={saving}
          >
            Skip / Bypass for Now
          </button>
          <button
            className="btn btn--primary"
            onClick={handleSaveAndContinue}
            disabled={!isValidFormat || saving}
            style={{ minWidth: 200 }}
          >
            {saving ? (
              <>
                <span className="spinner" style={{ width: 14, height: 14 }} /> Saving Key...
              </>
            ) : (
              <>
                <KeyIcon width={15} height={15} /> Save Key &amp; Launch Studio
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
