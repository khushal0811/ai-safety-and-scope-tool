import { useState } from 'react';
import type { UserProfile } from '../types/user';
import { createEmailUser } from '../lib/authStore';
import { signInWithGoogle, signInWithGithub } from '../lib/supabaseClient';
import { GoogleIcon, GithubIcon, XIcon, ShieldIcon } from './Icons';

interface Props {
  currentUser: UserProfile | null;
  onLogin: (user: UserProfile) => void;
  onLogout: () => void;
  onClose: () => void;
}

export function AuthModal({ currentUser, onLogin, onLogout, onClose }: Props) {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleGoogleLogin() {
    setLoading(true);
    setError(null);
    try {
      const { error: supaError } = await signInWithGoogle();
      if (supaError) {
        setLoading(false);
        const msg = supaError.message || '';
        if (msg.includes('not enabled') || msg.includes('Unsupported provider') || msg.includes('validation_failed')) {
          setError('Google OAuth is not enabled in your Supabase project (Authentication > Providers > Google).');
        } else {
          setError(msg);
        }
      }
    } catch (err: any) {
      setLoading(false);
      setError(err?.message || 'Google sign in failed');
    }
  }

  async function handleGithubLogin() {
    setLoading(true);
    setError(null);
    try {
      const { error: supaError } = await signInWithGithub();
      if (supaError) {
        setLoading(false);
        const msg = supaError.message || '';
        if (msg.includes('not enabled') || msg.includes('Unsupported provider') || msg.includes('validation_failed')) {
          setError('GitHub OAuth is not enabled in your Supabase project (Authentication > Providers > GitHub).');
        } else {
          setError(msg);
        }
      }
    } catch (err: any) {
      setLoading(false);
      setError(err?.message || 'GitHub sign in failed');
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal__head">
          <div className="row">
            <span className="brand__mark" style={{ width: 24, height: 24 }}>
              <ShieldIcon width={14} height={14} />
            </span>
            <strong style={{ fontSize: 14 }}>{currentUser ? 'User Account' : 'Sign in to VallumSST'}</strong>
          </div>
          <button className="btn btn--ghost btn--icon" onClick={onClose} aria-label="Close modal">
            <XIcon />
          </button>
        </div>

        <div className="modal__body">
          {currentUser ? (
            <div className="auth-profile">
              <div className="auth-profile__avatar">
                <img src={currentUser.avatarUrl} alt={currentUser.name} />
              </div>
              <div className="auth-profile__info">
                <h3>{currentUser.name}</h3>
                <span className="mono text-muted">{currentUser.email}</span>
                <div className="tag-row" style={{ marginTop: 8 }}>
                  <span className="tag tag--ok">
                    {currentUser.provider === 'google'
                      ? '● Google OAuth Active'
                      : currentUser.provider === 'github'
                      ? '● GitHub OAuth Active'
                      : '● Email Account Active'}
                  </span>
                  <span className="tag">PostgreSQL Sync Enabled</span>
                </div>
              </div>

              <div className="note" style={{ marginTop: 18 }}>
                Your audits are automatically linked to your user account and preserved across sessions.
              </div>

              <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button className="btn btn--danger" onClick={() => { onLogout(); onClose(); }}>
                  Sign Out
                </button>
                <button className="btn btn--primary" onClick={onClose}>
                  Done
                </button>
              </div>
            </div>
          ) : (
            <div>
              <p className="card__desc" style={{ marginBottom: 20 }}>
                Sign in with your Google or GitHub account to preserve your pentest audit history, sync Rules of Engagement, and access custom model profiles.
              </p>

              {error && (
                <div style={{
                  padding: '10px 14px',
                  borderRadius: 'var(--radius)',
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  color: 'var(--unsafe)',
                  fontSize: 12.5,
                  marginBottom: 16,
                  lineHeight: 1.45,
                }}>
                  {error}
                </div>
              )}

              {/* OAuth Buttons: Google & GitHub */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 18 }}>
                <button
                  className="btn btn--block btn--google"
                  onClick={handleGoogleLogin}
                  disabled={loading}
                  style={{
                    height: 42,
                    fontSize: 13,
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 8,
                  }}
                >
                  <GoogleIcon width={16} height={16} />
                  <span>Google</span>
                </button>
                <button
                  className="btn btn--block btn--github"
                  onClick={handleGithubLogin}
                  disabled={loading}
                  style={{
                    height: 42,
                    fontSize: 13,
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 8,
                  }}
                >
                  <GithubIcon width={16} height={16} />
                  <span>GitHub</span>
                </button>
              </div>

              <div className="divider-label">
                <span>or enter details</span>
              </div>

              <div className="field" style={{ marginTop: 14 }}>
                <label className="field__label">Full Name</label>
                <input
                  type="text"
                  className="input"
                  placeholder="Your Name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div className="field">
                <label className="field__label">Email Address</label>
                <input
                  type="email"
                  className="input"
                  placeholder="your.email@university.edu"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <div className="note" style={{ marginTop: 14 }}>
                VallumSST enforces client privacy. Pentest commands are never shared across accounts.
              </div>

              <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button className="btn" onClick={onClose}>Cancel</button>
                <button
                  className="btn btn--primary"
                  onClick={() => {
                    if (!email.trim()) {
                      setError('Please enter your email address.');
                      return;
                    }
                    const user = createEmailUser(email.trim(), name.trim() || email.trim().split('@')[0], true);
                    onLogin(user);
                    onClose();
                  }}
                  disabled={!email.trim()}
                >
                  Sign In with Email
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
