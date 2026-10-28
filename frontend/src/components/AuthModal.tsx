import { useState, type FormEvent } from 'react';
import type { UserProfile } from '../types/user';
import { resolveUserRole } from '../lib/authStore';
import {
  signInWithGoogle,
  signInWithGithub,
  signInWithEmailPassword,
  signUpWithEmailPassword,
} from '../lib/supabaseClient';
import { GoogleIcon, GithubIcon, XIcon, VallumIcon, CheckIcon, AlertIcon } from './Icons';

interface Props {
  currentUser: UserProfile | null;
  onLogin: (user: UserProfile) => void;
  onLogout: () => void;
  onClose: () => void;
}

export function AuthModal({ currentUser, onLogin, onLogout, onClose }: Props) {
  const [tab, setTab] = useState<'signin' | 'register'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

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

  async function handleEmailAuthSubmit(e: FormEvent) {
    e.preventDefault();
    const cleanEmail = email.trim();
    if (!cleanEmail || !password.trim()) {
      setError('Please provide both your email address and password.');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccessNotice(null);

    if (tab === 'signin') {
      const { user: supaUser, error: supaError } = await signInWithEmailPassword(cleanEmail, password);
      setLoading(false);

      if (supaError) {
        if (supaError.message.includes('Email not confirmed')) {
          setError('Email verification required. Please click the verification link sent to your inbox before signing in.');
        } else if (supaError.message.includes('Invalid login credentials')) {
          setError('Invalid email or password. If you do not have an account, switch to "Create Account".');
        } else {
          setError(supaError.message);
        }
        return;
      }

      if (supaUser) {
        const userProfile: UserProfile = {
          id: supaUser.id,
          email: supaUser.email || cleanEmail,
          name: (supaUser.user_metadata?.full_name || cleanEmail.split('@')[0]) as string,
          avatarUrl: (supaUser.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(cleanEmail)}`) as string,
          provider: 'email',
          role: resolveUserRole(cleanEmail),
          isVerified: !!supaUser.email_confirmed_at,
          createdAt: supaUser.created_at || new Date().toISOString(),
        };
        onLogin(userProfile);
        onClose();
      }
    } else {
      // Register new user
      if (password.length < 6) {
        setLoading(false);
        setError('Password must be at least 6 characters.');
        return;
      }

      const { user: supaUser, session, error: supaError } = await signUpWithEmailPassword(
        cleanEmail,
        password,
        name.trim() || cleanEmail.split('@')[0]
      );
      setLoading(false);

      if (supaError) {
        setError(supaError.message);
        return;
      }

      if (session && supaUser) {
        // Immediate session without confirmation
        const userProfile: UserProfile = {
          id: supaUser.id,
          email: supaUser.email || cleanEmail,
          name: (supaUser.user_metadata?.full_name || name.trim() || cleanEmail.split('@')[0]) as string,
          avatarUrl: (supaUser.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(cleanEmail)}`) as string,
          provider: 'email',
          role: resolveUserRole(cleanEmail),
          isVerified: true,
          createdAt: supaUser.created_at || new Date().toISOString(),
        };
        onLogin(userProfile);
        onClose();
      } else {
        setSuccessNotice('Account registered! A confirmation email has been dispatched. Please verify your email before signing in.');
        setTab('signin');
      }
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 440 }}>
        <div className="modal__head">
          <div className="row" style={{ gap: 8 }}>
            <span className="brand__mark" style={{ width: 24, height: 24, padding: 2 }}>
              <VallumIcon width={16} height={16} />
            </span>
            <strong style={{ fontSize: 14 }}>{currentUser ? 'User Account' : 'Sign in to Vallum'}</strong>
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
                <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                  <h3 style={{ margin: 0 }}>{currentUser.name}</h3>
                  {currentUser.role === 'admin' ? (
                    <span style={{
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: 'rgba(234, 179, 8, 0.16)',
                      border: '1px solid rgba(234, 179, 8, 0.4)',
                      color: '#eab308',
                      letterSpacing: '0.04em',
                    }}>
                      SUPER ADMIN
                    </span>
                  ) : (
                    <span style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: 'rgba(34, 211, 238, 0.12)',
                      border: '1px solid rgba(34, 211, 238, 0.3)',
                      color: '#22d3ee',
                      letterSpacing: '0.02em',
                    }}>
                      PENETRATION TESTER
                    </span>
                  )}
                </div>
                <span className="mono text-muted" style={{ fontSize: 12 }}>{currentUser.email}</span>
                <div className="tag-row" style={{ marginTop: 8 }}>
                  <span className="tag tag--ok">
                    {currentUser.provider === 'google'
                      ? '● Google OAuth'
                      : currentUser.provider === 'github'
                      ? '● GitHub OAuth'
                      : '● Verified Email'}
                  </span>
                  <span className="tag">PostgreSQL Sync Active</span>
                </div>
              </div>

              <div className="note" style={{ marginTop: 18 }}>
                Audits, custom RoEs, and encrypted API vault keys are synchronized to your verified account.
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
              {/* Tab Switcher: Sign In vs Create Account */}
              <div className="segmented" style={{ marginBottom: 16 }}>
                <button
                  type="button"
                  className="segmented__btn"
                  aria-pressed={tab === 'signin'}
                  onClick={() => { setTab('signin'); setError(null); }}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  className="segmented__btn"
                  aria-pressed={tab === 'register'}
                  onClick={() => { setTab('register'); setError(null); }}
                >
                  Create Account
                </button>
              </div>

              {error && (
                <div className="note note--bad" style={{ marginBottom: 14 }}>
                  <AlertIcon width={14} height={14} style={{ flexShrink: 0 }} />
                  <span>{error}</span>
                </div>
              )}

              {successNotice && (
                <div className="note note--warn" style={{ marginBottom: 14 }}>
                  <CheckIcon width={14} height={14} style={{ flexShrink: 0 }} />
                  <span>{successNotice}</span>
                </div>
              )}

              {/* OAuth Buttons: Google & GitHub */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 16 }}>
                <button
                  type="button"
                  className="btn btn--block btn--google"
                  onClick={handleGoogleLogin}
                  disabled={loading}
                  style={{ height: 40, fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                >
                  <GoogleIcon width={16} height={16} />
                  <span>Google</span>
                </button>
                <button
                  type="button"
                  className="btn btn--block btn--github"
                  onClick={handleGithubLogin}
                  disabled={loading}
                  style={{ height: 40, fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                >
                  <GithubIcon width={16} height={16} />
                  <span>GitHub</span>
                </button>
              </div>

              <div className="divider-label" style={{ marginBottom: 14 }}>
                <span>or email &amp; password</span>
              </div>

              <form onSubmit={handleEmailAuthSubmit}>
                {tab === 'register' && (
                  <div className="field">
                    <label className="field__label">Full Name</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="e.g. Khushal Arora"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                )}

                <div className="field">
                  <label className="field__label">Email Address</label>
                  <input
                    type="email"
                    className="input"
                    placeholder="analyst@agency.internal"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>

                <div className="field">
                  <label className="field__label">Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" className="btn" onClick={onClose}>
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn btn--primary"
                    disabled={loading || !email.trim() || !password.trim()}
                  >
                    {loading ? 'Authenticating...' : tab === 'signin' ? 'Sign In' : 'Create Account'}
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
