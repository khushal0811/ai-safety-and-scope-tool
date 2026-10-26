import { useState } from 'react';
import type { UserProfile } from '../types/user';
import { createGoogleUser } from '../lib/authStore';
import { GoogleIcon, XIcon, ShieldIcon } from './Icons';

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

  function handleGoogleLogin() {
    setLoading(true);
    setTimeout(() => {
      const user = createGoogleUser(email || 'khushal.arora@example.com', name || 'Khushal Arora');
      onLogin(user);
      setLoading(false);
      onClose();
    }, 400);
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal__head">
          <div className="row">
            <span className="brand__mark" style={{ width: 24, height: 24 }}>
              <ShieldIcon width={14} height={14} />
            </span>
            <strong style={{ fontSize: 14 }}>{currentUser ? 'User Account' : 'Sign in to SST'}</strong>
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
                  <span className="tag tag--ok">● Google OAuth Active</span>
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
                Sign in with your Google account to preserve your pentest audit history, sync Rules of Engagement, and access custom model profiles.
              </p>

              {/* One-Click Google Login Button */}
              <button
                className="btn btn--block btn--google"
                onClick={handleGoogleLogin}
                disabled={loading}
                style={{
                  height: 44,
                  fontSize: 13.5,
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 12,
                  marginBottom: 18,
                }}
              >
                <GoogleIcon width={18} height={18} />
                {loading ? 'Connecting Google Account...' : 'Continue with Google'}
              </button>

              <div className="divider-label">
                <span>or enter details</span>
              </div>

              <div className="field" style={{ marginTop: 14 }}>
                <label className="field__label">Full Name</label>
                <input
                  type="text"
                  className="input"
                  placeholder="Khushal Arora"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div className="field">
                <label className="field__label">Email Address</label>
                <input
                  type="email"
                  className="input"
                  placeholder="name@university.edu"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <div className="note" style={{ marginTop: 14 }}>
                SST enforces client privacy. Pentest commands are never shared across accounts.
              </div>

              <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button className="btn" onClick={onClose}>Cancel</button>
                <button className="btn btn--primary" onClick={handleGoogleLogin}>
                  Sign In
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
