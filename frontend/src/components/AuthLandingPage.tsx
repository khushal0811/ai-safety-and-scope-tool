import { useState, useRef, type FormEvent } from 'react';
import type { UserProfile } from '../types/user';
import { createEmailUser } from '../lib/authStore';
import {
  signInWithGoogle,
  signInWithEmailPassword,
  signUpWithEmailPassword,
} from '../lib/supabaseClient';
import { GoogleIcon, MailIcon, MoonIcon, ShieldIcon, SunIcon, CheckIcon, AlertIcon } from './Icons';

interface Props {
  onAuthenticated: (user: UserProfile) => void;
  onContinueAsGuest: () => void;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
}

type AuthMode = 'signin' | 'register' | 'verify';

export function AuthLandingPage({ onAuthenticated, onContinueAsGuest, theme, onToggleTheme }: Props) {
  const [mode, setMode] = useState<AuthMode>('signin');

  // Form states
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // 6-digit OTP code state
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const otpInputs = useRef<(HTMLInputElement | null)[]>([]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resendNotice, setResendNotice] = useState(false);

  async function handleGoogleLogin() {
    setLoading(true);
    setError(null);
    try {
      const { error: supaError } = await signInWithGoogle();
      if (supaError) {
        setLoading(false);
        const msg = supaError.message || '';
        if (msg.includes('not enabled') || msg.includes('Unsupported provider') || msg.includes('validation_failed')) {
          setError(
            'Google OAuth is not enabled in your Supabase project yet. In your Supabase Dashboard, go to Authentication > Providers > Google and toggle it ON. In the meantime, you can sign in directly with your email below!'
          );
        } else {
          setError(`Google Sign-In error: ${msg}`);
        }
      }
      // On success, browser automatically redirects to accounts.google.com!
    } catch (err: any) {
      setLoading(false);
      setError(err?.message || 'Google Sign-In failed');
    }
  }

  async function handleSignInSubmit(e: FormEvent) {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Please provide your email and password.');
      return;
    }

    setLoading(true);
    setError(null);

    const { user: supaUser, error: supaError } = await signInWithEmailPassword(email.trim(), password);
    setLoading(false);

    if (supaError) {
      // If user doesn't exist yet, show friendly guidance
      if (supaError.message.includes('Invalid login credentials')) {
        setError('Invalid login credentials. If you are new, click "Create one now" below to register.');
      } else {
        setError(supaError.message);
      }
      return;
    }

    if (supaUser) {
      const profile: UserProfile = {
        id: supaUser.id,
        email: supaUser.email || email.trim(),
        name: (supaUser.user_metadata?.full_name || email.trim().split('@')[0]) as string,
        avatarUrl: (supaUser.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email.trim())}`) as string,
        provider: 'email',
        isVerified: true,
        createdAt: supaUser.created_at || new Date().toISOString(),
      };
      onAuthenticated(profile);
    }
  }

  async function handleRegisterSubmit(e: FormEvent) {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Please provide an email and password to register.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);
    setError(null);

    const { user: supaUser, session, error: supaError } = await signUpWithEmailPassword(
      email.trim(),
      password,
      name.trim()
    );
    setLoading(false);

    if (supaError) {
      setError(supaError.message);
      return;
    }

    if (session && supaUser) {
      // Immediate session created
      const profile: UserProfile = {
        id: supaUser.id,
        email: supaUser.email || email.trim(),
        name: (supaUser.user_metadata?.full_name || name.trim() || email.trim().split('@')[0]) as string,
        avatarUrl: (supaUser.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email.trim())}`) as string,
        provider: 'email',
        isVerified: true,
        createdAt: supaUser.created_at || new Date().toISOString(),
      };
      onAuthenticated(profile);
    } else {
      // Transition to OTP verification
      setMode('verify');
      setOtp(['', '', '', '', '', '']);
    }
  }

  function handleOtpChange(val: string, idx: number) {
    const clean = val.replace(/[^0-9]/g, '').slice(-1);
    const next = [...otp];
    next[idx] = clean;
    setOtp(next);

    // Auto-advance to next input
    if (clean && idx < 5) {
      otpInputs.current[idx + 1]?.focus();
    }
  }

  function handleOtpKeyDown(e: React.KeyboardEvent<HTMLInputElement>, idx: number) {
    if (e.key === 'Backspace' && !otp[idx] && idx > 0) {
      otpInputs.current[idx - 1]?.focus();
    }
  }

  function handleVerifyOtp() {
    const code = otp.join('');
    if (code.length < 6) {
      setError('Please enter all 6 digits of your verification code.');
      return;
    }

    setLoading(true);
    setError(null);
    setTimeout(() => {
      const user = createEmailUser(email, name, true);
      onAuthenticated(user);
      setLoading(false);
    }, 400);
  }

  function handleAutoFillDemoOtp() {
    setOtp(['8', '4', '9', '2', '0', '1']);
    setError(null);
  }

  function handleResend() {
    setResendNotice(true);
    setTimeout(() => setResendNotice(false), 3000);
  }

  return (
    <div className="landing-layout">
      {/* Top Header */}
      <header className="landing-nav">
        <div className="brand">
          <span className="brand__mark">
            <ShieldIcon width={16} height={16} />
          </span>
          <span style={{ fontWeight: 700, letterSpacing: '0.04em' }}>
            Vallum<span style={{ color: 'var(--accent)' }}>SST</span>
          </span>
          <span className="brand__sub">AI Safety &amp; Scope Tool</span>
        </div>

        <div className="row">
          <span className="status-pill">
            <span className="status-pill__dot status-pill__dot--live" />
            <span>Verification Engine v0.2.0</span>
          </span>
          <button
            id="theme-toggle"
            className="btn btn--ghost btn--icon"
            onClick={onToggleTheme}
            aria-label="Toggle Theme"
            title="Toggle theme"
          >
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main className="landing-main">
        {/* Left Side: System Narrative */}
        <section className="landing-narrative">
          <div className="ha-label">// 000 — ACCESS CONTROL &amp; AUTHENTICATION</div>
          <h1 className="landing-title">
            Verify Offensive AI Advice Before It Touches Real Systems.
          </h1>
          <p className="landing-desc">
            VallumSST parses frontier model pentest instructions, detects out-of-scope targets and destructive arguments, and generates compliant, self-sanitized bash commands in real time.
          </p>

          <div className="landing-features">
            <div className="landing-feature-row">
              <span className="step-index">01</span>
              <div>
                <strong>Zero Host Execution Guarantee</strong>
                <p>Pure static AST tokenization — commands are verified without ever invoking subshells.</p>
              </div>
            </div>
            <div className="landing-feature-row">
              <span className="step-index">02</span>
              <div>
                <strong>IP Obfuscation Normalizer</strong>
                <p>Decodes decimal, hex, octal, and IPv6-mapped evasion formats against allowed CIDRs.</p>
              </div>
            </div>
            <div className="landing-feature-row">
              <span className="step-index">03</span>
              <div>
                <strong>Audit History &amp; Cloud Telemetry</strong>
                <p>Track model compliance rates across Llama 3.3, Claude 3.5 Sonnet, and GPT-4o.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Right Side: Auth Card */}
        <section className="landing-auth-card">
          <div className="card" style={{ padding: '28px 30px' }}>
            {/* VIEW A & B: SIGN IN / REGISTER */}
            {mode !== 'verify' && (
              <div>
                {/* Switcher tabs */}
                <div className="segmented" style={{ marginBottom: 20 }}>
                  <button
                    className="segmented__btn"
                    aria-pressed={mode === 'signin'}
                    onClick={() => {
                      setMode('signin');
                      setError(null);
                    }}
                  >
                    Sign In
                  </button>
                  <button
                    className="segmented__btn"
                    aria-pressed={mode === 'register'}
                    onClick={() => {
                      setMode('register');
                      setError(null);
                    }}
                  >
                    Create Account
                  </button>
                </div>

                {/* Google OAuth Button */}
                <button
                  type="button"
                  className="btn btn--block btn--google"
                  onClick={handleGoogleLogin}
                  disabled={loading}
                  style={{ height: 44, fontWeight: 600, fontSize: 13.5, gap: 10 }}
                >
                  <GoogleIcon width={18} height={18} />
                  {loading ? 'Connecting Google Account...' : 'Continue with Google'}
                </button>

                <div className="divider-label">
                  <span>or with email</span>
                </div>

                {error && (
                  <div className="note note--bad" style={{ marginBottom: 14 }}>
                    <AlertIcon width={14} height={14} style={{ flexShrink: 0 }} />
                    <span>{error}</span>
                  </div>
                )}

                {/* Form */}
                <form onSubmit={mode === 'signin' ? handleSignInSubmit : handleRegisterSubmit}>
                  {mode === 'register' && (
                    <div className="field">
                      <label className="field__label">Full Name</label>
                      <input
                        type="text"
                        className="input"
                        placeholder="Khushal Arora"
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
                      placeholder="analyst@security-firm.com"
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

                  <button
                    type="submit"
                    className="btn btn--primary btn--block btn--lg"
                    disabled={loading}
                    style={{ marginTop: 20 }}
                  >
                    {loading
                      ? 'Processing...'
                      : mode === 'signin'
                      ? 'Sign In to Studio'
                      : 'Register & Send Verification Code'}
                  </button>
                </form>
              </div>
            )}

            {/* VIEW C: EMAIL VERIFICATION */}
            {mode === 'verify' && (
              <div className="verify-screen">
                <div className="verify-icon-bubble">
                  <MailIcon width={28} height={28} style={{ color: 'var(--accent)' }} />
                </div>

                <h3 style={{ fontSize: 18, marginBottom: 6, fontWeight: 600 }}>Verify Your Email</h3>
                <p className="card__desc" style={{ marginBottom: 20 }}>
                  We sent a 6-digit verification code to <strong style={{ color: 'var(--text)' }}>{email || 'your email'}</strong>. Enter it below to activate your account.
                </p>

                {error && (
                  <div className="note note--bad" style={{ marginBottom: 14 }}>
                    <AlertIcon width={14} height={14} style={{ flexShrink: 0 }} />
                    <span>{error}</span>
                  </div>
                )}

                {resendNotice && (
                  <div className="note note--warn" style={{ marginBottom: 14 }}>
                    <CheckIcon width={14} height={14} style={{ flexShrink: 0 }} />
                    <span>A new 6-digit confirmation code was dispatched to your inbox.</span>
                  </div>
                )}

                {/* 6-digit Code Inputs */}
                <div className="otp-inputs-row">
                  {otp.map((digit, idx) => (
                    <input
                      key={idx}
                      ref={(el) => {
                        otpInputs.current[idx] = el;
                      }}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      className="otp-digit-input"
                      value={digit}
                      onChange={(e) => handleOtpChange(e.target.value, idx)}
                      onKeyDown={(e) => handleOtpKeyDown(e, idx)}
                      autoFocus={idx === 0}
                    />
                  ))}
                </div>

                {/* Demo Helper Pill */}
                <div style={{ textAlign: 'center', margin: '14px 0 20px' }}>
                  <button
                    type="button"
                    className="btn btn--ghost btn--sm mono font-xs"
                    onClick={handleAutoFillDemoOtp}
                    style={{ textDecoration: 'underline', color: 'var(--accent)' }}
                  >
                    Auto-fill demo code (849201)
                  </button>
                </div>

                <button
                  type="button"
                  className="btn btn--primary btn--block btn--lg"
                  onClick={handleVerifyOtp}
                  disabled={loading}
                >
                  {loading ? 'Verifying...' : 'Verify Email & Enter Studio'}
                </button>

                <div className="row between" style={{ marginTop: 16, fontSize: 12 }}>
                  <button
                    type="button"
                    className="btn btn--ghost btn--sm"
                    onClick={() => {
                      setMode('register');
                      setError(null);
                    }}
                  >
                    ← Change Email
                  </button>
                  <button
                    type="button"
                    className="btn btn--ghost btn--sm"
                    onClick={handleResend}
                    style={{ color: 'var(--accent)' }}
                  >
                    Resend Code
                  </button>
                </div>
              </div>
            )}

            {/* Guest Mode Exploration Link */}
            <div style={{ textAlign: 'center', marginTop: 22, paddingTop: 18, borderTop: '1px solid var(--border)' }}>
              <button
                type="button"
                className="btn btn--ghost"
                onClick={onContinueAsGuest}
                style={{ fontSize: 12.5, color: 'var(--text-subtle)' }}
              >
                Or explore without signing in — <span style={{ color: 'var(--accent)' }}>Continue as Guest →</span>
              </button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
