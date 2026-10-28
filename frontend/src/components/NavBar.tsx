import { useEffect, useState } from 'react';
import { checkBackendHealth, isLiveMode, subscribeLiveStatus } from '../services/auditService';
import type { UserProfile } from '../types/user';
import { BenchmarkIcon, HistoryIcon, MoonIcon, SettingsIcon, ShieldIcon, SunIcon, UserIcon, VallumIcon } from './Icons';

export type AppPage = 'studio' | 'history' | 'benchmark' | 'past-benchmarks' | 'settings';

interface Props {
  activePage: AppPage;
  onNavigate: (page: AppPage) => void;
  auditCount: number;
  benchmarkCount?: number;
  currentUser: UserProfile | null;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onOpenAuth: () => void;
  trustTier: 'hybrid' | 'deterministic';
  onSelectTrustTier: (tier: 'hybrid' | 'deterministic') => void;
}

export function NavBar({
  activePage,
  onNavigate,
  auditCount,
  benchmarkCount = 0,
  currentUser,
  theme,
  onToggleTheme,
  onOpenAuth,
  trustTier,
  onSelectTrustTier,
}: Props) {
  const [live, setLive] = useState<boolean>(isLiveMode());

  useEffect(() => {
    return subscribeLiveStatus(setLive);
  }, []);

  return (
    <header className="nav">
      <div className="container nav__inner">
        {/* Brand */}
        <div className="brand" onClick={() => onNavigate('studio')} style={{ cursor: 'pointer' }}>
          <span className="brand__mark" style={{ width: 26, height: 26, padding: 3 }}>
            <VallumIcon width={20} height={20} />
          </span>
          <span style={{ fontWeight: 800, fontSize: 15.5, letterSpacing: '0.02em', color: 'var(--text)' }}>
            Vallum
          </span>
          <span className="brand__sub" style={{ display: 'none' }}>AI Safety &amp; Scope Boundary Engine</span>
        </div>

        {/* Primary Page Navigation Tabs (Decongested) */}
        <nav className="nav-page-tabs">
          <button
            className={`nav-tab ${activePage === 'studio' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('studio')}
            title="Audit Studio — Inspect Pentest Commands"
          >
            <ShieldIcon width={13} height={13} />
            <span>Audit</span>
          </button>
          <button
            className={`nav-tab ${activePage === 'history' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('history')}
            title="Past Audits &amp; Compliance Attestations"
          >
            <HistoryIcon width={13} height={13} />
            <span>Past Audits</span>
            {auditCount > 0 && <span className="nav-tab__count">{auditCount}</span>}
          </button>
          <button
            className={`nav-tab ${activePage === 'benchmark' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('benchmark')}
            title="Benchmark Studio — Multi-Model Evaluation"
          >
            <BenchmarkIcon width={13} height={13} />
            <span>Benchmark</span>
          </button>
          <button
            className={`nav-tab ${activePage === 'past-benchmarks' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('past-benchmarks')}
            title="Past Benchmark Runs &amp; Leaderboards"
          >
            <HistoryIcon width={13} height={13} />
            <span>Past Benchmarks</span>
            {benchmarkCount > 0 && <span className="nav-tab__count">{benchmarkCount}</span>}
          </button>
        </nav>

        {/* Right Actions */}
        <div className="nav__actions">
          {/* Trust Tier Switcher */}
          <div className="trust-tier-toggle" role="group" aria-label="Engine trust tier">
            <button
              type="button"
              className={`trust-tier-btn ${trustTier === 'hybrid' ? 'trust-tier-btn--active' : ''}`}
              onClick={() => onSelectTrustTier('hybrid')}
              title="Hybrid Mode: Pass 1 AST static parser + Pass 2 Groq AI Judge context layer"
            >
              <span className="trust-tier-btn__dot trust-tier-btn__dot--hybrid" />
              <span>Hybrid</span>
            </button>
            <button
              type="button"
              className={`trust-tier-btn ${trustTier === 'deterministic' ? 'trust-tier-btn--active' : ''}`}
              onClick={() => onSelectTrustTier('deterministic')}
              title="Deterministic-Only Mode: Strict Pass 1 AST engine authoritative. AI Judge is advisory only."
            >
              <span className="trust-tier-btn__dot trust-tier-btn__dot--deterministic" />
              <span>Deterministic</span>
            </button>
          </div>

          {/* Status pill (Compact) */}
          <span
            className="status-pill"
            title={live ? 'Connected to FastAPI backend engine (click to refresh status)' : 'Running client-side demo engine (click to probe backend)'}
            onClick={() => checkBackendHealth()}
            style={{ cursor: 'pointer' }}
          >
            <span className={`status-pill__dot ${live ? 'status-pill__dot--live' : ''}`} />
            <span className="status-pill__text">{live ? 'Live' : 'Demo'}</span>
          </span>

          {/* User Auth Profile or Login button */}
          {currentUser ? (
            <button
              className="user-nav-pill"
              onClick={onOpenAuth}
              title={`Logged in as ${currentUser.email} (${currentUser.role === 'admin' ? 'Super Admin' : 'Penetration Tester'})`}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              <img src={currentUser.avatarUrl} alt={currentUser.name} className="user-nav-pill__avatar" />
              <span className="user-nav-pill__name">{currentUser.name.split(' ')[0]}</span>
              {currentUser.role === 'admin' ? (
                <span style={{
                  fontSize: 9.5,
                  fontWeight: 700,
                  padding: '1.5px 5px',
                  borderRadius: 3,
                  background: 'rgba(234, 179, 8, 0.16)',
                  border: '1px solid rgba(234, 179, 8, 0.4)',
                  color: '#eab308',
                  letterSpacing: '0.06em',
                }}>
                  ADMIN
                </span>
              ) : (
                <span style={{
                  fontSize: 9.5,
                  fontWeight: 600,
                  padding: '1.5px 5px',
                  borderRadius: 3,
                  background: 'rgba(34, 211, 238, 0.12)',
                  border: '1px solid rgba(34, 211, 238, 0.3)',
                  color: '#22d3ee',
                  letterSpacing: '0.03em',
                }}>
                  TESTER
                </span>
              )}
            </button>
          ) : (
            <button
              className="btn btn--google-nav"
              onClick={onOpenAuth}
              title="Sign in with Google, GitHub, or Email"
            >
              <UserIcon width={14} height={14} />
              <span>Sign In</span>
            </button>
          )}

          {/* Settings Action Button */}
          <button
            id="nav-settings-btn"
            className={`btn btn--ghost btn--icon ${activePage === 'settings' ? 'btn--icon-active' : ''}`}
            aria-label="Settings"
            title="Settings &amp; API Keys Vault"
            onClick={() => onNavigate('settings')}
          >
            <SettingsIcon width={15} height={15} />
          </button>

          {/* Theme Toggle */}
          <button
            id="theme-toggle"
            className="btn btn--ghost btn--icon"
            aria-label="Toggle theme"
            onClick={onToggleTheme}
            title="Toggle theme"
          >
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </div>
    </header>
  );
}
