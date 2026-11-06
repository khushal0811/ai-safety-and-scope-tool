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
}: Props) {
  const [live, setLive] = useState<boolean>(isLiveMode());

  useEffect(() => {
    return subscribeLiveStatus(setLive);
  }, []);

  return (
    <header className="nav">
      <div className="container nav__inner">
        {/* Brand */}
        <div
          className="brand"
          role="button"
          tabIndex={0}
          onClick={() => onNavigate('studio')}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigate('studio');
            }
          }}
          style={{ cursor: 'pointer', gap: 10 }}
        >
          <span className="brand__mark" style={{ width: 34, height: 34, padding: 4 }}>
            <VallumIcon width={25} height={25} />
          </span>
          <span style={{ fontWeight: 800, fontSize: 17, letterSpacing: '-0.01em', color: 'var(--text)' }}>
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
          {/* Status pill (Compact) */}
          <span
            className="status-pill"
            title={live ? 'Connected to FastAPI backend engine (click to refresh status)' : 'Running client-side demo engine (click to probe backend)'}
            role="button"
            tabIndex={0}
            onClick={() => checkBackendHealth()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                checkBackendHealth();
              }
            }}
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
              <img
                src={/^https:\/\//i.test(currentUser.avatarUrl || '')
                  ? currentUser.avatarUrl
                  : `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(currentUser.email || currentUser.name)}`}
                alt={currentUser.name}
                referrerPolicy="no-referrer"
                onError={(e) => {
                  // Switch to the generated avatar once; never loop if the fallback also fails
                  const fallback = `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(currentUser.email || currentUser.name)}`;
                  if (!e.currentTarget.src.startsWith(fallback)) e.currentTarget.src = fallback;
                }}
                className="user-nav-pill__avatar"
              />
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
