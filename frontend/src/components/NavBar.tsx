import { isLiveMode } from '../services/auditService';
import type { UserProfile } from '../types/user';
import { GoogleIcon, HistoryIcon, MoonIcon, SettingsIcon, ShieldIcon, SunIcon } from './Icons';

export type AppPage = 'studio' | 'history' | 'settings';

interface Props {
  activePage: AppPage;
  onNavigate: (page: AppPage) => void;
  auditCount: number;
  currentUser: UserProfile | null;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onOpenAuth: () => void;
}

export function NavBar({
  activePage,
  onNavigate,
  auditCount,
  currentUser,
  theme,
  onToggleTheme,
  onOpenAuth,
}: Props) {
  const live = isLiveMode();

  return (
    <header className="nav">
      <div className="container nav__inner">
        {/* Brand */}
        <div className="brand" onClick={() => onNavigate('studio')} style={{ cursor: 'pointer' }}>
          <span className="brand__mark">
            <ShieldIcon width={16} height={16} />
          </span>
          <span style={{ fontWeight: 700, letterSpacing: '0.04em' }}>SST</span>
          <span className="brand__sub" style={{ display: 'none' }}>Safety &amp; Scope Tool</span>
        </div>

        {/* Primary Page Navigation Tabs */}
        <nav className="nav-page-tabs">
          <button
            className={`nav-tab ${activePage === 'studio' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('studio')}
          >
            Audit Studio
          </button>
          <button
            className={`nav-tab ${activePage === 'history' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('history')}
          >
            <HistoryIcon width={13} height={13} />
            Past Audits
            {auditCount > 0 && <span className="nav-tab__count">{auditCount}</span>}
          </button>
          <button
            className={`nav-tab ${activePage === 'settings' ? 'nav-tab--active' : ''}`}
            onClick={() => onNavigate('settings')}
          >
            <SettingsIcon width={13} height={13} />
            Settings
          </button>
        </nav>

        {/* Right Actions */}
        <div className="nav__actions">
          {/* Status pill */}
          <span
            className="status-pill"
            title={live ? 'Connected to backend engine' : 'Running client-side demo engine'}
          >
            <span className={`status-pill__dot ${live ? 'status-pill__dot--live' : ''}`} />
            <span className="status-pill__text">{live ? 'Live Engine' : 'Demo Mode'}</span>
          </span>

          {/* User Auth Profile or Google Login button */}
          {currentUser ? (
            <button
              className="user-nav-pill"
              onClick={onOpenAuth}
              title={`Logged in as ${currentUser.email}`}
            >
              <img src={currentUser.avatarUrl} alt={currentUser.name} className="user-nav-pill__avatar" />
              <span className="user-nav-pill__name">{currentUser.name.split(' ')[0]}</span>
            </button>
          ) : (
            <button
              className="btn btn--google-nav"
              onClick={onOpenAuth}
              title="Sign in with your Google account"
            >
              <GoogleIcon width={14} height={14} />
              <span>Sign In</span>
            </button>
          )}

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
