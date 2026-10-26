import { isLiveMode } from '../services/auditService';
import { KeyIcon, MoonIcon, ShieldIcon, SunIcon } from './Icons';

interface Props {
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onOpenSettings: () => void;
}

export function NavBar({ theme, onToggleTheme, onOpenSettings }: Props) {
  const live = isLiveMode();
  return (
    <header className="nav">
      <div className="container nav__inner">
        <div className="brand">
          <span className="brand__mark">
            <ShieldIcon width={16} height={16} />
          </span>
          SST <span className="brand__sub">Safety &amp; Scope Tool</span>
        </div>
        <div className="nav__actions">
          <span className="status-pill" title={live ? 'Connected to backend engine' : 'Running client-side demo engine'}>
            <span className={`status-pill__dot ${live ? 'status-pill__dot--live' : ''}`} />
            {live ? 'Engine online' : 'Demo mode'}
          </span>
          <button id="theme-toggle" className="btn btn--ghost btn--icon" aria-label="Toggle theme" onClick={onToggleTheme}>
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
          <button id="open-settings" className="btn btn--ghost btn--icon" aria-label="API key settings" onClick={onOpenSettings}>
            <KeyIcon />
          </button>
        </div>
      </div>
    </header>
  );
}
