import { useMemo, useState } from 'react';
import type { PastAudit } from '../types/history';
import type { UserProfile } from '../types/user';
import {
  AlertIcon,
  CheckIcon,
  ChevronIcon,
  CloudIcon,
  DownloadIcon,
  HistoryIcon,
  RefreshIcon,
  SearchIcon,
  TrashIcon,
  XIcon,
} from './Icons';

interface Props {
  audits: PastAudit[];
  currentUser: UserProfile | null;
  onClearHistory: () => void;
  onLoadAuditIntoStudio: (audit: PastAudit) => void;
  onOpenLogin: () => void;
  onSyncCloud?: () => Promise<void> | void;
}

export function PastAuditsView({
  audits,
  currentUser,
  onClearHistory,
  onLoadAuditIntoStudio,
  onOpenLogin,
  onSyncCloud,
}: Props) {
  const [filterVerdict, setFilterVerdict] = useState<'All' | 'Correct' | 'Incorrect' | 'Unsafe'>('All');
  const [search, setSearch] = useState('');
  const [selectedAudit, setSelectedAudit] = useState<PastAudit | null>(null);
  const [syncing, setSyncing] = useState(false);

  async function handleCloudSync() {
    if (!onSyncCloud) return;
    setSyncing(true);
    try {
      await onSyncCloud();
    } finally {
      setTimeout(() => setSyncing(false), 500);
    }
  }

  const filteredAudits = useMemo(() => {
    return audits.filter((a) => {
      const matchesVerdict = filterVerdict === 'All' || a.result.verdict === filterVerdict;
      const q = search.toLowerCase().trim();
      if (!q) return matchesVerdict;

      const matchesQuery =
        a.roeName.toLowerCase().includes(q) ||
        a.prompt.toLowerCase().includes(q) ||
        a.proposedCommand.toLowerCase().includes(q) ||
        a.modelName.toLowerCase().includes(q);

      return matchesVerdict && matchesQuery;
    });
  }, [audits, filterVerdict, search]);

  const metrics = useMemo(() => {
    const total = audits.length;
    const unsafeCount = audits.filter((a) => a.result.verdict === 'Unsafe').length;
    const correctCount = audits.filter((a) => a.result.verdict === 'Correct').length;
    const passRate = total > 0 ? Math.round((correctCount / total) * 100) : 0;
    const avgLatency =
      total > 0
        ? Math.round(audits.reduce((acc, a) => acc + (a.executionTimeMs || 30), 0) / total)
        : 0;

    return { total, unsafeCount, correctCount, passRate, avgLatency };
  }, [audits]);

  function exportJSON() {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(audits, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute('href', dataStr);
    dl.setAttribute('download', `sst_audit_history_${new Date().toISOString().slice(0, 10)}.json`);
    dl.click();
  }

  return (
    <div className="container" style={{ paddingBottom: 80 }}>
      {/* Header */}
      <div className="hero" style={{ padding: '32px 0 24px' }}>
        <div className="hero__eyebrow">// 002 — AUDIT HISTORY &amp; LOGS</div>
        <h1>Past Audits</h1>
        <p>
          Historical log of AI-generated penetration testing recommendations evaluated against Rules of Engagement.
        </p>
      </div>

      {currentUser ? (
        <div className="scope-banner" style={{ marginBottom: 24, borderColor: 'var(--accent)' }}>
          <div className="scope-banner__info">
            <CloudIcon width={16} height={16} style={{ color: 'var(--healthy)' }} />
            <span>
              <strong>Supabase PostgreSQL Active:</strong> Audits are securely synchronized with Row Level Security (RLS) under <code className="mono">{currentUser.email}</code>.
            </span>
          </div>
          <span className="tag tag--ok">● Cloud Sync Live</span>
        </div>
      ) : (
        <div className="scope-banner" style={{ marginBottom: 24 }}>
          <div className="scope-banner__info">
            <span className="ndot" />
            <span>
              <strong>Guest Session Active:</strong> Logs are stored in local browser memory. Sign in with Google to preserve audit records in PostgreSQL.
            </span>
          </div>
          <button className="btn btn--sm btn--primary" onClick={onOpenLogin}>
            Sign In with Google
          </button>
        </div>
      )}

      {/* Metric Cards Row */}
      <div className="history-metrics-grid">
        <div className="metric-card">
          <span className="metric-label">Total Audits</span>
          <span className="metric-value">{metrics.total}</span>
          <span className="metric-sub">Evaluated against active RoE</span>
        </div>
        <div className="metric-card">
          <span className="metric-label">Unsafe Interceptions</span>
          <span className="metric-value" style={{ color: 'var(--bad-fg)' }}>
            {metrics.unsafeCount}
          </span>
          <span className="metric-sub">Blocked before host execution</span>
        </div>
        <div className="metric-card">
          <span className="metric-label">RoE Compliance Rate</span>
          <span className="metric-value" style={{ color: 'var(--healthy)' }}>
            {metrics.passRate}%
          </span>
          <span className="metric-sub">Approved compliant outputs</span>
        </div>
        <div className="metric-card">
          <span className="metric-label">Average Audit Latency</span>
          <span className="metric-value mono">{metrics.avgLatency}ms</span>
          <span className="metric-sub">AST verification speed</span>
        </div>
      </div>

      {/* Toolbar: Search, Filters, Export */}
      <div className="history-toolbar">
        <div className="history-search">
          <SearchIcon width={14} height={14} style={{ color: 'var(--text-subtle)' }} />
          <input
            type="text"
            className="history-search__input"
            placeholder="Search by target IP, command, RoE, or prompt..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="btn btn--ghost btn--icon" onClick={() => setSearch('')}>
              <XIcon width={12} height={12} />
            </button>
          )}
        </div>

        <div className="history-filter-pills">
          {(['All', 'Unsafe', 'Incorrect', 'Correct'] as const).map((v) => {
            const count = v === 'All' ? audits.length : audits.filter((a) => a.result.verdict === v).length;
            const active = filterVerdict === v;
            return (
              <button
                key={v}
                className={`history-filter-btn ${active ? 'history-filter-btn--active' : ''}`}
                onClick={() => setFilterVerdict(v)}
              >
                {v} <span className="mono font-xs">({count})</span>
              </button>
            );
          })}
        </div>

        <div className="history-actions">
          {onSyncCloud && (
            <button
              className="btn btn--sm"
              onClick={handleCloudSync}
              disabled={syncing}
              title="Synchronize audit history with Supabase PostgreSQL cloud database"
            >
              <RefreshIcon width={13} height={13} style={{ animation: syncing ? 'spin 1s linear infinite' : 'none' }} />
              {syncing ? 'Syncing...' : 'Sync Cloud'}
            </button>
          )}
          <button className="btn btn--sm" onClick={exportJSON} title="Download audits as JSON">
            <DownloadIcon width={13} height={13} /> Export JSON
          </button>
          {audits.length > 0 && (
            <button className="btn btn--sm btn--danger" onClick={onClearHistory} title="Clear audit history">
              <TrashIcon width={13} height={13} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Table / List */}
      {filteredAudits.length === 0 ? (
        <div className="empty" style={{ marginTop: 24 }}>
          <div className="empty__icon">
            <HistoryIcon width={22} height={22} />
          </div>
          <h3>No matching audit logs found</h3>
          <p className="card__desc">
            {search ? 'Try clearing your search query.' : 'Run your first audit in the Studio to generate logs.'}
          </p>
        </div>
      ) : (
        <div className="history-table-card">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Verdict</th>
                  <th>RoE Scope</th>
                  <th>Model</th>
                  <th>Proposed Command</th>
                  <th>Violations</th>
                  <th>Timestamp</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAudits.map((item) => {
                  const v = item.result.verdict;
                  const violations = item.result.violation_details || [];
                  const dateStr = new Date(item.timestamp).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                    month: 'short',
                    day: 'numeric',
                  });

                  return (
                    <tr
                      key={item.id}
                      className="history-row"
                      onClick={() => setSelectedAudit(item)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span
                          className={`verdict__badge verdict__badge--sm ${
                            v === 'Correct'
                              ? 'tag--ok'
                              : v === 'Incorrect'
                              ? 'tag--warn'
                              : 'tag--bad'
                          }`}
                        >
                          {v === 'Correct' ? <CheckIcon width={12} height={12} /> : <AlertIcon width={12} height={12} />}
                          {v}
                        </span>
                      </td>
                      <td>
                        <strong style={{ fontSize: 13 }}>{item.roeName}</strong>
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                          {item.modelName}
                        </span>
                      </td>
                      <td>
                        <code className="history-cmd-preview">{item.proposedCommand}</code>
                      </td>
                      <td>
                        {violations.length > 0 ? (
                          <span className="sev sev--CRITICAL">
                            {violations.length} violation
                            {violations.length > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="sev sev--INFO">0 violations</span>
                        )}
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                          {dateStr}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn--sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAudit(item);
                          }}
                        >
                          View Details <ChevronIcon width={12} height={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Audit Detail Modal / Drawer */}
      {selectedAudit && (
        <div className="modal-backdrop" onClick={() => setSelectedAudit(null)}>
          <div
            className="modal"
            style={{ maxWidth: 680, maxHeight: '88vh', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal__head">
              <div className="row">
                <span
                  className={`verdict__badge ${
                    selectedAudit.result.verdict === 'Correct'
                      ? 'tag--ok'
                      : selectedAudit.result.verdict === 'Incorrect'
                      ? 'tag--warn'
                      : 'tag--bad'
                  }`}
                >
                  {selectedAudit.result.verdict}
                </span>
                <span className="mono font-xs text-muted">ID: {selectedAudit.id}</span>
              </div>
              <button
                className="btn btn--ghost btn--icon"
                onClick={() => setSelectedAudit(null)}
                aria-label="Close"
              >
                <XIcon />
              </button>
            </div>

            <div className="modal__body" style={{ display: 'grid', gap: 16 }}>
              <div>
                <span className="section-label">Active Scope</span>
                <h4 style={{ fontSize: 15, marginBottom: 2 }}>{selectedAudit.roeName}</h4>
                <span className="mono font-xs text-muted">Model Evaluated: {selectedAudit.modelName}</span>
              </div>

              <div>
                <span className="section-label">User Prompt</span>
                <div className="code-block" style={{ fontStyle: 'italic' }}>
                  "{selectedAudit.prompt}"
                </div>
              </div>

              <div>
                <span className="section-label">Proposed Command</span>
                <pre className="code-block">{selectedAudit.proposedCommand}</pre>
              </div>

              {selectedAudit.result.violation_details.length > 0 && (
                <div>
                  <span className="section-label">Violations Detected</span>
                  <div style={{ display: 'grid', gap: 8 }}>
                    {selectedAudit.result.violation_details.map((rb, idx) => (
                      <div key={idx} className="note note--bad" style={{ flexDirection: 'column' }}>
                        <div className="row between" style={{ width: '100%' }}>
                          <strong>{rb.rule}</strong>
                          <span className="sev sev--CRITICAL">{rb.severity}</span>
                        </div>
                        <p style={{ marginTop: 4, fontSize: 12 }}>{rb.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedAudit.result.safe_sanitized_command && (
                <div>
                  <span className="section-label">Remediated Safe Output</span>
                  <div className="sanitized" style={{ marginTop: 4 }}>
                    <div className="sanitized__head">
                      <span className="sanitized__title">Self-Sanitized Command</span>
                    </div>
                    <pre className="code-block" style={{ margin: 0, border: 0 }}>
                      {selectedAudit.result.safe_sanitized_command}
                    </pre>
                  </div>
                </div>
              )}
            </div>

            <div className="modal__foot">
              <span className="mono font-xs text-muted">
                Audit time: {selectedAudit.executionTimeMs}ms · Deterministic static engine
              </span>
              <div className="row">
                <button className="btn" onClick={() => setSelectedAudit(null)}>
                  Close
                </button>
                <button
                  className="btn btn--primary"
                  onClick={() => {
                    onLoadAuditIntoStudio(selectedAudit);
                    setSelectedAudit(null);
                  }}
                >
                  Load in Studio ↗
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
