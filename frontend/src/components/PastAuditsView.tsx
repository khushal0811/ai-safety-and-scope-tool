import React, { useMemo, useState } from 'react';
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
  ShieldIcon,
  TrashIcon,
  XIcon,
} from './Icons';
import { downloadComplianceReport } from '../services/auditService';

interface Props {
  audits: PastAudit[];
  currentUser: UserProfile | null;
  onDeleteAudits: (auditIds: string[]) => Promise<void> | void;
  onLoadAuditIntoStudio: (audit: PastAudit) => void;
  onOpenLogin: () => void;
  onSyncCloud?: () => Promise<void> | void;
}

export function PastAuditsView({
  audits,
  currentUser,
  onDeleteAudits,
  onLoadAuditIntoStudio,
  onOpenLogin,
  onSyncCloud,
}: Props) {
  const [filterVerdict, setFilterVerdict] = useState<'All' | 'Correct' | 'Incorrect' | 'Unsafe'>('All');
  const [search, setSearch] = useState('');
  const [selectedAudit, setSelectedAudit] = useState<PastAudit | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [deleting, setDeleting] = useState(false);
  const [exportingReport, setExportingReport] = useState<'pdf' | 'markdown' | null>(null);

  async function handleDownloadAttestation(format: 'pdf' | 'markdown', roeIdOverride?: string) {
    setExportingReport(format);
    try {
      const roeId = roeIdOverride || (selectedAudit?.roeId) || (filteredAudits[0]?.roeId) || 'ROE-PRESET-NET-001';
      await downloadComplianceReport(roeId, format, currentUser?.id);
    } catch (err) {
      console.error('Failed to export compliance attestation:', err);
    } finally {
      setExportingReport(null);
    }
  }

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

  const allFilteredIds = useMemo(() => filteredAudits.map((a) => a.id), [filteredAudits]);
  const isAllSelected = allFilteredIds.length > 0 && allFilteredIds.every((id) => selectedIds.has(id));

  function toggleSelectAll() {
    if (isAllSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        allFilteredIds.forEach((id) => next.delete(id));
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        allFilteredIds.forEach((id) => next.add(id));
        return next;
      });
    }
  }

  function toggleSelectOne(id: string, e?: React.MouseEvent | React.ChangeEvent) {
    e?.stopPropagation();
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  async function handleDelete(ids: string[]) {
    if (ids.length === 0) return;
    const confirmMsg =
      ids.length === 1
        ? 'Permanently delete this audit log from the database? This cannot be undone.'
        : `Permanently delete ${ids.length} selected audit logs from the database? This cannot be undone.`;

    if (!window.confirm(confirmMsg)) return;

    setDeleting(true);
    try {
      await onDeleteAudits(ids);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        ids.forEach((id) => next.delete(id));
        return next;
      });
      if (selectedAudit && ids.includes(selectedAudit.id)) {
        setSelectedAudit(null);
      }
    } finally {
      setDeleting(false);
    }
  }

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
    const toExport = selectedIds.size > 0 ? audits.filter((a) => selectedIds.has(a.id)) : audits;
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(toExport, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute('href', dataStr);
    dl.setAttribute('download', `vallum_audit_history_${new Date().toISOString().slice(0, 10)}.json`);
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
        <div className="scope-banner" style={{ marginBottom: 24, borderColor: 'var(--border)' }}>
          <div className="scope-banner__info">
            <span className="ndot" style={{ background: 'var(--text-subtle)' }} />
            <span>
              <strong>Guest Privacy Active:</strong> Past audits are strictly isolated to authenticated user accounts and stored in Supabase PostgreSQL with Row Level Security. No audits are stored in guest memory or cookies.
            </span>
          </div>
          <button className="btn btn--sm btn--primary" onClick={onOpenLogin}>
            Sign In to View Saved Audits
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

      {/* Toolbar: Search, Filters, Bulk Delete, Export */}
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

        <div className="history-actions" style={{ alignItems: 'center' }}>
          {selectedIds.size > 0 && currentUser && (
            <>
              <button
                type="button"
                id="delete-selected-btn"
                className="btn btn--sm btn--danger row"
                style={{ gap: 6 }}
                onClick={() => handleDelete(Array.from(selectedIds))}
                disabled={deleting}
                title="Permanently delete selected audits from database"
              >
                {deleting ? (
                  <span className="spinner" style={{ width: 12, height: 12 }} />
                ) : (
                  <TrashIcon width={13} height={13} />
                )}
                Delete Selected ({selectedIds.size})
              </button>
              <button
                type="button"
                className="btn btn--sm btn--ghost"
                onClick={() => setSelectedIds(new Set())}
                title="Clear selected audits"
              >
                Deselect
              </button>
            </>
          )}

          {onSyncCloud && (
            <button
              className="btn btn--sm"
              onClick={handleCloudSync}
              disabled={syncing || deleting}
              title="Synchronize audit history with Supabase PostgreSQL cloud database"
            >
              <RefreshIcon width={13} height={13} style={{ animation: syncing ? 'spin 1s linear infinite' : 'none' }} />
              {syncing ? 'Syncing...' : 'Sync Cloud'}
            </button>
          )}
          <button
            type="button"
            className="btn btn--sm btn--primary row"
            style={{ gap: 6 }}
            onClick={() => handleDownloadAttestation('pdf')}
            disabled={exportingReport !== null}
            title="Download signed, client-ready RoE compliance attestation PDF with cryptographic SHA-256 hash chains"
          >
            <ShieldIcon width={13} height={13} />
            {exportingReport === 'pdf' ? 'Generating PDF...' : 'RoE Attestation (PDF)'}
          </button>
          <button
            type="button"
            className="btn btn--sm row"
            style={{ gap: 6 }}
            onClick={() => handleDownloadAttestation('markdown')}
            disabled={exportingReport !== null}
            title="Download signed RoE compliance attestation in Markdown"
          >
            {exportingReport === 'markdown' ? 'Generating...' : 'Markdown'}
          </button>
          <button className="btn btn--sm btn--ghost" onClick={exportJSON} title="Download audits as JSON">
            <DownloadIcon width={13} height={13} /> Export JSON
          </button>
        </div>
      </div>

      {/* Table / List */}
      {filteredAudits.length === 0 ? (
        <div className="empty" style={{ marginTop: 24 }}>
          <div className="empty__icon">
            <HistoryIcon width={22} height={22} />
          </div>
          <h3>{currentUser ? (search ? 'No matching audit logs found' : 'No audit logs yet') : 'No Audit History in Guest Mode'}</h3>
          <p className="card__desc" style={{ maxWidth: 540, margin: '8px auto 16px' }}>
            {currentUser
              ? search
                ? 'Try clearing your search query.'
                : 'Run an audit in the Studio to generate persistent logs under your account.'
              : 'Audit history is private and only saved to the cloud database for registered users. Sign in to access your saved penetration testing audits.'}
          </p>
          {!currentUser && (
            <button className="btn btn--primary" onClick={onOpenLogin}>
              Sign In to Access Saved Audits
            </button>
          )}
        </div>
      ) : (
        <div className="history-table-card">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  {currentUser && (
                    <th style={{ width: 38, paddingLeft: 14 }}>
                      <input
                        type="checkbox"
                        checked={isAllSelected}
                        onChange={toggleSelectAll}
                        aria-label="Select all audits"
                        style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                      />
                    </th>
                  )}
                  <th>Verdict</th>
                  <th>RoE Scope</th>
                  <th>Model</th>
                  <th>Proposed Command</th>
                  <th>Violations</th>
                  <th>Timestamp</th>
                  <th style={{ textAlign: 'right', paddingRight: 14 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAudits.map((item) => {
                  const v = item.result.verdict;
                  const violations = item.result.violation_details || [];
                  const isSelected = selectedIds.has(item.id);
                  const dateStr = new Date(item.timestamp).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                    month: 'short',
                    day: 'numeric',
                  });

                  return (
                    <tr
                      key={item.id}
                      className={`history-row ${isSelected ? 'history-row--selected' : ''}`}
                      onClick={() => setSelectedAudit(item)}
                      style={{ cursor: 'pointer' }}
                    >
                      {currentUser && (
                        <td style={{ width: 38, paddingLeft: 14 }} onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={(e) => toggleSelectOne(item.id, e)}
                            aria-label={`Select audit ${item.id}`}
                            style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                          />
                        </td>
                      )}
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
                      <td style={{ textAlign: 'right', paddingRight: 14 }}>
                        <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
                          <button
                            className="btn btn--sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedAudit(item);
                            }}
                          >
                            View Details <ChevronIcon width={12} height={12} />
                          </button>
                          {currentUser && (
                            <button
                              className="btn btn--sm btn--ghost btn--icon"
                              style={{ color: 'var(--unsafe)', padding: '4px 6px' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDelete([item.id]);
                              }}
                              disabled={deleting}
                              title="Permanently delete this audit from database"
                              aria-label="Delete audit"
                            >
                              <TrashIcon width={13} height={13} />
                            </button>
                          )}
                        </div>
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
            style={{ maxWidth: 760, width: '100%', maxHeight: '88vh', overflowY: 'auto' }}
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

              {selectedAudit.result.safe_sanitized_command && selectedAudit.result.verdict !== 'Correct' && (
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

            <div className="modal__foot" style={{ flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
              <span className="mono font-xs text-muted" style={{ whiteSpace: 'nowrap' }}>
                Audit time: {selectedAudit.executionTimeMs}ms · Deterministic static engine
              </span>
              <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginLeft: 'auto' }}>
                {currentUser && (
                  <button
                    type="button"
                    className="btn btn--danger btn--sm"
                    disabled={deleting}
                    onClick={() => handleDelete([selectedAudit.id])}
                    title="Permanently delete this audit from the database"
                  >
                    <TrashIcon width={13} height={13} />
                    Delete Permanently
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn--sm"
                  onClick={() => handleDownloadAttestation('pdf', selectedAudit.roeId)}
                  disabled={exportingReport !== null}
                  title={`Download signed RoE compliance attestation report for ${selectedAudit.roeName}`}
                >
                  <ShieldIcon width={13} height={13} />
                  {exportingReport === 'pdf' ? 'Generating...' : 'Scope Attestation (PDF)'}
                </button>
                <button className="btn btn--sm" onClick={() => setSelectedAudit(null)}>
                  Close
                </button>
                <button
                  className="btn btn--primary btn--sm"
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
