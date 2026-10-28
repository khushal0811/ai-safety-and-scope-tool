import { useMemo, useState } from 'react';
import type { BenchmarkRunRecord } from '../types/benchmark';
import type { UserProfile } from '../types/user';
import {
  AlertIcon,
  CheckIcon,
  CopyIcon,
  DownloadIcon,
  HistoryIcon,
  RefreshIcon,
  SearchIcon,
  TrashIcon,
  XIcon,
} from './Icons';

interface Props {
  benchmarks: BenchmarkRunRecord[];
  currentUser: UserProfile | null;
  onDeleteBenchmarks: (benchmarkIds: string[]) => Promise<void> | void;
  onOpenLogin: () => void;
  onSyncCloud?: () => Promise<void> | void;
  onNavigateBenchmarkStudio?: () => void;
  onNavigateToStudio?: () => void;
}

export function PastBenchmarksView({
  benchmarks,
  currentUser,
  onDeleteBenchmarks,
  onOpenLogin,
  onSyncCloud,
  onNavigateBenchmarkStudio,
  onNavigateToStudio,
}: Props) {
  const handleNav = onNavigateBenchmarkStudio || onNavigateToStudio || (() => {});
  const [search, setSearch] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [inspectedRun, setInspectedRun] = useState<BenchmarkRunRecord | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  async function handleCloudSync() {
    if (!onSyncCloud) return;
    setSyncing(true);
    try {
      await onSyncCloud();
    } finally {
      setTimeout(() => setSyncing(false), 500);
    }
  }

  function copyText(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  function renderSafeCommandLines(commandStr: string) {
    const lines = commandStr.split('\n');
    return lines.map((line, lineIdx) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return <div key={lineIdx} style={{ height: 6 }} />;
      }
      if (trimmed.startsWith('#')) {
        return (
          <div key={lineIdx} style={{ color: 'var(--text-subtle)', fontStyle: 'italic', paddingLeft: 2 }}>
            {line}
          </div>
        );
      }
      return (
        <div key={lineIdx} style={{ color: 'var(--ok-fg)', display: 'flex', alignItems: 'flex-start' }}>
          <span style={{ color: 'var(--text-subtle)', userSelect: 'none', marginRight: 8, flexShrink: 0 }}>$</span>
          <span style={{ flex: 1, wordBreak: 'break-all' }}>{line}</span>
        </div>
      );
    });
  }

  // Filter benchmarks by search query
  const filteredBenchmarks = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return benchmarks;
    return benchmarks.filter(
      (b) =>
        b.scenario_title?.toLowerCase().includes(q) ||
        b.prompt?.toLowerCase().includes(q) ||
        b.roe_id?.toLowerCase().includes(q) ||
        b.fastest_model?.toLowerCase().includes(q)
    );
  }, [benchmarks, search]);

  const allFilteredIds = useMemo(() => filteredBenchmarks.map((b) => b.benchmark_id), [filteredBenchmarks]);
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
        ? 'Permanently delete this benchmark run from the database? This cannot be undone.'
        : `Permanently delete ${ids.length} selected benchmark runs from the database? This cannot be undone.`;

    if (!window.confirm(confirmMsg)) return;

    setDeleting(true);
    try {
      await onDeleteBenchmarks(ids);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        ids.forEach((id) => next.delete(id));
        return next;
      });
      if (inspectedRun && ids.includes(inspectedRun.benchmark_id)) {
        setInspectedRun(null);
      }
    } finally {
      setDeleting(false);
    }
  }

  function exportJSON() {
    const toExport = selectedIds.size > 0
      ? benchmarks.filter((b) => selectedIds.has(b.benchmark_id))
      : benchmarks;
    const blob = new Blob([JSON.stringify(toExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vallum_benchmark_history_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Aggregate metrics
  const avgCompliance = useMemo(() => {
    if (benchmarks.length === 0) return 0;
    const sum = benchmarks.reduce((acc, b) => acc + (b.compliance_rate || 0), 0);
    return Math.round(sum / benchmarks.length);
  }, [benchmarks]);

  const avgScopeViolation = useMemo(() => {
    if (benchmarks.length === 0) return 0;
    const sum = benchmarks.reduce((acc, b) => acc + (b.scope_violation_rate || 0), 0);
    return Math.round(sum / benchmarks.length);
  }, [benchmarks]);

  const avgLatency = useMemo(() => {
    if (benchmarks.length === 0) return 0;
    const sum = benchmarks.reduce((acc, b) => acc + (b.average_latency_ms || 0), 0);
    return Math.round(sum / benchmarks.length);
  }, [benchmarks]);

  return (
    <main className="container canvas-container" style={{ maxWidth: 1100, paddingBottom: 80 }}>
      {/* View Header */}
      <section className="hero" style={{ textAlign: 'center', paddingBottom: 16 }}>
        <span className="hero__eyebrow">// 003 — MULTI-MODEL BENCHMARK ARCHIVE</span>
        <h1>Past Frontier Benchmarks</h1>
        <p style={{ margin: '8px auto 0', maxWidth: 640 }}>
          Historical comparative evaluation matrix records assessing frontier LLMs against active Rules of Engagement scopes.
        </p>
      </section>

      {/* Guest Mode Warning Banner */}
      {!currentUser && (
        <div className="model-key-banner" style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
              <HistoryIcon width={16} height={16} style={{ color: 'var(--warn-fg)', flexShrink: 0 }} />
              <span>
                <strong>Guest Mode Active:</strong> Benchmark history is stored in local session only. Sign in to sync your evaluation records across devices with encrypted database persistence.
              </span>
            </div>
            <button type="button" className="btn btn--sm btn--primary" onClick={onOpenLogin}>
              Sign In to Persist
            </button>
          </div>
        </div>
      )}

      {/* Global Telemetry Score Cards */}
      {benchmarks.length > 0 && (
        <div className="benchmark-score-grid" style={{ marginBottom: 24 }}>
          <div className="benchmark-score-card">
            <div className="benchmark-score-card__top">
              <span className="metric-label">Total Benchmarks</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>
                {benchmarks.length} Runs
              </span>
            </div>
            <div className="benchmark-score-card__value mono">{benchmarks.length}</div>
            <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>Multi-model parallel runs</span>
          </div>

          <div className="benchmark-score-card">
            <div className="benchmark-score-card__top">
              <span className="metric-label">Avg Compliance</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--ok-fg)' }}>
                {avgCompliance}%
              </span>
            </div>
            <div className="benchmark-score-card__value" style={{ color: 'var(--ok-fg)' }}>
              {avgCompliance}%
            </div>
            <div className="benchmark-score-card__bar">
              <div
                className="benchmark-score-card__bar-fill"
                style={{ width: `${avgCompliance}%`, background: 'var(--ok-fg)' }}
              />
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>Verified compliant output</span>
          </div>

          <div className="benchmark-score-card">
            <div className="benchmark-score-card__top">
              <span className="metric-label">Avg Scope Violations</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--bad-fg)' }}>
                {avgScopeViolation}%
              </span>
            </div>
            <div className="benchmark-score-card__value" style={{ color: avgScopeViolation > 0 ? 'var(--bad-fg)' : 'var(--text)' }}>
              {avgScopeViolation}%
            </div>
            <div className="benchmark-score-card__bar">
              <div
                className="benchmark-score-card__bar-fill"
                style={{ width: `${avgScopeViolation}%`, background: 'var(--bad-fg)' }}
              />
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>Out-of-scope targets</span>
          </div>

          <div className="benchmark-score-card">
            <div className="benchmark-score-card__top">
              <span className="metric-label">Avg Response Time</span>
            </div>
            <div className="benchmark-score-card__value mono">
              {avgLatency}
              <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-subtle)', marginLeft: 4 }}>ms</span>
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>Multi-model average inference</span>
          </div>
        </div>
      )}

      {/* Control & Filter Bar */}
      <div className="card" style={{ padding: '12px 16px', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div style={{ position: 'relative', flex: '1 1 280px', minWidth: 200 }}>
            <SearchIcon
              width={14}
              height={14}
              style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-subtle)' }}
            />
            <input
              type="text"
              className="input input--sm"
              placeholder="Search by scenario, prompt, RoE, or model..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 30, width: '100%' }}
            />
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {currentUser && onSyncCloud && (
              <button
                type="button"
                className="btn btn--sm btn--secondary"
                onClick={handleCloudSync}
                disabled={syncing}
                title="Synchronize history from cloud PostgreSQL database"
              >
                <RefreshIcon width={13} height={13} className={syncing ? 'spin' : ''} />
                <span>{syncing ? 'Syncing...' : 'Sync Database'}</span>
              </button>
            )}

            <button
              type="button"
              className="btn btn--sm btn--secondary"
              onClick={exportJSON}
              disabled={benchmarks.length === 0}
              title="Export benchmark history as JSON"
            >
              <DownloadIcon width={13} height={13} />
              <span>Export JSON</span>
            </button>

            <button
              type="button"
              className="btn btn--sm btn--primary"
              onClick={handleNav}
            >
              Run New Benchmark →
            </button>
          </div>
        </div>

        {/* Selection & Bulk Actions Row */}
        {filteredBenchmarks.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 10, marginTop: 10, borderTop: '1px solid var(--border)' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer', color: 'var(--text-muted)' }}>
              <input
                type="checkbox"
                checked={isAllSelected}
                onChange={toggleSelectAll}
                style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
              />
              <span>Select All ({filteredBenchmarks.length})</span>
            </label>

            {selectedIds.size > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-subtle)' }}>
                  {selectedIds.size} selected
                </span>
                <button
                  type="button"
                  className="btn btn--sm btn--danger"
                  onClick={() => handleDelete(Array.from(selectedIds))}
                  disabled={deleting}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  <TrashIcon width={12} height={12} />
                  <span>Delete Selected</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Benchmark Runs List */}
      {filteredBenchmarks.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <HistoryIcon width={36} height={36} style={{ color: 'var(--text-subtle)', margin: '0 auto 12px' }} />
          <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 6 }}>No Benchmark Runs Found</h3>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 440, margin: '0 auto 16px' }}>
            {search
              ? 'No benchmark evaluations match your search query.'
              : 'Run parallel multi-LLM benchmark evaluations against active Rules of Engagement to record frontier model safety metrics.'}
          </p>
          <button type="button" className="btn btn--sm btn--primary" onClick={handleNav}>
            Launch Benchmark Studio →
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filteredBenchmarks.map((run) => {
            const isSelected = selectedIds.has(run.benchmark_id);
            const dateStr = new Date(run.created_at).toLocaleString(undefined, {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            });

            return (
              <div
                key={run.benchmark_id}
                className="card benchmark-history-item"
                style={{
                  padding: 16,
                  borderColor: isSelected ? 'var(--accent)' : 'var(--border)',
                  background: isSelected ? 'rgba(74, 92, 224, 0.03)' : 'var(--surface-raised)',
                  transition: 'border-color 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={(e) => toggleSelectOne(run.benchmark_id, e)}
                    style={{ accentColor: 'var(--accent)', marginTop: 4, cursor: 'pointer' }}
                  />

                  <div style={{ flex: 1, minWidth: 0 }}>
                    {/* Top Row: Title, RoE badge, Date */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 700, fontSize: 14.5, color: 'var(--text)' }}>
                          {run.scenario_title || 'Custom Pentest Benchmark'}
                        </span>
                        <span className="badge font-xs" style={{ background: 'var(--surface-sunken)', color: 'var(--text-muted)' }}>
                          {run.roe_id}
                        </span>
                      </div>
                      <span className="mono font-xs" style={{ color: 'var(--text-subtle)' }}>
                        {dateStr}
                      </span>
                    </div>

                    {/* Prompt Snippet */}
                    <div className="mono font-xs" style={{ color: 'var(--text-muted)', marginBottom: 12, background: 'var(--surface-sunken)', padding: '6px 10px', borderRadius: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {run.prompt}
                    </div>

                    {/* Quantitative Metric Badges */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', fontSize: 12 }}>
                      <div>
                        <span style={{ color: 'var(--text-subtle)', marginRight: 6 }}>Compliance:</span>
                        <span style={{ fontWeight: 800, color: 'var(--ok-fg)' }}>{run.compliance_rate}%</span>
                      </div>

                      <div>
                        <span style={{ color: 'var(--text-subtle)', marginRight: 6 }}>Scope Violations:</span>
                        <span style={{ fontWeight: 800, color: run.scope_violation_rate > 0 ? 'var(--bad-fg)' : 'var(--ok-fg)' }}>
                          {run.scope_violation_rate}%
                          {run.total_models > 0 && (
                            <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-subtle)', marginLeft: 4 }}>
                              ({run.scope_violation_count !== undefined ? run.scope_violation_count : Math.round((run.scope_violation_rate / 100) * run.total_models)}/{run.total_models})
                            </span>
                          )}
                        </span>
                      </div>

                      <div>
                        <span style={{ color: 'var(--text-subtle)', marginRight: 6 }}>Hallucinations:</span>
                        <span style={{ fontWeight: 800, color: '#a855f7' }}>{run.hallucination_rate}%</span>
                      </div>

                      <div>
                        <span style={{ color: 'var(--text-subtle)', marginRight: 6 }}>Avg Latency:</span>
                        <span className="mono" style={{ fontWeight: 700 }}>{run.average_latency_ms?.toFixed(0) || 0}ms</span>
                      </div>

                      {run.fastest_model && (
                        <div>
                          <span style={{ color: 'var(--text-subtle)', marginRight: 6 }}>Fastest:</span>
                          <span style={{ color: 'var(--accent)', fontWeight: 600 }}>⚡ {run.fastest_model.split(' ')[0]}</span>
                        </div>
                      )}

                      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                          type="button"
                          className="btn btn--sm btn--secondary"
                          onClick={() => setInspectedRun(run)}
                        >
                          Inspect Matrix ({run.total_models || run.items?.length || 0} Models)
                        </button>
                        <button
                          type="button"
                          className="btn btn--sm btn--ghost"
                          onClick={() => handleDelete([run.benchmark_id])}
                          title="Delete benchmark run"
                          style={{ color: 'var(--bad-fg)' }}
                        >
                          <TrashIcon width={13} height={13} />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Detailed Side-by-Side Comparative Matrix Inspection Modal */}
      {inspectedRun && (
        <div className="modal-backdrop" onClick={() => setInspectedRun(null)}>
          <div
            className="modal-card benchmark-inspect-modal"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: 1100, width: '95vw', maxHeight: '90vh', overflowY: 'auto', padding: 0 }}
          >
            {/* Modal Header */}
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--surface-raised)' }}>
              <div>
                <span className="metric-label" style={{ display: 'block', marginBottom: 2 }}>
                  Historical Comparative Evaluation Matrix
                </span>
                <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>
                  {inspectedRun.scenario_title}
                </h3>
              </div>
              <button
                type="button"
                className="btn btn--ghost btn--icon"
                onClick={() => setInspectedRun(null)}
                aria-label="Close matrix modal"
              >
                <XIcon width={16} height={16} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: 20 }}>
              {/* Prompt Box */}
              <div style={{ marginBottom: 16 }}>
                <span className="metric-label" style={{ display: 'block', marginBottom: 4 }}>
                  Dispatched Pentest Prompt
                </span>
                <div className="mono font-xs" style={{ padding: '10px 14px', background: 'var(--surface-sunken)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                  {inspectedRun.prompt}
                </div>
              </div>

              {/* Score summary grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, textAlign: 'center', marginBottom: 20 }}>
                <div style={{ padding: 12, background: 'var(--ok-bg)', border: '1px solid var(--ok-bd)', borderRadius: 'var(--radius)' }}>
                  <span className="metric-label" style={{ color: 'var(--ok-fg)', display: 'block' }}>Compliance</span>
                  <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--ok-fg)' }}>{inspectedRun.compliance_rate}%</span>
                </div>
                <div style={{ padding: 12, background: 'var(--bad-bg)', border: '1px solid var(--bad-bd)', borderRadius: 'var(--radius)' }}>
                  <span className="metric-label" style={{ color: 'var(--bad-fg)', display: 'block' }}>Scope Violation</span>
                  <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--bad-fg)' }}>{inspectedRun.scope_violation_rate}%</span>
                </div>
                <div style={{ padding: 12, background: 'rgba(168, 85, 247, 0.1)', border: '1px solid rgba(168, 85, 247, 0.25)', borderRadius: 'var(--radius)' }}>
                  <span className="metric-label" style={{ color: '#a855f7', display: 'block' }}>Hallucination</span>
                  <span style={{ fontSize: 20, fontWeight: 800, color: '#a855f7' }}>{inspectedRun.hallucination_rate}%</span>
                </div>
                <div style={{ padding: 12, background: 'var(--surface-sunken)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                  <span className="metric-label" style={{ display: 'block' }}>Avg Latency</span>
                  <span className="mono" style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>
                    {inspectedRun.average_latency_ms?.toFixed(0) || 0}ms
                  </span>
                </div>
              </div>

              {/* Side-by-Side Model Cards */}
              <div>
                <span className="metric-label" style={{ display: 'block', marginBottom: 12 }}>
                  Evaluated Models ({inspectedRun.items?.length || 0})
                </span>

                <div className="benchmark-matrix-grid">
                  {(inspectedRun.items || []).map((item, idx) => {
                    const model = item.model;
                    const audit = item.audit;
                    const isCorrect = audit?.verdict === 'Correct';
                    const isUnsafe = audit?.verdict === 'Unsafe';
                    const isRefused = audit?.verdict === 'Refused';
                    const borderClass = isCorrect
                      ? 'benchmark-model-res-card--correct'
                      : isUnsafe
                      ? 'benchmark-model-res-card--unsafe'
                      : isRefused
                      ? 'benchmark-model-res-card--refused'
                      : 'benchmark-model-res-card--incorrect';

                    const scopeViolations = (audit?.violation_details || []).filter(
                      (v) => (v.category as string).toLowerCase() === 'scope'
                    );
                    const policyViolations = (audit?.violation_details || []).filter(
                      (v) => (v.category as string).toLowerCase() !== 'scope'
                    );

                    return (
                      <div key={idx} className={`benchmark-model-res-card ${borderClass}`}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 8, marginBottom: 10, borderBottom: '1px solid var(--border)' }}>
                          <div>
                            <span style={{ fontWeight: 700, fontSize: 13.5, color: 'var(--text)' }}>
                              {model?.model_name || 'Model'}
                            </span>
                            <span className="mono font-xs" style={{ color: 'var(--text-subtle)', display: 'block' }}>
                              {model?.latency_ms?.toFixed(0) || 0}ms • {model?.total_tokens || 0} tokens
                            </span>
                          </div>
                          <span
                            className={`badge font-xs ${
                              isCorrect
                                ? 'badge--success'
                                : isUnsafe
                                ? 'badge--danger'
                                : isRefused
                                ? 'badge--refused'
                                : 'badge--warning'
                            }`}
                          >
                            {isRefused ? 'Declined / Refused' : (audit?.verdict || 'Unknown')}
                          </span>
                        </div>

                        {/* Refusal Notice */}
                        {isRefused && (
                          <div
                            style={{
                              marginBottom: 10,
                              padding: '6px 10px',
                              background: 'rgba(167, 139, 250, 0.08)',
                              border: '1px solid rgba(167, 139, 250, 0.25)',
                              borderRadius: 4,
                              fontSize: 11.5,
                              color: '#c4b5fd',
                            }}
                          >
                            Model declined to assist with request. Excluded from comparative benchmark scoring.
                          </div>
                        )}

                        {/* Model Recommendation */}
                        <div style={{ marginBottom: 10 }}>
                          <span className="metric-label" style={{ fontSize: 10.5, display: 'block', marginBottom: 4 }}>
                            Model Recommendation
                          </span>
                          <div className="benchmark-cmd-block" style={{ maxHeight: 110 }}>
                            {model?.extracted_commands?.length > 0 ? (
                              model.extracted_commands.map((c, ci) => (
                                <div key={ci} style={{ color: 'var(--ok-fg)' }}>
                                  $ {c}
                                </div>
                              ))
                            ) : (
                              <span style={{ color: 'var(--text-subtle)' }}>{model?.raw_output || '// None'}</span>
                            )}
                          </div>
                        </div>

                        {/* Scope Violations */}
                        {scopeViolations.length > 0 && (
                          <div style={{ marginBottom: 8 }}>
                            <span className="metric-label" style={{ fontSize: 10.5, color: 'var(--bad-fg)', display: 'block', marginBottom: 4 }}>
                              Scope Violations Detected ({scopeViolations.length})
                            </span>
                            <div>
                              {scopeViolations.map((v, vIdx) => (
                                <div key={vIdx} className="benchmark-violation-chip" style={{ display: 'flex', alignItems: 'flex-start', gap: 6, borderColor: 'rgba(239, 68, 68, 0.3)' }}>
                                  <AlertIcon width={12} height={12} style={{ color: 'var(--bad-fg)', marginTop: 2, flexShrink: 0 }} />
                                  <div>
                                    <strong style={{ color: 'var(--bad-fg)' }}>{v.rule}:</strong> {v.detail}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Policy Deviations */}
                        {policyViolations.length > 0 && (
                          <div style={{ marginBottom: 8 }}>
                            <span className="metric-label" style={{ fontSize: 10.5, color: '#f59e0b', display: 'block', marginBottom: 4 }}>
                              Policy &amp; Tool Deviations ({policyViolations.length})
                            </span>
                            <div>
                              {policyViolations.map((v, vIdx) => (
                                <div key={vIdx} className="benchmark-violation-chip" style={{ display: 'flex', alignItems: 'flex-start', gap: 6, borderColor: 'rgba(245, 158, 11, 0.3)', background: 'rgba(245, 158, 11, 0.05)' }}>
                                  <AlertIcon width={12} height={12} style={{ color: '#f59e0b', marginTop: 2, flexShrink: 0 }} />
                                  <div>
                                    <strong style={{ color: '#f59e0b' }}>{v.rule}:</strong> {v.detail}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Self-Sanitized Safe Command (only displayed when original was Unsafe/Incorrect) */}
                        {audit?.safe_sanitized_command && audit.verdict !== 'Correct' && audit.verdict !== 'Refused' && (
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                              <span className="metric-label" style={{ fontSize: 10.5, color: 'var(--ok-fg)', display: 'flex', alignItems: 'center', gap: 4 }}>
                                <CheckIcon width={12} height={12} />
                                Self-Sanitized Safe Command
                              </span>
                              <button
                                type="button"
                                className="inline-link-btn font-xs"
                                onClick={() => copyText(`inspect-${idx}`, audit.safe_sanitized_command!)}
                                style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
                              >
                                {copiedId === `inspect-${idx}` ? (
                                  <span style={{ color: 'var(--ok-fg)' }}>Copied!</span>
                                ) : (
                                  <>
                                    <CopyIcon width={11} height={11} /> Copy
                                  </>
                                )}
                              </button>
                            </div>
                            <div className="benchmark-safe-cmd-block">
                              {renderSafeCommandLines(audit.safe_sanitized_command)}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', background: 'var(--surface-sunken)', display: 'flex', justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn--sm btn--primary" onClick={() => setInspectedRun(null)}>
                Close Matrix
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
