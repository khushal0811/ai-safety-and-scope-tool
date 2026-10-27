import React, { useEffect, useMemo, useState } from 'react';
import type { RoeScope } from '../types/audit';
import type {
  BenchmarkEvaluateItem,
  BenchmarkEvaluateResponse,
  BenchmarkRunRecord,
  FrontierModelInfo,
} from '../types/benchmark';
import type { UserProfile } from '../types/user';
import {
  BENCHMARK_SCENARIOS,
  formatScenarioPrompt,
} from '../data/scenarios';
import {
  deleteBenchmarkRuns,
  evaluateBenchmark,
  getBenchmarkHistory,
  getBenchmarkModels,
} from '../services/benchmarkService';
import { getOpenRouterKey } from '../lib/keyStore';
import {
  AlertIcon,
  BenchmarkIcon,
  CheckIcon,
  CopyIcon,
  DownloadIcon,
  HistoryIcon,
  KeyIcon,
  RefreshIcon,
  SearchIcon,
  SparkIcon,
  TrashIcon,
  XIcon,
} from './Icons';
import { computeSplitDiff } from '../lib/diff';

interface Props {
  activeRoe: RoeScope;
  allRoes: RoeScope[];
  onSelectRoe: (roe: RoeScope) => void;
  currentUser: UserProfile | null;
  onNavigateSettings: () => void;
}

export function BenchmarkStudioView({
  activeRoe,
  allRoes,
  onSelectRoe,
  currentUser,
  onNavigateSettings,
}: Props) {
  // Top Sub-Tabs: 'run' | 'history'
  const [subTab, setSubTab] = useState<'run' | 'history'>('run');

  // Available models from backend
  const [availableModels, setAvailableModels] = useState<FrontierModelInfo[]>([]);
  const [selectedModelIds, setSelectedModelIds] = useState<Set<string>>(
    new Set(['meta-llama/llama-3.1-70b-instruct', 'openai/gpt-4o', 'anthropic/claude-3.5-sonnet', 'google/gemini-pro-1.5'])
  );

  // Scenario & Prompt
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('smb-null-session');
  const [prompt, setPrompt] = useState<string>('');

  // Execution state
  const [running, setRunning] = useState<boolean>(false);
  const [currentResult, setCurrentResult] = useState<BenchmarkEvaluateResponse | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  // History state
  const [historyRuns, setHistoryRuns] = useState<BenchmarkRunRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [historySearch, setHistorySearch] = useState<string>('');
  const [selectedHistoryIds, setSelectedHistoryIds] = useState<Set<string>>(new Set());
  const [historyDeleting, setHistoryDeleting] = useState<boolean>(false);
  const [inspectedRun, setInspectedRun] = useState<BenchmarkRunRecord | null>(null);

  // Clipboard copy state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Check if OpenRouter key exists in vault/session
  const hasOpenRouterKey = Boolean(getOpenRouterKey()?.trim());

  // Load models on mount
  useEffect(() => {
    let mounted = true;
    getBenchmarkModels().then((models) => {
      if (mounted) setAvailableModels(models);
    });
    return () => {
      mounted = false;
    };
  }, []);

  // Update prompt whenever active scenario or active RoE changes
  useEffect(() => {
    if (selectedScenarioId === 'custom') return;
    const scen = BENCHMARK_SCENARIOS.find((s) => s.id === selectedScenarioId);
    if (scen) {
      setPrompt(formatScenarioPrompt(scen.promptTemplate, activeRoe));
    }
  }, [selectedScenarioId, activeRoe]);

  // Load history when tab opens
  const refreshHistory = async () => {
    setHistoryLoading(true);
    try {
      const records = await getBenchmarkHistory(currentUser?.id);
      setHistoryRuns(records);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    if (subTab === 'history') {
      refreshHistory();
    }
  }, [subTab, currentUser?.id]);

  // Model toggling
  function toggleModel(id: string) {
    setSelectedModelIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        if (next.size > 1) next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function selectAllModels() {
    setSelectedModelIds(new Set(availableModels.map((m) => m.id)));
  }

  function selectOpenSourceOnly() {
    setSelectedModelIds(new Set(['meta-llama/llama-3.1-70b-instruct']));
  }

  // Run benchmark evaluation
  async function handleRunBenchmark() {
    if (!prompt.trim() || running) return;
    setRunning(true);
    setRunError(null);

    const activeScenario = BENCHMARK_SCENARIOS.find((s) => s.id === selectedScenarioId);
    const scenarioTitle = activeScenario ? activeScenario.title : 'Custom Pentest Prompt';

    try {
      const result = await evaluateBenchmark(
        activeRoe,
        prompt.trim(),
        Array.from(selectedModelIds),
        scenarioTitle
      );
      setCurrentResult(result);
    } catch (err: any) {
      setRunError(err?.message || 'Benchmark run failed. Please check backend connection.');
    } finally {
      setRunning(false);
    }
  }

  // Copy helper
  function copyText(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  // Helper to cleanly render safe sanitized command lines without breaking terminal copy-paste
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

  // History filtering & deletion
  const filteredHistory = useMemo(() => {
    const q = historySearch.toLowerCase().trim();
    if (!q) return historyRuns;
    return historyRuns.filter(
      (r) =>
        r.scenario_title.toLowerCase().includes(q) ||
        r.prompt.toLowerCase().includes(q) ||
        r.roe_id.toLowerCase().includes(q) ||
        (r.fastest_model && r.fastest_model.toLowerCase().includes(q))
    );
  }, [historyRuns, historySearch]);

  const allFilteredHistoryIds = useMemo(() => filteredHistory.map((r) => r.benchmark_id), [filteredHistory]);
  const isAllHistorySelected =
    allFilteredHistoryIds.length > 0 && allFilteredHistoryIds.every((id) => selectedHistoryIds.has(id));

  function toggleSelectAllHistory() {
    if (isAllHistorySelected) {
      setSelectedHistoryIds((prev) => {
        const next = new Set(prev);
        allFilteredHistoryIds.forEach((id) => next.delete(id));
        return next;
      });
    } else {
      setSelectedHistoryIds((prev) => {
        const next = new Set(prev);
        allFilteredHistoryIds.forEach((id) => next.add(id));
        return next;
      });
    }
  }

  function toggleSelectOneHistory(id: string, e?: React.MouseEvent | React.ChangeEvent) {
    e?.stopPropagation();
    setSelectedHistoryIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleDeleteHistory(ids: string[]) {
    if (ids.length === 0) return;
    const confirmMsg =
      ids.length === 1
        ? 'Permanently delete this benchmark run from the database?'
        : `Permanently delete ${ids.length} selected benchmark runs from the database?`;
    if (!window.confirm(confirmMsg)) return;

    setHistoryDeleting(true);
    try {
      await deleteBenchmarkRuns(ids, currentUser?.id);
      setHistoryRuns((prev) => prev.filter((r) => !ids.includes(r.benchmark_id)));
      setSelectedHistoryIds((prev) => {
        const next = new Set(prev);
        ids.forEach((id) => next.delete(id));
        return next;
      });
    } finally {
      setHistoryDeleting(false);
    }
  }

  // Export JSON report
  function exportBenchmarkReport(run: BenchmarkRunRecord | BenchmarkEvaluateResponse) {
    const jsonStr = JSON.stringify(run, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vallum-benchmark-${run.benchmark_id || 'run'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="container" style={{ paddingTop: '24px', minHeight: '85vh' }}>
      <div className="benchmark-studio">
        {/* Header & Sub-Navigation */}
        <div className="benchmark-header">
          <div className="benchmark-header__titles">
            <div className="benchmark-header__title-row">
              <span className="benchmark-header__icon">
                <BenchmarkIcon width={20} height={20} />
              </span>
              <h1 className="benchmark-header__title">Benchmark Studio</h1>
              <span className="badge badge--accent font-xs">Multi-LLM Comparative Engine</span>
            </div>
            <p className="benchmark-header__subtitle">
              Simultaneously evaluate frontier LLMs on offensive cybersecurity tasks against deterministic Rules of Engagement.
            </p>
          </div>

          {/* Sub-Tabs */}
          <div className="benchmark-subtabs">
            <button
              className={`benchmark-subtab-btn ${subTab === 'run' ? 'benchmark-subtab-btn--active' : ''}`}
              onClick={() => setSubTab('run')}
            >
              <SparkIcon width={14} height={14} />
              Run Benchmark
            </button>
            <button
              className={`benchmark-subtab-btn ${subTab === 'history' ? 'benchmark-subtab-btn--active' : ''}`}
              onClick={() => setSubTab('history')}
            >
              <HistoryIcon width={14} height={14} />
              Past Benchmarks
              {historyRuns.length > 0 && (
                <span className="badge badge--neutral font-xs" style={{ marginLeft: 6, padding: '1px 6px' }}>
                  {historyRuns.length}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* ============================================================== */}
        {/* SUB-VIEW 1: RUN BENCHMARK                                      */}
        {/* ============================================================== */}
        {subTab === 'run' && (
          <div>
            {/* 1. Active Scope Strip */}
            <div className="benchmark-scope-strip" style={{ marginBottom: '20px' }}>
              <div className="benchmark-scope-strip__left">
                <div className="benchmark-scope-strip__dot" />
                <div>
                  <span className="benchmark-scope-strip__label">Active Rules of Engagement Scope</span>
                  <div className="benchmark-scope-strip__name">
                    {activeRoe.name}{' '}
                    <span style={{ fontWeight: 400, color: 'var(--text-muted)', fontSize: 12 }}>
                      ({activeRoe.engagement_type})
                    </span>
                  </div>
                </div>
              </div>

              {/* Scope constraints quick chips */}
              <div className="benchmark-scope-strip__chips">
                <span className="benchmark-chip">
                  Target: <strong>{activeRoe.target_hosts[0] || activeRoe.allowed_cidrs[0] || '127.0.0.1'}</strong>
                </span>
                <span className="benchmark-chip">
                  Subnet: <strong>{activeRoe.allowed_cidrs[0] || '192.168.1.0/24'}</strong>
                </span>
                <span className="benchmark-chip benchmark-chip--banned">
                  Banned: {activeRoe.prohibited_ips.slice(0, 2).join(', ')}
                </span>

                {/* Scope Switcher Dropdown */}
                <select
                  aria-label="Active Rules of Engagement Scope"
                  className="benchmark-scope-select"
                  value={activeRoe.roe_id}
                  onChange={(e) => {
                    const target = allRoes.find((r) => r.roe_id === e.target.value);
                    if (target) onSelectRoe(target);
                  }}
                >
                  {allRoes.map((r) => (
                    <option key={r.roe_id} value={r.roe_id}>
                      Switch to: {r.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* 2. Scenario Presets Selector */}
            <div style={{ marginBottom: '20px' }}>
              <div className="benchmark-section-label">
                <span className="benchmark-section-label__title">
                  1. Select Pentesting Benchmark Scenario
                </span>
                <button
                  type="button"
                  className="inline-link-btn font-xs"
                  onClick={() => {
                    setSelectedScenarioId('custom');
                    setPrompt('');
                  }}
                >
                  + Write Custom Prompt
                </button>
              </div>

              <div className="benchmark-scenarios-grid">
                {BENCHMARK_SCENARIOS.map((scen) => {
                  const isSelected = selectedScenarioId === scen.id;
                  return (
                    <button
                      key={scen.id}
                      type="button"
                      className={`benchmark-scenario-card ${isSelected ? 'benchmark-scenario-card--selected' : ''}`}
                      onClick={() => setSelectedScenarioId(scen.id)}
                    >
                      <div>
                        <div className="benchmark-scenario-card__header">
                          <span className="benchmark-scenario-card__title">{scen.title}</span>
                          <span className="badge badge--neutral font-xs">{scen.badge}</span>
                        </div>
                        <p className="benchmark-scenario-card__desc">{scen.description}</p>
                      </div>
                    </button>
                  );
                })}

                {/* Custom Option Card */}
                <button
                  type="button"
                  className={`benchmark-scenario-card ${selectedScenarioId === 'custom' ? 'benchmark-scenario-card--selected' : ''}`}
                  onClick={() => setSelectedScenarioId('custom')}
                >
                  <div>
                    <div className="benchmark-scenario-card__header">
                      <span className="benchmark-scenario-card__title">✍️ Custom Pentest Task</span>
                      <span className="badge badge--accent font-xs">Custom</span>
                    </div>
                    <p className="benchmark-scenario-card__desc">
                      Type any offensive security prompt or specific penetration testing objective manually.
                    </p>
                  </div>
                </button>
              </div>
            </div>

            {/* 3. Prompt Editor */}
            <div style={{ marginBottom: '20px' }}>
              <div className="benchmark-section-label">
                <span className="benchmark-section-label__title">
                  2. Pentest Prompt Dispatched to Models
                </span>
                <span className="mono font-xs" style={{ color: 'var(--text-subtle)' }}>
                  {prompt.length} chars • auto-adapted to {activeRoe.name}
                </span>
              </div>
              <textarea
                className="benchmark-prompt-box"
                placeholder="e.g., Authorized target is 192.168.1.100. Enumerate SMB shares and test for null sessions."
                value={prompt}
                onChange={(e) => {
                  setPrompt(e.target.value);
                  if (selectedScenarioId !== 'custom') setSelectedScenarioId('custom');
                }}
              />
            </div>

            {/* 4. Model Selection Grid with OpenRouter Lock Notice */}
            <div style={{ marginBottom: '20px' }}>
              <div className="benchmark-section-label">
                <span className="benchmark-section-label__title">3. Target Frontier LLMs</span>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button type="button" className="inline-link-btn font-xs" onClick={selectAllModels}>
                    Select All
                  </button>
                  <span style={{ color: 'var(--border-strong)' }}>•</span>
                  <button type="button" className="inline-link-btn font-xs" onClick={selectOpenSourceOnly}>
                    Llama 3.3 Only
                  </button>
                </div>
              </div>

              {/* Banner if OpenRouter key is not set */}
              {!hasOpenRouterKey && (
                <div className="model-key-banner" style={{ marginBottom: 14 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5 }}>
                      <KeyIcon width={15} height={15} style={{ color: 'var(--warn-fg)', flexShrink: 0 }} />
                      <span>
                        <strong>Frontier Models Gated:</strong> To benchmark GPT-4o, Claude 3.5 Sonnet, and Gemini 1.5 Pro live, enter your OpenRouter key in Settings. Meta Llama 3.3 is ready to test immediately via the built-in system key.
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn btn--sm btn--primary"
                      onClick={onNavigateSettings}
                    >
                      Configure in Settings →
                    </button>
                  </div>
                </div>
              )}

              <div className="benchmark-models-grid">
                {(availableModels.length > 0 ? availableModels : [
                  { id: 'meta-llama/llama-3.1-70b-instruct', name: 'Llama 3.3 70B', provider: 'Meta', tier: 'frontier', recommended: true, context_length: 128000, description: 'Built-in System Key' },
                  { id: 'openai/gpt-4o', name: 'GPT-4o', provider: 'OpenAI', tier: 'frontier', recommended: true, context_length: 128000, description: 'Flagship Multimodal' },
                  { id: 'anthropic/claude-3.5-sonnet', name: 'Claude 3.5 Sonnet', provider: 'Anthropic', tier: 'frontier', recommended: true, context_length: 200000, description: 'Deep Tool & Logic' },
                  { id: 'google/gemini-pro-1.5', name: 'Gemini 1.5 Pro', provider: 'Google', tier: 'frontier', recommended: true, context_length: 2000000, description: '2M Token Context' },
                ]).map((m) => {
                  const isSelected = selectedModelIds.has(m.id);
                  const isLlama = m.id.includes('llama');
                  const isLocked = !hasOpenRouterKey && !isLlama;

                  return (
                    <div
                      key={m.id}
                      onClick={() => {
                        if (isLocked) {
                          onNavigateSettings();
                        } else {
                          toggleModel(m.id);
                        }
                      }}
                      className={`benchmark-model-card ${
                        isSelected && !isLocked ? 'benchmark-model-card--selected' : ''
                      } ${isLocked ? 'benchmark-model-card--locked' : ''}`}
                    >
                      <div>
                        <div className="benchmark-model-card__header">
                          <span className="benchmark-model-card__provider">{m.provider}</span>
                          {isLlama ? (
                            <span className="badge badge--success font-xs">System Key Ready</span>
                          ) : isLocked ? (
                            <span className="badge badge--warning font-xs" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                              <KeyIcon width={10} height={10} /> Key Required
                            </span>
                          ) : (
                            <span className="badge badge--accent font-xs">Frontier</span>
                          )}
                        </div>

                        <div className="benchmark-model-card__body">
                          <input
                            type="checkbox"
                            checked={isSelected && !isLocked}
                            disabled={isLocked}
                            onChange={() => {}}
                            style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }}
                          />
                          <span className="benchmark-model-card__name">{m.name}</span>
                        </div>
                      </div>

                      <div className="benchmark-model-card__footer">
                        <span>{(m.context_length / 1000).toFixed(0)}k context</span>
                        {isLocked ? (
                          <span style={{ color: 'var(--warn-fg)', fontWeight: 600 }}>Settings →</span>
                        ) : (
                          <span className="mono" style={{ color: 'var(--ok-fg)' }}>Available</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 5. Dispatch Action Bar */}
            <div className="benchmark-dispatch-bar">
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                Benchmarking <strong style={{ color: 'var(--text)' }}>{selectedModelIds.size} models</strong> in parallel with Zero Host Execution guarantee.
              </div>

              <button
                type="button"
                className="benchmark-dispatch-btn"
                onClick={handleRunBenchmark}
                disabled={running || !prompt.trim() || selectedModelIds.size === 0}
              >
                {running ? (
                  <>
                    <span className="btn-spinner" />
                    <span>Benchmarking Frontier Models...</span>
                  </>
                ) : (
                  <>
                    <SparkIcon width={16} height={16} />
                    <span>Run Benchmark ({selectedModelIds.size} Models) ⚡</span>
                  </>
                )}
              </button>
            </div>

            {/* Error Banner */}
            {runError && (
              <div className="field-error-banner" style={{ marginBottom: 20 }}>
                <strong>Benchmark Error:</strong> {runError}
              </div>
            )}

            {/* 6. QUANTITATIVE SCORECARD & COMPARATIVE MATRIX */}
            {currentResult && (
              <div style={{ marginTop: 24, paddingTop: 24, borderTop: '1px solid var(--border)' }}>
                {/* Scorecard Header */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18, flexWrap: 'wrap', gap: 10 }}>
                  <div>
                    <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span>Benchmark Scorecard &amp; Comparative Analysis</span>
                      {currentResult.benchmark_id && (
                        <span className="badge badge--neutral mono font-xs">{currentResult.benchmark_id}</span>
                      )}
                    </h2>
                    <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                      Deterministic compliance verdict breakdown across {currentResult.items.length} tested models.
                    </p>
                  </div>

                  <button
                    type="button"
                    className="btn btn--sm btn--ghost"
                    onClick={() => exportBenchmarkReport(currentResult)}
                    title="Export complete benchmark report as JSON"
                  >
                    <DownloadIcon width={13} height={13} />
                    Export JSON Report
                  </button>
                </div>

                {/* 4 Quantitative Score Metric Cards */}
                <div className="benchmark-scorecard-grid">
                  {/* 1. Compliance Rate */}
                  <div className="benchmark-score-card">
                    <div className="benchmark-score-card__top">
                      <span className="metric-label">Compliance Rate (CR)</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--ok-fg)' }}>
                        {currentResult.summary.correct_count}/{currentResult.summary.total_models}
                      </span>
                    </div>
                    <div className="benchmark-score-card__value">
                      {currentResult.summary.compliance_rate}%
                    </div>
                    <div className="benchmark-score-card__bar">
                      <div
                        className="benchmark-score-card__bar-fill"
                        style={{ width: `${currentResult.summary.compliance_rate}%`, background: 'var(--ok-fg)' }}
                      />
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                      Strict adherence to target CIDRs &amp; prohibited tools
                    </span>
                  </div>

                  {/* 2. Scope Violation Rate */}
                  <div className="benchmark-score-card">
                    <div className="benchmark-score-card__top">
                      <span className="metric-label">Scope Violation Rate</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--bad-fg)' }}>
                        {(currentResult.summary.scope_violation_count !== undefined
                          ? currentResult.summary.scope_violation_count
                          : Math.round((currentResult.summary.scope_violation_rate / 100) * currentResult.summary.total_models))}/{currentResult.summary.total_models}
                      </span>
                    </div>
                    <div className="benchmark-score-card__value">
                      {currentResult.summary.scope_violation_rate}%
                    </div>
                    <div className="benchmark-score-card__bar">
                      <div
                        className="benchmark-score-card__bar-fill"
                        style={{ width: `${currentResult.summary.scope_violation_rate}%`, background: 'var(--bad-fg)' }}
                      />
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                      Out-of-scope targets or destructive payloads
                    </span>
                  </div>

                  {/* 3. Hallucination Rate */}
                  <div className="benchmark-score-card">
                    <div className="benchmark-score-card__top">
                      <span className="metric-label">Hallucination Rate</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: '#a855f7' }}>
                        {currentResult.summary.hallucination_rate}%
                      </span>
                    </div>
                    <div className="benchmark-score-card__value">
                      {currentResult.summary.hallucination_rate}%
                    </div>
                    <div className="benchmark-score-card__bar">
                      <div
                        className="benchmark-score-card__bar-fill"
                        style={{ width: `${currentResult.summary.hallucination_rate}%`, background: '#a855f7' }}
                      />
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                      Invented CVEs or fictional command flags
                    </span>
                  </div>

                  {/* 4. Speed & Latency */}
                  <div className="benchmark-score-card">
                    <div className="benchmark-score-card__top">
                      <span className="metric-label">Average Latency</span>
                      {currentResult.summary.fastest_model && (
                        <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--accent)' }}>
                          ⚡ {currentResult.summary.fastest_model.split(' ')[0]}
                        </span>
                      )}
                    </div>
                    <div className="benchmark-score-card__value mono">
                      {currentResult.summary.average_latency_ms.toFixed(0)}
                      <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-subtle)', marginLeft: 4 }}>ms</span>
                    </div>
                    <div className="benchmark-score-card__bar">
                      <div
                        className="benchmark-score-card__bar-fill"
                        style={{ width: '100%', background: 'var(--accent)' }}
                      />
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                      Fastest: {currentResult.summary.fastest_model || 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Comparative Latency & Verdict Bar Chart */}
                <div className="benchmark-latency-card">
                  <span className="metric-label" style={{ display: 'block', marginBottom: 12 }}>
                    Comparative Response Latency &amp; Verdicts
                  </span>
                  <div>
                    {currentResult.items.map((item) => {
                      const maxLatency = Math.max(
                        ...currentResult.items.map((i) => i.model.latency_ms || 1),
                        500
                      );
                      const pct = Math.min(100, Math.max(12, (item.model.latency_ms / maxLatency) * 100));
                      const verdictBg =
                        item.audit.verdict === 'Correct'
                          ? 'var(--ok-fg)'
                          : item.audit.verdict === 'Unsafe'
                          ? 'var(--bad-fg)'
                          : 'var(--warn-fg)';

                      return (
                        <div key={item.model.model_id} className="benchmark-latency-row">
                          <span className="benchmark-latency-row__label">{item.model.model_name}</span>
                          <div className="benchmark-latency-row__track">
                            <div
                              className="benchmark-latency-row__bar"
                              style={{ width: `${pct}%`, background: verdictBg }}
                            />
                          </div>
                          <span className="benchmark-latency-row__val">
                            {item.model.latency_ms > 0 ? `${item.model.latency_ms.toFixed(0)}ms` : '—'}
                          </span>
                          <span
                            className={`badge font-xs ${
                              item.audit.verdict === 'Correct'
                                ? 'badge--success'
                                : item.audit.verdict === 'Unsafe'
                                ? 'badge--danger'
                                : 'badge--warning'
                            }`}
                            style={{ width: 80, justifyContent: 'center' }}
                          >
                            {item.audit.verdict}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Side-by-Side Comparative Output Matrix */}
                <div style={{ marginTop: 24 }}>
                  <span className="metric-label" style={{ display: 'block', marginBottom: 14 }}>
                    Side-by-Side Model Outputs &amp; Self-Sanitized Safe Remediations
                  </span>

                  <div className="benchmark-matrix-grid">
                    {currentResult.items.map((item, idx) => {
                      const { model, audit } = item;
                      const isCorrect = audit.verdict === 'Correct';
                      const isUnsafe = audit.verdict === 'Unsafe';
                      const isUnauthorized = model.status === 'unauthorized';

                      const borderClass = isCorrect
                        ? 'benchmark-model-res-card--correct'
                        : isUnsafe
                        ? 'benchmark-model-res-card--unsafe'
                        : 'benchmark-model-res-card--incorrect';

                      return (
                        <div key={model.model_id || idx} className={`benchmark-model-res-card ${borderClass}`}>
                          {/* Model Card Header */}
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 10, marginBottom: 12, borderBottom: '1px solid var(--border)' }}>
                              <div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                  <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>
                                    {model.model_name}
                                  </span>
                                  <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                                    ({model.provider})
                                  </span>
                                </div>
                                <span className="mono font-xs" style={{ color: 'var(--text-subtle)' }}>
                                  {model.latency_ms > 0 ? `${model.latency_ms.toFixed(0)}ms` : '—'} • {model.total_tokens || 0} tokens
                                </span>
                              </div>

                              <span
                                className={`badge font-xs ${
                                  isCorrect
                                    ? 'badge--success'
                                    : isUnsafe
                                    ? 'badge--danger'
                                    : isUnauthorized
                                    ? 'badge--warning'
                                    : 'badge--neutral'
                                }`}
                              >
                                {isUnauthorized ? 'Unauthorized' : audit.verdict}
                              </span>
                            </div>

                            {/* Raw Model Output / Recommendation */}
                            <div style={{ marginBottom: 12 }}>
                              <span className="metric-label" style={{ fontSize: 10.5, display: 'block', marginBottom: 4 }}>
                                Model Recommendation
                              </span>
                              <div className="benchmark-cmd-block">
                                {model.extracted_commands.length > 0 ? (
                                  model.extracted_commands.map((cmd, i) => (
                                    <div key={i} style={{ color: 'var(--ok-fg)' }}>
                                      $ {cmd}
                                    </div>
                                  ))
                                ) : (
                                  <span style={{ color: 'var(--text-subtle)' }}>
                                    {model.raw_output || model.error_message || '// No command generated'}
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Violations breakdown partitioned into Scope vs Policy */}
                            {audit.violation_details.length > 0 && (() => {
                              const scopeViolations = audit.violation_details.filter(v => (v.category as string).toLowerCase() === 'scope');
                              const policyViolations = audit.violation_details.filter(v => (v.category as string).toLowerCase() !== 'scope');

                              return (
                                <div style={{ marginBottom: 12 }}>
                                  {/* Scope Violations */}
                                  {scopeViolations.length > 0 && (
                                    <div style={{ marginBottom: policyViolations.length > 0 ? 8 : 0 }}>
                                      <span className="metric-label" style={{ fontSize: 10.5, color: 'var(--bad-fg)', display: 'block', marginBottom: 4 }}>
                                        Scope Violations Detected ({scopeViolations.length})
                                      </span>
                                      <div>
                                        {scopeViolations.map((v, vIdx) => (
                                          <div key={`scope-${vIdx}`} className="benchmark-violation-chip" style={{ display: 'flex', alignItems: 'flex-start', gap: 6, borderColor: 'rgba(239, 68, 68, 0.3)' }}>
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
                                    <div>
                                      <span className="metric-label" style={{ fontSize: 10.5, color: '#f59e0b', display: 'block', marginBottom: 4 }}>
                                        Policy &amp; Tool Deviations ({policyViolations.length})
                                      </span>
                                      <div>
                                        {policyViolations.map((v, vIdx) => (
                                          <div key={`policy-${vIdx}`} className="benchmark-violation-chip" style={{ display: 'flex', alignItems: 'flex-start', gap: 6, borderColor: 'rgba(245, 158, 11, 0.3)', background: 'rgba(245, 158, 11, 0.05)' }}>
                                            <AlertIcon width={12} height={12} style={{ color: '#f59e0b', marginTop: 2, flexShrink: 0 }} />
                                            <div>
                                              <strong style={{ color: '#f59e0b' }}>{v.rule}:</strong> {v.detail}
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })()}

                            {/* Self-Sanitized Safe Remediation */}
                            {audit.safe_sanitized_command && (
                              <div style={{ marginTop: 8 }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                                  <span className="metric-label" style={{ fontSize: 10.5, color: 'var(--ok-fg)', display: 'flex', alignItems: 'center', gap: 4 }}>
                                    <CheckIcon width={12} height={12} />
                                    Self-Sanitized Safe Command
                                  </span>
                                  <button
                                    type="button"
                                    className="inline-link-btn font-xs"
                                    onClick={() => copyText(`safe-${idx}`, audit.safe_sanitized_command!)}
                                    style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
                                  >
                                    {copiedId === `safe-${idx}` ? (
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

                                {/* Expandable Side-by-Side Git Diff Drawer */}
                                {model.extracted_commands.length > 0 && !isCorrect && (
                                  <details className="accordion" style={{ marginTop: 10 }}>
                                    <summary style={{ fontSize: 11, padding: '6px 10px' }}>
                                      Side-by-Side Git Diff (Original vs Remediated)
                                    </summary>
                                    <div className="accordion__body" style={{ padding: '8px 10px 10px' }}>
                                      <div className="split-diff" style={{ fontSize: 11 }}>
                                        <div className="split-diff__pane">
                                          <div className="split-diff__header split-diff__header--orig" style={{ fontSize: 10, padding: '4px 8px' }}>
                                            Original
                                          </div>
                                          <div className="split-diff__body" style={{ padding: '4px 0' }}>
                                            {computeSplitDiff(model.extracted_commands.join('\n'), audit.safe_sanitized_command).map((r, ri) => (
                                              <div key={ri} className={r.type === 'deleted' || r.type === 'modified' ? 'split-diff__row split-diff__row--del' : 'split-diff__row'}>
                                                <span className="split-diff__gutter" style={{ width: 22 }}>{r.lineNumLeft ?? ' '}</span>
                                                <span className="split-diff__content">
                                                  {r.leftTokens ? (
                                                    r.leftTokens.map((t, ti) => (
                                                      <span key={ti} className={t.type === 'del' ? 'diff__del' : undefined}>
                                                        {t.text}
                                                      </span>
                                                    ))
                                                  ) : (
                                                    r.leftContent ?? ''
                                                  )}
                                                </span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                        <div className="split-diff__pane">
                                          <div className="split-diff__header split-diff__header--safe" style={{ fontSize: 10, padding: '4px 8px' }}>
                                            Sanitized
                                          </div>
                                          <div className="split-diff__body" style={{ padding: '4px 0' }}>
                                            {computeSplitDiff(model.extracted_commands.join('\n'), audit.safe_sanitized_command).map((r, ri) => (
                                              <div key={ri} className={r.type === 'added' || r.type === 'modified' ? 'split-diff__row split-diff__row--add' : 'split-diff__row'}>
                                                <span className="split-diff__gutter" style={{ width: 22 }}>{r.lineNumRight ?? ' '}</span>
                                                <span className="split-diff__content">
                                                  {r.rightTokens ? (
                                                    r.rightTokens.map((t, ti) => (
                                                      <span key={ti} className={t.type === 'add' ? 'diff__add' : undefined}>
                                                        {t.text}
                                                      </span>
                                                    ))
                                                  ) : (
                                                    r.rightContent ?? ''
                                                  )}
                                                </span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                  </details>
                                )}
                              </div>
                            )}
                          </div>

                          {/* Explanation footer */}
                          <div style={{ marginTop: 12, paddingTop: 8, borderTop: '1px solid var(--border)', fontSize: 11.5, color: 'var(--text-subtle)', fontStyle: 'italic' }}>
                            {audit.explanation}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ============================================================== */}
        {/* SUB-VIEW 2: PAST BENCHMARKS                                    */}
        {/* ============================================================== */}
        {subTab === 'history' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Historical Telemetry Cards */}
            <div className="history-metrics-grid">
              <div className="metric-card">
                <span className="metric-label">Total Benchmark Runs</span>
                <span className="metric-value">{historyRuns.length}</span>
                <span className="metric-sub">Multi-model test sessions</span>
              </div>
              <div className="metric-card">
                <span className="metric-label">Average Compliance Rate</span>
                <span className="metric-value" style={{ color: 'var(--ok-fg)' }}>
                  {historyRuns.length > 0
                    ? `${(
                        historyRuns.reduce((acc, r) => acc + (r.compliance_rate || 0), 0) /
                        historyRuns.length
                      ).toFixed(1)}%`
                    : '—'}
                </span>
                <span className="metric-sub">Adhering strictly to RoE</span>
              </div>
              <div className="metric-card">
                <span className="metric-label">Average Latency</span>
                <span className="metric-value mono" style={{ color: 'var(--accent)' }}>
                  {historyRuns.length > 0
                    ? `${(
                        historyRuns.reduce((acc, r) => acc + (r.average_latency_ms || 0), 0) /
                        historyRuns.length
                      ).toFixed(0)} ms`
                    : '—'}
                </span>
                <span className="metric-sub">Across successful model inferences</span>
              </div>
              <div className="metric-card">
                <span className="metric-label">Storage Integrity</span>
                <span className="metric-value" style={{ color: 'var(--text)' }}>
                  PostgreSQL
                </span>
                <span className="metric-sub">Row-level security encrypted</span>
              </div>
            </div>

            {/* Search & Actions Toolbar */}
            <div className="history-toolbar">
              <div className="history-search">
                <SearchIcon width={14} height={14} style={{ color: 'var(--text-subtle)' }} />
                <input
                  type="text"
                  placeholder="Search scenario, prompt, or RoE..."
                  className="history-search__input"
                  value={historySearch}
                  onChange={(e) => setHistorySearch(e.target.value)}
                />
              </div>

              <div className="history-actions">
                {/* Select All Checkbox Button */}
                {filteredHistory.length > 0 && (
                  <button
                    type="button"
                    className="history-filter-btn"
                    onClick={toggleSelectAllHistory}
                  >
                    <input
                      type="checkbox"
                      checked={isAllHistorySelected}
                      onChange={() => {}}
                      style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
                    />
                    <span>Select All ({filteredHistory.length})</span>
                  </button>
                )}

                {/* Delete Selected (N) button */}
                {selectedHistoryIds.size > 0 && (
                  <button
                    type="button"
                    className="btn btn--sm btn--danger"
                    onClick={() => handleDeleteHistory(Array.from(selectedHistoryIds))}
                    disabled={historyDeleting}
                  >
                    <TrashIcon width={13} height={13} />
                    <span>
                      {historyDeleting ? 'Deleting...' : `Delete Selected (${selectedHistoryIds.size})`}
                    </span>
                  </button>
                )}

                <button
                  type="button"
                  className="btn btn--sm btn--ghost"
                  onClick={refreshHistory}
                  disabled={historyLoading}
                  title="Refresh benchmarks from database"
                >
                  <RefreshIcon width={13} height={13} className={historyLoading ? 'animate-spin' : ''} />
                  Refresh
                </button>
              </div>
            </div>

            {/* Historical Runs List */}
            {historyLoading ? (
              <div className="metric-card" style={{ padding: 48, textAlign: 'center' }}>
                <span className="btn-spinner" style={{ margin: '0 auto 12px' }} />
                <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>Loading benchmark history from database...</p>
              </div>
            ) : filteredHistory.length === 0 ? (
              <div className="metric-card" style={{ padding: 48, textAlign: 'center' }}>
                <BenchmarkIcon width={36} height={36} style={{ margin: '0 auto 12px', color: 'var(--border-strong)' }} />
                <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>
                  No Historical Benchmark Runs Found
                </h3>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)', maxWidth: 460, margin: '0 auto' }}>
                  {historySearch
                    ? 'No benchmark runs match your search query.'
                    : 'Run your first multi-LLM benchmark in the "Run Benchmark" tab to record empirical compliance telemetry.'}
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {filteredHistory.map((run) => {
                  const isSelected = selectedHistoryIds.has(run.benchmark_id);

                  return (
                    <div
                      key={run.benchmark_id}
                      className={`benchmark-history-row ${isSelected ? 'benchmark-history-row--selected' : ''}`}
                      onClick={() => setInspectedRun(run)}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 14, minWidth: 0, flex: 1 }}>
                        {/* Checkbox */}
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => toggleSelectOneHistory(run.benchmark_id, e)}
                          style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }}
                        />

                        <div style={{ minWidth: 0, flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                            <span style={{ fontWeight: 700, fontSize: 13.5, color: 'var(--text)' }}>
                              {run.scenario_title}
                            </span>
                            <span className="badge badge--neutral mono font-xs">{run.benchmark_id}</span>
                            <span className="badge badge--accent font-xs">{run.roe_id}</span>
                            <span style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                              {new Date(run.created_at).toLocaleString()}
                            </span>
                          </div>

                          <p className="mono font-xs" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {run.prompt}
                          </p>
                        </div>
                      </div>

                      {/* Score metrics & action buttons */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ textAlign: 'center', padding: '4px 8px', background: 'var(--ok-bg)', border: '1px solid var(--ok-bd)', borderRadius: 4 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--ok-fg)', display: 'block' }}>CR</span>
                          <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--ok-fg)' }}>{run.compliance_rate}%</span>
                        </div>

                        <div style={{ textAlign: 'center', padding: '4px 8px', background: 'var(--bad-bg)', border: '1px solid var(--bad-bd)', borderRadius: 4 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--bad-fg)', display: 'block' }}>SVR</span>
                          <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--bad-fg)' }}>{run.scope_violation_rate}%</span>
                        </div>

                        <div style={{ textAlign: 'center', padding: '4px 8px', background: 'var(--surface-sunken)', border: '1px solid var(--border)', borderRadius: 4 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-subtle)', display: 'block' }}>Latency</span>
                          <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>
                            {run.average_latency_ms.toFixed(0)}ms
                          </span>
                        </div>

                        <button
                          type="button"
                          className="btn btn--sm btn--primary"
                          onClick={() => setInspectedRun(run)}
                          style={{ fontSize: 12 }}
                        >
                          Inspect Matrix ↗
                        </button>

                        <button
                          type="button"
                          className="btn btn--sm btn--ghost"
                          onClick={() => handleDeleteHistory([run.benchmark_id])}
                          title="Delete this benchmark run permanently"
                          style={{ padding: '6px 8px', color: 'var(--bad-fg)' }}
                        >
                          <TrashIcon width={14} height={14} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* HISTORICAL INSPECTION MODAL */}
            {inspectedRun && (
              <div
                className="modal-backdrop"
                onClick={() => setInspectedRun(null)}
              >
                <div
                  className="modal-content"
                  style={{ maxWidth: 960, maxHeight: '88vh', display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden' }}
                  onClick={(e) => e.stopPropagation()}
                >
                  {/* Modal Header */}
                  <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--surface-sunken)' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 800, fontSize: 16, color: 'var(--text)' }}>
                          {inspectedRun.scenario_title}
                        </span>
                        <span className="badge badge--neutral mono font-xs">{inspectedRun.benchmark_id}</span>
                        <span className="badge badge--accent font-xs">{inspectedRun.roe_id}</span>
                      </div>
                      <span style={{ fontSize: 11.5, color: 'var(--text-subtle)', marginTop: 2, display: 'block' }}>
                        Executed: {new Date(inspectedRun.created_at).toLocaleString()} • {inspectedRun.total_models} models tested
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <button
                        type="button"
                        className="btn btn--sm btn--ghost"
                        onClick={() => exportBenchmarkReport(inspectedRun)}
                      >
                        <DownloadIcon width={13} height={13} /> JSON
                      </button>
                      <button
                        type="button"
                        className="btn btn--sm btn--ghost btn--icon"
                        onClick={() => setInspectedRun(null)}
                      >
                        <XIcon width={16} height={16} />
                      </button>
                    </div>
                  </div>

                  {/* Modal Body */}
                  <div style={{ padding: '20px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
                    {/* Evaluated Prompt */}
                    <div style={{ padding: '12px 14px', background: 'var(--surface-sunken)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                      <span className="metric-label" style={{ display: 'block', marginBottom: 4 }}>
                        Evaluated Prompt
                      </span>
                      <div className="mono font-xs" style={{ whiteSpace: 'pre-wrap', color: 'var(--text)' }}>
                        {inspectedRun.prompt}
                      </div>
                    </div>

                    {/* Score summary grid */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, textAlign: 'center' }}>
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
                          {inspectedRun.average_latency_ms.toFixed(0)}ms
                        </span>
                      </div>
                    </div>

                    {/* Side-by-Side Model Cards */}
                    <div>
                      <span className="metric-label" style={{ display: 'block', marginBottom: 12 }}>
                        Comparative Model Results ({inspectedRun.items?.length || 0})
                      </span>

                      <div className="benchmark-matrix-grid">
                        {(inspectedRun.items || []).map((item: BenchmarkEvaluateItem, idx: number) => {
                          const { model, audit } = item;
                          const isCorrect = audit?.verdict === 'Correct';
                          const isUnsafe = audit?.verdict === 'Unsafe';

                          const borderClass = isCorrect
                            ? 'benchmark-model-res-card--correct'
                            : isUnsafe
                            ? 'benchmark-model-res-card--unsafe'
                            : 'benchmark-model-res-card--incorrect';

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
                                    isCorrect ? 'badge--success' : isUnsafe ? 'badge--danger' : 'badge--warning'
                                  }`}
                                >
                                  {audit?.verdict || 'Unknown'}
                                </span>
                              </div>

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

                              {audit?.safe_sanitized_command && (
                                <div>
                                  <span className="metric-label" style={{ fontSize: 10.5, color: 'var(--ok-fg)', display: 'block', marginBottom: 4 }}>
                                    Self-Sanitized Safe Command
                                  </span>
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
          </div>
        )}
      </div>
    </div>
  );
}
