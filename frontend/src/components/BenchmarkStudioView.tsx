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
  // Top Sub-Tabs
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
    <div className="container py-8" style={{ minHeight: '85vh' }}>
      {/* Header & Sub-Navigation */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="p-1.5 rounded-md bg-accent/10 text-accent inline-flex">
              <BenchmarkIcon width={18} height={18} />
            </span>
            <h1 className="text-2xl font-bold tracking-tight" style={{ fontFamily: 'var(--font-headline)' }}>
              Benchmark Studio
            </h1>
            <span className="badge badge--accent text-xs">Multi-LLM Comparative Engine</span>
          </div>
          <p className="text-xs text-muted-foreground">
            Simultaneously evaluate frontier LLMs on offensive cybersecurity tasks against deterministic Rules of Engagement.
          </p>
        </div>

        {/* Sub-Tabs */}
        <div className="flex items-center gap-2 bg-surface p-1 rounded-lg border border-border">
          <button
            className={`btn btn--sm ${subTab === 'run' ? 'btn--primary' : 'btn--ghost'}`}
            onClick={() => setSubTab('run')}
          >
            <SparkIcon width={13} height={13} />
            Run Benchmark
          </button>
          <button
            className={`btn btn--sm ${subTab === 'history' ? 'btn--primary' : 'btn--ghost'}`}
            onClick={() => setSubTab('history')}
          >
            <HistoryIcon width={13} height={13} />
            Past Benchmarks
            {historyRuns.length > 0 && (
              <span className="badge badge--neutral text-xs ml-1 px-1.5 py-0.5">{historyRuns.length}</span>
            )}
          </button>
        </div>
      </div>

      {/* SUB-VIEW 1: RUN BENCHMARK */}
      {subTab === 'run' && (
        <div className="space-y-6">
          {/* 1. Active Scope Strip */}
          <div className="card p-4 bg-surface border border-border flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
              <div>
                <span className="text-xs font-semibold text-muted-foreground tracking-wide uppercase">
                  Active Rules of Engagement Scope
                </span>
                <div className="text-sm font-bold text-foreground flex items-center gap-2">
                  <span>{activeRoe.name}</span>
                  <span className="text-xs font-normal text-muted-foreground">({activeRoe.engagement_type})</span>
                </div>
              </div>
            </div>

            {/* Scope constraints quick chips */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="px-2 py-1 bg-surface-sunken border border-border rounded font-mono">
                Target: {activeRoe.target_hosts[0] || activeRoe.allowed_cidrs[0] || '127.0.0.1'}
              </span>
              <span className="px-2 py-1 bg-surface-sunken border border-border rounded font-mono">
                Subnet: {activeRoe.allowed_cidrs[0] || '192.168.1.0/24'}
              </span>
              <span className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded font-mono">
                Banned: {activeRoe.prohibited_ips.slice(0, 2).join(', ')}
              </span>

              {/* Scope Switcher Dropdown */}
              <select
                aria-label="Active Rules of Engagement Scope"
                className="select select--sm text-xs bg-surface border-border ml-2"
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
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                1. Select Pentesting Benchmark Scenario
              </label>
              <button
                className="text-xs text-accent hover:underline"
                onClick={() => {
                  setSelectedScenarioId('custom');
                  setPrompt('');
                }}
              >
                + Write Custom Prompt
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {BENCHMARK_SCENARIOS.map((scen) => {
                const isSelected = selectedScenarioId === scen.id;
                return (
                  <button
                    key={scen.id}
                    className={`p-3 text-left rounded-lg border transition-all flex flex-col justify-between ${
                      isSelected
                        ? 'bg-accent/10 border-accent text-foreground shadow-sm'
                        : 'bg-surface border-border hover:border-accent/40 text-muted-foreground hover:text-foreground'
                    }`}
                    onClick={() => setSelectedScenarioId(scen.id)}
                  >
                    <div>
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="text-xs font-bold text-foreground">{scen.title}</span>
                        <span className="badge badge--neutral text-[10px] py-0 px-1">{scen.badge}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2">
                        {scen.description}
                      </p>
                    </div>
                  </button>
                );
              })}

              {/* Custom option pill */}
              <button
                className={`p-3 text-left rounded-lg border transition-all flex flex-col justify-center ${
                  selectedScenarioId === 'custom'
                    ? 'bg-accent/10 border-accent text-foreground'
                    : 'bg-surface border-border hover:border-accent/40 text-muted-foreground'
                }`}
                onClick={() => setSelectedScenarioId('custom')}
              >
                <span className="text-xs font-bold text-foreground">✍️ Custom Pentest Task</span>
                <p className="text-[11px] text-muted-foreground">Type any offensive security prompt manually</p>
              </button>
            </div>
          </div>

          {/* 3. Prompt Editor */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                2. Pentest Prompt Dispatched to Models
              </label>
              <span className="text-[11px] font-mono text-muted-foreground">
                {prompt.length} chars • auto-adapted to {activeRoe.name}
              </span>
            </div>
            <textarea
              className="w-full h-24 p-3 rounded-lg bg-surface-sunken border border-border font-mono text-xs text-foreground focus:outline-none focus:border-accent resize-y leading-relaxed"
              placeholder="e.g., Authorized target is 192.168.1.100. Enumerate SMB shares and test for null sessions."
              value={prompt}
              onChange={(e) => {
                setPrompt(e.target.value);
                if (selectedScenarioId !== 'custom') setSelectedScenarioId('custom');
              }}
            />
          </div>

          {/* 4. Model Selection Grid with OpenRouter Lock Notice */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                3. Target Frontier LLMs
              </label>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="text-xs text-accent hover:underline"
                  onClick={selectAllModels}
                >
                  Select All
                </button>
                <span className="text-muted-foreground">•</span>
                <button
                  type="button"
                  className="text-xs text-muted-foreground hover:underline"
                  onClick={selectOpenSourceOnly}
                >
                  Llama 3.3 Only
                </button>
              </div>
            </div>

            {/* Banner if OpenRouter key is not set */}
            {!hasOpenRouterKey && (
              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-center justify-between gap-3 text-xs text-amber-300">
                <div className="flex items-center gap-2">
                  <KeyIcon width={15} height={15} className="text-amber-400 shrink-0" />
                  <span>
                    <strong>Frontier Models Gated:</strong> To query GPT-4o, Claude 3.5 Sonnet, and Gemini 1.5 Pro live, add your OpenRouter API key in Settings. Meta Llama 3.3 is available immediately via the built-in system key.
                  </span>
                </div>
                <button
                  className="btn btn--sm btn--primary shrink-0 py-1 px-3 text-xs"
                  onClick={onNavigateSettings}
                >
                  Configure in Settings →
                </button>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
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
                    className={`p-3.5 rounded-lg border cursor-pointer transition-all flex flex-col justify-between ${
                      isSelected && !isLocked
                        ? 'bg-surface border-accent shadow-sm ring-1 ring-accent/30'
                        : isLocked
                        ? 'bg-surface/50 border-border opacity-70 hover:opacity-100 hover:border-amber-500/40'
                        : 'bg-surface border-border hover:border-border-hover'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between gap-1 mb-1.5">
                        <span className="text-xs font-semibold text-muted-foreground uppercase">{m.provider}</span>
                        {isLlama ? (
                          <span className="badge badge--success text-[10px] py-0 px-1.5">System Key Ready</span>
                        ) : isLocked ? (
                          <span className="badge badge--warning text-[10px] py-0 px-1.5 flex items-center gap-1">
                            <KeyIcon width={10} height={10} /> Key Required
                          </span>
                        ) : (
                          <span className="badge badge--accent text-[10px] py-0 px-1.5">Frontier</span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={isSelected && !isLocked}
                          disabled={isLocked}
                          onChange={() => {}}
                          className="checkbox checkbox--sm accent-accent"
                        />
                        <span className="text-sm font-bold text-foreground">{m.name}</span>
                      </div>
                    </div>

                    <div className="mt-3 pt-2 border-t border-border/50 text-[11px] text-muted-foreground flex items-center justify-between">
                      <span>{(m.context_length / 1000).toFixed(0)}k context</span>
                      {isLocked ? (
                        <span className="text-amber-400 font-medium">Settings →</span>
                      ) : (
                        <span className="text-emerald-400 font-mono">Available</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 5. Dispatch Action Bar */}
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="text-xs text-muted-foreground">
              Benchmarking <strong className="text-foreground">{selectedModelIds.size} models</strong> in parallel with Zero Host Execution guarantee.
            </div>

            <button
              className="btn btn--primary btn--lg w-full sm:w-auto px-6 py-2.5 font-bold tracking-wide shadow-lg shadow-accent/20 flex items-center justify-center gap-2"
              onClick={handleRunBenchmark}
              disabled={running || !prompt.trim() || selectedModelIds.size === 0}
            >
              {running ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
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
            <div className="p-3.5 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3 text-xs text-red-300">
              <AlertIcon width={16} height={16} className="text-red-400 shrink-0" />
              <span>{runError}</span>
            </div>
          )}

          {/* 6. QUANTITATIVE SCORECARD & COMPARATIVE MATRIX */}
          {currentResult && (
            <div className="space-y-6 pt-4 border-t border-border animate-fadeIn">
              {/* Scorecard Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold text-foreground flex items-center gap-2">
                    <span>Benchmark Scorecard &amp; Comparative Analysis</span>
                    {currentResult.benchmark_id && (
                      <span className="badge badge--neutral font-mono text-xs">{currentResult.benchmark_id}</span>
                    )}
                  </h2>
                  <p className="text-xs text-muted-foreground">
                    Deterministic compliance verdict breakdown across {currentResult.items.length} tested models.
                  </p>
                </div>

                <button
                  className="btn btn--sm btn--ghost border border-border"
                  onClick={() => exportBenchmarkReport(currentResult)}
                  title="Export complete benchmark report as JSON"
                >
                  <DownloadIcon width={13} height={13} />
                  Export JSON Report
                </button>
              </div>

              {/* 4 Quantitative Score Metric Cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
                {/* 1. Compliance Rate */}
                <div className="card p-4 bg-surface border border-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-muted-foreground uppercase">Compliance Rate (CR)</span>
                    <span className="text-xs font-bold text-emerald-400">
                      {currentResult.summary.correct_count}/{currentResult.summary.total_models}
                    </span>
                  </div>
                  <div className="text-2xl font-black text-foreground mb-2">
                    {currentResult.summary.compliance_rate}%
                  </div>
                  {/* Progress Bar */}
                  <div className="w-full bg-surface-sunken h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-emerald-500 h-full rounded-full transition-all duration-700"
                      style={{ width: `${currentResult.summary.compliance_rate}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-muted-foreground mt-1.5 block">
                    Strict adherence to target CIDRs &amp; prohibited tools
                  </span>
                </div>

                {/* 2. Scope Violation Rate */}
                <div className="card p-4 bg-surface border border-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-muted-foreground uppercase">Scope Violation Rate</span>
                    <span className="text-xs font-bold text-red-400">
                      {currentResult.summary.unsafe_count}/{currentResult.summary.total_models}
                    </span>
                  </div>
                  <div className="text-2xl font-black text-foreground mb-2">
                    {currentResult.summary.scope_violation_rate}%
                  </div>
                  <div className="w-full bg-surface-sunken h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-red-500 h-full rounded-full transition-all duration-700"
                      style={{ width: `${currentResult.summary.scope_violation_rate}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-muted-foreground mt-1.5 block">
                    Out-of-scope targets or destructive payloads
                  </span>
                </div>

                {/* 3. Hallucination Rate */}
                <div className="card p-4 bg-surface border border-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-muted-foreground uppercase">Hallucination Rate</span>
                    <span className="text-xs font-bold text-purple-400">
                      {currentResult.summary.hallucination_rate}%
                    </span>
                  </div>
                  <div className="text-2xl font-black text-foreground mb-2">
                    {currentResult.summary.hallucination_rate}%
                  </div>
                  <div className="w-full bg-surface-sunken h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-purple-500 h-full rounded-full transition-all duration-700"
                      style={{ width: `${currentResult.summary.hallucination_rate}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-muted-foreground mt-1.5 block">
                    Invented CVEs or fictional command flags
                  </span>
                </div>

                {/* 4. Speed & Latency */}
                <div className="card p-4 bg-surface border border-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-muted-foreground uppercase">Average Latency</span>
                    {currentResult.summary.fastest_model && (
                      <span className="text-xs font-bold text-accent">
                        ⚡ {currentResult.summary.fastest_model.split(' ')[0]}
                      </span>
                    )}
                  </div>
                  <div className="text-2xl font-black font-mono text-foreground mb-2">
                    {currentResult.summary.average_latency_ms.toFixed(0)}
                    <span className="text-sm font-normal text-muted-foreground ml-1">ms</span>
                  </div>
                  <div className="w-full bg-surface-sunken h-2 rounded-full overflow-hidden">
                    <div className="bg-accent h-full rounded-full" style={{ width: '100%' }} />
                  </div>
                  <span className="text-[10px] text-muted-foreground mt-1.5 block">
                    Fastest: {currentResult.summary.fastest_model || 'N/A'}
                  </span>
                </div>
              </div>

              {/* Comparative Latency & Verdict Bar Chart */}
              <div className="card p-4 bg-surface border border-border">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block mb-3">
                  Comparative Response Latency &amp; Verdicts
                </span>
                <div className="space-y-2.5">
                  {currentResult.items.map((item) => {
                    const maxLatency = Math.max(
                      ...currentResult.items.map((i) => i.model.latency_ms || 1),
                      500
                    );
                    const pct = Math.min(100, Math.max(12, (item.model.latency_ms / maxLatency) * 100));
                    const verdictColor =
                      item.audit.verdict === 'Correct'
                        ? 'bg-emerald-500'
                        : item.audit.verdict === 'Unsafe'
                        ? 'bg-red-500'
                        : 'bg-amber-500';

                    return (
                      <div key={item.model.model_id} className="flex items-center gap-3 text-xs">
                        <span className="w-32 font-medium text-foreground truncate">{item.model.model_name}</span>
                        <div className="flex-1 bg-surface-sunken h-5 rounded overflow-hidden flex items-center p-1">
                          <div
                            className={`h-3 rounded transition-all duration-500 ${verdictColor}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="w-16 font-mono text-right text-muted-foreground">
                          {item.model.latency_ms > 0 ? `${item.model.latency_ms.toFixed(0)}ms` : '—'}
                        </span>
                        <span
                          className={`badge text-[10px] w-20 justify-center ${
                            item.audit.verdict === 'Correct'
                              ? 'badge--success'
                              : item.audit.verdict === 'Unsafe'
                              ? 'badge--danger'
                              : 'badge--warning'
                          }`}
                        >
                          {item.audit.verdict}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Side-by-Side Comparative Output Matrix */}
              <div className="space-y-3">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">
                  Side-by-Side Model Outputs &amp; Self-Sanitized Safe Remediations
                </span>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {currentResult.items.map((item, idx) => {
                    const { model, audit } = item;
                    const isCorrect = audit.verdict === 'Correct';
                    const isUnsafe = audit.verdict === 'Unsafe';
                    const isUnauthorized = model.status === 'unauthorized';

                    return (
                      <div
                        key={model.model_id || idx}
                        className={`card p-4 bg-surface border transition-all flex flex-col justify-between ${
                          isCorrect
                            ? 'border-emerald-500/40'
                            : isUnsafe
                            ? 'border-red-500/40'
                            : 'border-border'
                        }`}
                      >
                        {/* Model Card Header */}
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-2 pb-2 border-b border-border">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-sm text-foreground">{model.model_name}</span>
                                <span className="text-[10px] text-muted-foreground">({model.provider})</span>
                              </div>
                              <span className="text-[11px] font-mono text-muted-foreground">
                                {model.latency_ms > 0 ? `${model.latency_ms.toFixed(0)}ms` : '—'} • {model.total_tokens || 0} tokens
                              </span>
                            </div>

                            <span
                              className={`badge text-xs font-bold ${
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
                          <div className="space-y-1.5 mb-3">
                            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
                              Model Recommendation
                            </span>
                            <div className="p-2.5 rounded bg-surface-sunken border border-border font-mono text-xs text-foreground overflow-x-auto whitespace-pre-wrap max-h-36">
                              {model.extracted_commands.length > 0 ? (
                                model.extracted_commands.map((cmd, i) => (
                                  <div key={i} className="text-emerald-300">
                                    $ {cmd}
                                  </div>
                                ))
                              ) : (
                                <span className="text-muted-foreground">
                                  {model.raw_output || model.error_message || '// No command generated'}
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Violations breakdown if Unsafe/Incorrect */}
                          {audit.violation_details.length > 0 && (
                            <div className="space-y-1.5 mb-3">
                              <span className="text-[11px] font-semibold text-red-400 uppercase tracking-wider">
                                Scope Violations Detected ({audit.violation_details.length})
                              </span>
                              <div className="space-y-1 text-xs">
                                {audit.violation_details.map((v, vIdx) => (
                                  <div
                                    key={vIdx}
                                    className="p-2 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-[11px] flex items-start gap-1.5"
                                  >
                                    <AlertIcon width={13} height={13} className="shrink-0 mt-0.5 text-red-400" />
                                    <div>
                                      <strong>{v.rule}:</strong> {v.detail}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Self-Sanitized Safe Remediation */}
                          {audit.safe_sanitized_command && (
                            <div className="space-y-1.5 mt-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1">
                                  <CheckIcon width={12} height={12} />
                                  Self-Sanitized Safe Command
                                </span>
                                <button
                                  className="text-[11px] text-accent hover:underline flex items-center gap-1"
                                  onClick={() => copyText(`safe-${idx}`, audit.safe_sanitized_command!)}
                                >
                                  {copiedId === `safe-${idx}` ? (
                                    <span className="text-emerald-400">Copied!</span>
                                  ) : (
                                    <>
                                      <CopyIcon width={11} height={11} /> Copy
                                    </>
                                  )}
                                </button>
                              </div>
                              <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/30 font-mono text-xs text-emerald-200 overflow-x-auto">
                                $ {audit.safe_sanitized_command}
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Explanation footer */}
                        <div className="mt-3 pt-2 border-t border-border/50 text-[11px] text-muted-foreground italic">
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

      {/* SUB-VIEW 2: PAST BENCHMARKS */}
      {subTab === 'history' && (
        <div className="space-y-4">
          {/* Historical Telemetry Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="card p-3.5 bg-surface border border-border">
              <span className="text-xs text-muted-foreground uppercase font-semibold">Total Benchmark Runs</span>
              <div className="text-2xl font-bold text-foreground mt-1">{historyRuns.length}</div>
            </div>
            <div className="card p-3.5 bg-surface border border-border">
              <span className="text-xs text-muted-foreground uppercase font-semibold">Average Compliance Rate</span>
              <div className="text-2xl font-bold text-emerald-400 mt-1">
                {historyRuns.length > 0
                  ? `${(
                      historyRuns.reduce((acc, r) => acc + (r.compliance_rate || 0), 0) /
                      historyRuns.length
                    ).toFixed(1)}%`
                  : '—'}
              </div>
            </div>
            <div className="card p-3.5 bg-surface border border-border">
              <span className="text-xs text-muted-foreground uppercase font-semibold">Average Latency</span>
              <div className="text-2xl font-bold font-mono text-accent mt-1">
                {historyRuns.length > 0
                  ? `${(
                      historyRuns.reduce((acc, r) => acc + (r.average_latency_ms || 0), 0) /
                      historyRuns.length
                    ).toFixed(0)} ms`
                  : '—'}
              </div>
            </div>
          </div>

          {/* Search & Actions Toolbar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-surface p-3 rounded-lg border border-border">
            <div className="relative w-full sm:w-80">
              <input
                type="text"
                placeholder="Search scenario, prompt, or RoE..."
                className="input input--sm w-full pl-8 text-xs"
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
              />
              <span className="absolute left-2.5 top-2.5 text-muted-foreground">
                <SearchIcon width={13} height={13} />
              </span>
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
              {/* Select All Checkbox */}
              {filteredHistory.length > 0 && (
                <button
                  className="btn btn--sm btn--ghost text-xs flex items-center gap-1.5"
                  onClick={toggleSelectAllHistory}
                >
                  <input
                    type="checkbox"
                    checked={isAllHistorySelected}
                    onChange={() => {}}
                    className="checkbox checkbox--sm accent-accent"
                  />
                  <span>Select All ({filteredHistory.length})</span>
                </button>
              )}

              {/* Delete Selected (N) button */}
              {selectedHistoryIds.size > 0 && (
                <button
                  className="btn btn--sm btn--danger text-xs flex items-center gap-1.5 animate-fadeIn"
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
                className="btn btn--sm btn--ghost border border-border text-xs"
                onClick={refreshHistory}
                disabled={historyLoading}
                title="Refresh benchmarks from database"
              >
                <RefreshIcon width={13} height={13} className={historyLoading ? 'animate-spin' : ''} />
                Refresh
              </button>
            </div>
          </div>

          {/* Historical Runs Table / List */}
          {historyLoading ? (
            <div className="card p-12 text-center text-muted-foreground border border-border">
              <span className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin inline-block mb-2" />
              <p className="text-xs">Loading benchmark history from database...</p>
            </div>
          ) : filteredHistory.length === 0 ? (
            <div className="card p-12 text-center text-muted-foreground border border-border space-y-2">
              <BenchmarkIcon width={32} height={32} className="mx-auto text-muted-foreground/40 mb-2" />
              <h3 className="text-sm font-bold text-foreground">No Historical Benchmark Runs Found</h3>
              <p className="text-xs max-w-md mx-auto">
                {historySearch
                  ? 'No benchmark runs match your search query.'
                  : 'Run your first multi-LLM benchmark in the "Run Benchmark" tab to record empirical compliance telemetry.'}
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {filteredHistory.map((run) => {
                const isSelected = selectedHistoryIds.has(run.benchmark_id);

                return (
                  <div
                    key={run.benchmark_id}
                    className={`card p-4 bg-surface border transition-all flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:border-accent/40 ${
                      isSelected ? 'border-accent ring-1 ring-accent/30 bg-surface' : 'border-border'
                    }`}
                    onClick={() => setInspectedRun(run)}
                  >
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      {/* Checkbox */}
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={(e) => toggleSelectOneHistory(run.benchmark_id, e)}
                        className="checkbox checkbox--sm accent-accent mt-1 shrink-0"
                      />

                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="text-sm font-bold text-foreground">{run.scenario_title}</span>
                          <span className="badge badge--neutral font-mono text-[10px]">{run.benchmark_id}</span>
                          <span className="badge badge--accent text-[10px]">{run.roe_id}</span>
                          <span className="text-[11px] text-muted-foreground">
                            {new Date(run.created_at).toLocaleString()}
                          </span>
                        </div>

                        <p className="text-xs text-muted-foreground truncate font-mono">
                          {run.prompt}
                        </p>
                      </div>
                    </div>

                    {/* Metrics Badges & Action Buttons */}
                    <div className="flex items-center gap-3 shrink-0" onClick={(e) => e.stopPropagation()}>
                      {/* CR % */}
                      <div className="text-center px-2 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded">
                        <span className="text-[10px] font-semibold text-emerald-400 block">CR</span>
                        <span className="text-xs font-bold text-emerald-300">{run.compliance_rate}%</span>
                      </div>

                      {/* SVR % */}
                      <div className="text-center px-2 py-1 bg-red-500/10 border border-red-500/20 rounded">
                        <span className="text-[10px] font-semibold text-red-400 block">SVR</span>
                        <span className="text-xs font-bold text-red-300">{run.scope_violation_rate}%</span>
                      </div>

                      {/* Latency */}
                      <div className="text-center px-2 py-1 bg-surface-sunken border border-border rounded font-mono">
                        <span className="text-[10px] font-semibold text-muted-foreground block">Latency</span>
                        <span className="text-xs font-bold text-foreground">{run.average_latency_ms.toFixed(0)}ms</span>
                      </div>

                      {/* Inspect button */}
                      <button
                        className="btn btn--sm btn--primary text-xs"
                        onClick={() => setInspectedRun(run)}
                      >
                        Inspect Matrix ↗
                      </button>

                      {/* Single Delete Trash button */}
                      <button
                        className="btn btn--sm btn--ghost text-muted-foreground hover:text-red-400 p-1.5"
                        onClick={() => handleDeleteHistory([run.benchmark_id])}
                        title="Delete this benchmark run permanently"
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
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
              <div
                className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden"
                onClick={(e) => e.stopPropagation()}
              >
                {/* Modal Header */}
                <div className="p-4 border-b border-border flex items-center justify-between gap-3 bg-surface-sunken">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-base text-foreground">{inspectedRun.scenario_title}</span>
                      <span className="badge badge--neutral font-mono text-xs">{inspectedRun.benchmark_id}</span>
                      <span className="badge badge--accent text-xs">{inspectedRun.roe_id}</span>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      Executed: {new Date(inspectedRun.created_at).toLocaleString()} • {inspectedRun.total_models} models tested
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      className="btn btn--sm btn--ghost border border-border"
                      onClick={() => exportBenchmarkReport(inspectedRun)}
                    >
                      <DownloadIcon width={13} height={13} /> JSON
                    </button>
                    <button
                      className="btn btn--sm btn--ghost p-1.5 text-muted-foreground hover:text-foreground"
                      onClick={() => setInspectedRun(null)}
                    >
                      <XIcon width={16} height={16} />
                    </button>
                  </div>
                </div>

                {/* Modal Body */}
                <div className="p-5 overflow-y-auto space-y-4">
                  {/* Prompt */}
                  <div className="p-3 bg-surface-sunken border border-border rounded-lg">
                    <span className="text-[11px] font-semibold text-muted-foreground uppercase block mb-1">
                      Evaluated Prompt
                    </span>
                    <div className="font-mono text-xs text-foreground whitespace-pre-wrap">{inspectedRun.prompt}</div>
                  </div>

                  {/* Summary Scores */}
                  <div className="grid grid-cols-4 gap-3 text-center">
                    <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                      <span className="text-xs text-emerald-400 font-semibold block">Compliance Rate</span>
                      <span className="text-xl font-black text-emerald-300">{inspectedRun.compliance_rate}%</span>
                    </div>
                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <span className="text-xs text-red-400 font-semibold block">Scope Violation</span>
                      <span className="text-xl font-black text-red-300">{inspectedRun.scope_violation_rate}%</span>
                    </div>
                    <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg">
                      <span className="text-xs text-purple-400 font-semibold block">Hallucination Rate</span>
                      <span className="text-xl font-black text-purple-300">{inspectedRun.hallucination_rate}%</span>
                    </div>
                    <div className="p-3 bg-surface-sunken border border-border rounded-lg">
                      <span className="text-xs text-muted-foreground font-semibold block">Avg Latency</span>
                      <span className="text-xl font-black text-foreground font-mono">
                        {inspectedRun.average_latency_ms.toFixed(0)}ms
                      </span>
                    </div>
                  </div>

                  {/* Side-by-Side Model Cards */}
                  <div className="space-y-3">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">
                      Comparative Model Results ({inspectedRun.items?.length || 0})
                    </span>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                      {(inspectedRun.items || []).map((item: BenchmarkEvaluateItem, idx: number) => {
                        const { model, audit } = item;
                        const isCorrect = audit?.verdict === 'Correct';
                        const isUnsafe = audit?.verdict === 'Unsafe';

                        return (
                          <div
                            key={idx}
                            className={`p-4 rounded-lg bg-surface border ${
                              isCorrect
                                ? 'border-emerald-500/40'
                                : isUnsafe
                                ? 'border-red-500/40'
                                : 'border-border'
                            }`}
                          >
                            <div className="flex items-center justify-between pb-2 mb-2 border-b border-border">
                              <div>
                                <span className="font-bold text-sm text-foreground">{model?.model_name || 'Model'}</span>
                                <span className="text-xs text-muted-foreground block font-mono">
                                  {model?.latency_ms?.toFixed(0) || 0}ms • {model?.total_tokens || 0} tokens
                                </span>
                              </div>
                              <span
                                className={`badge text-xs ${
                                  isCorrect ? 'badge--success' : isUnsafe ? 'badge--danger' : 'badge--warning'
                                }`}
                              >
                                {audit?.verdict || 'Unknown'}
                              </span>
                            </div>

                            {/* Commands */}
                            <div className="space-y-1 mb-2">
                              <span className="text-[11px] font-semibold text-muted-foreground uppercase">
                                Model Recommendation
                              </span>
                              <div className="p-2 rounded bg-surface-sunken border border-border font-mono text-xs max-h-28 overflow-y-auto">
                                {model?.extracted_commands?.length > 0 ? (
                                  model.extracted_commands.map((c, ci) => (
                                    <div key={ci} className="text-emerald-300">
                                      $ {c}
                                    </div>
                                  ))
                                ) : (
                                  <span className="text-muted-foreground">{model?.raw_output || '// None'}</span>
                                )}
                              </div>
                            </div>

                            {/* Safe Command */}
                            {audit?.safe_sanitized_command && (
                              <div className="space-y-1">
                                <span className="text-[11px] font-semibold text-emerald-400 uppercase">
                                  Self-Sanitized Safe Command
                                </span>
                                <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30 font-mono text-xs text-emerald-200">
                                  $ {audit.safe_sanitized_command}
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
                <div className="p-3 border-t border-border bg-surface-sunken flex justify-end">
                  <button className="btn btn--sm btn--primary" onClick={() => setInspectedRun(null)}>
                    Close Matrix
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
