import { useEffect, useMemo, useState } from 'react';
import type { AuditResult, RoeScope } from './types/audit';
import type { PastAudit } from './types/history';
import type { UserProfile } from './types/user';
import type { BenchmarkEvaluateResponse, BenchmarkRunRecord } from './types/benchmark';
import { ROE_PRESETS } from './data/presets';
import { buildExamples, MODELS, type PromptExample } from './data/models';
import { runAudit, queryLiveModel } from './services/auditService';
import { getStoredUser, saveUser, initSupabaseAuthListener } from './lib/authStore';
import { getPastAudits, savePastAudit, deletePastAudits, clearPastAudits, syncPastAuditsFromCloud } from './lib/historyStore';
import {
  getPastBenchmarks,
  savePastBenchmark,
  deletePastBenchmarks,
  clearPastBenchmarks,
  syncPastBenchmarksFromCloud,
} from './lib/benchmarkStore';
import { getOpenRouterKey, hasVaultOpenRouterKey, fetchVaultStatus } from './lib/keyStore';
import { NavBar, type AppPage } from './components/NavBar';
import { RoeSelector, type RoeMode } from './components/RoeSelector';
import { PromptComposer } from './components/PromptComposer';
import { AuditResultView } from './components/AuditResultView';
import { PastAuditsView } from './components/PastAuditsView';
import { PastBenchmarksView } from './components/PastBenchmarksView';
import { BenchmarkStudioView } from './components/BenchmarkStudioView';
import { SettingsView } from './components/SettingsView';
import { AuthLandingPage } from './components/AuthLandingPage';
import { AuthModal } from './components/AuthModal';
import { InitialSetupModal } from './components/InitialSetupModal';
import { ShieldIcon } from './components/Icons';

type Theme = 'light' | 'dark';
type Step = 1 | 2 | 3;

function initialTheme(): Theme {
  const saved = localStorage.getItem('sst.theme');
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [page, setPage] = useState<AppPage>('studio');
  const [step, setStep] = useState<Step>(1);

  // Authentication state
  const [user, setUser] = useState<UserProfile | null>(getStoredUser);
  const [guestMode, setGuestMode] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [initialSetupOpen, setInitialSetupOpen] = useState(false);

  // Past Audits history state (Strict Privacy: empty for guests)
  const [audits, setAudits] = useState<PastAudit[]>(() => (user ? getPastAudits(user.id) : []));

  // Past Benchmarks history state (Strict Privacy: empty for guests)
  const [benchmarks, setBenchmarks] = useState<BenchmarkRunRecord[]>(() =>
    user ? getPastBenchmarks(user.id) : []
  );

  // Studio state
  const [roeMode, setRoeMode] = useState<RoeMode>('preset');
  const [presetId, setPresetId] = useState(ROE_PRESETS[0].roe_id);
  const [customRoe, setCustomRoe] = useState('');
  const [customScope, setCustomScope] = useState<RoeScope | null>(null);

  const [modelId, setModelId] = useState(MODELS[0].id);
  const [prompt, setPrompt] = useState('');
  const [modelOutput, setModelOutput] = useState('');
  const [activeExample, setActiveExample] = useState<string | null>(null);

  // Live Model Generation & Key Access Gate
  const [hasOpenRouterKey, setHasOpenRouterKey] = useState<boolean>(() =>
    Boolean(getOpenRouterKey() || hasVaultOpenRouterKey())
  );
  const [queryingModel, setQueryingModel] = useState(false);
  const [queryError, setQueryError] = useState<string | null>(null);

  const [trustTier, setTrustTier] = useState<'hybrid' | 'deterministic'>(() => {
    return (localStorage.getItem('vallum.trust_tier') as 'hybrid' | 'deterministic') || 'hybrid';
  });

  function handleSelectTrustTier(tier: 'hybrid' | 'deterministic') {
    setTrustTier(tier);
    localStorage.setItem('vallum.trust_tier', tier);
  }

  const [result, setResult] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('sst.theme', theme);
  }, [theme]);

  // Check OpenRouter key connectivity from local session or cloud database vault
  // Wait for database vault check before deciding whether to open or skip the setup modal
  useEffect(() => {
    let active = true;
    if (getOpenRouterKey() || hasVaultOpenRouterKey()) {
      setHasOpenRouterKey(true);
      setInitialSetupOpen(false);
      return;
    }
    if (user?.id) {
      fetchVaultStatus(user.id)
        .then((st) => {
          if (active) {
            const hasKey = Boolean(st.hasOpenRouterKey || getOpenRouterKey() || hasVaultOpenRouterKey());
            setHasOpenRouterKey(hasKey);
            if (hasKey) {
              setInitialSetupOpen(false);
              try {
                localStorage.setItem(`sst.initial_setup_completed_${user.id}`, 'true');
              } catch {
                // ignore
              }
            } else {
              let alreadyBypassed = false;
              try {
                alreadyBypassed = localStorage.getItem(`sst.initial_setup_completed_${user.id}`) === 'true';
              } catch {
                // ignore
              }
              if (!alreadyBypassed) {
                setInitialSetupOpen(true);
              }
            }
          }
        })
        .catch(() => {
          if (active && !getOpenRouterKey() && !hasVaultOpenRouterKey()) {
            setHasOpenRouterKey(false);
            let alreadyBypassed = false;
            try {
              alreadyBypassed = localStorage.getItem(`sst.initial_setup_completed_${user.id}`) === 'true';
            } catch {
              // ignore
            }
            if (!alreadyBypassed) {
              setInitialSetupOpen(true);
            }
          }
        });
    } else if (guestMode) {
      const hasKey = Boolean(getOpenRouterKey());
      setHasOpenRouterKey(hasKey);
      let guestBypassed = false;
      try {
        guestBypassed = localStorage.getItem('sst.initial_setup_completed_guest') === 'true';
      } catch {
        // ignore
      }
      if (!hasKey && !guestBypassed) {
        setInitialSetupOpen(true);
      }
    }
    return () => {
      active = false;
    };
  }, [user?.id, guestMode, page]);

  // Keep selected model valid
  useEffect(() => {
    const activeModel = MODELS.find((m) => m.id === modelId);
    if (!activeModel) {
      setModelId(MODELS[0].id);
    }
  }, [modelId]);

  // Listen for Supabase session changes
  useEffect(() => {
    const unsub = initSupabaseAuthListener((newUser) => {
      if (newUser) {
        setUser(newUser);
      }
    });
    return unsub;
  }, []);

  // Synchronize past audits & past benchmarks with Supabase PostgreSQL cloud database (Strictly isolated by user_id)
  useEffect(() => {
    if (user) {
      syncPastAuditsFromCloud(user.id).then(setAudits);
      syncPastBenchmarksFromCloud(user.id).then(setBenchmarks);
    } else {
      setAudits([]);
      setBenchmarks([]);
    }
  }, [user, page]);

  function handleLogin(u: UserProfile) {
    setUser(u);
    saveUser(u);
    setBenchmarks(getPastBenchmarks(u.id));
    syncPastBenchmarksFromCloud(u.id).then(setBenchmarks);
  }

  function handleLogout() {
    setUser(null);
    saveUser(null);
    setAudits([]);
    setBenchmarks([]);
    setGuestMode(false);
    setPage('studio');
  }

  function handleClearHistory() {
    clearPastAudits(user?.id);
    clearPastBenchmarks(user?.id);
    setAudits([]);
    setBenchmarks([]);
  }

  async function handleDeleteAudits(auditIds: string[]) {
    if (user) {
      const updated = await deletePastAudits(auditIds, user.id);
      setAudits(updated);
    } else {
      const toDelete = new Set(auditIds);
      setAudits((prev) => prev.filter((a) => !toDelete.has(a.id)));
    }
  }

  async function handleDeleteBenchmarks(benchmarkIds: string[]) {
    if (user) {
      const updated = await deletePastBenchmarks(benchmarkIds, user.id);
      setBenchmarks(updated);
    } else {
      const toDelete = new Set(benchmarkIds);
      setBenchmarks((prev) => prev.filter((b) => !toDelete.has(b.benchmark_id)));
    }
  }

  function handleBenchmarkComplete(res: BenchmarkEvaluateResponse) {
    const modelItems = res.items || [];
    const summary = res.summary || {
      total_models: modelItems.length,
      correct_count: modelItems.filter((i) => i.audit?.verdict === 'Correct').length,
      unsafe_count: modelItems.filter((i) => i.audit?.verdict === 'Unsafe').length,
      incorrect_count: modelItems.filter((i) => i.audit?.verdict === 'Incorrect').length,
      compliance_rate: 100,
      scope_violation_rate: 0,
      hallucination_rate: 0,
      average_latency_ms: 0,
    };

    const record: BenchmarkRunRecord = {
      benchmark_id: res.benchmark_id || `bm_${Date.now()}`,
      created_at: new Date().toISOString(),
      user_id: user?.id || null,
      scenario_title: res.scenario_title || 'Custom Benchmark',
      prompt: res.prompt,
      roe_id: res.roe_id || 'custom-roe',
      compliance_rate: summary.compliance_rate,
      scope_violation_rate: summary.scope_violation_rate,
      scope_violation_count: summary.scope_violation_count,
      hallucination_rate: summary.hallucination_rate,
      average_latency_ms: summary.average_latency_ms,
      total_models: summary.total_models || modelItems.length,
      fastest_model: summary.fastest_model || undefined,
      summary,
      items: modelItems,
    };

    if (user) {
      const updated = savePastBenchmark(record, user.id);
      setBenchmarks(updated);
    } else {
      // In-session memory for active guest session
      setBenchmarks((prev) => [record, ...prev.filter((b) => b.benchmark_id !== record.benchmark_id)]);
    }
  }

  const activeScope = roeMode === 'preset' ? ROE_PRESETS.find((p) => p.roe_id === presetId) ?? null : customScope;
  const examples = useMemo(() => (activeScope ? buildExamples(activeScope) : buildExamples(ROE_PRESETS[0])), [activeScope]);

  // Keep a loaded example in sync with the selected preset's addresses.
  useEffect(() => {
    if (!activeExample) return;
    const ex = examples.find((e) => e.id === activeExample);
    if (ex) {
      setPrompt(ex.prompt);
    }
  }, [examples, activeExample]);

  function loadExample(ex: PromptExample) {
    setActiveExample(ex.id);
    setPrompt(ex.prompt);
    setModelOutput('');
    setQueryError(null);
  }

  async function handleQueryLiveModel() {
    if (!prompt.trim()) return;
    if (!hasOpenRouterKey) {
      setInitialSetupOpen(true);
      setQueryError('An OpenRouter API key is required to query models. Please configure your key in Settings or the setup modal.');
      return;
    }
    setQueryingModel(true);
    setQueryError(null);
    try {
      const res = await queryLiveModel(prompt, modelId, user?.id);
      if (res.error) {
        setQueryError(res.error);
      } else {
        setModelOutput(res.text);
      }
    } catch (err: any) {
      setQueryError(err?.message || 'Failed to query live model');
    } finally {
      setQueryingModel(false);
    }
  }

  const blockedReason = !hasOpenRouterKey
    ? 'An OpenRouter API key is required to audit recommendations or benchmark models. Server system keys are disabled.'
    : !activeScope
      ? roeMode === 'custom'
        ? 'Upload a document or paste RoE text and click "Extract Scope" to define boundaries.'
        : 'Select a preset scope to continue.'
      : !modelOutput.trim()
        ? 'Click "Ask Model Live ⚡" to query the model or paste commands into the box to audit.'
        : null;

  async function handleRun() {
    if (!hasOpenRouterKey) {
      setInitialSetupOpen(true);
      setQueryError('An OpenRouter API key is required to perform an audit.');
      return;
    }
    if (!activeScope || !modelOutput.trim()) return;
    setLoading(true);
    setQueryError(null);
    try {
      const res = await runAudit(
        {
          roe: activeScope,
          model_id: modelId,
          user_prompt: prompt,
          model_output: modelOutput,
          deterministic_only: trustTier === 'deterministic',
        },
        user?.id
      );
      setResult(res);
      setStep(3); // Transition into Step 3 (Audit Verdict & Safe Rewriter)

      const modelObj = MODELS.find((m) => m.id === modelId);
      const newAudit: PastAudit = {
        id: res.audit_id || 'aud_' + Math.random().toString(36).substring(2, 8),
        timestamp: new Date().toISOString(),
        roeId: activeScope.roe_id,
        roeName: activeScope.name,
        modelId,
        modelName: modelObj ? modelObj.label : modelId,
        prompt: prompt.trim() || 'Custom Prompt',
        proposedCommand: modelOutput.trim(),
        executionTimeMs: 34,
        result: res,
      };

      if (user) {
        const updated = savePastAudit(newAudit, user.id);
        setAudits(updated);
      } else {
        setAudits((prev) => [newAudit, ...prev.filter((a) => a.id !== newAudit.id)]);
      }
    } catch (err: any) {
      console.error('[Vallum] Audit verification error:', err);
      setQueryError(err?.message || 'Audit verification failed. Backend service may be unreachable.');
    } finally {
      setLoading(false);
    }
  }

  function handleResetAll() {
    setResult(null);
    setStep(1);
  }

  function handleAuditAnother() {
    setResult(null);
    setStep(2);
  }

  function handleLoadAuditIntoStudio(audit: PastAudit) {
    // Restore state from selected historical audit
    const preset = ROE_PRESETS.find((p) => p.roe_id === audit.roeId);
    if (preset) {
      setRoeMode('preset');
      setPresetId(preset.roe_id);
    }
    setModelId(audit.modelId);
    setPrompt(audit.prompt);
    setModelOutput(audit.proposedCommand);
    setResult(audit.result);
    setStep(3);
    setPage('studio');
  }

  // LANDING PAGE: If user is not authenticated and has not entered guest mode
  if (!user && !guestMode) {
    return (
      <AuthLandingPage
        onAuthenticated={handleLogin}
        onContinueAsGuest={() => setGuestMode(true)}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
      />
    );
  }

  return (
    <div className="app">
      <NavBar
        activePage={page}
        onNavigate={setPage}
        auditCount={audits.length}
        benchmarkCount={benchmarks.length}
        currentUser={user}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        onOpenAuth={() => setAuthModalOpen(true)}
        trustTier={trustTier}
        onSelectTrustTier={handleSelectTrustTier}
      />

      {/* PAGE 1: AUDIT STUDIO */}
      {page === 'studio' && (
        <main className="container canvas-container">
          <section className="hero" style={{ textAlign: 'center', paddingBottom: 16 }}>
            <span className="hero__eyebrow">// 001 — DYNAMIC AUDIT STUDIO</span>
            <h1>Audit AI Pentest Advice Against Rules of Engagement</h1>
            <p style={{ margin: '8px auto 0', maxWidth: 640 }}>
              Define engagement boundaries, query offensive models, and get automated safety verdicts with self-sanitized, compliant commands.
            </p>
          </section>

          {/* Stepper Navigation (Gamma AI style) */}
          <nav className="stepper-nav" aria-label="Audit Progress">
            <button
              className={`step-node ${step === 1 ? 'step-node--active' : step > 1 ? 'step-node--done' : ''}`}
              onClick={() => setStep(1)}
            >
              <span className="step-node__badge">{step > 1 ? '✓' : '1'}</span>
              <span>Rules of Engagement</span>
            </button>
            <span className="step-connector">→</span>
            <button
              className={`step-node ${step === 2 ? 'step-node--active' : step > 2 ? 'step-node--done' : ''}`}
              disabled={!activeScope}
              onClick={() => activeScope && setStep(2)}
            >
              <span className="step-node__badge">{step > 2 ? '✓' : '2'}</span>
              <span>Model &amp; Pentest Prompt</span>
            </button>
            <span className="step-connector">→</span>
            <button
              className={`step-node ${step === 3 ? 'step-node--active' : ''}`}
              disabled={!result && !loading}
              onClick={() => result && setStep(3)}
            >
              <span className="step-node__badge">3</span>
              <span>Audit &amp; Remediation</span>
            </button>
          </nav>

          {/* Locked Scope Banner when on Step 2 or 3 */}
          {step > 1 && activeScope ? (
            <div className="scope-banner">
              <div className="scope-banner__info">
                <span className="tag tag--ok">
                  <ShieldIcon width={13} height={13} /> Locked Scope
                </span>
                <strong>{activeScope.name}</strong>
                <span className="muted">
                  (Allowed: {activeScope.allowed_cidrs.join(', ') || activeScope.allowed_domains.join(', ')} · Target: {activeScope.target_hosts.join(', ')})
                </span>
              </div>
              <button className="btn btn--sm btn--ghost" onClick={() => setStep(1)}>
                ← Change Scope
              </button>
            </div>
          ) : null}

          {/* Step 1: RoE Selector */}
          {step === 1 && (
            <RoeSelector
              mode={roeMode}
              onModeChange={setRoeMode}
              presetId={presetId}
              onPresetChange={setPresetId}
              customText={customRoe}
              onCustomTextChange={setCustomRoe}
              activeScope={activeScope}
              onCustomScopeParsed={setCustomScope}
              onContinue={() => setStep(2)}
            />
          )}

          {/* Step 2: Model & Prompt Composer */}
          {step === 2 && (
            <PromptComposer
              modelId={modelId}
              onModelChange={(newId) => {
                setModelId(newId);
                setQueryError(null);
              }}
              prompt={prompt}
              onPromptChange={(v) => {
                setPrompt(v);
                setActiveExample(null);
                setQueryError(null);
              }}
              modelOutput={modelOutput}
              onModelOutputChange={(v) => {
                setModelOutput(v);
                setActiveExample(null);
              }}
              examples={examples}
              activeExample={activeExample}
              onExample={loadExample}
              hasOpenRouterKey={hasOpenRouterKey}
              onNavigateToSettings={() => setPage('settings')}
              onQueryLiveModel={handleQueryLiveModel}
              queryingModel={queryingModel}
              queryError={queryError}
              canRun={!blockedReason}
              blockedReason={blockedReason}
              loading={loading}
              onRun={handleRun}
              onBack={() => setStep(1)}
            />
          )}

          {/* Step 3: Audit Verdict & Safe Rewriter */}
          {step === 3 && (
            <AuditResultView
              result={result}
              loading={loading}
              onAuditAnother={handleAuditAnother}
              onResetAll={handleResetAll}
              activeScope={activeScope}
              currentUser={user}
            />
          )}
        </main>
      )}

      {/* PAGE 2: PAST AUDITS HISTORY */}
      {page === 'history' && (
        <PastAuditsView
          audits={audits}
          currentUser={user}
          onDeleteAudits={handleDeleteAudits}
          onLoadAuditIntoStudio={handleLoadAuditIntoStudio}
          onOpenLogin={() => setAuthModalOpen(true)}
          onSyncCloud={async () => {
            const synced = await syncPastAuditsFromCloud(user?.id);
            setAudits(synced);
          }}
        />
      )}

      {/* PAGE 3: BENCHMARK STUDIO */}
      {page === 'benchmark' && (
        <BenchmarkStudioView
          activeRoe={activeScope || ROE_PRESETS[0]}
          allRoes={ROE_PRESETS}
          onSelectRoe={(newRoe) => {
            setPresetId(newRoe.roe_id);
            setRoeMode('preset');
          }}
          currentUser={user}
          onNavigateSettings={() => setPage('settings')}
          onNavigatePastBenchmarks={() => setPage('past-benchmarks')}
          onBenchmarkComplete={handleBenchmarkComplete}
          pastBenchmarkCount={benchmarks.length}
        />
      )}

      {/* PAGE 4: PAST BENCHMARKS HISTORY */}
      {page === 'past-benchmarks' && (
        <PastBenchmarksView
          benchmarks={benchmarks}
          currentUser={user}
          onDeleteBenchmarks={handleDeleteBenchmarks}
          onOpenLogin={() => setAuthModalOpen(true)}
          onSyncCloud={async () => {
            const synced = await syncPastBenchmarksFromCloud(user?.id);
            setBenchmarks(synced);
          }}
          onNavigateBenchmarkStudio={() => setPage('benchmark')}
        />
      )}

      {/* PAGE 5: DEDICATED SETTINGS PAGE */}
      {page === 'settings' && (
        <SettingsView
          currentUser={user}
          onOpenLogin={() => setAuthModalOpen(true)}
          onLogout={handleLogout}
          onClearHistory={handleClearHistory}
          onOpenInitialSetup={() => setInitialSetupOpen(true)}
        />
      )}

      {/* Global Footer */}
      <footer className="footer">
        <div className="container">
          <span>Vallum · static analysis only, commands are never executed on host</span>
          <span className="mono">v0.2.0 · multi-page architecture</span>
        </div>
      </footer>

      {/* Auth Modal */}
      {authModalOpen && (
        <AuthModal
          currentUser={user}
          onLogin={handleLogin}
          onLogout={handleLogout}
          onClose={() => setAuthModalOpen(false)}
        />
      )}

      {/* Initial Onboarding Setup Modal Overlay */}
      {initialSetupOpen && (
        <InitialSetupModal
          user={user}
          isOpen={initialSetupOpen}
          onClose={() => setInitialSetupOpen(false)}
          onKeySaved={() => {
            setHasOpenRouterKey(true);
            setInitialSetupOpen(false);
          }}
        />
      )}
    </div>
  );
}
