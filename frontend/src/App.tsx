import { useEffect, useMemo, useState } from 'react';
import type { AuditResult, RoeScope } from './types/audit';
import type { PastAudit } from './types/history';
import type { UserProfile } from './types/user';
import { ROE_PRESETS } from './data/presets';
import { buildExamples, MODELS, type PromptExample } from './data/models';
import { runAudit } from './services/auditService';
import { getStoredUser, saveUser, initSupabaseAuthListener } from './lib/authStore';
import { getPastAudits, savePastAudit, clearPastAudits, syncPastAuditsFromCloud } from './lib/historyStore';
import { NavBar, type AppPage } from './components/NavBar';
import { RoeSelector, type RoeMode } from './components/RoeSelector';
import { PromptComposer } from './components/PromptComposer';
import { AuditResultView } from './components/AuditResultView';
import { PastAuditsView } from './components/PastAuditsView';
import { SettingsView } from './components/SettingsView';
import { AuthLandingPage } from './components/AuthLandingPage';
import { AuthModal } from './components/AuthModal';
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

  // Past Audits history state (Strict Privacy: empty for guests)
  const [audits, setAudits] = useState<PastAudit[]>(() => (user ? getPastAudits(user.id) : []));

  // Studio state
  const [roeMode, setRoeMode] = useState<RoeMode>('preset');
  const [presetId, setPresetId] = useState(ROE_PRESETS[0].roe_id);
  const [customRoe, setCustomRoe] = useState('');
  const [customScope, setCustomScope] = useState<RoeScope | null>(null);

  const [modelId, setModelId] = useState(MODELS[0].id);
  const [prompt, setPrompt] = useState('');
  const [modelOutput, setModelOutput] = useState('');
  const [activeExample, setActiveExample] = useState<string | null>(null);

  const [result, setResult] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('sst.theme', theme);
  }, [theme]);

  // Listen for Supabase session changes
  useEffect(() => {
    const unsub = initSupabaseAuthListener((newUser) => {
      if (newUser) {
        setUser(newUser);
      }
    });
    return unsub;
  }, []);

  // Synchronize past audits with Supabase PostgreSQL cloud database (Strictly isolated by user_id)
  useEffect(() => {
    if (user) {
      syncPastAuditsFromCloud(user.id).then(setAudits);
    } else {
      setAudits([]);
    }
  }, [user, page]);

  function handleLogin(u: UserProfile) {
    setUser(u);
    saveUser(u);
  }

  function handleLogout() {
    setUser(null);
    saveUser(null);
    setAudits([]);
    setGuestMode(false);
    setPage('studio');
  }

  function handleClearHistory() {
    clearPastAudits(user?.id);
    setAudits([]);
  }

  const activeScope = roeMode === 'preset' ? ROE_PRESETS.find((p) => p.roe_id === presetId) ?? null : customScope;
  const examples = useMemo(() => (activeScope ? buildExamples(activeScope) : buildExamples(ROE_PRESETS[0])), [activeScope]);

  // Keep a loaded example in sync with the selected preset's addresses.
  useEffect(() => {
    if (!activeExample) return;
    const ex = examples.find((e) => e.id === activeExample);
    if (ex) {
      setPrompt(ex.prompt);
      setModelOutput(ex.simulatedOutput);
    }
  }, [examples, activeExample]);

  function loadExample(ex: PromptExample) {
    setActiveExample(ex.id);
    setPrompt(ex.prompt);
    setModelOutput(ex.simulatedOutput);
  }

  const blockedReason = !activeScope
    ? roeMode === 'custom'
      ? 'Upload a document or paste RoE text and click "Extract Scope" to define boundaries.'
      : 'Select a preset scope to continue.'
    : !modelOutput.trim()
      ? 'Load an example or paste a model response to audit.'
      : null;

  async function handleRun() {
    if (!activeScope || !modelOutput.trim()) return;
    setLoading(true);
    try {
      const res = await runAudit({ roe: activeScope, model_id: modelId, user_prompt: prompt, model_output: modelOutput }, user?.id);
      setResult(res);
      setStep(3); // Transition into Step 3 (Audit Verdict & Safe Rewriter)

      // Automatically record audit to Past Audits store ONLY for authenticated users
      if (user) {
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

        const updated = savePastAudit(newAudit, user.id);
        setAudits(updated);
      }
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
        currentUser={user}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        onOpenAuth={() => setAuthModalOpen(true)}
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
              onModelChange={setModelId}
              prompt={prompt}
              onPromptChange={(v) => {
                setPrompt(v);
                setActiveExample(null);
              }}
              modelOutput={modelOutput}
              onModelOutputChange={(v) => {
                setModelOutput(v);
                setActiveExample(null);
              }}
              examples={examples}
              activeExample={activeExample}
              onExample={loadExample}
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
            />
          )}
        </main>
      )}

      {/* PAGE 2: PAST AUDITS HISTORY */}
      {page === 'history' && (
        <PastAuditsView
          audits={audits}
          currentUser={user}
          onClearHistory={handleClearHistory}
          onLoadAuditIntoStudio={handleLoadAuditIntoStudio}
          onOpenLogin={() => setAuthModalOpen(true)}
          onSyncCloud={async () => {
            const synced = await syncPastAuditsFromCloud(user?.id);
            setAudits(synced);
          }}
        />
      )}

      {/* PAGE 3: DEDICATED SETTINGS PAGE */}
      {page === 'settings' && (
        <SettingsView
          currentUser={user}
          onOpenLogin={() => setAuthModalOpen(true)}
          onLogout={handleLogout}
          onClearHistory={handleClearHistory}
        />
      )}

      {/* Global Footer */}
      <footer className="footer">
        <div className="container">
          <span>SST · static analysis only, commands are never executed on host</span>
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
    </div>
  );
}
