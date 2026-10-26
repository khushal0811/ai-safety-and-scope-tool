import { useEffect, useMemo, useState } from 'react';
import type { AuditResult } from './types/audit';
import { ROE_PRESETS } from './data/presets';
import { buildExamples, MODELS, type PromptExample } from './data/models';
import { runAudit } from './services/auditService';
import { NavBar } from './components/NavBar';
import { RoeSelector, type RoeMode } from './components/RoeSelector';
import { PromptComposer } from './components/PromptComposer';
import { AuditResultView } from './components/AuditResultView';
import { SettingsModal } from './components/SettingsModal';
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
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [step, setStep] = useState<Step>(1);

  const [roeMode, setRoeMode] = useState<RoeMode>('preset');
  const [presetId, setPresetId] = useState(ROE_PRESETS[0].roe_id);
  const [customRoe, setCustomRoe] = useState('');

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

  const activeScope = roeMode === 'preset' ? ROE_PRESETS.find((p) => p.roe_id === presetId) ?? null : null;
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
    ? 'Custom RoE parsing ships in Phase 3 — select a preset to run an audit.'
    : !modelOutput.trim()
      ? 'Load an example or paste a model response to audit.'
      : null;

  async function handleRun() {
    if (!activeScope || !modelOutput.trim()) return;
    setLoading(true);
    try {
      const res = await runAudit({ roe: activeScope, model_id: modelId, user_prompt: prompt, model_output: modelOutput });
      setResult(res);
      setStep(3); // Transition smoothly into Audit Verdict step
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

  return (
    <div className="app">
      <NavBar theme={theme} onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))} onOpenSettings={() => setSettingsOpen(true)} />

      <main className="container canvas-container">
        <section className="hero" style={{ textAlign: 'center', paddingBottom: 16 }}>
          <span className="hero__eyebrow">● Dynamic AI Safety &amp; Scope Auditor</span>
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

        {/* Step 1: Define RoE Scope */}
        {step === 1 && (
          <RoeSelector
            mode={roeMode}
            onModeChange={setRoeMode}
            presetId={presetId}
            onPresetChange={setPresetId}
            customText={customRoe}
            onCustomTextChange={setCustomRoe}
            activeScope={activeScope}
            onContinue={() => setStep(2)}
          />
        )}

        {/* Step 2: Prompt Target Model */}
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

      <footer className="footer">
        <div className="container">
          <span>SST · static analysis only, commands are never executed</span>
          <span className="mono">v0.1.0 · dynamic flow</span>
        </div>
      </footer>

      {settingsOpen ? <SettingsModal onClose={() => setSettingsOpen(false)} /> : null}
    </div>
  );
}
