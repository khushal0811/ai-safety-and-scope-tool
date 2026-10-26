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

type Theme = 'light' | 'dark';

function initialTheme(): Theme {
  const saved = localStorage.getItem('sst.theme');
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [settingsOpen, setSettingsOpen] = useState(false);

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
      setResult(await runAudit({ roe: activeScope, model_id: modelId, user_prompt: prompt, model_output: modelOutput }));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <NavBar theme={theme} onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))} onOpenSettings={() => setSettingsOpen(true)} />

      <main className="container">
        <section className="hero">
          <span className="hero__eyebrow">● Audit playground</span>
          <h1>Keep AI pentest advice inside the Rules of Engagement.</h1>
          <p>
            Define a scope, ask a model for a pentest command, and SST flags out-of-scope targets, destructive payloads and
            hallucinated CVEs, then rewrites the command so it stays in scope.
          </p>
        </section>

        <div className="workspace">
          <div className="workspace__col">
            <RoeSelector
              mode={roeMode}
              onModeChange={setRoeMode}
              presetId={presetId}
              onPresetChange={setPresetId}
              customText={customRoe}
              onCustomTextChange={setCustomRoe}
              activeScope={activeScope}
            />
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
            />
          </div>
          <div className="workspace__col workspace__col--sticky">
            <AuditResultView result={result} loading={loading} />
          </div>
        </div>
      </main>

      <footer className="footer">
        <div className="container">
          <span>SST · static analysis only, commands are never executed</span>
          <span className="mono">v0.1.0 · phase 1</span>
        </div>
      </footer>

      {settingsOpen ? <SettingsModal onClose={() => setSettingsOpen(false)} /> : null}
    </div>
  );
}
