import { MODELS, type PromptExample } from '../data/models';
import { SparkIcon, KeyIcon, AlertIcon } from './Icons';

interface Props {
  modelId: string;
  onModelChange: (id: string) => void;
  prompt: string;
  onPromptChange: (p: string) => void;
  modelOutput: string;
  onModelOutputChange: (o: string) => void;
  examples: PromptExample[];
  activeExample: string | null;
  onExample: (ex: PromptExample) => void;
  hasOpenRouterKey: boolean;
  onNavigateToSettings: () => void;
  onQueryLiveModel: () => void;
  queryingModel: boolean;
  queryError: string | null;
  canRun: boolean;
  blockedReason: string | null;
  loading: boolean;
  onRun: () => void;
  onBack?: () => void;
}

export function PromptComposer(p: Props) {
  const selectedModel = MODELS.find((m) => m.id === p.modelId) || MODELS[0];

  return (
    <section className="card card--hero" aria-labelledby="step2-title">
      <div className="card__header">
        <span className="step-index">STEP 02</span>
        <div>
          <h2 className="card__title" id="step2-title">Ask Frontier Model &amp; Audit Output</h2>
          <p className="card__desc">Choose a model, compose your offensive prompt, and inspect recommendations against your RoE.</p>
        </div>
      </div>
      <div className="card__body">
        <div className="field">
          <div className="row between" style={{ marginBottom: 6 }}>
            <label className="field__label" htmlFor="model-select" style={{ margin: 0 }}>
              Target model
            </label>
            {p.hasOpenRouterKey ? (
              <span className="tag tag--ok" style={{ fontSize: 11 }}>
                ● OpenRouter Connected
              </span>
            ) : (
              <span className="tag tag--warn" style={{ fontSize: 11, color: 'var(--warn-fg)' }}>
                ⚠ OpenRouter Key Required
              </span>
            )}
          </div>
          <select
            id="model-select"
            className="select"
            value={p.modelId}
            onChange={(e) => p.onModelChange(e.target.value)}
          >
            {MODELS.map((m) => {
              const isLocked = !p.hasOpenRouterKey;
              return (
                <option key={m.id} value={m.id} disabled={isLocked}>
                  {isLocked ? `🔒 ${m.label} — ${m.vendor} (Requires Key)` : `${m.label} — ${m.vendor}`}
                </option>
              );
            })}
          </select>

          {!p.hasOpenRouterKey && (
            <div className="model-key-banner">
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <KeyIcon width={16} height={16} style={{ color: 'var(--warn-fg)', flexShrink: 0 }} />
                <div style={{ flex: 1, fontSize: 12.5, lineHeight: 1.5 }}>
                  <strong>OpenRouter API Key Required:</strong> Live model queries and automated audits require your personal OpenRouter API key. Server system keys are disabled for user tasks. Please enter your key in{' '}
                  <button
                    type="button"
                    className="inline-link-btn"
                    onClick={p.onNavigateToSettings}
                  >
                    Settings
                  </button>
                  .
                </div>
              </div>
            </div>
          )}
        </div>

        <p className="section-label">Examples</p>
        <div className="chip-row">
          {p.examples.map((ex) => (
            <button
              key={ex.id}
              type="button"
              id={`example-${ex.id}`}
              className={`chip ${p.activeExample === ex.id ? 'chip--active' : ''}`}
              onClick={() => p.onExample(ex)}
            >
              {ex.label}
            </button>
          ))}
        </div>

        <div className="field">
          <label className="field__label" htmlFor="prompt-input">
            <span>Pentest prompt</span>
          </label>
          <textarea
            id="prompt-input"
            className="textarea"
            rows={3}
            maxLength={4000}
            placeholder="Authorized target is 192.168.1.105. Enumerate SMB shares…"
            value={p.prompt}
            onChange={(e) => p.onPromptChange(e.target.value)}
          />
          <div className="row between" style={{ marginTop: 8, gap: 10, flexWrap: 'wrap' }}>
            <span className="muted" style={{ fontSize: 12 }}>
              Ask the selected model live, or paste command outputs manually below.
            </span>
            {!p.hasOpenRouterKey ? (
              <button
                type="button"
                id="query-model-btn"
                className="btn btn--sm btn--primary row"
                style={{ gap: 6, background: 'var(--warn-fg)', borderColor: 'var(--warn-fg)' }}
                onClick={p.onNavigateToSettings}
                title="Enter your personal OpenRouter API key in Settings to ask models live"
              >
                <KeyIcon width={14} height={14} /> Configure Key to Ask Live ⚡
              </button>
            ) : (
              <button
                type="button"
                id="query-model-btn"
                className="btn btn--sm btn--primary row"
                style={{ gap: 6 }}
                disabled={!p.prompt.trim() || p.queryingModel || p.loading}
                onClick={p.onQueryLiveModel}
                title={`Query ${selectedModel.label} with this prompt`}
              >
                {p.queryingModel ? (
                  <>
                    <span className="spinner" style={{ width: 13, height: 13 }} /> Querying {selectedModel.label}…
                  </>
                ) : (
                  <>
                    <SparkIcon width={14} height={14} /> Ask Model Live ⚡
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {p.queryError && (
          <div className="field-error-banner row" style={{ gap: 8, marginBottom: 12 }}>
            <AlertIcon width={16} height={16} style={{ color: 'var(--unsafe)', flexShrink: 0 }} />
            <div style={{ flex: 1 }}>
              {p.queryError}
              {p.queryError.toLowerCase().includes('openrouter') && !p.hasOpenRouterKey && (
                <button
                  type="button"
                  className="inline-link-btn"
                  style={{ marginLeft: 6 }}
                  onClick={p.onNavigateToSettings}
                >
                  Configure in Settings →
                </button>
              )}
            </div>
          </div>
        )}

        <div className="field">
          <label className="field__label" htmlFor="model-output">
            <span>Model response</span>
            <span className="tag">
              {p.queryingModel
                ? 'querying...'
                : p.modelOutput
                ? 'live / custom command'
                : 'awaiting query or paste'}
            </span>
          </label>
          <textarea
            id="model-output"
            className="textarea textarea--mono"
            rows={6}
            maxLength={20000}
            placeholder="Run 'Ask Model Live ⚡' above or paste raw AI pentest commands here to audit them against your RoE."
            value={p.modelOutput}
            onChange={(e) => p.onModelOutputChange(e.target.value)}
          />
        </div>

        <div className="card__actions">
          {p.onBack ? (
            <button className="btn btn--lg" onClick={p.onBack} disabled={p.loading || p.queryingModel}>
              ← Change Scope
            </button>
          ) : null}
          <button
            id="run-audit"
            className="btn btn--primary btn--lg"
            style={{ flex: 1 }}
            disabled={!p.canRun || p.loading || p.queryingModel}
            onClick={p.onRun}
          >
            {p.loading ? (
              <>
                <span className="spinner" /> Analyzing Scope &amp; Rewriting…
              </>
            ) : (
              <>
                <SparkIcon /> Audit Recommendation ⚡
              </>
            )}
          </button>
        </div>
        {p.blockedReason ? (
          <p className="muted" style={{ fontSize: 12, marginTop: 8, textAlign: 'center' }}>
            {p.blockedReason}
          </p>
        ) : null}
      </div>
    </section>
  );
}
