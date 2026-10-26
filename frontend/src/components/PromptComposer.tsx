import { MODELS, type PromptExample } from '../data/models';
import { SparkIcon } from './Icons';

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
  canRun: boolean;
  blockedReason: string | null;
  loading: boolean;
  onRun: () => void;
  onBack?: () => void;
}

export function PromptComposer(p: Props) {
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
          <label className="field__label" htmlFor="model-select">Target model</label>
          <select id="model-select" className="select" value={p.modelId} onChange={(e) => p.onModelChange(e.target.value)}>
            {MODELS.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label} — {m.vendor}
              </option>
            ))}
          </select>
        </div>

        <p className="section-label">Examples</p>
        <div className="chip-row">
          {p.examples.map((ex) => (
            <button
              key={ex.id}
              id={`example-${ex.id}`}
              className={`chip ${p.activeExample === ex.id ? 'chip--active' : ''}`}
              onClick={() => p.onExample(ex)}
            >
              {ex.label}
            </button>
          ))}
        </div>

        <div className="field">
          <label className="field__label" htmlFor="prompt-input">Pentest prompt</label>
          <textarea
            id="prompt-input"
            className="textarea"
            rows={3}
            maxLength={4000}
            placeholder="Authorized target is 192.168.1.105. Enumerate SMB shares…"
            value={p.prompt}
            onChange={(e) => p.onPromptChange(e.target.value)}
          />
        </div>

        <div className="field">
          <label className="field__label" htmlFor="model-output">
            <span>Model response</span>
            <span className="tag">demo · simulated</span>
          </label>
          <textarea
            id="model-output"
            className="textarea textarea--mono"
            rows={6}
            maxLength={20000}
            placeholder="Paste any AI-generated pentest response here to audit it."
            value={p.modelOutput}
            onChange={(e) => p.onModelOutputChange(e.target.value)}
          />
        </div>

        <div className="card__actions">
          {p.onBack ? (
            <button className="btn btn--lg" onClick={p.onBack} disabled={p.loading}>
              ← Change Scope
            </button>
          ) : null}
          <button
            id="run-audit"
            className="btn btn--primary btn--lg"
            style={{ flex: 1 }}
            disabled={!p.canRun || p.loading}
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
