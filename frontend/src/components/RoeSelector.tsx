import { useRef, useState, type DragEvent } from 'react';
import type { RoeScope } from '../types/audit';
import { ROE_PRESETS } from '../data/presets';
import { MAX_ROE_BYTES, validateRoeFile } from '../lib/roeFile';
import { AlertIcon, ChevronIcon, FileIcon, InfoIcon, UploadIcon, XIcon } from './Icons';

export type RoeMode = 'preset' | 'custom';

interface Props {
  mode: RoeMode;
  onModeChange: (m: RoeMode) => void;
  presetId: string;
  onPresetChange: (id: string) => void;
  customText: string;
  onCustomTextChange: (t: string) => void;
  activeScope: RoeScope | null;
  onContinue?: () => void;
}

const MAX_CHARS = MAX_ROE_BYTES; // conservative: 1 char >= 1 byte

export function RoeSelector(p: Props) {
  return (
    <section className="card card--hero" aria-labelledby="step1-title">
      <div className="card__header">
        <span className="step-index">STEP 01</span>
        <div>
          <h2 className="card__title" id="step1-title">Define Rules of Engagement (RoE)</h2>
          <p className="card__desc">Choose an engagement preset or upload your client's scope document to define boundaries.</p>
        </div>
      </div>
      <div className="card__body">
        <div className="segmented" role="group" aria-label="Scope source">
          <button id="roe-mode-preset" className="segmented__btn" aria-pressed={p.mode === 'preset'} onClick={() => p.onModeChange('preset')}>
            Pre-Built Scope Presets (Privacy Preserving)
          </button>
          <button id="roe-mode-custom" className="segmented__btn" aria-pressed={p.mode === 'custom'} onClick={() => p.onModeChange('custom')}>
            Upload Custom RoE (.md / .txt)
          </button>
        </div>

        {p.mode === 'preset' ? (
          <PresetList presetId={p.presetId} onChange={p.onPresetChange} />
        ) : (
          <CustomRoe text={p.customText} onChange={p.onCustomTextChange} />
        )}

        {p.activeScope ? <ScopeSummary scope={p.activeScope} /> : null}

        {p.onContinue ? (
          <div className="card__actions">
            <div className="muted" style={{ fontSize: 13 }}>
              {p.activeScope ? (
                <span>
                  Locked on: <strong>{p.activeScope.name}</strong> ({p.activeScope.allowed_cidrs.join(', ')})
                </span>
              ) : (
                'Select a preset or upload scope to continue'
              )}
            </div>
            <button
              id="confirm-scope-btn"
              className="btn btn--primary btn--lg"
              disabled={!p.activeScope}
              onClick={p.onContinue}
            >
              Confirm Scope &amp; Continue to Prompt →
            </button>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function PresetList({ presetId, onChange }: { presetId: string; onChange: (id: string) => void }) {
  return (
    <div className="preset-list" role="radiogroup" aria-label="RoE presets">
      {ROE_PRESETS.map((preset) => {
        const active = preset.roe_id === presetId;
        return (
          <div key={preset.roe_id} className={`preset ${active ? 'preset--active' : ''}`}>
            <button
              id={`preset-${preset.roe_id}`}
              className="preset__head"
              role="radio"
              aria-checked={active}
              onClick={() => onChange(preset.roe_id)}
            >
              <span className="preset__radio" />
              <span>
                <span className="preset__name">{preset.name}</span>
                <br />
                <span className="preset__type">{preset.engagement_type}</span>
              </span>
              <ChevronIcon className="preset__chev" />
            </button>
            {active ? <div className="preset__body">{preset.summary}</div> : null}
          </div>
        );
      })}
    </div>
  );
}

function CustomRoe({ text, onChange }: { text: string; onChange: (t: string) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);

  async function handleFile(file: File | undefined) {
    if (!file) return;
    const res = await validateRoeFile(file);
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setError(null);
    setFileName(file.name);
    onChange(res.text);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setOver(false);
    void handleFile(e.dataTransfer.files[0]);
  }

  return (
    <div>
      <div
        id="roe-dropzone"
        className={`dropzone ${over ? 'dropzone--over' : ''}`}
        role="button"
        tabIndex={0}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
      >
        <UploadIcon width={20} height={20} />
        <div className="dropzone__title">Drop an RoE document or click to browse</div>
        <div className="dropzone__hint">.md or .txt · max 500 KB · UTF-8 only</div>
        <input
          ref={inputRef}
          id="roe-file-input"
          type="file"
          accept=".md,.markdown,.txt,text/plain,text/markdown"
          className="sr-only"
          onChange={(e) => {
            void handleFile(e.target.files?.[0]);
            e.target.value = '';
          }}
        />
      </div>

      {error ? (
        <div className="note note--bad" style={{ marginTop: 10 }} role="alert">
          <AlertIcon /> {error}
        </div>
      ) : null}

      {fileName ? (
        <div className="file-chip">
          <span className="row">
            <FileIcon /> <span className="mono">{fileName}</span>
          </span>
          <button
            className="btn btn--ghost btn--icon btn--sm"
            aria-label="Remove file"
            onClick={() => {
              setFileName(null);
              onChange('');
            }}
          >
            <XIcon width={14} height={14} />
          </button>
        </div>
      ) : null}

      <div className="field" style={{ marginTop: 12 }}>
        <label className="field__label" htmlFor="roe-text">
          <span>Or paste RoE text</span>
          <span className="mono">{text.length.toLocaleString()} chars</span>
        </label>
        <textarea
          id="roe-text"
          className="textarea textarea--mono"
          rows={7}
          maxLength={MAX_CHARS}
          placeholder={'# Rules of Engagement\nIn scope: 10.0.0.0/24\nOut of scope: 10.0.0.1 (gateway)\nProhibited: DoS, data deletion'}
          value={text}
          onChange={(e) => onChange(e.target.value)}
        />
      </div>

      <div className="note">
        <InfoIcon />
        <span>
          Structured extraction runs server-side with Llama 3 (Phase 3), isolated against prompt injection. Until then, audits
          require a preset scope.
        </span>
      </div>
    </div>
  );
}

function ScopeSummary({ scope }: { scope: RoeScope }) {
  return (
    <div className="scope-summary" aria-label="Active scope summary">
      <div>
        <p className="section-label">In scope</p>
        <div className="tag-row">
          {scope.allowed_cidrs.map((c) => (
            <span key={c} className="tag tag--ok">{c}</span>
          ))}
          {scope.allowed_domains.map((d) => (
            <span key={d} className="tag tag--ok">{d}</span>
          ))}
          {scope.target_hosts.map((h) => (
            <span key={h} className="tag">target {h}</span>
          ))}
        </div>
      </div>
      <div>
        <p className="section-label">Prohibited</p>
        <div className="tag-row">
          {scope.prohibited_ips.map((ip) => (
            <span key={ip} className="tag tag--bad">{ip}</span>
          ))}
          {scope.prohibited_actions.map((a) => (
            <span key={a} className="tag tag--warn">no {a.replaceAll('_', ' ')}</span>
          ))}
          <span className="tag tag--warn">max nmap -T{scope.max_nmap_timing}</span>
        </div>
      </div>
    </div>
  );
}
