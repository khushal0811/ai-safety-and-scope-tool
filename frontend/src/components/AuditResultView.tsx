import { useEffect, useMemo, useState } from 'react';
import type { AuditResult, TargetFinding, Verdict } from '../types/audit';
import { MODELS } from '../data/models';
import { diffWords, computeSplitDiff, type SplitDiffRow } from '../lib/diff';
import { AlertIcon, BanIcon, CheckIcon, CopyIcon, ShieldIcon } from './Icons';

/**
 * XSS note: model output is attacker-influenced. Everything below renders
 * through React text nodes only — never dangerouslySetInnerHTML.
 */

const VERDICT_ICON: Record<Verdict, typeof CheckIcon> = { Correct: CheckIcon, Incorrect: AlertIcon, Unsafe: BanIcon };
const STATUS_LABEL: Record<TargetFinding['status'], { cls: string; label: string }> = {
  in_scope: { cls: 'tag--ok', label: 'in scope' },
  out_of_scope: { cls: 'tag--bad', label: 'out of scope' },
  prohibited: { cls: 'tag--bad', label: 'prohibited' },
};

export function AuditResultView({
  result,
  loading,
  onAuditAnother,
  onResetAll,
}: {
  result: AuditResult | null;
  loading: boolean;
  onAuditAnother?: () => void;
  onResetAll?: () => void;
}) {
  if (loading) return <LoadingState />;
  if (!result) return <EmptyState />;
  return <ResultBody result={result} onAuditAnother={onAuditAnother} onResetAll={onResetAll} />;
}

function EmptyState() {
  return (
    <div className="empty">
      <div className="empty__icon">
        <ShieldIcon width={20} height={20} />
      </div>
      <h3>No audit yet</h3>
      <p>Pick a scope, load an example, and run an audit to see the verdict, findings and a sanitized command.</p>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="card card__body skeleton" aria-busy="true" aria-label="Running audit">
      <div className="skeleton__bar" style={{ width: '40%', height: 28 }} />
      <div className="skeleton__bar" style={{ width: '90%' }} />
      <div className="skeleton__bar" style={{ width: '75%' }} />
      <div className="skeleton__bar" style={{ width: '82%' }} />
    </div>
  );
}

function ResultBody({
  result,
  onAuditAnother,
  onResetAll,
}: {
  result: AuditResult;
  onAuditAnother?: () => void;
  onResetAll?: () => void;
}) {
  const Icon = VERDICT_ICON[result.verdict];
  const modelLabel = MODELS.find((m) => m.id === result.selected_model)?.label ?? result.selected_model;
  const uniqueTargets = useMemo(() => {
    const seen = new Map<string, TargetFinding>();
    result.targets.forEach((t) => seen.set(`${t.kind}:${t.token}`, t));
    return [...seen.values()];
  }, [result.targets]);

  return (
    <div className="result" id="audit-result">
      <div className={`verdict verdict--${result.verdict}`} role="status">
        <span className="verdict__badge">
          <Icon /> {result.verdict}
        </span>
        <p className="verdict__text">{result.explanation}</p>
        <div className="verdict__meta">
          {result.audit_id}
          <br />
          {modelLabel}
        </div>
      </div>

      {result.verdict !== 'Correct' ? <SanitizedBox result={result} /> : null}

      <section className="card" aria-labelledby="findings-title">
        <div className="card__header">
          <span className="step-index">03</span>
          <div>
            <h2 className="card__title" id="findings-title">Findings</h2>
            <p className="card__desc">
              {result.extracted_commands.length} command(s) · {uniqueTargets.length} target(s) · {result.violation_details.length} finding(s)
            </p>
          </div>
        </div>
        <div className="card__body" style={{ display: 'grid', gap: 18 }}>
          <div>
            <p className="section-label">Detected commands</p>
            {result.extracted_commands.length ? (
              <ul className="code-list">
                {result.extracted_commands.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            ) : (
              <p className="muted">No commands detected.</p>
            )}
          </div>

          {uniqueTargets.length ? (
            <div>
              <p className="section-label">Targets</p>
              <div className="tag-row">
                {uniqueTargets.map((t) => (
                  <span key={`${t.kind}:${t.token}`} className={`tag ${STATUS_LABEL[t.status].cls}`} title={t.obfuscated ? `Obfuscated: ${t.token}` : undefined}>
                    {t.obfuscated ? `${t.token} → ${t.normalized}` : t.normalized} · {STATUS_LABEL[t.status].label}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {result.violation_details.length ? (
            <div>
              <p className="section-label">Flagged rules</p>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Severity</th>
                      <th>Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.violation_details.map((v, i) => (
                      <tr key={i}>
                        <td className="table__rule">{v.rule}</td>
                        <td>
                          <span className={`sev sev--${v.severity}`}>{v.severity}</span>
                        </td>
                        <td className="table__detail">{v.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="note">
              <CheckIcon /> No rule violations detected.
            </div>
          )}

          {result.modifications_made.length ? (
            <details className="accordion" open={result.verdict !== 'Correct'}>
              <summary>Remediation notes</summary>
              <div className="accordion__body">
                <ul>
                  {result.modifications_made.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              </div>
            </details>
          ) : null}

          {result.mode === 'demo' ? (
            <p className="muted" style={{ fontSize: 12 }}>
              Demo mode: client-side preview of the deterministic engine. The authoritative FastAPI engine and Llama 3 rewriter
              arrive in Phases 2–3.
            </p>
          ) : null}

          {onAuditAnother || onResetAll ? (
            <div className="card__actions" style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
              {onResetAll ? (
                <button className="btn btn--lg" onClick={onResetAll}>
                  ← Start New Audit (Change Scope)
                </button>
              ) : null}
              {onAuditAnother ? (
                <button className="btn btn--primary btn--lg" style={{ flex: 1 }} onClick={onAuditAnother}>
                  Audit Another Prompt in this Scope ⚡
                </button>
              ) : null}
            </div>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function SideBySideDiff({ rows }: { rows: SplitDiffRow[] }) {
  return (
    <div className="split-diff" aria-label="Side-by-side git diff view">
      {/* Left Pane: Original Command(s) */}
      <div className="split-diff__pane">
        <div className="split-diff__header split-diff__header--orig">
          <span>Original (Model Proposed)</span>
          <span style={{ fontSize: 10, opacity: 0.8 }}>Red lines removed/modified</span>
        </div>
        <div className="split-diff__body">
          {rows.map((row, i) => {
            const isDel = row.type === 'deleted' || row.type === 'modified';
            const isEmpty = !row.leftContent && row.type === 'added';
            const rowClass = isEmpty
              ? 'split-diff__row split-diff__row--empty'
              : isDel
              ? 'split-diff__row split-diff__row--del'
              : 'split-diff__row';

            return (
              <div key={i} className={rowClass}>
                <span className="split-diff__gutter">{row.lineNumLeft ?? ' '}</span>
                <span className="split-diff__content">
                  {row.leftTokens ? (
                    row.leftTokens.map((t, ti) => (
                      <span key={ti} className={t.type === 'del' ? 'diff__del' : undefined}>
                        {t.text}
                      </span>
                    ))
                  ) : (
                    row.leftContent ?? ''
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Pane: Sanitized Safe Command */}
      <div className="split-diff__pane">
        <div className="split-diff__header split-diff__header--safe">
          <span>Sanitized (RoE Compliant)</span>
          <span style={{ fontSize: 10, opacity: 0.8 }}>Green lines added/remediated</span>
        </div>
        <div className="split-diff__body">
          {rows.map((row, i) => {
            const isAdd = row.type === 'added' || row.type === 'modified';
            const isEmpty = !row.rightContent && row.type === 'deleted';
            const rowClass = isEmpty
              ? 'split-diff__row split-diff__row--empty'
              : isAdd
              ? 'split-diff__row split-diff__row--add'
              : 'split-diff__row';

            return (
              <div key={i} className={rowClass}>
                <span className="split-diff__gutter">{row.lineNumRight ?? ' '}</span>
                <span className="split-diff__content">
                  {row.rightTokens ? (
                    row.rightTokens.map((t, ti) => (
                      <span key={ti} className={t.type === 'add' ? 'diff__add' : undefined}>
                        {t.text}
                      </span>
                    ))
                  ) : (
                    row.rightContent ?? ''
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function SanitizedBox({ result }: { result: AuditResult }) {
  const [copied, setCopied] = useState(false);
  const [showDiff, setShowDiff] = useState(true);
  const [diffMode, setDiffMode] = useState<'split' | 'unified'>('split');
  const original = result.extracted_commands.join('\n');
  const safe = result.safe_sanitized_command;
  const parts = useMemo(() => (safe ? diffWords(original, safe) : []), [original, safe]);
  const splitRows = useMemo(() => (safe ? computeSplitDiff(original, safe) : []), [original, safe]);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1600);
    return () => clearTimeout(t);
  }, [copied]);

  if (!safe) {
    return (
      <div className="note note--bad" role="alert">
        <BanIcon />
        <span>
          <strong>No safe equivalent.</strong> The requested action cannot be executed within the current scope. Every
          command targeted hard-denied assets or performed prohibited actions.
        </span>
      </div>
    );
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(safe!);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="sanitized" aria-labelledby="sanitized-title">
      <div className="sanitized__head">
        <span className="sanitized__title" id="sanitized-title">
          <ShieldIcon /> Self-sanitized command
        </span>
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <div className="diff-mode-toggle" aria-label="Diff display format">
            <button
              type="button"
              className={`diff-mode-btn ${diffMode === 'split' ? 'diff-mode-btn--active' : ''}`}
              onClick={() => {
                setDiffMode('split');
                setShowDiff(true);
              }}
            >
              Side-by-Side
            </button>
            <button
              type="button"
              className={`diff-mode-btn ${diffMode === 'unified' ? 'diff-mode-btn--active' : ''}`}
              onClick={() => {
                setDiffMode('unified');
                setShowDiff(true);
              }}
            >
              Inline
            </button>
          </div>
          <button id="toggle-diff" className="btn btn--sm btn--ghost" onClick={() => setShowDiff((s) => !s)}>
            {showDiff ? 'Hide diff' : 'Show diff'}
          </button>
          <button id="copy-sanitized" className="btn btn--sm" onClick={copy}>
            {copied ? <CheckIcon width={14} height={14} /> : <CopyIcon width={14} height={14} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      </div>
      <div className="sanitized__body">
        <pre className="code-block">{safe}</pre>
        {showDiff ? (
          <div>
            <p className="section-label" style={{ marginBottom: 8 }}>
              {diffMode === 'split' ? 'Git Split Diff (Original vs Sanitized)' : 'Inline Word Diff (Original → Sanitized)'}
            </p>
            {diffMode === 'split' ? (
              <SideBySideDiff rows={splitRows} />
            ) : (
              <div className="code-block diff" aria-label="Diff between original and sanitized command">
                {parts.map((part, i) => (
                  <span key={i} className={part.type === 'add' ? 'diff__add' : part.type === 'del' ? 'diff__del' : undefined}>
                    {part.text}
                  </span>
                ))}
              </div>
            )}
          </div>
        ) : null}
      </div>
    </section>
  );
}
