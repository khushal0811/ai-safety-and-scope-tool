import { useEffect, useMemo, useState } from 'react';
import type { AuditResult, RoeScope, TargetFinding, Verdict } from '../types/audit';
import type { UserProfile } from '../types/user';
import type { SandboxDryRunResult } from '../types/sandbox';
import { MODELS } from '../data/models';
import { diffWords, computeSplitDiff, type SplitDiffRow } from '../lib/diff';
import { AlertIcon, BanIcon, CheckIcon, CopyIcon, DownloadIcon, ShieldIcon, TerminalIcon } from './Icons';
import { downloadComplianceReport, executeSandboxDryRun } from '../services/auditService';

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
  activeScope,
  currentUser,
}: {
  result: AuditResult | null;
  loading: boolean;
  onAuditAnother?: () => void;
  onResetAll?: () => void;
  activeScope?: RoeScope | null;
  currentUser?: UserProfile | null;
}) {
  if (loading) return <LoadingState />;
  if (!result) return <EmptyState />;
  return (
    <ResultBody
      result={result}
      onAuditAnother={onAuditAnother}
      onResetAll={onResetAll}
      activeScope={activeScope}
      currentUser={currentUser}
    />
  );
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
  activeScope,
  currentUser,
}: {
  result: AuditResult;
  onAuditAnother?: () => void;
  onResetAll?: () => void;
  activeScope?: RoeScope | null;
  currentUser?: UserProfile | null;
}) {
  const Icon = VERDICT_ICON[result.verdict];
  const modelLabel = MODELS.find((m) => m.id === result.selected_model)?.label ?? result.selected_model;
  const [exportingFormat, setExportingFormat] = useState<'pdf' | 'markdown' | 'json' | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  async function handleExportReport(format: 'pdf' | 'markdown' | 'json') {
    setExportingFormat(format);
    setExportError(null);
    try {
      const targetRoeId = activeScope?.roe_id || 'ROE-PRESET-NET-001';
      await downloadComplianceReport(targetRoeId, format, currentUser?.id);
    } catch (err: any) {
      setExportError(err?.message || 'Failed to download compliance report');
    } finally {
      setExportingFormat(null);
    }
  }

  const [sandboxCommand, setSandboxCommand] = useState<string | null>(null);

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
          <br />
          <span
            className={`trust-tier-badge ${result.trust_tier === 'deterministic' ? 'trust-tier-badge--det' : 'trust-tier-badge--hyb'}`}
            style={{ marginTop: 4, display: 'inline-block' }}
          >
            {result.trust_tier === 'deterministic' ? '🔒 Deterministic Mode' : '⚡ Hybrid Engine'}
          </span>
        </div>
      </div>

      {result.ai_judge_notes && result.ai_judge_notes.length > 0 ? (
        <section className="card advisory-card" aria-labelledby="advisory-title" style={{ marginTop: 12 }}>
          <div className="card__header" style={{ paddingBottom: 8 }}>
            <span className="step-index" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#eab308', borderColor: 'rgba(234, 179, 8, 0.3)' }}>
              AI
            </span>
            <div>
              <h2 className="card__title" id="advisory-title" style={{ fontSize: 14 }}>
                AI Judge Advisory Observations
              </h2>
              <p className="card__desc">
                {result.trust_tier === 'deterministic'
                  ? 'Deterministic-Only Mode is active: the Pass 1 AST verdict is locked and strictly authoritative. The following LPU observations are provided as advisory annotations.'
                  : 'Contextual triage observations from the Pass 2 AI Judge.'}
              </p>
            </div>
          </div>
          <div className="card__body" style={{ paddingTop: 0 }}>
            <ul className="advisory-list">
              {result.ai_judge_notes.map((note, i) => (
                <li key={i} className="advisory-item">
                  <span className="advisory-bullet">•</span>
                  <span className="advisory-text">{note}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      ) : null}

      {result.verdict !== 'Correct' ? <SanitizedBox result={result} roeId={activeScope?.roe_id} /> : null}

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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <p className="section-label">Detected commands</p>
              <span className="muted font-xs mono">Phase 4.5 Micro-Sandbox Dry-Run</span>
            </div>
            {result.extracted_commands.length ? (
              <ul className="code-list">
                {result.extracted_commands.map((c, i) => (
                  <li key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <span className="mono" style={{ flex: 1, overflowX: 'auto' }}>{c}</span>
                    <button
                      type="button"
                      className={`btn btn--sm ${sandboxCommand === c ? 'btn--primary' : 'btn--ghost'} row`}
                      style={{ padding: '3px 8px', fontSize: 11, gap: 4, flexShrink: 0 }}
                      onClick={() => setSandboxCommand((prev) => (prev === c ? null : c))}
                      title="Dry-run command in network-egress disabled micro-sandbox"
                    >
                      <TerminalIcon width={11} height={11} />
                      {sandboxCommand === c ? 'Close' : 'Dry-Run'}
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No commands detected.</p>
            )}

            {sandboxCommand && (
              <MicroSandboxConsole
                command={sandboxCommand}
                roeId={activeScope?.roe_id}
                onClose={() => setSandboxCommand(null)}
              />
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
              Demo mode: client-side preview of the deterministic engine. The authoritative FastAPI engine and Claude Haiku rewriter
              are active in Live mode.
            </p>
          ) : null}

          {/* Phase 4.4: Cryptographic RoE Attestation Export */}
          <div
            className="attestation-box"
            style={{
              padding: '14px 18px',
              background: 'var(--surface-sunken)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div
                  style={{
                    width: 34,
                    height: 34,
                    borderRadius: 6,
                    background: 'rgba(98, 114, 240, 0.15)',
                    display: 'grid',
                    placeItems: 'center',
                    color: 'var(--accent)',
                    border: '1px solid rgba(98, 114, 240, 0.3)',
                  }}
                >
                  <ShieldIcon width={18} height={18} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <strong style={{ fontSize: 13.5, letterSpacing: '-0.01em' }}>
                      Formal RoE Compliance Attestation
                    </strong>
                    <span className="tag tag--ok" style={{ fontSize: 10, padding: '1px 6px' }}>
                      SHA-256 Chained
                    </span>
                  </div>
                  <p className="muted" style={{ fontSize: 12, margin: '2px 0 0' }}>
                    SOC 2 (CC6.1/7.2), ISO 27001, and CREST-certified engagement non-repudiation report.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  id="export-attestation-pdf-btn"
                  className="btn btn--sm btn--primary row"
                  style={{ gap: 6 }}
                  onClick={() => handleExportReport('pdf')}
                  disabled={exportingFormat !== null}
                  title="Download signed, client-ready PDF attestation report"
                >
                  <DownloadIcon width={13} height={13} />
                  {exportingFormat === 'pdf' ? 'Generating PDF...' : 'Attestation Report (PDF)'}
                </button>
                <button
                  type="button"
                  id="export-attestation-md-btn"
                  className="btn btn--sm row"
                  style={{ gap: 6 }}
                  onClick={() => handleExportReport('markdown')}
                  disabled={exportingFormat !== null}
                  title="Download attestation report in GitHub-flavored Markdown"
                >
                  {exportingFormat === 'markdown' ? 'Generating...' : 'Markdown'}
                </button>
                <button
                  type="button"
                  id="export-attestation-json-btn"
                  className="btn btn--sm btn--ghost"
                  onClick={() => handleExportReport('json')}
                  disabled={exportingFormat !== null}
                  title="Download raw hash chain ledger as JSON"
                >
                  {exportingFormat === 'json' ? 'Exporting...' : 'JSON'}
                </button>
              </div>
            </div>

            {exportError && (
              <div className="alert alert--bad" style={{ fontSize: 12, padding: '8px 12px' }}>
                {exportError}
              </div>
            )}
          </div>

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

function SanitizedBox({ result, roeId }: { result: AuditResult; roeId?: string }) {
  const [copied, setCopied] = useState(false);
  const [showDiff, setShowDiff] = useState(true);
  const [diffMode, setDiffMode] = useState<'split' | 'unified'>('split');
  const [sandboxOpen, setSandboxOpen] = useState(false);
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
          <button
            type="button"
            id="dry-run-sandbox-btn"
            className={`btn btn--sm ${sandboxOpen ? 'btn--primary' : ''} row`}
            style={{ gap: 6 }}
            onClick={() => setSandboxOpen((s) => !s)}
            title="Dry-run sanitized command in network-egress disabled ephemeral micro-sandbox"
          >
            <TerminalIcon width={13} height={13} />
            {sandboxOpen ? 'Close Sandbox' : 'Dry-Run Micro-Sandbox'}
          </button>
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

        {sandboxOpen && (
          <MicroSandboxConsole command={safe} roeId={roeId} onClose={() => setSandboxOpen(false)} />
        )}

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

function MicroSandboxConsole({
  command,
  roeId,
  onClose,
}: {
  command: string;
  roeId?: string;
  onClose: () => void;
}) {
  const [running, setRunning] = useState(true);
  const [result, setResult] = useState<SandboxDryRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setRunning(true);
    setError(null);
    executeSandboxDryRun(command, roeId)
      .then((res) => {
        if (active) {
          setResult(res);
          setRunning(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err?.message || 'Dry-run evaluation failed');
          setRunning(false);
        }
      });
    return () => {
      active = false;
    };
  }, [command, roeId]);

  return (
    <div
      className="sandbox-console card"
      style={{
        marginTop: 14,
        background: '#0a0d14',
        border: '1px solid var(--border-s)',
        borderRadius: 'var(--radius)',
        overflow: 'hidden',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.45)',
      }}
    >
      {/* Console Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          background: 'rgba(255, 255, 255, 0.03)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ff5f56', display: 'inline-block' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ffbd2e', display: 'inline-block' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#27c93f', display: 'inline-block' }} />
          </div>
          <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: '#e6edf3', letterSpacing: '-0.01em' }}>
            vallum-sandbox (isolated-dry-run)
          </span>
          <span
            className="tag tag--ok mono"
            style={{ fontSize: 10, padding: '1px 6px', background: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}
          >
            EGRESS: DISABLED
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {result && (
            <span
              className={`mono font-xs ${result.syntax_valid ? 'tag tag--ok' : 'tag tag--bad'}`}
              style={{ fontSize: 11 }}
            >
              {result.syntax_valid ? `✓ Valid Syntax (Exit ${result.exit_code})` : `✗ Syntax Error (Exit ${result.exit_code})`}
            </span>
          )}
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={onClose}
            style={{ padding: '2px 8px', fontSize: 11 }}
          >
            Close ✕
          </button>
        </div>
      </div>

      {/* Console Body */}
      <div style={{ padding: '14px 16px' }}>
        {running ? (
          <div style={{ padding: '18px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
            <span className="spinner" style={{ width: 16, height: 16, display: 'inline-block', marginBottom: 8 }} />
            <div className="mono font-xs">Decomposing AST and pre-checking CLI grammar in micro-sandbox...</div>
          </div>
        ) : error ? (
          <div className="alert alert--bad" style={{ fontSize: 12 }}>
            {error}
          </div>
        ) : result ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Diagnostics */}
            {result.diagnostics.length > 0 && (
              <div
                style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: 4,
                  padding: '8px 12px',
                }}
              >
                <span className="mono font-xs" style={{ color: 'var(--text-subtle)', display: 'block', marginBottom: 4 }}>
                  Pre-Flight Diagnostics:
                </span>
                <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11.5 }}>
                  {result.diagnostics.map((d, i) => (
                    <li key={i} className="mono" style={{ color: d.includes('Error') ? 'var(--bad-fg)' : 'var(--text-muted)' }}>
                      {d}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Terminal Screen */}
            <div
              style={{
                background: '#040711',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: 4,
                padding: '12px 14px',
                fontFamily: 'var(--font-mono)',
                fontSize: 11.5,
                lineHeight: 1.55,
                overflowX: 'auto',
                maxHeight: 260,
              }}
            >
              {result.simulated_stdout && (
                <pre style={{ margin: 0, color: '#a5d6ff', whiteSpace: 'pre-wrap' }}>
                  {result.simulated_stdout}
                </pre>
              )}
              {result.simulated_stderr && (
                <pre style={{ margin: '8px 0 0', color: '#ff7b72', whiteSpace: 'pre-wrap' }}>
                  {result.simulated_stderr}
                </pre>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, color: 'var(--text-subtle)' }}>
              <span className="mono">0 packets released to host/network interfaces</span>
              <span className="mono">Virtual sandbox elapsed: {result.elapsed_ms}ms</span>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

