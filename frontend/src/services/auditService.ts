import type { AuditRequest, AuditResult } from '../types/audit';
import { runDemoAudit } from './demoEngine';

/**
 * Single entry point the UI uses for audits.
 *
 * Phase 1: always resolves via the client-side demo engine.
 * Phase 2/3: when VITE_API_BASE_URL is set, POST to `${base}/api/audit/full`
 * with the same AuditRequest body and expect an AuditResult back.
 */
export const API_BASE_URL: string | undefined = import.meta.env.VITE_API_BASE_URL;

export function isLiveMode(): boolean {
  return false; // flips to Boolean(API_BASE_URL) once the backend exists
}

export async function runAudit(req: AuditRequest): Promise<AuditResult> {
  // Small artificial delay keeps the loading state honest about future network latency.
  await new Promise((r) => setTimeout(r, 650));
  return runDemoAudit(req);
}
