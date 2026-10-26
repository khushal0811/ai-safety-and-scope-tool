import type { AuditResult } from './audit';

export interface PastAudit {
  id: string;
  timestamp: string;
  roeId: string;
  roeName: string;
  modelId: string;
  modelName: string;
  prompt: string;
  proposedCommand: string;
  executionTimeMs: number;
  result: AuditResult;
}
