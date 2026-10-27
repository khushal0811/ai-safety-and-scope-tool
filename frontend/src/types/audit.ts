/**
 * Shared contracts for Vallum.
 * Field names are snake_case on purpose: they mirror the FastAPI/Pydantic
 * schemas planned for Phase 2 so the demo engine can be swapped for the
 * real API without touching UI components.
 */

export type Verdict = 'Correct' | 'Incorrect' | 'Unsafe';
export type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

/** scope/destructive/policy => Unsafe, accuracy => Incorrect */
export type ViolationCategory = 'scope' | 'destructive' | 'policy' | 'accuracy';

export interface RoeScope {
  roe_id: string;
  name: string;
  engagement_type: string;
  summary: string;
  allowed_cidrs: string[];
  allowed_domains: string[];
  target_hosts: string[];
  /** Individual IPs or CIDR blocks that must never be touched. */
  prohibited_ips: string[];
  allowed_tools: string[];
  prohibited_tools: string[];
  /** Flags / argument substrings that are banned (e.g. `--os-shell`). */
  prohibited_flags: string[];
  prohibited_actions: string[];
  /** Highest permitted nmap timing template (-T0..-T5). */
  max_nmap_timing: number;
}

export interface Violation {
  rule: string;
  category: ViolationCategory;
  severity: Severity;
  detail: string;
  command?: string;
}

export type TargetStatus = 'in_scope' | 'out_of_scope' | 'prohibited';

export interface TargetFinding {
  token: string;
  normalized: string;
  kind: 'ip' | 'cidr' | 'domain';
  status: TargetStatus;
  obfuscated: boolean;
}

export interface AuditRequest {
  roe: RoeScope;
  model_id: string;
  user_prompt: string;
  model_output: string;
}

export interface AuditResult {
  audit_id: string;
  timestamp: string;
  mode: 'demo' | 'live';
  selected_model: string;
  user_prompt: string;
  raw_model_output: string;
  extracted_commands: string[];
  targets: TargetFinding[];
  verdict: Verdict;
  violation_details: Violation[];
  /** null when no safe equivalent exists inside the current scope. */
  safe_sanitized_command: string | null;
  modifications_made: string[];
  explanation: string;
}
