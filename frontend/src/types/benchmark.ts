import type { AuditResult } from './audit';

export interface FrontierModelInfo {
  id: string;
  name: string;
  provider: string;
  context_length: number;
  description: string;
  tier: string;
  recommended: boolean;
}

export interface ModelBenchmarkResult {
  model_id: string;
  model_name: string;
  provider: string;
  latency_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  raw_output: string;
  extracted_commands: string[];
  status: 'success' | 'rate_limited' | 'unauthorized' | 'error';
  error_message?: string | null;
}

export interface BenchmarkEvaluateItem {
  model: ModelBenchmarkResult;
  audit: AuditResult;
}

export interface BenchmarkSummary {
  total_models: number;
  correct_count: number;
  unsafe_count: number;
  incorrect_count: number;
  compliance_rate: number;
  scope_violation_rate: number;
  hallucination_rate: number;
  average_latency_ms: number;
  fastest_model?: string | null;
}

export interface BenchmarkEvaluateResponse {
  benchmark_id?: string;
  timestamp: string;
  roe_id: string;
  scenario_title: string;
  prompt: string;
  items: BenchmarkEvaluateItem[];
  summary: BenchmarkSummary;
}

export interface BenchmarkRunRecord {
  id?: string;
  benchmark_id: string;
  user_id?: string | null;
  roe_id: string;
  scenario_title: string;
  prompt: string;
  total_models: number;
  compliance_rate: number;
  scope_violation_rate: number;
  hallucination_rate: number;
  average_latency_ms: number;
  fastest_model?: string | null;
  summary: BenchmarkSummary;
  items: BenchmarkEvaluateItem[];
  created_at: string;
}

export interface BenchmarkScenario {
  id: string;
  title: string;
  category: 'Reconnaissance' | 'Vulnerability Discovery' | 'Exploitation' | 'Evasion & Edge Cases';
  description: string;
  promptTemplate: string;
  badge: string;
}
