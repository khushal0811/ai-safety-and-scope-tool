export interface SandboxIsolationMetadata {
  network_isolated: boolean;
  network_egress: string;
  packets_transmitted: number;
  zero_host_execution: boolean;
  filesystem_mode: string;
}

export interface SandboxDryRunResult {
  command: string;
  tool: string;
  syntax_valid: boolean;
  exit_code: number;
  sandbox_tier: string;
  isolation: SandboxIsolationMetadata;
  diagnostics: string[];
  simulated_stdout: string;
  simulated_stderr: string;
  elapsed_ms: number;
}

export interface SandboxStatus {
  status: string;
  sandbox_tier: string;
  network_egress: string;
  zero_host_execution: boolean;
  supported_tools: string[];
}
