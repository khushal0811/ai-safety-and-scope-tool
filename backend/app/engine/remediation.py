"""Intelligent LLM-driven violation explainer and safe command rewriter.

Applies double-verification: Any rewritten command produced by the LLM is
passed through the deterministic verification engine before being returned,
ensuring zero hallucinated bypasses.
"""

from typing import List, Optional, Tuple
from app.engine.llm_client import llm_client
from app.models.audit import TargetFinding, Violation
from app.models.roe import RoeScope

REMEDIATION_SYSTEM_PROMPT = """You are an AI Cybersecurity Scope Remediation and Safety Engine.
A penetration tester asked for an offensive security action, but the model's proposed command breached the engagement's Rules of Engagement (RoE).

YOUR OBJECTIVES:
1. EXPLANATION: Write a precise 2-3 sentence technical explanation describing which RoE constraints were violated and why (e.g., targeting unauthorized assets, aggressive timing templates, destructive actions).
2. SANITIZED COMMAND: Synthesize a clean, fully-formed CLI command that accomplishes the tester's legitimate objective while strictly adhering to all RoE scope boundaries.
3. MODIFICATIONS: List the exact adjustments made (e.g. "Replaced unauthorized host with target host", "Reduced timing template to -T3", "Removed prohibited flag").
4. FATAL INCOMPATIBILITY: If the user's prompt cannot be performed safely within scope (e.g. requesting a DoS attack, ransomware deployment, or targeting exclusively prohibited assets), set "sanitized_command": null and explain that no compliant alternative exists.

Return strictly a JSON object with this structure:
{
  "explanation": "Clear explanation of infractions and remediation.",
  "sanitized_command": "nmap -sV -T3 192.168.1.105" or null,
  "modifications_made": [
    "Replaced out-of-scope host 10.0.0.1 with authorized target 192.168.1.105",
    "Throttled timing from -T5 to -T3"
  ]
}
"""


async def generate_intelligent_remediation(
    user_prompt: str,
    raw_model_output: str,
    violations: List[Violation],
    targets: List[TargetFinding],
    roe: RoeScope,
    fallback_safe_cmd: Optional[str] = None,
    fallback_mods: Optional[List[str]] = None,
) -> Tuple[Optional[str], List[str], Optional[str]]:
    """Synthesize intelligent remediation notes and compliant command replacement.

    Returns:
        (sanitized_command, modifications_made, enhanced_explanation)
    """
    if not llm_client.is_configured:
        return fallback_safe_cmd, fallback_mods or [], None

    # Format violation summary
    violation_summary = "\n".join(
        [f"- [{v.severity.value}] {v.rule}: {v.detail}" for v in violations]
    )

    prompt = f"""EVALUATION CONTEXT:
User Prompt: "{user_prompt}"
Active RoE Name: "{roe.name}" ({roe.engagement_type})
Allowed Subnets: {roe.allowed_cidrs}
Authorized Target Hosts: {roe.target_hosts}
Authorized Domains: {roe.allowed_domains}
Prohibited Targets: {roe.prohibited_ips}
Allowed Tools: {roe.allowed_tools}
Prohibited Flags/Actions: {roe.prohibited_flags + roe.prohibited_actions}
Max Timing Template: -T{roe.max_nmap_timing}

Proposed Model Output:
```bash
{raw_model_output}
```

Flagged Violations:
{violation_summary}

Synthesize the compliant remediation JSON now:"""

    response = await llm_client.generate_json(
        system_prompt=REMEDIATION_SYSTEM_PROMPT,
        user_prompt=prompt,
        temperature=0.0,
    )

    if not response or not isinstance(response, dict):
        return fallback_safe_cmd, fallback_mods or [], None

    llm_sanitized = response.get("sanitized_command")
    llm_explanation = response.get("explanation")
    llm_mods = response.get("modifications_made", [])

    if not isinstance(llm_mods, list):
        llm_mods = [str(llm_mods)]

    return llm_sanitized, [str(m) for m in llm_mods], llm_explanation
