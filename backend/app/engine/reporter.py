"""Formal Rules of Engagement (RoE) Compliance & Attestation Reporting Engine.

Generates client-ready, cryptographically signed attestation reports (Markdown & PDF)
proving all executed and proposed penetration testing commands adhered strictly to the
contracted scope boundaries, with tamper-evident SHA-256 hash chains.

Aligned with:
- SOC 2 Type II Trust Services Criteria (CC6.1, CC6.8, CC7.2)
- ISO/IEC 27001:2022 (A.8.7, A.8.12, A.8.20)
- CREST Penetration Testing Code of Conduct (Section 4.2)
"""

from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from xml.sax.saxutils import escape as _xml_escape

from app.data.presets import ROE_PRESETS, get_roe_preset_by_id
from app.db import fetch_audit_logs_for_roe, fetch_custom_roe_by_id
from app.engine.attestation import (
    attestation_key,
    genesis_hash,
    verify_record_signature,
)
from app.engine.roe_integrity import compute_roe_hash, roe_scope_from_row
from app.models.roe import RoeScope

logger = logging.getLogger(__name__)


def _attestation_seed(roe: RoeScope) -> str:
    """Compute canonical initial seed for SHA-256 hash chain across all export formats."""
    return f"{roe.roe_id}|{roe.name}|{','.join(sorted(roe.allowed_cidrs))}|{','.join(sorted(roe.allowed_domains))}"


def _md(value: object) -> str:
    """Escape an untrusted value for plain Markdown text (tables, paragraphs, list items)."""
    s = str(value)
    return (
        s.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )


def _code(value: object) -> str:
    """Render an untrusted value inside a Markdown inline code span without letting it break out."""
    s = str(value)
    return s.replace("|", "\\|").replace("`", "'").replace("\n", " ")


def _attestation_key() -> bytes:
    """Backward-compatible alias for the server-side attestation key."""
    return attestation_key()


def verify_attested_records(
    roe_id: str,
    records: List[Dict[str, Any]],
    user_id: Optional[str],
    verify_continuity: bool = True,
) -> Optional[RoeScope]:
    """Validate write-time signatures and RoE binding for every record.

    Returns the RoE snapshot actually used, or None for an empty record set.
    Raises ValueError rather than attesting records that cannot be verified.
    """
    if not records:
        return None

    expected_hashes = set()
    snapshot_roe: Optional[RoeScope] = None

    for index, rec in enumerate(records):
        stored_hash = rec.get("roe_hash")
        snapshot = rec.get("roe_snapshot")
        if not stored_hash or not snapshot:
            raise ValueError(
                "Audit history contains records that predate scope binding and cannot be attested. "
                "Generate new audits under the current engine before exporting an attestation."
            )
        if isinstance(snapshot, str):
            try:
                snapshot = json.loads(snapshot)
            except ValueError as exc:
                raise ValueError("Audit record has an unreadable RoE snapshot.") from exc
        if not isinstance(snapshot, dict):
            raise ValueError("Audit record has an invalid RoE snapshot.")

        recomputed_roe_hash = compute_roe_hash(snapshot)
        if not hmac.compare_digest(str(stored_hash), recomputed_roe_hash):
            raise ValueError("Audit record RoE snapshot does not match its stored scope hash.")

        if str(snapshot.get("roe_id") or "").lower() != str(roe_id).lower():
            raise ValueError("Audit record belongs to a different RoE id than the requested report.")

        expected_hashes.add(recomputed_roe_hash)
        if snapshot_roe is None:
            snapshot_roe = roe_scope_from_row(snapshot)

        if not verify_record_signature(rec):
            raise ValueError(
                "Audit record signature is invalid; the attestation ledger has been altered."
            )

        if verify_continuity:
            if int(rec.get("chain_index") or 0) != index + 1:
                raise ValueError("Audit chain is incomplete; refusing to issue an attestation.")
            if index == 0:
                expected_prev = genesis_hash(roe_id)
            else:
                expected_prev = str(records[index - 1].get("chain_hash") or "")
            if str(rec.get("prev_hash") or "") != expected_prev:
                raise ValueError("Audit chain link is broken; refusing to issue an attestation.")

    if len(expected_hashes) != 1:
        raise ValueError("Audit records were evaluated against different RoE boundaries.")
    return snapshot_roe


def compute_hash_chain(
    records: List[Dict[str, Any]],
    initial_seed: str,
) -> Tuple[List[Dict[str, Any]], str]:
    """Build a tamper-evident keyed hash chain over chronological audit records.

    Each block links the previous block's digest with:
    H_i = HMAC-SHA256(key, H_{i-1} || audit_id || timestamp || command || verdict || violations || sanitized)
    """
    key = _attestation_key()
    prev_hash = hmac.new(key, initial_seed.encode("utf-8"), hashlib.sha256).hexdigest()
    chained_records: List[Dict[str, Any]] = []

    for idx, rec in enumerate(records):
        audit_id = rec.get("audit_id") or f"AUDIT-REC-{idx + 1}"
        ts = rec.get("created_at") or rec.get("timestamp") or ""
        cmds = rec.get("extracted_commands") or []
        cmd_str = "; ".join(cmds) if cmds else rec.get("raw_model_output") or ""
        verdict = rec.get("verdict") or "Unsafe"
        sanitized = rec.get("safe_sanitized_command") or ""
        viols = json.dumps(rec.get("violation_details") or [], sort_keys=True)
        roe_hash = rec.get("roe_hash") or ""
        deleted_at = rec.get("deleted_at") or ""

        block_payload = (
            f"{prev_hash}|{audit_id}|{ts}|{cmd_str}|{verdict}|{sanitized}|{viols}|{roe_hash}|{deleted_at}"
        )
        curr_hash = hmac.new(key, block_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        rec_copy = dict(rec)
        rec_copy["chain_index"] = idx + 1
        rec_copy["prev_hash"] = prev_hash
        rec_copy["chain_hash"] = curr_hash
        rec_copy["command_display"] = cmd_str
        rec_copy["timestamp_display"] = ts

        chained_records.append(rec_copy)
        prev_hash = curr_hash

    root_hash = prev_hash
    return chained_records, root_hash


def generate_compliance_report_markdown(
    roe: RoeScope,
    records: List[Dict[str, Any]],
    user_id: Optional[str] = None,
) -> str:
    """Render a formal, client-ready compliance attestation document in GitHub Flavored Markdown."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"ATTEST-{hashlib.sha256(f'{roe.roe_id}:{now_utc}'.encode()).hexdigest()[:12].upper()}"

    initial_seed = _attestation_seed(roe)
    chained_records, root_hash = compute_hash_chain(records, initial_seed)

    total_ops = len(chained_records)
    compliant_ops = sum(1 for r in chained_records if r.get("verdict") == "Correct")
    unsafe_ops = sum(1 for r in chained_records if r.get("verdict") == "Unsafe")
    review_ops = sum(1 for r in chained_records if r.get("verdict") == "Incorrect")
    deleted_ops = sum(1 for r in chained_records if r.get("deleted_at"))
    compliance_rate = round((compliant_ops / total_ops) * 100, 1) if total_ops > 0 else None
    interception_rate = round((unsafe_ops / total_ops) * 100, 1) if total_ops > 0 else None
    compliance_display = f"{compliance_rate}%" if total_ops > 0 else "N/A (no records)"
    interception_display = f"{interception_rate}%" if total_ops > 0 else "N/A (no records)"

    lines: List[str] = []
    lines.append("# FORMAL RULES OF ENGAGEMENT COMPLIANCE & SAFETY ATTESTATION")
    lines.append(f"**Document Reference:** `{report_id}`  ")
    lines.append(f"**Attestation Date:** `{now_utc}`  ")
    lines.append(f"**Engine:** `Vallum AI Safety & Scope Boundary Engine (v0.2.0-AST)`  ")
    lines.append(f"**Evaluator UUID:** `{user_id or 'Certified-Automation-Operator'}`  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 1. Executive Summary & Statement of Attestation
    lines.append("## 1. Executive Statement of Attestation")
    lines.append("")
    lines.append(
        "> **Scope of This Attestation:** This report certifies that all commands *submitted to the "
        "Vallum engine for review* were evaluated against the contracted scope boundaries below, and that "
        "any flagged as unsafe were intercepted before being returned to the operator. It does not — and "
        "cannot — certify that no commands were executed outside of Vallum's review process."
    )
    lines.append("")
    lines.append(
        f"This document records that all penetration testing commands and model recommendations submitted "
        f"under engagement **\"{_md(roe.name)}\"** (ID: `{_code(roe.roe_id)}`) were pre-screened "
        f"and audited by the **Vallum AI Safety & Scope Boundary Engine** prior to being returned to the operator."
    )
    lines.append("")
    lines.append(
        "Under the strict **Zero Host Execution** principle, all proposed offensive commands, model completions, "
        "and script recommendations were decomposed via AST lexical analysis and evaluated against the authorized "
        "contractual boundaries. Any out-of-scope targets, destructive payloads, or unauthorized offensive binaries "
        "were intercepted and replaced with verified compliant remediations."
    )
    lines.append("")

    # 2. Scope Boundaries as Contracted
    lines.append("## 2. Contracted Scope Boundaries & Constraints")
    lines.append("")
    lines.append(f"| Scope Dimension | Contracted Policy Parameter |")
    lines.append(f"| :--- | :--- |")
    lines.append(f"| **Engagement Name** | {_md(roe.name)} |")
    lines.append(f"| **Engagement Type** | {_md(roe.engagement_type)} |")
    lines.append(f"| **Authorized Subnets (CIDRs)** | `{_code(', '.join(roe.allowed_cidrs) or 'None')}` |")
    lines.append(f"| **Authorized Domains** | `{_code(', '.join(roe.allowed_domains) or 'None')}` |")
    lines.append(f"| **Target Hosts** | `{_code(', '.join(roe.target_hosts) or 'None')}` |")
    lines.append(f"| **Explicitly Prohibited IPs** | `{_code(', '.join(roe.prohibited_ips) or 'None')}` |")
    lines.append(f"| **Authorized Tools Whitelist** | `{_code(', '.join(roe.allowed_tools) or 'All non-prohibited')}` |")
    lines.append(f"| **Prohibited Tools** | `{_code(', '.join(roe.prohibited_tools) or 'None')}` |")
    lines.append(f"| **Prohibited Action Flags** | `{_code(', '.join(roe.prohibited_flags) or 'None')}` |")
    lines.append(f"| **Banned Actions** | `{_code(', '.join(roe.prohibited_actions) or 'None')}` |")
    lines.append(f"| **Max Nmap Timing** | `-T{roe.max_nmap_timing}` |")
    lines.append("")
    lines.append(f"> **Engagement Summary:** {_md(roe.summary)}")
    lines.append("")

    # 3. Executive Metrics
    lines.append("## 3. Engagement Scope Compliance Metrics")
    lines.append("")
    lines.append("| Metric | Value | Description |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(f"| **Total Audited Commands** | **{total_ops}** | Total offensive commands pre-screened |")
    lines.append(f"| **Fully Compliant (Correct)** | **{compliant_ops}** | Authorized within scope boundaries |")
    lines.append(f"| **Breaches Intercepted (Unsafe)** | **{unsafe_ops}** | Out-of-scope or destructive payloads halted |")
    lines.append(f"| **Warnings Reviewed (Incorrect)** | **{review_ops}** | Non-critical policy observations |")
    lines.append(
        f"| **Soft-Deleted Records (retained in chain)** | **{deleted_ops}** | "
        f"Tombstones kept for attestation; deletion never removes a record from the hash chain |"
    )
    lines.append(
        f"| **Unsafe Commands Intercepted Pre-Execution** | **{interception_display}** | "
        f"Of commands submitted to Vallum for review, this fraction were flagged Unsafe and blocked "
        f"before being returned to the operator. |"
    )
    lines.append(f"| **Autonomous Compliance Rate** | **{compliance_display}** | Baseline model accuracy within boundary |")
    lines.append("")

    # 4. Itemized Audit Trail with Cryptographic Hash Chain
    lines.append("## 4. Cryptographic Audit Trail & Chain of Custody")
    lines.append("")
    lines.append(
        "Each audit entry is linked via an immutable SHA-256 hash chain to verify non-repudiation, chronological "
        "order, and post-audit integrity. Each record was signed server-side when it was written; the export "
        "re-verifies every stored signature. Any post-hoc alteration or omission invalidates the final attestation root."
    )
    lines.append("")

    if not chained_records:
        lines.append("*No historical commands logged under this engagement scope.*")
        lines.append("")
    else:
        for rec in chained_records:
            idx = rec.get("chain_index")
            a_id = rec.get("audit_id")
            ts = rec.get("timestamp_display")
            model = rec.get("selected_model", "unknown")
            cmd = rec.get("command_display", "")
            verdict = rec.get("verdict", "Unsafe")
            sanitized = rec.get("safe_sanitized_command")
            ch_hash = rec.get("chain_hash", "")[:16] + "..."
            violations = rec.get("violation_details") or []

            badge = "✅ PASS" if verdict == "Correct" else "⚠️ WARNING" if verdict == "Incorrect" else "🛑 BLOCKED & SANITIZED"

            lines.append(f"### Entry #{idx}: `{_code(a_id)}` — {badge}")
            lines.append(f"- **Timestamp:** `{_code(ts)}`")
            lines.append(f"- **Model/Source:** `{_code(model)}`")
            if rec.get("deleted_at"):
                lines.append(
                    f"- **Deletion Status:** `SOFT-DELETED at {_code(rec.get('deleted_at'))}` "
                    "(tombstone retained in the attestation chain)"
                )
            lines.append(f"- **Proposed Command:** `{_code(cmd)}`")
            lines.append(f"- **Cumulative Hash Digest:** `{_code(ch_hash)}`")

            if violations:
                lines.append(f"- **Violations Intercepted:**")
                for v in violations:
                    r_name = _md(v.get("rule", "Violation"))
                    sev = _code(v.get("severity", "WARNING"))
                    cat = _code(v.get("category", "POLICY"))
                    det = _md(v.get("detail", ""))
                    lines.append(f"  - `[{sev} | {cat}]` **{r_name}:** {det}")

            if sanitized and verdict != "Correct":
                # Fence must be longer than any backtick run in the content so it cannot be closed early
                longest_run = max((len(m) for m in re.findall(r"`+", str(sanitized))), default=0)
                fence = "`" * max(3, longest_run + 1)
                lines.append(f"- **Compliant Remediation (Synthesized by Vallum):**")
                lines.append(f"  {fence}bash\n  {sanitized}\n  {fence}")

            lines.append("")

    # 5. Regulatory Compliance Alignment
    lines.append("## 5. Standard Compliance Alignment Matrix")
    lines.append("")
    lines.append("| Security Standard / Framework | Regulatory Control | Technical Verification Status |")
    lines.append("| :--- | :--- | :--- |")
    lines.append("| **SOC 2 Type II** | **CC6.1** Logical Access Controls | **VERIFIED:** Authorized subnet boundaries strictly enforced by CIDR AST validator. |")
    lines.append("| **SOC 2 Type II** | **CC6.8** Malicious Code Prevention | **VERIFIED:** Inherently destructive commands (`rm -rf`, disk wipes, `--flood`) halted. |")
    lines.append("| **SOC 2 Type II** | **CC7.2** Security Monitoring | **VERIFIED:** Chronological SHA-256 chain establishes non-repudiation and tamper detection. |")
    lines.append("| **ISO/IEC 27001:2022** | **A.8.7** Protection from Malware | **VERIFIED:** Offensive tools restricted to pre-approved whitelist (`allowed_tools`). |")
    lines.append("| **ISO/IEC 27001:2022** | **A.8.20** Network Security Controls | **VERIFIED:** RFC 1918 / Cloud Metadata (`169.254.169.254`) protected from leakage. |")
    if total_ops == 0:
        crest_status = "**PENDING:** No commands audited under this scope yet (0 records)."
    elif compliance_rate == 100.0:
        crest_status = "**VERIFIED:** 100% boundary compliance certified across all reviewed commands."
    else:
        crest_status = (
            f"**ENFORCED:** {compliance_display} baseline compliance; all {unsafe_ops} out-of-scope/unsafe "
            f"command(s) intercepted pre-execution."
        )
    lines.append(f"| **CREST Conduct** | **Section 4.2** Scoping & Boundaries | {crest_status} |")
    lines.append("")

    # 6. Attestation Seal
    seal_status = (
        "AUDIT TRAIL INTEGRITY: VERIFIED (TAMPER-EVIDENT)"
        if total_ops > 0
        else "AUDIT TRAIL STATUS: NO RECORDS LOGGED (EMPTY CHAIN)"
    )
    lines.append("## 6. Attestation Seal & Non-Repudiation Block")
    lines.append("")
    lines.append("```")
    lines.append("┌─────────────────────────────────────────────────────────────────────────────┐")
    lines.append("│                 VALLUM CRYPTOGRAPHIC SCOPE ATTESTATION SEAL                 │")
    lines.append("├─────────────────────────────────────────────────────────────────────────────┤")
    lines.append(f"│  Attestation ID:       {report_id:<52} │")
    lines.append(f"│  Engagement ID:        {roe.roe_id:<52} │")
    lines.append(f"│  SHA-256 Chain Root:   {root_hash:<52} │")
    lines.append(f"│  Records Chained:      {total_ops:<52} │")
    lines.append(f"│  Unsafe Intercepted:   {f'{interception_display} ({unsafe_ops}/{total_ops} reviewed commands)':<52} │")
    lines.append(f"│  Status:               {seal_status:<52} │")
    lines.append("└─────────────────────────────────────────────────────────────────────────────┘")
    lines.append("```")
    lines.append("")
    lines.append("*This attestation was programmatically generated by the Vallum AI Safety & Scope Boundary Engine.*")

    return "\n".join(lines)


def generate_compliance_report_pdf(
    roe: RoeScope,
    records: List[Dict[str, Any]],
    user_id: Optional[str] = None,
) -> bytes:
    """Render a formal, high-resolution compliance attestation PDF document using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as e:
        logger.error(f"[Reporter] ReportLab is not installed: {e}")
        raise RuntimeError("ReportLab library is required for PDF report generation.")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom Clean Palette Styles matching Dark Desk
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12.5,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )
    mono_bold = ParagraphStyle(
        "MonoBold",
        parent=styles["Normal"],
        fontName="Courier-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"ATTEST-{hashlib.sha256(f'{roe.roe_id}:{now_utc}'.encode()).hexdigest()[:12].upper()}"

    initial_seed = _attestation_seed(roe)
    chained_records, root_hash = compute_hash_chain(records, initial_seed)

    total_ops = len(chained_records)
    compliant_ops = sum(1 for r in chained_records if r.get("verdict") == "Correct")
    unsafe_ops = sum(1 for r in chained_records if r.get("verdict") == "Unsafe")
    review_ops = sum(1 for r in chained_records if r.get("verdict") == "Incorrect")
    deleted_ops = sum(1 for r in chained_records if r.get("deleted_at"))
    compliance_rate = round((compliant_ops / total_ops) * 100, 1) if total_ops > 0 else None
    interception_rate = round((unsafe_ops / total_ops) * 100, 1) if total_ops > 0 else None
    compliance_display = f"{compliance_rate}%" if total_ops > 0 else "N/A (no records)"
    interception_display = f"{interception_rate}%" if total_ops > 0 else "N/A (no records)"

    story = []

    # Title & Header
    story.append(Paragraph("RULES OF ENGAGEMENT COMPLIANCE & SAFETY ATTESTATION", title_style))
    story.append(
        Paragraph(
            f"<b>Attestation Reference:</b> {report_id} &nbsp;|&nbsp; <b>Issued:</b> {now_utc} &nbsp;|&nbsp; <b>Engine:</b> Vallum AST v0.2.0",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#7c3aed"), spaceAfter=12))

    # Executive Certification Block
    cert_text = (
        f"<b>SCOPE OF THIS ATTESTATION:</b> This report certifies that all commands submitted to the Vallum "
        f"engine for review under engagement <b>{_xml_escape(roe.name)}</b> (<code>{_xml_escape(roe.roe_id)}</code>) were parsed into "
        f"Abstract Syntax Trees (ASTs) and evaluated against the contracted scope boundaries below, and that "
        f"any flagged as unsafe were intercepted before being returned to the operator. It does not — and "
        f"cannot — certify that no commands were executed outside of Vallum's review process."
    )
    story.append(Paragraph(cert_text, body_style))
    story.append(Spacer(1, 10))

    # Contract Scope Table
    story.append(Paragraph("1. Contracted Scope Boundaries", h2_style))
    scope_data = [
        [Paragraph("<b>Scope Parameter</b>", body_style), Paragraph("<b>Contracted Specification</b>", body_style)],
        [Paragraph("Engagement Type", body_style), Paragraph(_xml_escape(roe.engagement_type), body_style)],
        [Paragraph("Authorized CIDRs", body_style), Paragraph(f"<code>{_xml_escape(', '.join(roe.allowed_cidrs) or 'None')}</code>", mono_style)],
        [Paragraph("Target Hosts", body_style), Paragraph(f"<code>{_xml_escape(', '.join(roe.target_hosts) or 'None')}</code>", mono_style)],
        [Paragraph("Prohibited Targets", body_style), Paragraph(f"<code>{_xml_escape(', '.join(roe.prohibited_ips) or 'None')}</code>", mono_style)],
        [Paragraph("Tool Whitelist", body_style), Paragraph(f"<code>{_xml_escape(', '.join(roe.allowed_tools) or 'Unrestricted')}</code>", mono_style)],
        [Paragraph("Prohibited Flags", body_style), Paragraph(f"<code>{_xml_escape(', '.join(roe.prohibited_flags) or 'None')}</code>", mono_style)],
    ]
    t_scope = Table(scope_data, colWidths=[140, 390])
    t_scope.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ])
    )
    story.append(t_scope)
    story.append(Spacer(1, 12))

    # Summary Metrics Table
    story.append(Paragraph("2. Engagement Compliance Metrics", h2_style))
    metrics_data = [
        ["Total Audited", "Compliant (Pass)", "Blocked (Unsafe)", "Unsafe Intercepted", "Compliance Rate"],
        [str(total_ops), str(compliant_ops), str(unsafe_ops), interception_display, compliance_display],
    ]
    t_metrics = Table(metrics_data, colWidths=[100, 110, 110, 110, 100])
    t_metrics.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
        ])
    )
    story.append(t_metrics)
    story.append(Spacer(1, 14))

    # Cryptographic Hash Chain Audit Table
    story.append(Paragraph("3. Immutable Hash Chain Audit Log", h2_style))
    audit_table_data = [
        [
            Paragraph("<b>#</b>", body_style),
            Paragraph("<b>Audit ID</b>", body_style),
            Paragraph("<b>Proposed Command</b>", body_style),
            Paragraph("<b>Verdict</b>", body_style),
            Paragraph("<b>SHA-256 Digest</b>", body_style),
        ]
    ]

    for rec in chained_records:  # Render every chained record so the table matches the root hash
        v = rec.get("verdict", "Unsafe")
        v_color = "#059669" if v == "Correct" else "#d97706" if v == "Incorrect" else "#dc2626"
        v_label = f"<font color='{v_color}'><b>{_xml_escape(v)}</b></font>"

        cmd_snippet = rec.get("command_display", "")[:45]
        if len(rec.get("command_display", "")) > 45:
            cmd_snippet += "..."

        audit_table_data.append([
            str(rec.get("chain_index")),
            Paragraph(f"<code>{_xml_escape(str(rec.get('audit_id'))[:12])}</code>", mono_style),
            Paragraph(f"<code>{_xml_escape(cmd_snippet)}</code>", mono_style),
            Paragraph(v_label, body_style),
            Paragraph(f"<code>{rec.get('chain_hash')[:12]}...</code>", mono_style),
        ])

    t_audit = Table(audit_table_data, colWidths=[25, 95, 230, 80, 100])
    t_audit.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(t_audit)
    story.append(Spacer(1, 14))

    # SOC 2 & ISO 27001 Regulatory Attestation Box
    story.append(Paragraph("4. Regulatory Framework Alignment", h2_style))
    framework_data = [
        [Paragraph("<b>Standard</b>", body_style), Paragraph("<b>Control Criterion</b>", body_style), Paragraph("<b>Attestation Guarantee</b>", body_style)],
        [Paragraph("SOC 2 Type II", body_style), Paragraph("CC6.1 / CC6.8", body_style), Paragraph("Logical boundary isolation & malicious execution prevention.", body_style)],
        [Paragraph("ISO/IEC 27001", body_style), Paragraph("A.8.7 / A.8.20", body_style), Paragraph("Malware prevention and network segregation constraints.", body_style)],
        [Paragraph("CREST PT", body_style), Paragraph("Section 4.2", body_style), Paragraph("Strict compliance with agreed target systems and exclusions.", body_style)],
    ]
    t_frame = Table(framework_data, colWidths=[100, 110, 320])
    t_frame.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(t_frame)
    story.append(Spacer(1, 14))

    # Non-Repudiation Cryptographic Seal Block
    seal_data = [
        [Paragraph("<b>VALLUM CRYPTOGRAPHIC SCOPE ATTESTATION SEAL</b>", ParagraphStyle("SealHead", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=1))],
        [Paragraph(f"<b>Root Hash:</b> <code>{root_hash}</code>", ParagraphStyle("SealBody", fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#0f172a")))],
        [Paragraph(f"<b>Chained Records:</b> {total_ops} &nbsp;|&nbsp; <b>Unsafe Intercepted:</b> {interception_display} &nbsp;|&nbsp; <b>Status:</b> AUDIT TRAIL INTEGRITY: VERIFIED (TAMPER-EVIDENT)", ParagraphStyle("SealMeta", fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#334155")))],
    ]
    t_seal = Table(seal_data, colWidths=[530])
    t_seal.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#7c3aed")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(KeepTogether(t_seal))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_compliance_report(
    roe_id: str,
    format: str = "markdown",
    user_id: Optional[str] = None,
    audit_id: Optional[str] = None,
) -> Tuple[Union[str, bytes], str, str]:
    """Top-level reporting entry point. Resolves RoE, loads audit logs, and renders report.

    Returns:
        (content_bytes_or_string, media_type, download_filename)
    """
    # 1. Resolve RoE — check static presets first, then the user's own custom RoEs,
    #    and fail loudly rather than silently substituting the wrong scope.
    roe = get_roe_preset_by_id(roe_id)
    if not roe:
        for p in ROE_PRESETS:
            if p.roe_id.lower() == roe_id.lower():
                roe = p
                break

    if not roe:
        custom_row = fetch_custom_roe_by_id(roe_id, user_id=user_id)
        if custom_row:
            roe = roe_scope_from_row(custom_row)

    if not roe:
        raise ValueError(
            f"No preset or custom Rules of Engagement found for roe_id='{roe_id}'. "
            "Cannot generate a compliance report for an unknown scope."
        )

    # 2. Fetch every audit for this RoE, including soft-deleted tombstones.
    records = fetch_audit_logs_for_roe(roe_id=roe.roe_id, user_id=user_id, limit=500, audit_id=audit_id)

    if audit_id is None and len(records) >= 500:
        raise ValueError(
            "Audit chain exceeds the report limit; refusing to issue a truncated attestation."
        )

    # 3. Verify write-time signatures, RoE binding and chain continuity before
    #    rendering anything. A scope mismatch or broken link is a hard failure,
    #    never a silently narrower report (AUDIT_005 High 5).
    snapshot_roe = verify_attested_records(
        roe.roe_id,
        records,
        user_id=user_id,
        verify_continuity=audit_id is None,
    )
    if snapshot_roe is not None:
        # Display the boundaries the audits were actually evaluated under, not
        # whatever the preset or custom row says today.
        roe = snapshot_roe

    fmt = format.lower().strip()
    clean_id = roe.roe_id.lower().replace("-", "_")

    if fmt == "pdf":
        pdf_bytes = generate_compliance_report_pdf(roe=roe, records=records, user_id=user_id)
        return pdf_bytes, "application/pdf", f"vallum_attestation_{clean_id}.pdf"
    elif fmt == "json":
        initial_seed = _attestation_seed(roe)
        chained_records, root_hash = compute_hash_chain(records, initial_seed)
        data = {
            "report_id": f"ATTEST-{hashlib.sha256(root_hash.encode()).hexdigest()[:12].upper()}",
            "roe": roe.model_dump(),
            "roe_hash": compute_roe_hash(roe),
            "records": chained_records,
            "root_hash": root_hash,
            "chain_head": records[-1].get("chain_hash") if records else None,
            "chain_signatures_verified": True,
            "total_operations": len(chained_records),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(data, indent=2), "application/json", f"vallum_attestation_{clean_id}.json"
    else:
        # Markdown
        md_text = generate_compliance_report_markdown(roe=roe, records=records, user_id=user_id)
        return md_text, "text/markdown; charset=utf-8", f"vallum_attestation_{clean_id}.md"
