from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

SEVERITY_ICONS = {"P0": "🔴", "P1": "🟠", "P2": "🟡", "P3": "⚪"}
CATEGORY_ICONS = {
    "auth": "🔐",
    "payment": "💳",
    "secrets": "🔑",
    "injection": "💉",
    "webhook": "🔗",
    "database": "🗄️",
    "crypto": "🔑",
    "infrastructure": "🔧",
    "quality": "📋",
    "xss": "🌐",
}


def generate_audit_report(
    run_id: str,
    summary: dict,
    findings: List[dict],
    ingest: dict,
    config: dict,
    review_brief_path: Optional[Path] = None,
    version: str = "1.0.0",
) -> str:
    """
    Generate comprehensive human-readable audit report.

    This is AUDIT_REPORT.md - the full report for:
    - HITL reviewers
    - Artifact storage (Tier 3)
    - Export/download
    """
    _ = (config, review_brief_path)

    lines = []

    # Header
    lines.extend(
        [
            "# 🛡️ Omar Gate Audit Report",
            "",
            f"**Run ID:** `{run_id}`",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Policy:** {summary.get('policy_pack', 'omar')} v{summary.get('policy_pack_version', '1.0')}",
            f"**Duration:** {summary.get('duration_ms', 0)}ms",
            "",
            "---",
            "",
        ]
    )

    # Executive Summary
    counts = summary.get("counts", {})
    gate_result = "BLOCKED" if counts.get("P0", 0) + counts.get("P1", 0) > 0 else "PASSED"
    gate_icon = "❌" if gate_result == "BLOCKED" else "✅"

    lines.extend(
        [
            "## Executive Summary",
            "",
            f"**Gate Result:** {gate_icon} {gate_result}",
            "",
            "| Severity | Count | Description |",
            "|----------|-------|-------------|",
            f"| {SEVERITY_ICONS['P0']} P0 | {counts.get('P0', 0)} | Critical - Immediate action required |",
            f"| {SEVERITY_ICONS['P1']} P1 | {counts.get('P1', 0)} | High - Action required before merge |",
            f"| {SEVERITY_ICONS['P2']} P2 | {counts.get('P2', 0)} | Medium - Should fix soon |",
            f"| {SEVERITY_ICONS['P3']} P3 | {counts.get('P3', 0)} | Low - Consider fixing |",
            f"| **Total** | **{counts.get('total', 0)}** | |",
            "",
            "---",
            "",
        ]
    )

    # Repository Stats
    stats = ingest.get("stats", {})
    hotspots = ingest.get("hotspots", {})
    hotspot_count = sum(len(files) for files in hotspots.values())

    lines.extend(
        [
            "## Repository Analysis",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Files Scanned | {stats.get('in_scope_files', 0)} |",
            f"| Total Lines | {stats.get('total_lines', 0):,} |",
            f"| Hotspots Identified | {hotspot_count} |",
            f"| Package Manager | {ingest.get('dependencies', {}).get('package_manager', 'unknown')} |",
            "",
        ]
    )

    # Hotspot breakdown
    if any(files for files in hotspots.values()):
        lines.extend(["### Hotspot Categories", ""])
        for category, files in hotspots.items():
            if files:
                icon = CATEGORY_ICONS.get(category, "📁")
                lines.append(f"- {icon} **{category.title()}**: {len(files)} files")
        lines.append("")

    lines.extend(["---", ""])

    # Findings by Severity
    lines.extend(["## Findings Detail", ""])

    for severity in ["P0", "P1", "P2", "P3"]:
        sev_findings = [f for f in findings if f.get("severity") == severity]
        if not sev_findings:
            continue

        icon = SEVERITY_ICONS[severity]
        lines.extend([
            f"### {icon} {severity} Findings ({len(sev_findings)})",
            "",
        ])

        for idx, finding in enumerate(sev_findings, start=1):
            cat_icon = CATEGORY_ICONS.get(str(finding.get("category", "")).lower(), "📋")
            confidence = finding.get("confidence")
            if isinstance(confidence, (int, float)):
                confidence_display = f"{confidence:.0%}"
            else:
                confidence_display = "n/a"

            line_start = finding.get("line_start", 0)
            line_end = finding.get("line_end", line_start)

            lines.extend(
                [
                    f"#### {idx}. {cat_icon} {finding.get('category', 'Unknown')}",
                    "",
                    f"**File:** `{finding.get('file_path', 'unknown')}:{line_start}-{line_end}`",
                    f"**Source:** {finding.get('source', 'unknown')}",
                    f"**Confidence:** {confidence_display}",
                    f"**Fingerprint:** `{finding.get('fingerprint', 'n/a')[:12]}...`",
                    "",
                    f"**Issue:** {finding.get('message', 'No description')}",
                    "",
                ]
            )

            # Snippet (if present and not a secret)
            snippet = finding.get("snippet", "")
            if snippet and str(finding.get("category", "")).lower() != "secrets":
                lines.extend(
                    [
                        "<details>",
                        "<summary>View Code Snippet</summary>",
                        "",
                        "```",
                        snippet[:500] + ("..." if len(snippet) > 500 else ""),
                        "```",
                        "",
                        "</details>",
                        "",
                    ]
                )

            # Recommendation
            if finding.get("recommendation"):
                lines.extend([f"**Recommendation:** {finding.get('recommendation')}", ""])

            lines.append("---")
            lines.append("")

    # If no findings
    if not findings:
        lines.extend(
            [
                "### ✅ No Findings",
                "",
                "No security or quality issues were detected in this scan.",
                "",
                "---",
                "",
            ]
        )

    # Scan Metadata
    lines.extend(
        [
            "## Scan Metadata",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Run ID | `{run_id}` |",
            f"| Dedupe Key | `{summary.get('dedupe_key', 'n/a')[:8]}...` |",
            f"| Policy Pack | {summary.get('policy_pack', 'omar')} |",
            f"| Policy Version | {summary.get('policy_pack_version', '1.0')} |",
            f"| Stages | {', '.join(summary.get('stages_completed', []))} |",
            f"| Duration | {summary.get('duration_ms', 0)}ms |",
            "",
        ]
    )

    # Tool versions
    tool_versions = summary.get("tool_versions", {})
    if tool_versions:
        lines.extend(["### Tool Versions", ""])
        for tool, version in tool_versions.items():
            lines.append(f"- **{tool}:** {version}")
        lines.append("")

    # Errors
    errors = summary.get("errors")
    if not errors and summary.get("error"):
        errors = [summary.get("error")]
    if errors:
        lines.extend(["### Errors & Warnings", ""])
        for error in errors:
            lines.append(f"- ⚠️ {error}")
        lines.append("")

    # Footer
    lines.extend(
        [
            "---",
            "",
            f"<sub>Generated by Omar Gate v{version} | [Request HITL Review](https://sentinelayer.com/hitl)</sub>",
        ]
    )

    return "\n".join(lines)


def write_audit_report(
    run_dir: Path,
    run_id: str,
    summary: dict,
    findings: List[dict],
    ingest: dict,
    config: dict,
    version: str = "1.0.0",
) -> Path:
    """Write AUDIT_REPORT.md to run directory."""
    content = generate_audit_report(
        run_id=run_id,
        summary=summary,
        findings=findings,
        ingest=ingest,
        config=config,
        version=version,
    )

    report_path = run_dir / "AUDIT_REPORT.md"
    report_path.write_text(content, encoding="utf-8")
    return report_path
