from __future__ import annotations

from typing import List, Optional

from .models import GateResult

MARKER_PREFIX = "<!-- omar-gate:run_id="


def marker(run_id: str) -> str:
    return f"{MARKER_PREFIX}{run_id} -->"


def render_pr_comment(
    result: GateResult,
    run_id: str,
    dashboard_url: Optional[str],
    cost_usd: Optional[float],
    version: str,
    findings: Optional[List[dict]] = None,
    warnings: Optional[List[str]] = None,
    scan_mode: str = "pr-diff",
    files_scanned: int = 0,
    deterministic_count: int = 0,
    llm_count: int = 0,
) -> str:
    """Render PR comment with full analysis details."""

    status_emoji = {
        "passed": "✅",
        "blocked": "❌",
        "error": "🔴",
        "bypassed": "⚠️",
    }.get(result.status, "❓")

    lines = [
        marker(run_id),
        f"## 🛡️ Omar Gate: {status_emoji} {result.status.upper()}",
        "",
        f"**Result:** {result.reason}",
        (
            f"**Counts:** 🔴 P0={result.counts.p0} • 🟠 P1={result.counts.p1} • 🟡 P2={result.counts.p2} • ⚪ P3={result.counts.p3}"
        ),
    ]

    if cost_usd is not None:
        lines.append(
            f"**Scan:** {scan_mode} • **Files:** {files_scanned} • **Cost:** ${cost_usd:.2f}"
        )
    else:
        lines.append(f"**Scan:** {scan_mode} • **Files:** {files_scanned}")

    lines.append("")

    if warnings:
        lines.append("### ⚠️ Warnings")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    if findings:
        lines.append("### Top Findings")
        lines.append("")
        for finding in findings[:5]:
            severity = finding.get("severity", "?")
            sev_icon = {"P0": "🔴", "P1": "🟠", "P2": "🟡", "P3": "⚪"}.get(
                severity, "❓"
            )
            category = finding.get("category", "unknown")
            file_path = finding.get("file_path", "?")
            line_start = finding.get("line_start", "?")
            message = finding.get("message", "")
            recommendation = finding.get("recommendation")

            lines.append(f"#### {sev_icon} {severity}: {category}")
            lines.append(f"**File:** `{file_path}:{line_start}`")
            lines.append(f"**Issue:** {message}")
            if recommendation:
                lines.append(f"**Fix:** {recommendation}")
            lines.append("")

    lines.append("---")
    lines.append("")
    footer = (
        f"Omar Gate v{version} • run_id={run_id[:8]} • det={deterministic_count} llm={llm_count}"
    )
    if dashboard_url:
        lines.append(f"[View full report]({dashboard_url}) • {footer}")
    else:
        lines.append(footer)
    lines.append("")

    return "\n".join(lines)
