from __future__ import annotations

from .models import GateResult

MARKER_PREFIX = "<!-- omar-gate:run_id="

def marker(run_id: str) -> str:
    return f"{MARKER_PREFIX}{run_id} -->"

def render_pr_comment(
    result: GateResult,
    run_id: str,
    dashboard_url: str | None,
    cost_usd: float | None,
    action_version: str,
    warnings: list[str] | None = None,
) -> str:
    status_emoji = {
        "passed": "✅ PASSED",
        "blocked": "❌ BLOCKED",
        "bypassed": "⚠️ BYPASSED",
        "skipped": "⏭️ SKIPPED",
        "error": "🚫 ERROR",
    }.get(result.status, result.status.upper())

    lines = []
    lines.append(marker(run_id))
    lines.append(f"## 🛡️ Omar Gate: {status_emoji}")
    lines.append("")
    lines.append(result.reason)
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    lines.append(f"| 🔴 P0 | {result.counts.p0} |")
    lines.append(f"| 🟠 P1 | {result.counts.p1} |")
    lines.append(f"| 🟡 P2 | {result.counts.p2} |")
    lines.append(f"| ⚪ P3 | {result.counts.p3} |")
    lines.append("")
    if warnings:
        lines.append("### Warnings")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    if dashboard_url:
        lines.append(f"📊 View run in PlexAura: {dashboard_url}")
    if cost_usd is not None:
        lines.append(f"💸 Est. LLM cost: ${cost_usd:.2f}")
    lines.append("")
    lines.append(f"<sub>Omar Gate {action_version}</sub>")
    return "\n".join(lines)
