from __future__ import annotations

from typing import List, Optional

from .models import GateResult, GateStatus

MARKER_PREFIX = "<!-- sentinellayer:omar-gate:v1:"

def marker(repo_full_name: str, pr_number: int) -> str:
    return f"{MARKER_PREFIX}{repo_full_name}:{pr_number} -->"


def marker_prefix() -> str:
    return MARKER_PREFIX


def _status_key(status: GateStatus | str) -> str:
    return status.value if isinstance(status, GateStatus) else str(status)


def _status_badge(status: GateStatus | str) -> str:
    badges = {
        "passed": "✅ PASSED",
        "blocked": "❌ BLOCKED",
        "bypassed": "⚠️ BYPASSED",
        "needs_approval": "⏸️ NEEDS APPROVAL",
        "error": "🔴 ERROR",
    }
    return badges.get(_status_key(status), "❓ UNKNOWN")


def _next_steps(status: GateStatus | str) -> str:
    steps = {
        "passed": [
            "No action required. You may merge once other checks pass.",
        ],
        "blocked": [
            "Fix the blocking findings (P0/P1/P2 per policy) and re-run Omar Gate.",
            "If a bypass is required, follow your team's exception workflow.",
        ],
        "bypassed": [
            "Gate was bypassed. Ensure manual review and document the exception.",
        ],
        "needs_approval": [
            "Approval required. Add the approval label or re-run via workflow_dispatch.",
        ],
        "error": [
            "Gate failed closed. Inspect logs and artifacts, then re-run.",
        ],
    }
    lines = steps.get(_status_key(status), ["Review the run details and take appropriate action."])
    return "\n".join(f"- {line}" for line in lines)


def _warnings_section(warnings: Optional[List[str]]) -> str:
    if not warnings:
        return ""
    lines = ["### ⚠️ Warnings", ""]
    lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines)


def _findings_section(findings: Optional[List[dict]]) -> str:
    if not findings:
        return ""
    lines = [
        "<details>",
        "<summary>Top Findings (max 5)</summary>",
        "",
    ]
    for idx, finding in enumerate(findings[:5], start=1):
        severity = finding.get("severity", "?")
        file_path = finding.get("file_path", "?")
        line_start = finding.get("line_start", "?")
        message = finding.get("message", "No description")
        category = finding.get("category", "Issue")
        lines.append(
            f"{idx}. **{severity}** `{file_path}:{line_start}` - {category}: {message}"
        )
    lines.extend(["", "</details>"])
    return "\n".join(lines)


def render_pr_comment(
    result: GateResult,
    run_id: str,
    repo_full_name: str,
    pr_number: int,
    dashboard_url: Optional[str],
    artifacts_url: Optional[str],
    cost_usd: Optional[float],
    version: str,
    findings: Optional[List[dict]] = None,
    warnings: Optional[List[str]] = None,
    scan_mode: str = "pr-diff",
    policy_pack: str = "omar",
    policy_pack_version: str = "v1",
    duration_ms: Optional[int] = None,
    deterministic_count: int = 0,
    llm_count: int = 0,
    dedupe_key: Optional[str] = None,
) -> str:
    """Render PR comment with full analysis details."""

    status_badge = _status_badge(result.status)
    duration_value = f"{int(duration_ms)}ms" if duration_ms is not None else "n/a"
    cost_value = f"${cost_usd:.2f}" if cost_usd is not None else "n/a"
    dedupe_short = (dedupe_key or "n/a")[:12]
    run_id_short = run_id[:8]

    warnings_section = _warnings_section(warnings)
    findings_section = _findings_section(findings)
    next_steps = _next_steps(result.status)

    artifacts_link = artifacts_url or dashboard_url or ""
    if artifacts_link:
        report_links = (
            f"- [AUDIT_REPORT.md]({artifacts_link}) (if artifacts uploaded)\n"
            f"- [REVIEW_BRIEF.md]({artifacts_link})"
        )
    else:
        report_links = "- Artifacts not available."

    lines = [
        f"## 🛡️ Omar Gate: {status_badge}",
        "",
        f"**Result:** {result.reason}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 P0 | {result.counts.p0} |",
        f"| 🟠 P1 | {result.counts.p1} |",
        f"| 🟡 P2 | {result.counts.p2} |",
        f"| ⚪ P3 | {result.counts.p3} |",
        "",
        f"**Scan:** {scan_mode} • **Policy:** {policy_pack}@{policy_pack_version} • **Duration:** {duration_value} • **Cost:** {cost_value}",
        "",
    ]

    if warnings_section:
        lines.append(warnings_section)
        lines.append("")

    if findings_section:
        lines.append(findings_section)
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "### Next Steps",
            "",
            next_steps,
            "",
            "<details>",
            "<summary>View full report</summary>",
            "",
            report_links,
            "",
            "</details>",
            "",
            "---",
            "",
            f"<sub>Omar Gate v{version} • run_id={run_id_short} • dedupe={dedupe_short} • det={deterministic_count} llm={llm_count}</sub>",
            "",
            marker(repo_full_name, pr_number),
        ]
    )

    return "\n".join(lines)
