from __future__ import annotations

import os

from ..models import GateResult, GateStatus


def _status_key(status: GateStatus | str) -> str:
    return status.value if isinstance(status, GateStatus) else str(status)


def write_step_summary(
    gate_result: GateResult,
    summary: dict,
    findings: list[dict],
    run_id: str,
    version: str,
) -> None:
    """
    Write GitHub Actions Step Summary.

    This appears in the job summary, providing quick visibility
    without clicking into logs.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    counts = summary.get("counts", {}) if summary else {}
    if not counts:
        counts = {
            "P0": gate_result.counts.p0,
            "P1": gate_result.counts.p1,
            "P2": gate_result.counts.p2,
            "P3": gate_result.counts.p3,
        }

    status_icon = {
        "passed": "✅",
        "blocked": "❌",
        "bypassed": "⚠️",
        "needs_approval": "⏸️",
        "error": "🔴",
    }.get(_status_key(gate_result.status), "❓")

    md = [
        f"## 🛡️ Omar Gate: {status_icon} {_status_key(gate_result.status).upper()}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 P0 | {counts.get('P0', 0)} |",
        f"| 🟠 P1 | {counts.get('P1', 0)} |",
        f"| 🟡 P2 | {counts.get('P2', 0)} |",
        f"| ⚪ P3 | {counts.get('P3', 0)} |",
        "",
        f"**Result:** {gate_result.reason}",
        "",
    ]

    if findings:
        md.append("### Top Findings")
        md.append("")
        for finding in findings[:3]:
            severity = finding.get("severity", "?")
            file_path = finding.get("file_path", "?")
            line_start = finding.get("line_start", "?")
            message = finding.get("message", "No description")
            md.append(
                f"- **{severity}** `{file_path}:{line_start}` - {message}"
            )
        md.append("")

    md.append(f"<sub>Omar Gate v{version} • run_id={run_id[:8]}</sub>")
    md.append("")

    with open(summary_path, "a", encoding="utf-8") as summary_file:
        summary_file.write("\n".join(md))
