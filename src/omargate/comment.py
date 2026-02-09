from __future__ import annotations

from typing import Iterable, List, Optional

from .formatting import (
    format_int,
    format_usd,
    github_blob_url,
    humanize_duration_ms,
    truncate,
)
from .models import GateResult, GateStatus

MARKER_PREFIX = "<!-- sentinelayer:omar-gate:v1:"

_SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


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


def _blocking_severities(severity_gate: str) -> List[str]:
    gate = (severity_gate or "P1").strip().upper()
    if gate == "P0":
        return ["P0"]
    if gate == "P1":
        return ["P0", "P1"]
    if gate == "P2":
        return ["P0", "P1", "P2"]
    return []


def _gate_label(severity_gate: str) -> str:
    gate = (severity_gate or "P1").strip().upper()
    if gate == "NONE":
        return "none (disabled)"
    blocking = _blocking_severities(gate)
    if not blocking:
        return gate
    return f"{gate} (blocks {', '.join(blocking)})"


def _next_steps(status: GateStatus | str, severity_gate: str) -> str:
    gate = (severity_gate or "P1").strip().upper()
    blocking = _blocking_severities(gate)
    blocking_label = "/".join(blocking) if blocking else "configured severities"

    steps = {
        "passed": [
            "No action required from Omar Gate. Merge once other required checks pass.",
        ],
        "blocked": [
            f"Fix findings at or above the gate threshold ({blocking_label}), then re-run Omar Gate.",
            "If you believe a finding is a false positive, document the rationale and follow your exception workflow.",
        ],
        "bypassed": [
            "Gate was bypassed. Ensure manual review and document the exception.",
        ],
        "needs_approval": [
            "Approval required before scanning can proceed. Follow your repo's approval workflow (label or manual rerun).",
        ],
        "error": [
            "Gate failed closed. Inspect logs/artifacts, fix the underlying error, then re-run.",
        ],
    }
    lines = steps.get(_status_key(status), ["Review the run details and take appropriate action."])
    return "\n".join(f"- {line}" for line in lines)


def _warnings_section(warnings: Optional[List[str]]) -> str:
    if not warnings:
        return ""
    lines = ["<details>", "<summary>Warnings</summary>", ""]
    lines.extend(f"- {truncate(str(w), 400)}" for w in warnings[:25])
    if len(warnings) > 25:
        lines.append(f"- ...and {len(warnings) - 25} more")
    lines.extend(["", "</details>"])
    return "\n".join(lines)


def _select_top_findings(findings: Iterable[dict], *, max_items: int = 5) -> List[dict]:
    out: List[dict] = []
    seen = set()
    for finding in sorted(
        (f for f in findings or [] if isinstance(f, dict)),
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 99),
            float(f.get("confidence", 0.0) or 0.0) * -1.0,
            str(f.get("file_path") or ""),
            int(f.get("line_start") or 0),
        ),
    ):
        fid = str(finding.get("id") or "")
        fp = str(finding.get("fingerprint") or "")
        dedupe_key = fp or fid or (
            str(finding.get("severity") or ""),
            str(finding.get("category") or ""),
            str(finding.get("file_path") or ""),
            str(finding.get("line_start") or ""),
            str(finding.get("message") or ""),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        out.append(finding)
        if len(out) >= max_items:
            break
    return out


def _top_findings_section(
    findings: Optional[List[dict]],
    *,
    server_url: str,
    repo_full_name: str,
    head_sha: Optional[str],
    max_items: int = 5,
) -> str:
    if not findings:
        return ""

    selected = _select_top_findings(findings, max_items=max_items)
    if not selected:
        return ""

    lines = ["### Top Findings", ""]
    for idx, finding in enumerate(selected, start=1):
        severity = str(finding.get("severity") or "?").upper()
        file_path = str(finding.get("file_path") or "?").replace("\\", "/")
        line_start = finding.get("line_start")
        category = str(finding.get("category") or "Issue")
        message = truncate(str(finding.get("message") or "No description").strip(), 220)

        loc = f"{file_path}:{line_start}" if line_start else file_path
        link = None
        if head_sha and repo_full_name and file_path and file_path != "?":
            link = github_blob_url(
                server_url=server_url,
                repo_full_name=repo_full_name,
                head_sha=head_sha,
                path=file_path,
                line=int(line_start) if line_start else None,
            )
        if link:
            loc_md = f"[`{loc}`]({link})"
        else:
            loc_md = f"`{loc}`"

        lines.append(f"{idx}. **{severity}** {loc_md} · **{category}**: {message}")

    return "\n".join(lines)


def render_pr_comment(
    result: GateResult,
    run_id: str,
    repo_full_name: str,
    pr_number: int,
    dashboard_url: Optional[str],
    artifacts_url: Optional[str],
    estimated_cost_usd: Optional[float],
    version: str,
    findings: Optional[List[dict]] = None,
    warnings: Optional[List[str]] = None,
    review_brief_md: Optional[str] = None,
    scan_mode: str = "pr-diff",
    policy_pack: str = "omar",
    policy_pack_version: str = "v1",
    severity_gate: str = "P1",
    duration_ms: Optional[int] = None,
    files_scanned: Optional[int] = None,
    llm_engine: str = "disabled",
    llm_model: str = "n/a",
    actual_cost_usd: Optional[float] = None,
    deterministic_count: int = 0,
    llm_count: int = 0,
    dedupe_key: Optional[str] = None,
    head_sha: Optional[str] = None,
    server_url: str = "https://github.com",
) -> str:
    """
    Render the PR comment for Omar Gate.

    Design goals:
    - Short by default; actionable without expanding details
    - Accurate (no "0.00" when cost is unknown; no model=none when LLM ran)
    - Accessible (avoid meaning encoded only by emoji)
    """
    status_badge = _status_badge(result.status)
    gate_label = _gate_label(severity_gate)

    duration_value = humanize_duration_ms(duration_ms)
    estimated_cost_value = format_usd(estimated_cost_usd)
    actual_cost_value = format_usd(actual_cost_usd)

    blocking = set(_blocking_severities(severity_gate))

    warnings_section = _warnings_section(warnings)
    top_findings_section = _top_findings_section(
        findings,
        server_url=server_url,
        repo_full_name=repo_full_name,
        head_sha=head_sha,
        max_items=5,
    )
    next_steps = _next_steps(result.status, severity_gate)

    # Links / artifacts
    links: List[str] = []
    if artifacts_url:
        links.append(f"- Workflow run: {artifacts_url}")
    if dashboard_url:
        links.append(f"- Dashboard: {dashboard_url}")
    if not links:
        links.append("- Links not available (missing token or context).")

    artifacts_help = [
        "- Reports generated on the runner:",
        "  - `AUDIT_REPORT.md` (full report)",
        "  - `REVIEW_BRIEF.md` (reviewer summary)",
        "  - `FINDINGS.jsonl` (all findings)",
        "  - `PACK_SUMMARY.json` (counts + integrity)",
        f"- Run artifacts: `.sentinelayer/runs/{run_id}/`",
        "- Upload with `actions/upload-artifact` (replace the step id if yours is not `omar`):",
        "```yaml",
        "- uses: actions/upload-artifact@v4",
        "  if: always()",
        "  with:",
        "    name: sentinelayer-${{ steps.omar.outputs.run_id }}",
        "    path: .sentinelayer/runs/${{ steps.omar.outputs.run_id }}",
        "```",
        "- Optional: a small upload bundle is also staged under `.sentinelayer/artifacts/` when the workspace is writable.",
    ]

    # Keep the inline brief short; artifacts are the source of truth.
    inline_review_brief = ""
    if review_brief_md:
        trimmed = review_brief_md.strip()
        if len(trimmed) > 12_000:
            trimmed = trimmed[:12_000].rstrip() + "\n\n...(truncated)...\n"
        inline_review_brief = "\n".join(
            [
                "",
                "<details>",
                "<summary>Reviewer Brief (inline, truncated)</summary>",
                "",
                trimmed,
                "",
                "</details>",
            ]
        )

    # Counts table with explicit blocking semantics.
    lines = [
        f"## 🛡️ Omar Gate: {status_badge}",
        "",
        f"**Gate:** `{gate_label}`",
        f"**Policy:** `{policy_pack}@{policy_pack_version}` • **Scan:** `{scan_mode}`",
        f"**Duration:** `{duration_value}`"
        + (f" • **Files:** `{format_int(int(files_scanned))}`" if files_scanned is not None else "")
        + f" • **LLM:** `{llm_engine}` (`{llm_model}`)"
        + f" • **Cost (est.):** `{estimated_cost_value}`"
        + (f" • **Cost (actual):** `{actual_cost_value}`" if actual_cost_usd is not None else ""),
        "",
        f"**Result:** {result.reason}",
        "",
        "| Severity | Count | Blocks Merge? |",
        "|----------|------:|:------------:|",
        f"| P0 (Critical) | {format_int(result.counts.p0)} | {'Yes' if 'P0' in blocking else 'No'} |",
        f"| P1 (High) | {format_int(result.counts.p1)} | {'Yes' if 'P1' in blocking else 'No'} |",
        f"| P2 (Medium) | {format_int(result.counts.p2)} | {'Yes' if 'P2' in blocking else 'No'} |",
        f"| P3 (Low) | {format_int(result.counts.p3)} | No |",
        "",
    ]

    if top_findings_section:
        lines.append(top_findings_section)
        lines.append("")

    lines.extend(["### Next Steps", "", next_steps, ""])

    if warnings_section:
        lines.append(warnings_section)
        lines.append("")

    lines.extend(
        [
            "<details>",
            "<summary>Artifacts & Full Report</summary>",
            "",
            "\n".join(links),
            "",
            "\n".join(artifacts_help),
            inline_review_brief,
            "",
            "</details>",
            "",
            "---",
            "",
            f"<sub>Omar Gate v{version} · run_id={run_id[:8]} · dedupe={(dedupe_key or 'n/a')[:8]} · raw_findings(det={deterministic_count}, llm={llm_count})</sub>",
            "",
            marker(repo_full_name, pr_number),
        ]
    )

    return "\n".join(lines)
