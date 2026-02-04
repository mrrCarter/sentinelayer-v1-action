from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from .analyze import AnalysisOrchestrator
from .comment import marker, marker_prefix, render_pr_comment
from .config import OmarGateConfig
from .context import GitHubContext
from .gate import evaluate_gate
from .github import GitHubClient, findings_to_annotations
from .idempotency import compute_idempotency_key
from .logging import OmarLogger
from .models import GateConfig
from .artifacts import write_audit_report
from .packaging import get_run_dir, write_findings_jsonl, write_pack_summary
from .publish import prepare_artifacts_for_upload, write_step_summary
from .package import write_artifact_manifest
from .preflight import (
    check_branch_protection,
    check_cost_approval,
    check_dedupe,
    check_fork_policy,
    check_rate_limits,
    estimate_cost,
)

ACTION_VERSION = "1.2.0"
ACTION_MAJOR_VERSION = "1"
CHECK_NAME = "Omar Gate"


def main() -> int:
    """Main entry point."""
    return asyncio.run(async_main())


async def async_main() -> int:
    """Async main entry point."""

    try:
        config = OmarGateConfig()
    except Exception as exc:
        print(f"::error::Configuration error: {exc}")
        return 2

    try:
        ctx = GitHubContext.from_environment()
    except Exception as exc:
        print(f"::error::Failed to load GitHub context: {exc}")
        return 2

    repo_root = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    run_id = str(uuid.uuid4())
    run_dir = get_run_dir(run_id)
    logger = OmarLogger(run_id)

    logger.info(
        "Omar Gate starting",
        repo=ctx.repo_full_name,
        pr_number=ctx.pr_number,
        head_sha=ctx.head_sha,
        scan_mode=config.scan_mode,
    )

    dashboard_url = None
    if config.plexaura_token.get_secret_value():
        dashboard_url = f"https://sentinellayer.com/runs/{run_id}"

    idem_key = compute_idempotency_key(
        repo=ctx.repo_full_name,
        pr_number=ctx.pr_number or 0,
        head_sha=ctx.head_sha,
        scan_mode=config.scan_mode,
        policy_pack=config.policy_pack,
        policy_pack_version=config.policy_pack_version,
        action_major_version=ACTION_MAJOR_VERSION,
    )

    token = config.github_token.get_secret_value() or os.environ.get("GITHUB_TOKEN", "")
    gh = GitHubClient(token=token, repo=ctx.repo_full_name)

    estimated_cost = _estimate_cost(ctx, gh, config)

    # === PREFLIGHT ===
    with logger.stage("preflight"):
        should_skip, existing_url = await check_dedupe(
            gh, ctx.head_sha, idem_key, CHECK_NAME
        )
        if should_skip:
            logger.info("Skipping - already analyzed", existing_url=existing_url)
            return 10

        proceed, scan_mode_override, fork_reason = check_fork_policy(ctx, config)
        if not proceed:
            logger.info("Blocked by fork policy", reason=fork_reason)
            if ctx.pr_number:
                comment_body = (
                    "## 🛡️ Omar Gate: Blocked\n\n"
                    "Fork PRs cannot access secrets required for full analysis. "
                    "Please ask a maintainer to run the scan via workflow_dispatch.\n\n"
                    f"{marker(ctx.repo_full_name, ctx.pr_number)}"
                )
                gh.create_or_update_pr_comment(
                    ctx.pr_number,
                    comment_body,
                    marker_prefix(),
                )
            return 12

        proceed, rate_reason = await check_rate_limits(
            gh, ctx.pr_number, config, logger
        )
        if not proceed:
            logger.info("Rate limited", reason=rate_reason)
            return 11

        approved, cost_status = await check_cost_approval(
            estimated_cost, config, ctx, gh
        )
        if not approved:
            logger.info("Cost approval required", status=cost_status)
            return 13

        bp_ok, bp_message = check_branch_protection(gh, ctx, CHECK_NAME)
        if not bp_ok:
            logger.warning("Branch protection issue", message=bp_message)

    # === ANALYSIS ===
    limited_mode = scan_mode_override == "limited"

    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=repo_root,
        allow_llm=not limited_mode,
    )

    diff_content: Optional[str] = None
    changed_files: Optional[list[str]] = None
    if config.scan_mode == "pr-diff" and ctx.pr_number:
        with logger.stage("fetch_diff"):
            diff_content = await gh.get_pr_diff(ctx.pr_number)
            changed_files = await gh.get_pr_changed_files(ctx.pr_number)

    if limited_mode:
        logger.info("Running in limited mode (deterministic only)")

    scan_start = time.perf_counter()
    analysis = await orchestrator.run(
        scan_mode=config.scan_mode,
        diff_content=diff_content,
        changed_files=changed_files,
        run_dir=run_dir,
        run_id=run_id,
        version=ACTION_VERSION,
        dashboard_url=dashboard_url,
    )

    # === PACKAGING ===
    summary_payload: dict = {}
    scan_duration_ms = 0
    with logger.stage("packaging"):
        findings_path = run_dir / "FINDINGS.jsonl"
        write_findings_jsonl(findings_path, analysis.findings)

        pack_counts = {
            key: analysis.counts[key] for key in ("P0", "P1", "P2", "P3")
        }
        fingerprint_count = sum(
            1 for finding in analysis.findings if finding.get("fingerprint")
        )
        scan_duration_ms = int((time.perf_counter() - scan_start) * 1000)
        pack_summary_path = write_pack_summary(
            run_dir=run_dir,
            run_id=run_id,
            writer_complete=True,
            findings_path=findings_path,
            counts=pack_counts,
            tool_versions={
                "action": ACTION_VERSION,
                "policy_pack": config.policy_pack_version,
            },
            stages_completed=["preflight", "ingest", "deterministic", "llm", "packaging"],
            review_brief_path=analysis.review_brief_path,
            fingerprint_count=fingerprint_count,
            dedupe_key=idem_key,
            policy_pack=config.policy_pack,
            policy_pack_version=config.policy_pack_version,
            error=None,
            duration_ms=scan_duration_ms,
        )
        try:
            summary_payload = json.loads(pack_summary_path.read_text(encoding="utf-8"))
            write_audit_report(
                run_dir=run_dir,
                run_id=run_id,
                summary=summary_payload,
                findings=analysis.findings,
                ingest=analysis.ingest,
                config={"severity_gate": config.severity_gate},
                version=ACTION_VERSION,
            )
        except Exception as exc:
            logger.warning("Audit report generation failed", error=str(exc))
            analysis.warnings.append("Audit report generation failed")

        try:
            write_artifact_manifest(run_dir, run_id)
        except Exception as exc:
            logger.warning("Manifest generation failed", error=str(exc))
            analysis.warnings.append("Manifest generation failed")

        try:
            workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))
            artifacts_dir = workspace / ".sentinellayer" / "artifacts"
            prepare_artifacts_for_upload(run_dir, artifacts_dir)
        except Exception as exc:
            logger.warning("Artifact preparation failed", error=str(exc))
            analysis.warnings.append("Artifact preparation failed")

    # === GATE EVALUATION ===
    with logger.stage("gate_eval"):
        gate_result = evaluate_gate(
            run_dir,
            GateConfig(severity_gate=config.severity_gate),
        )

    status_value = (
        gate_result.status.value
        if hasattr(gate_result.status, "value")
        else str(gate_result.status)
    )
    logger.info(
        "Gate evaluation complete",
        status=status_value,
        block_merge=gate_result.block_merge,
        counts=analysis.counts,
    )

    # === PUBLISHING ===
    with logger.stage("publish"):
        cost_usd = analysis.llm_usage.get("cost_usd", 0.0) if analysis.llm_usage else 0.0

        if ctx.pr_number:
            github_run_id = os.environ.get("GITHUB_RUN_ID")
            server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
            artifacts_url = (
                f"{server_url}/{ctx.repo_full_name}/actions/runs/{github_run_id}"
                if github_run_id
                else None
            )
            comment_body = render_pr_comment(
                result=gate_result,
                run_id=run_id,
                repo_full_name=ctx.repo_full_name,
                pr_number=ctx.pr_number,
                dashboard_url=dashboard_url,
                artifacts_url=artifacts_url,
                cost_usd=cost_usd,
                version=ACTION_VERSION,
                findings=analysis.findings[:5],
                warnings=analysis.warnings,
                scan_mode=config.scan_mode,
                policy_pack=config.policy_pack,
                policy_pack_version=config.policy_pack_version,
                duration_ms=summary_payload.get("duration_ms") or scan_duration_ms,
                deterministic_count=analysis.deterministic_count,
                llm_count=analysis.llm_count,
                dedupe_key=gate_result.dedupe_key or idem_key,
            )
            gh.create_or_update_pr_comment(
                ctx.pr_number,
                comment_body,
                marker_prefix(),
            )

        counts = summary_payload.get("counts", {}) or analysis.counts
        summary_text = (
            f"🔴 P0={counts.get('P0', 0)} • 🟠 P1={counts.get('P1', 0)} • "
            f"🟡 P2={counts.get('P2', 0)} • ⚪ P3={counts.get('P3', 0)}"
        )
        status_key = (
            gate_result.status.value
            if hasattr(gate_result.status, "value")
            else str(gate_result.status)
        )
        conclusion_map = {
            "passed": "success",
            "blocked": "failure",
            "bypassed": "neutral",
            "needs_approval": "action_required",
            "error": "failure",
        }
        annotations = findings_to_annotations(analysis.findings)
        gh.create_check_run(
            name=CHECK_NAME,
            head_sha=ctx.head_sha,
            conclusion=conclusion_map.get(status_key, "failure"),
            summary=summary_text,
            title=f"Omar Gate: {status_key.upper()}",
            text=gate_result.reason,
            details_url=dashboard_url,
            external_id=idem_key,
            annotations=annotations,
        )

        write_step_summary(
            gate_result=gate_result,
            summary=summary_payload,
            findings=analysis.findings,
            run_id=run_id,
            version=ACTION_VERSION,
        )

    # === TELEMETRY (best effort) ===
    if config.telemetry_tier > 0:
        with logger.stage("telemetry"):
            try:
                await _upload_telemetry(
                    config=config,
                    run_id=run_id,
                    idem_key=idem_key,
                    analysis=analysis,
                    gate_result=gate_result,
                    ctx=ctx,
                )
            except Exception as exc:
                logger.warning("Telemetry upload failed", error=str(exc))

    # === OUTPUTS ===
    _write_github_outputs(
        run_id=run_id,
        gate_result=gate_result,
        analysis=analysis,
        idem_key=idem_key,
        findings_path=findings_path,
        pack_summary_path=pack_summary_path,
    )

    return 1 if gate_result.block_merge else 0


async def _upload_telemetry(
    config: OmarGateConfig,
    run_id: str,
    idem_key: str,
    analysis,
    gate_result,
    ctx: GitHubContext,
) -> None:
    """Upload telemetry to PlexAura (best effort)."""
    _ = (config, run_id, idem_key, analysis, gate_result, ctx)
    return None


def _write_github_outputs(
    run_id: str,
    gate_result,
    analysis,
    idem_key: str,
    findings_path: Path,
    pack_summary_path: Path,
) -> None:
    """Write GitHub Actions outputs."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return

    with open(output_path, "a", encoding="utf-8") as f:
        status_value = (
            gate_result.status.value
            if hasattr(gate_result.status, "value")
            else str(gate_result.status)
        )
        f.write(f"gate_status={status_value}\n")
        f.write(f"run_id={run_id}\n")
        f.write(f"p0_count={analysis.counts['P0']}\n")
        f.write(f"p1_count={analysis.counts['P1']}\n")
        f.write(f"p2_count={analysis.counts['P2']}\n")
        f.write(f"p3_count={analysis.counts['P3']}\n")
        f.write(f"findings_artifact={findings_path}\n")
        f.write(f"pack_summary_artifact={pack_summary_path}\n")
        f.write(f"idempotency_key={idem_key}\n")
        cost = analysis.llm_usage.get("cost_usd", 0.0) if analysis.llm_usage else 0.0
        f.write(f"estimated_cost_usd={cost:.4f}\n")


def _load_event() -> dict:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    try:
        return json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _estimate_cost(
    ctx: GitHubContext,
    gh: GitHubClient,
    config: OmarGateConfig,
) -> float:
    if not ctx.pr_number:
        return 0.0

    event = _load_event()
    pr = event.get("pull_request") or {}

    if not pr:
        try:
            pr = gh.get_pull_request(ctx.pr_number)
        except Exception:
            pr = {}

    additions = int(pr.get("additions") or 0)
    deletions = int(pr.get("deletions") or 0)
    changed_files = int(pr.get("changed_files") or 0)

    return estimate_cost(
        file_count=changed_files,
        total_lines=additions + deletions,
        model=config.model,
    )


if __name__ == "__main__":
    sys.exit(main())
