from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .analyze import AnalysisOrchestrator
from .comment import marker, render_pr_comment
from .config import OmarGateConfig
from .context import GitHubContext
from .gate import evaluate_gate
from .github import GitHubClient
from .idempotency import compute_idempotency_key
from .logging import OmarLogger
from .models import GateConfig
from .packaging import new_run_dir, write_findings_jsonl, write_pack_summary
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
    run_dir = new_run_dir(Path("/tmp/omar_runs"))
    run_id = run_dir.name
    logger = OmarLogger(run_id)

    logger.info(
        "Omar Gate starting",
        repo=ctx.repo_full_name,
        pr_number=ctx.pr_number,
        head_sha=ctx.head_sha,
        scan_mode=config.scan_mode,
    )

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
                    f"{marker(run_id)}\n"
                    "🛡️ Omar Gate: Blocked\n\n"
                    "Fork PRs cannot access secrets required for full analysis. "
                    "Please ask a maintainer to run the scan via workflow_dispatch."
                )
                gh.create_or_update_pr_comment(
                    ctx.pr_number,
                    comment_body,
                    marker(run_id),
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

    analysis = await orchestrator.run(
        scan_mode=config.scan_mode,
        diff_content=diff_content,
        changed_files=changed_files,
    )

    # === PACKAGING ===
    with logger.stage("packaging"):
        findings_path = run_dir / "FINDINGS.jsonl"
        write_findings_jsonl(findings_path, analysis.findings)

        pack_counts = {
            key: analysis.counts[key] for key in ("P0", "P1", "P2", "P3")
        }
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
            error=None,
        )

    # === GATE EVALUATION ===
    with logger.stage("gate_eval"):
        gate_result = evaluate_gate(
            run_dir,
            GateConfig(severity_gate=config.severity_gate),
        )

    logger.info(
        "Gate evaluation complete",
        status=gate_result.status,
        block_merge=gate_result.block_merge,
        counts=analysis.counts,
    )

    # === PUBLISHING ===
    with logger.stage("publish"):
        cost_usd = analysis.llm_usage.get("cost_usd", 0.0) if analysis.llm_usage else 0.0

        dashboard_url = None
        if config.plexaura_token.get_secret_value():
            dashboard_url = f"https://sentinellayer.com/runs/{run_id}"

        comment_body = render_pr_comment(
            result=gate_result,
            run_id=run_id,
            dashboard_url=dashboard_url,
            cost_usd=cost_usd,
            version=ACTION_VERSION,
            findings=analysis.findings[:5],
            warnings=analysis.warnings,
            scan_mode=config.scan_mode,
            files_scanned=analysis.total_files_scanned,
            deterministic_count=analysis.deterministic_count,
            llm_count=analysis.llm_count,
        )

        if ctx.pr_number:
            gh.create_or_update_pr_comment(
                ctx.pr_number,
                comment_body,
                marker(run_id),
            )

        gh.create_check_run(
            name=CHECK_NAME,
            head_sha=ctx.head_sha,
            conclusion="failure" if gate_result.block_merge else "success",
            summary=gate_result.reason,
            details_url=dashboard_url,
            external_id=idem_key,
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
        f.write(f"gate_status={gate_result.status}\n")
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
