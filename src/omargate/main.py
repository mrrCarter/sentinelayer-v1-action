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
from .telemetry import (
    ConsentConfig,
    TelemetryCollector,
    fetch_oidc_token,
    get_max_tier,
    should_upload_tier,
    validate_payload_tier,
)
from .telemetry.schemas import build_tier1_payload, build_tier2_payload, findings_to_summary
from .telemetry.uploader import upload_artifacts, upload_telemetry
from .utils import ensure_writable_dir, json_dumps

ACTION_VERSION = "1.2.0"
ACTION_MAJOR_VERSION = "1"
CHECK_NAME = "Omar Gate"


def main() -> int:
    """Main entry point."""
    return asyncio.run(async_main())

def _publish_strict() -> bool:
    """Return True when publish failures should fail the run."""
    if os.environ.get("ACT", "").lower() == "true":
        return False
    return True


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
    collector = TelemetryCollector(run_id=run_id, repo_full_name=ctx.repo_full_name)
    collector.scan_mode = config.scan_mode

    logger.info(
        "Omar Gate starting",
        repo=ctx.repo_full_name,
        pr_number=ctx.pr_number,
        head_sha=ctx.head_sha,
        scan_mode=config.scan_mode,
    )

    dashboard_url = None
    if config.sentinelayer_token.get_secret_value():
        dashboard_url = f"https://sentinelayer.com/runs/{run_id}"

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
    preflight_success = True
    collector.stage_start("preflight")
    try:
        with logger.stage("preflight"):
            should_skip, existing_url = await check_dedupe(
                gh, ctx.head_sha, idem_key, CHECK_NAME
            )
            if should_skip:
                collector.dedupe_skipped = True
                preflight_success = False
                logger.info("Skipping - already analyzed", existing_url=existing_url)
                return 10

            proceed, scan_mode_override, fork_reason = check_fork_policy(ctx, config)
            if not proceed:
                collector.fork_blocked = True
                preflight_success = False
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
                collector.rate_limit_skipped = True
                preflight_success = False
                logger.info("Rate limited", reason=rate_reason)
                return 11

            approved, cost_status = await check_cost_approval(
                estimated_cost, config, ctx, gh
            )
            collector.approval_state = cost_status
            if not approved:
                preflight_success = False
                logger.info("Cost approval required", status=cost_status)
                return 13

            bp_ok, bp_message = check_branch_protection(gh, ctx, CHECK_NAME)
            if not bp_ok:
                logger.warning("Branch protection issue", message=bp_message)
    except Exception as exc:
        preflight_success = False
        collector.record_error("preflight", str(exc))
        raise
    finally:
        collector.stage_end("preflight", success=preflight_success)

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
        collector.stage_start("fetch_diff")
        try:
            with logger.stage("fetch_diff"):
                diff_content = await gh.get_pr_diff(ctx.pr_number)
                changed_files = await gh.get_pr_changed_files(ctx.pr_number)
        except Exception as exc:
            collector.record_error("fetch_diff", str(exc))
            collector.stage_end("fetch_diff", success=False)
            raise
        else:
            collector.stage_end("fetch_diff", success=True)

    if limited_mode:
        logger.info("Running in limited mode (deterministic only)")

    scan_start = time.perf_counter()
    collector.stage_start("analysis")
    try:
        analysis = await orchestrator.run(
            scan_mode=config.scan_mode,
            diff_content=diff_content,
            changed_files=changed_files,
            run_dir=run_dir,
            run_id=run_id,
            version=ACTION_VERSION,
            dashboard_url=dashboard_url,
        )
    except Exception as exc:
        collector.record_error("analysis", str(exc))
        collector.stage_end("analysis", success=False)
        raise
    else:
        collector.stage_end("analysis", success=True)

    if analysis.llm_usage:
        model_used = analysis.llm_usage.get("model") or ""
        collector.record_llm_usage(
            model=model_used,
            tokens_in=analysis.llm_usage.get("tokens_in", 0),
            tokens_out=analysis.llm_usage.get("tokens_out", 0),
            cost_usd=analysis.llm_usage.get("cost_usd", 0),
            latency_ms=analysis.llm_usage.get("latency_ms", 0),
            fallback_used=bool(model_used and model_used == config.model_fallback),
        )

    ingest_stats = analysis.ingest_stats or {}
    collector.files_scanned = int(
        ingest_stats.get("in_scope_files", analysis.total_files_scanned or 0) or 0
    )
    total_files = int(ingest_stats.get("total_files", 0) or 0)
    collector.files_skipped = max(total_files - collector.files_scanned, 0)
    collector.total_lines = int(ingest_stats.get("total_lines", 0) or 0)

    # === PACKAGING ===
    summary_payload: dict = {}
    scan_duration_ms = 0
    packaging_success = True
    collector.stage_start("packaging")
    try:
        with logger.stage("packaging"):
            ingest_path = run_dir / "INGEST.json"
            ingest_path.write_text(json_dumps(analysis.ingest), encoding="utf-8")
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
                stages_completed=[
                    "preflight",
                    "ingest",
                    "deterministic",
                    "llm",
                    "packaging",
                ],
                review_brief_path=analysis.review_brief_path,
                fingerprint_count=fingerprint_count,
                dedupe_key=idem_key,
                policy_pack=config.policy_pack,
                policy_pack_version=config.policy_pack_version,
                error=None,
                duration_ms=scan_duration_ms,
            )
            try:
                summary_payload = json.loads(
                    pack_summary_path.read_text(encoding="utf-8")
                )
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
                artifacts_override = os.environ.get("SENTINELAYER_ARTIFACTS_DIR")
                if artifacts_override:
                    artifacts_dir = Path(artifacts_override)
                else:
                    workspace = os.environ.get("GITHUB_WORKSPACE")
                    artifacts_dir = (
                        Path(workspace) / ".sentinelayer" / "artifacts"
                        if workspace
                        else None
                    )

                if artifacts_dir and ensure_writable_dir(artifacts_dir):
                    prepare_artifacts_for_upload(run_dir, artifacts_dir)
                else:
                    logger.info(
                        "Artifact preparation skipped",
                        reason="workspace not writable",
                    )
            except Exception as exc:
                logger.warning("Artifact preparation failed", error=str(exc))
                analysis.warnings.append("Artifact preparation failed")
    except Exception as exc:
        packaging_success = False
        collector.record_error("packaging", str(exc))
        raise
    finally:
        collector.stage_end("packaging", success=packaging_success)

    # === GATE EVALUATION ===
    gate_success = True
    collector.stage_start("gate_eval")
    try:
        with logger.stage("gate_eval"):
            gate_result = evaluate_gate(
                run_dir,
                GateConfig(severity_gate=config.severity_gate),
            )
    except Exception as exc:
        gate_success = False
        collector.record_error("gate_eval", str(exc))
        raise
    finally:
        collector.stage_end("gate_eval", success=gate_success)

    status_value = (
        gate_result.status.value
        if hasattr(gate_result.status, "value")
        else str(gate_result.status)
    )
    collector.record_gate_result(status_value, gate_result.reason)
    collector.record_findings(
        analysis.counts,
        analysis.deterministic_count,
        analysis.llm_count,
    )
    logger.info(
        "Gate evaluation complete",
        status=status_value,
        block_merge=gate_result.block_merge,
        counts=analysis.counts,
    )

    # === PUBLISHING ===
    publish_success = True
    collector.stage_start("publish")
    try:
        with logger.stage("publish"):
            cost_usd = (
                analysis.llm_usage.get("cost_usd", 0.0) if analysis.llm_usage else 0.0
            )

            if not gh.token:
                message = "GitHub token missing; publish calls unavailable"
                if _publish_strict():
                    raise RuntimeError(message)
                logger.warning(message)
                analysis.warnings.append(message)
            elif ctx.pr_number:
                try:
                    github_run_id = os.environ.get("GITHUB_RUN_ID")
                    server_url = os.environ.get(
                        "GITHUB_SERVER_URL", "https://github.com"
                    )
                    artifacts_url = (
                        f"{server_url}/{ctx.repo_full_name}/actions/runs/{github_run_id}"
                        if github_run_id
                        else None
                    )
                    llm_model_used = "none"
                    if analysis.llm_success and analysis.llm_usage:
                        llm_model_used = analysis.llm_usage.get("model", config.model)

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
                        duration_ms=summary_payload.get("duration_ms")
                        or scan_duration_ms,
                        deterministic_count=analysis.deterministic_count,
                        llm_count=analysis.llm_count,
                        dedupe_key=gate_result.dedupe_key or idem_key,
                        llm_model=llm_model_used,
                    )
                    gh.create_or_update_pr_comment(
                        ctx.pr_number,
                        comment_body,
                        marker_prefix(),
                    )
                except Exception as exc:
                    if _publish_strict():
                        raise
                    logger.warning("PR comment failed", error=str(exc))
                    analysis.warnings.append("PR comment failed")

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
            if not gh.token:
                message = "GitHub token missing; check run unavailable"
                if _publish_strict():
                    raise RuntimeError(message)
                logger.warning(message)
                analysis.warnings.append(message)
            else:
                try:
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
                except Exception as exc:
                    if _publish_strict():
                        raise
                    logger.warning("Check run creation failed", error=str(exc))
                    analysis.warnings.append("Check run creation failed")

            write_step_summary(
                gate_result=gate_result,
                summary=summary_payload,
                findings=analysis.findings,
                run_id=run_id,
                version=ACTION_VERSION,
            )
    except Exception as exc:
        publish_success = False
        collector.record_error("publish", str(exc))
        raise
    finally:
        collector.stage_end("publish", success=publish_success)

    # === TELEMETRY (best effort) ===
    consent = _resolve_consent(config)
    if get_max_tier(consent) > 0:
        telemetry_success = True
        collector.stage_start("telemetry")
        try:
            with logger.stage("telemetry"):
                try:
                    await _upload_telemetry(
                        config=config,
                        run_id=run_id,
                        idem_key=idem_key,
                        analysis=analysis,
                        gate_result=gate_result,
                        ctx=ctx,
                        run_dir=run_dir,
                        collector=collector,
                        logger=logger,
                        consent=consent,
                    )
                except Exception as exc:
                    telemetry_success = False
                    collector.record_error("telemetry", str(exc))
                    logger.warning("Telemetry upload failed", error=str(exc))
        finally:
            collector.stage_end("telemetry", success=telemetry_success)

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
    run_dir: Path,
    collector: TelemetryCollector,
    logger: OmarLogger,
    consent: ConsentConfig,
) -> None:
    """Upload telemetry to Sentinelayer (best effort)."""
    _ = (run_id, gate_result)

    sentinelayer_token = config.sentinelayer_token.get_secret_value()
    oidc_token = await fetch_oidc_token(logger=logger)

    if should_upload_tier(1, consent):
        tier1_payload = build_tier1_payload(collector)
        if validate_payload_tier(tier1_payload, consent):
            await upload_telemetry(
                tier1_payload,
                sentinelayer_token=sentinelayer_token,
                oidc_token=oidc_token,
                logger=logger,
            )

    if should_upload_tier(2, consent):
        if not sentinelayer_token and not oidc_token:
            logger.warning("Telemetry tier 2 requires authentication")
        else:
            tier2_payload = build_tier2_payload(
                collector=collector,
                repo_owner=ctx.repo_owner,
                repo_name=ctx.repo_name,
                branch=ctx.head_ref or ctx.base_ref or "main",
                pr_number=ctx.pr_number,
                head_sha=ctx.head_sha,
                is_fork_pr=ctx.is_fork,
                policy_pack=config.policy_pack,
                policy_pack_version=config.policy_pack_version,
                action_version=ACTION_VERSION,
                findings_summary=findings_to_summary(analysis.findings),
                idempotency_key=idem_key,
                severity_threshold=config.severity_gate,
            )
            if validate_payload_tier(tier2_payload, consent):
                await upload_telemetry(
                    tier2_payload,
                    sentinelayer_token=sentinelayer_token,
                    oidc_token=oidc_token,
                    logger=logger,
                )

    if should_upload_tier(3, consent):
        if not sentinelayer_token:
            logger.warning("Telemetry tier 3 requires sentinelayer_token")
            return None
        manifest_path = run_dir / "ARTIFACT_MANIFEST.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load artifact manifest", error=str(exc))
            return None
        await upload_artifacts(run_dir, manifest, sentinelayer_token, logger=logger)

    return None


def _resolve_consent(config: OmarGateConfig) -> ConsentConfig:
    """Resolve consent using explicit flags when set, otherwise telemetry_tier."""
    if config.share_metadata or config.share_artifacts or not config.telemetry:
        return ConsentConfig(
            telemetry=config.telemetry,
            share_metadata=config.share_metadata,
            share_artifacts=config.share_artifacts,
            training_consent=config.training_opt_in,
        )

    tier = config.telemetry_tier
    return ConsentConfig(
        telemetry=tier > 0,
        share_metadata=tier >= 2,
        share_artifacts=tier >= 3,
        training_consent=config.training_opt_in,
    )


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
