from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from .analyze import AnalysisOrchestrator
from .analyze.spec_context import fetch_spec_context
from .comment import marker, marker_prefix, render_pr_comment
from .config import OmarGateConfig
from .context import GitHubContext
from .gate import evaluate_gate
from .github import GitHubClient, findings_to_annotations
from .idempotency import compute_idempotency_key
from .ingest.codebase_snapshot import (
    build_codebase_snapshot,
    build_codebase_synopsis,
    write_codebase_ingest_artifacts,
)
from .logging import OmarLogger
from .models import Counts, GateConfig, GateResult, GateStatus
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
from .telemetry.schemas import (
    SpecComplianceTelemetry,
    build_tier1_payload,
    build_tier2_payload,
    findings_to_summary,
)
from .telemetry.uploader import upload_artifacts, upload_telemetry
from .utils import ensure_writable_dir, json_dumps, parse_iso8601

ACTION_VERSION = "1.3.4"
ACTION_MAJOR_VERSION = "1"
CHECK_NAME = "Omar Gate"

def _to_workspace_relative(path: Path) -> str:
    """
    Prefer workspace-relative artifact paths.

    Docker actions execute in a container where $GITHUB_WORKSPACE is typically mounted at
    /github/workspace. Downstream workflow steps run on the host, so absolute container paths
    are not useful.
    """
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        try:
            rel = path.relative_to(Path(workspace))
            return str(rel).replace("\\", "/")
        except ValueError:
            pass
    return str(path).replace("\\", "/")


def _escape_workflow_command(value: str) -> str:
    """
    Escape a string for GitHub workflow commands (annotation messages).

    See: https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
    """
    if value is None:
        return ""
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_gate_annotation(
    *,
    gate_result: GateResult,
    severity_gate: str,
    run_id: str,
    run_dir: Path,
    workflow_run_url: Optional[str],
    dashboard_url: Optional[str],
) -> None:
    status = (
        gate_result.status.value
        if hasattr(gate_result.status, "value")
        else str(gate_result.status)
    )

    level = "notice"
    if status in {"blocked", "error"}:
        level = "error"
    elif status in {"needs_approval"}:
        level = "error"
    elif status in {"bypassed"}:
        level = "warning"

    title = f"Omar Gate {status.upper()}"
    counts = gate_result.counts
    counts_str = f"P0={counts.p0}, P1={counts.p1}, P2={counts.p2}, P3={counts.p3}"
    link = workflow_run_url or dashboard_url or ""
    link_str = f" Details: {link}" if link else ""

    run_dir_display = _to_workspace_relative(run_dir)
    message = (
        f"{gate_result.reason} | gate={severity_gate} | {counts_str} | "
        f"run_id={run_id}{link_str} | artifacts={run_dir_display}"
    )

    sys.stderr.write(
        f"::{level} title={_escape_workflow_command(title)}::{_escape_workflow_command(message)}\n"
    )
    sys.stderr.flush()


def _latest_completed_check_run(runs: list[dict]) -> Optional[dict]:
    best: Optional[dict] = None
    best_ts: Optional[datetime] = None
    for run in runs:
        if run.get("status") != "completed":
            continue
        ts = parse_iso8601(run.get("completed_at"))
        if not ts:
            continue
        if best_ts is None or ts > best_ts:
            best = run
            best_ts = ts
    return best


def _counts_from_summary(summary: str) -> Counts:
    def _extract(sev: str) -> int:
        m = re.search(rf"\b{re.escape(sev)}=(\d+)\b", summary)
        return int(m.group(1)) if m else 0

    return Counts(
        p0=_extract("P0"),
        p1=_extract("P1"),
        p2=_extract("P2"),
        p3=_extract("P3"),
    )


def _counts_from_check_run_output(summary: str, text: str) -> Counts:
    """
    Prefer a machine-readable marker embedded in Check Run output.text, then fall back to parsing output.summary.

    Marker format:
      <!-- sentinelayer:counts:{"P0":0,"P1":0,"P2":0,"P3":0} -->
    """
    try:
        m = re.search(
            r"<!--\s*sentinelayer:counts:(\{.*?\})\s*-->",
            text or "",
            flags=re.DOTALL,
        )
        if m:
            payload = json.loads(m.group(1))
            return Counts(
                p0=int(payload.get("P0", 0) or 0),
                p1=int(payload.get("P1", 0) or 0),
                p2=int(payload.get("P2", 0) or 0),
                p3=int(payload.get("P3", 0) or 0),
            )
    except Exception:
        pass

    return _counts_from_summary(summary or "")


def _gate_result_from_check_run(run: dict, fallback_reason: str, extra_note: str) -> GateResult:
    conclusion = str(run.get("conclusion") or "").lower()
    output = run.get("output") or {}
    summary = str(output.get("summary") or "")
    text = str(output.get("text") or "")

    counts = _counts_from_check_run_output(summary=summary, text=text)
    cleaned_text = re.sub(
        r"<!--\s*sentinelayer:counts:(\{.*?\})\s*-->",
        "",
        text,
        flags=re.DOTALL,
    ).strip()
    reason = (cleaned_text or summary.strip() or fallback_reason).strip()
    if extra_note:
        reason = f"{reason} | {extra_note}"

    if conclusion == "success":
        status = GateStatus.PASSED
    elif conclusion == "neutral":
        status = GateStatus.BYPASSED
    elif conclusion == "action_required":
        status = GateStatus.NEEDS_APPROVAL
    elif conclusion == "failure":
        # Could be a real gate block or an internal error; either way we must block merge.
        status = GateStatus.BLOCKED
    else:
        status = GateStatus.ERROR
        if not reason:
            reason = f"Unable to resolve prior Omar Gate conclusion ({conclusion or 'unknown'})."

    block_merge = status in {GateStatus.BLOCKED, GateStatus.ERROR, GateStatus.NEEDS_APPROVAL}
    return GateResult(
        status=status,
        reason=reason,
        block_merge=block_merge,
        counts=counts,
        dedupe_key=str(run.get("external_id") or ""),
    )


def _exit_code_from_gate_result(result: GateResult) -> int:
    if result.status == GateStatus.NEEDS_APPROVAL:
        return 13
    return 1 if result.block_merge else 0


def _short_circuit_with_gate_result(
    *,
    run_dir: Path,
    run_id: str,
    gate_result: GateResult,
    config: OmarGateConfig,
    idem_key: str,
    skip_label: str,
    link_url: Optional[str],
    estimated_cost_usd: float = 0.0,
) -> int:
    findings_path, pack_summary_path = _write_preflight_artifacts(
        run_dir=run_dir,
        run_id=run_id,
        gate_result=gate_result,
        config=config,
        idem_key=idem_key,
        skip_label=skip_label,
        link_url=link_url,
    )

    write_step_summary(
        gate_result=gate_result,
        summary={
            "severity_gate": config.severity_gate,
            "counts": {
                "P0": gate_result.counts.p0,
                "P1": gate_result.counts.p1,
                "P2": gate_result.counts.p2,
                "P3": gate_result.counts.p3,
            },
        },
        findings=[],
        run_id=run_id,
        version=ACTION_VERSION,
    )
    _write_github_outputs(
        run_id=run_id,
        gate_result=gate_result,
        idem_key=idem_key,
        findings_path=findings_path,
        pack_summary_path=pack_summary_path,
        estimated_cost_usd=estimated_cost_usd,
        scan_mode=config.scan_mode,
        severity_gate=config.severity_gate,
        llm_provider=config.llm_provider,
        model=config.model,
        model_fallback=config.model_fallback,
        model_fallback_used=False,
        policy_pack=config.policy_pack,
        policy_pack_version=config.policy_pack_version,
    )

    try:
        _emit_gate_annotation(
            gate_result=gate_result,
            severity_gate=config.severity_gate,
            run_id=run_id,
            run_dir=run_dir,
            workflow_run_url=link_url,
            dashboard_url=None,
        )
    except Exception:
        pass

    return _exit_code_from_gate_result(gate_result)


def _find_check_run_by_external_id(runs: list[dict], external_id: str) -> Optional[dict]:
    for run in runs:
        if run.get("external_id") == external_id:
            return run
    return None


def _find_check_run_by_marker(runs: list[dict], marker: str) -> Optional[dict]:
    for candidate in runs:
        output = candidate.get("output") or {}
        summary = output.get("summary") or ""
        text = output.get("text") or ""
        if marker in summary or marker in text:
            return candidate
    return None


def _select_check_run_for_dedupe(runs: list[dict], idem_key: str) -> Optional[dict]:
    return _find_check_run_by_external_id(runs, idem_key) or _find_check_run_by_marker(
        runs, idem_key
    )


def _select_check_run_for_mirror(runs: list[dict]) -> Optional[dict]:
    return _latest_completed_check_run(runs) or (runs[0] if runs else None)


def _short_circuit_mirror_prior_check_run(
    *,
    gh: GitHubClient,
    head_sha: str,
    idem_key: str,
    check_name: str,
    select: str,  # "dedupe" or "latest"
    fallback_reason: str,
    note_prefix: str,
    run_dir: Path,
    run_id: str,
    config: OmarGateConfig,
    skip_label: str,
    explicit_url: Optional[str] = None,
) -> int:
    if not gh.token:
        raise RuntimeError("GitHub token missing; cannot resolve prior check run outcome")

    runs = gh.list_check_runs(head_sha, check_name)
    if select == "dedupe":
        run = _select_check_run_for_dedupe(runs, idem_key)
    else:
        run = _select_check_run_for_mirror(runs)

    if not run:
        raise RuntimeError("Unable to resolve a prior Omar Gate check run to mirror")

    link_url = explicit_url or run.get("html_url") or run.get("details_url")
    note = note_prefix + (f" See: {link_url}" if link_url else "")
    gate_result = _gate_result_from_check_run(
        run,
        fallback_reason=fallback_reason,
        extra_note=note,
    )

    return _short_circuit_with_gate_result(
        run_dir=run_dir,
        run_id=run_id,
        gate_result=gate_result,
        config=config,
        idem_key=idem_key,
        skip_label=skip_label,
        link_url=link_url,
    )


def _write_preflight_artifacts(
    run_dir: Path,
    run_id: str,
    gate_result: GateResult,
    config: OmarGateConfig,
    idem_key: str,
    skip_label: str,
    link_url: Optional[str],
) -> tuple[Path, Path]:
    # Ensure the output run directory exists so upload-artifact steps don't break on skips.
    run_dir.mkdir(parents=True, exist_ok=True)

    findings_path = run_dir / "FINDINGS.jsonl"
    if not findings_path.exists():
        findings_path.write_text("", encoding="utf-8")

    counts = {
        "P0": int(gate_result.counts.p0),
        "P1": int(gate_result.counts.p1),
        "P2": int(gate_result.counts.p2),
        "P3": int(gate_result.counts.p3),
    }
    pack_summary_path = write_pack_summary(
        run_dir=run_dir,
        run_id=run_id,
        writer_complete=True,
        findings_path=findings_path,
        counts=counts,
        tool_versions={
            "action": ACTION_VERSION,
            "policy_pack": config.policy_pack_version,
        },
        stages_completed=["preflight"],
        review_brief_path=None,
        severity_gate=config.severity_gate,
        llm_usage=None,
        error=f"preflight_short_circuit:{skip_label}",
        fingerprint_count=None,
        dedupe_key=idem_key,
        policy_pack=config.policy_pack,
        policy_pack_version=config.policy_pack_version,
        scan_mode=config.scan_mode,
        llm_provider=config.llm_provider,
        model_used=config.model,
        model_fallback=config.model_fallback,
        model_fallback_used=False,
        duration_ms=0,
    )

    skip_md = run_dir / "SKIP.md"
    url_line = f"\n\nLink: {link_url}\n" if link_url else "\n"
    skip_md.write_text(
        f"# Omar Gate Short-Circuit\n\nReason: {skip_label}\n{url_line}",
        encoding="utf-8",
    )

    return findings_path, pack_summary_path


def _map_category_to_spec_sections(category: str) -> set[str]:
    value = str(category or "").strip().lower()
    if not value:
        return set()

    security_tokens = {
        "security",
        "auth",
        "secret",
        "permission",
        "crypto",
        "xss",
        "sqli",
        "sql",
        "csrf",
        "injection",
        "dependency",
        "supply",
        "vuln",
        "cve",
    }
    quality_tokens = {
        "quality",
        "lint",
        "style",
        "complexity",
        "performance",
        "type",
        "typing",
        "test",
    }
    domain_tokens = {"domain", "business", "logic"}

    sections: set[str] = set()
    if any(token in value for token in security_tokens):
        sections.add("5")
    if any(token in value for token in quality_tokens):
        sections.add("7")
    if any(token in value for token in domain_tokens):
        sections.add("6")
    return sections


def _build_spec_compliance_from_findings(
    *,
    spec_context: Optional[dict],
    findings: list[dict],
) -> Optional[SpecComplianceTelemetry]:
    if not spec_context:
        return None

    spec_hash = str(spec_context.get("spec_hash") or "").strip().lower()
    if not spec_hash:
        return None

    sections_checked: set[str] = set()
    sections_violated: set[str] = set()

    if spec_context.get("security_rules"):
        sections_checked.add("5")
    if spec_context.get("quality_gates"):
        sections_checked.add("7")
    if spec_context.get("domain_rules"):
        sections_checked.add("6")

    for finding in findings or []:
        sections = _map_category_to_spec_sections(str(finding.get("category") or ""))
        if not sections:
            continue
        sections_checked.update(sections)
        sections_violated.update(sections)

    return SpecComplianceTelemetry(
        spec_hash=spec_hash,
        sections_checked=sorted(sections_checked),
        sections_violated=sorted(sections_violated),
    )


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

    # Defaults ensure we can emit telemetry even on config/context failures.
    exit_code = 2
    run_id = str(uuid.uuid4())
    run_dir = get_run_dir(run_id)
    logger = OmarLogger(run_id)
    collector = TelemetryCollector(
        run_id=run_id,
        repo_full_name=os.environ.get("GITHUB_REPOSITORY", "unknown/unknown"),
    )
    collector.exit_code = exit_code

    # Best-effort config-derived fields (may be overwritten after config parses).
    collector.scan_mode = (
        os.environ.get("INPUT_SCAN_MODE", "pr-diff").strip().lower() or "pr-diff"
    )
    collector.llm_provider = (
        (os.environ.get("INPUT_LLM_PROVIDER") or "openai").strip().lower() or "openai"
    )
    collector.model_used = (os.environ.get("INPUT_MODEL") or "").strip()

    config: Optional[OmarGateConfig] = None
    ctx: Optional[GitHubContext] = None
    repo_root = Path(os.environ.get("GITHUB_WORKSPACE", "."))

    dashboard_url: Optional[str] = None
    idem_key = ""
    analysis = None
    codebase_snapshot: Optional[dict] = None
    codebase_synopsis = ""
    spec_context: Optional[dict] = None
    spec_compliance: Optional[SpecComplianceTelemetry] = None
    gate_result: Optional[GateResult] = None
    findings_path: Optional[Path] = None
    pack_summary_path: Optional[Path] = None
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    workflow_run_url: Optional[str] = None

    try:
        try:
            config = OmarGateConfig()
        except Exception as exc:
            print(f"::error::Configuration error: {exc}")
            collector.record_error("config", str(exc))
            collector.record_preflight_exit(reason="config_error", exit_code=2)
            exit_code = 2
            return exit_code

        collector.scan_mode = config.scan_mode
        collector.llm_provider = config.llm_provider
        collector.model_used = config.model

        try:
            ctx = GitHubContext.from_environment()
        except Exception as exc:
            print(f"::error::Failed to load GitHub context: {exc}")
            collector.record_error("context", str(exc))
            collector.record_preflight_exit(reason="context_error", exit_code=2)
            exit_code = 2
            return exit_code

        logger.info(
            "Omar Gate starting",
            repo=ctx.repo_full_name,
            pr_number=ctx.pr_number,
            head_sha=ctx.head_sha,
            scan_mode=config.scan_mode,
        )

        github_run_id = os.environ.get("GITHUB_RUN_ID")
        workflow_run_url = (
            f"{server_url}/{ctx.repo_full_name}/actions/runs/{github_run_id}"
            if github_run_id
            else None
        )

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

        oidc_token = await fetch_oidc_token(logger=logger)
        if config.sentinelayer_spec_id:
            spec_context = await fetch_spec_context(
                spec_hash=config.sentinelayer_spec_id,
                sentinelayer_token=config.sentinelayer_token.get_secret_value(),
                oidc_token=oidc_token or "",
            )
            if spec_context:
                logger.info(
                    "Loaded Sentinelayer spec context",
                    spec_hash=str(spec_context.get("spec_hash", ""))[:12],
                )

        estimated_cost = _estimate_cost(ctx, gh, config)

        # === PREFLIGHT ===
        preflight_success = True
        scan_mode_override: Optional[str] = None
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

                    try:
                        exit_code = _short_circuit_mirror_prior_check_run(
                            gh=gh,
                            head_sha=ctx.head_sha,
                            idem_key=idem_key,
                            check_name=CHECK_NAME,
                            select="dedupe",
                            fallback_reason="Deduped",
                            note_prefix="Deduped (already analyzed). Mirroring prior Omar Gate result.",
                            run_dir=run_dir,
                            run_id=run_id,
                            config=config,
                            skip_label="dedupe",
                            explicit_url=existing_url,
                        )
                    except Exception as exc:
                        print(f"::error::Dedupe short-circuit failed: {exc}")
                        collector.record_error("preflight", str(exc))
                        exit_code = 2

                    collector.record_preflight_exit(reason="dedupe", exit_code=exit_code)
                    return exit_code

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
                        comment_url = gh.create_or_update_pr_comment(
                            ctx.pr_number,
                            comment_body,
                            marker_prefix(),
                        )
                        logger.info("PR comment upserted", url=comment_url)
                    exit_code = 12
                    collector.record_preflight_exit(reason="fork_blocked", exit_code=exit_code)
                    return exit_code

                proceed, rate_reason = await check_rate_limits(
                    gh, ctx.pr_number, config, logger
                )
                if not proceed:
                    collector.rate_limit_skipped = True
                    preflight_success = False
                    logger.info("Rate limited", reason=rate_reason)
                    if rate_reason == "api_error_require_approval":
                        gate_result = GateResult(
                            status=GateStatus.NEEDS_APPROVAL,
                            reason=(
                                "Rate limit enforcement unavailable due to GitHub API error; "
                                "approval required to proceed. "
                                "Set rate_limit_fail_mode=open to skip enforcement."
                            ),
                            block_merge=True,
                            counts=Counts(),
                            dedupe_key=idem_key,
                        )
                        status_value = (
                            gate_result.status.value
                            if hasattr(gate_result.status, "value")
                            else str(gate_result.status)
                        )
                        collector.record_gate_result(status_value, gate_result.reason)
                        exit_code = _short_circuit_with_gate_result(
                            run_dir=run_dir,
                            run_id=run_id,
                            gate_result=gate_result,
                            config=config,
                            idem_key=idem_key,
                            skip_label=f"rate_limit:{rate_reason}",
                            link_url=None,
                            estimated_cost_usd=estimated_cost,
                        )
                        collector.record_preflight_exit(reason="rate_limit", exit_code=exit_code)
                        return exit_code

                    try:
                        exit_code = _short_circuit_mirror_prior_check_run(
                            gh=gh,
                            head_sha=ctx.head_sha,
                            idem_key=idem_key,
                            check_name=CHECK_NAME,
                            select="latest",
                            fallback_reason="Rate limited",
                            note_prefix=f"Rate limited ({rate_reason}). Mirroring latest Omar Gate result.",
                            run_dir=run_dir,
                            run_id=run_id,
                            config=config,
                            skip_label=f"rate_limit:{rate_reason}",
                        )
                    except Exception:
                        # No prior check to mirror — create a clear neutral result.
                        wait_mins = config.min_scan_interval_minutes
                        reason_msg = (
                            f"Rate limited ({rate_reason}). "
                            f"Please wait ~{wait_mins} min before re-running."
                        )
                        print(f"::warning::{reason_msg}")
                        gate_result = GateResult(
                            status=GateStatus.BYPASSED,
                            reason=reason_msg,
                            block_merge=False,
                            counts=Counts(),
                            dedupe_key=idem_key,
                        )
                        try:
                            gh.create_check_run(
                                name=CHECK_NAME,
                                head_sha=ctx.head_sha,
                                conclusion="neutral",
                                summary=reason_msg,
                                title="Omar Gate: RATE LIMITED",
                                text=f"Scan skipped — cooldown period ({wait_mins} min) not met.",
                            )
                        except Exception:
                            pass
                        exit_code = 0

                    collector.record_preflight_exit(reason="rate_limit", exit_code=exit_code)
                    return exit_code

                approved, cost_status = await check_cost_approval(
                    estimated_cost, config, ctx, gh
                )
                collector.approval_state = cost_status
                if not approved:
                    preflight_success = False
                    logger.info("Cost approval required", status=cost_status)
                    exit_code = 13
                    collector.record_preflight_exit(reason="cost_approval", exit_code=exit_code)
                    return exit_code

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
                spec_context=spec_context,
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
            model_used = str(analysis.llm_usage.get("model") or "").strip()
            provider_used = (
                str(analysis.llm_usage.get("engine") or analysis.llm_usage.get("provider") or "")
                .strip()
                or None
            )
            fallback_used = bool(model_used and model_used == config.model_fallback)

            # Codex CLI runs may not provide token/cost accounting. Treat missing as 0 for telemetry.
            tokens_in = int(analysis.llm_usage.get("tokens_in") or 0)
            tokens_out = int(analysis.llm_usage.get("tokens_out") or 0)
            latency_ms = int(analysis.llm_usage.get("latency_ms") or 0)
            cost_raw = analysis.llm_usage.get("cost_usd")
            cost_usd = float(cost_raw) if cost_raw is not None else 0.0

            collector.record_llm_usage(
                model=model_used,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
                latency_ms=latency_ms,
                fallback_used=fallback_used,
                provider=provider_used,
                fallback_provider=provider_used if fallback_used else None,
                fallback_model=model_used if fallback_used else None,
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

                try:
                    # Deterministic, bounded codebase snapshot artifacts (no LLM required).
                    codebase_snapshot = build_codebase_snapshot(analysis.ingest)
                    codebase_synopsis = build_codebase_synopsis(
                        codebase_snapshot=codebase_snapshot,
                        quick_learn=analysis.quick_learn,
                    )
                    write_codebase_ingest_artifacts(
                        run_dir, analysis.ingest, snapshot=codebase_snapshot
                    )
                except Exception as exc:
                    logger.warning("Codebase snapshot generation failed", error=str(exc))
                    analysis.warnings.append("Codebase snapshot generation failed")

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
                    severity_gate=config.severity_gate,
                    llm_usage=analysis.llm_usage,
                    fingerprint_count=fingerprint_count,
                    dedupe_key=idem_key,
                    policy_pack=config.policy_pack,
                    policy_pack_version=config.policy_pack_version,
                    scan_mode=config.scan_mode,
                    llm_provider=(collector.llm_provider or config.llm_provider),
                    model_used=(collector.model_used or config.model),
                    model_fallback=config.model_fallback,
                    model_fallback_used=collector.model_fallback_used,
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

        if spec_context:
            spec_compliance = _build_spec_compliance_from_findings(
                spec_context=spec_context,
                findings=analysis.findings,
            )

        # === PUBLISHING ===
        publish_success = True
        collector.stage_start("publish")
        try:
            with logger.stage("publish"):
                # Avoid misleading "$0.00" when the engine cannot report usage (e.g. Codex CLI).
                if int(analysis.llm_count or 0) == 0:
                    cost_usd = 0.0
                elif analysis.llm_usage:
                    cost_raw = analysis.llm_usage.get("cost_usd")
                    cost_usd = float(cost_raw) if cost_raw is not None else None
                else:
                    cost_usd = None

                if not gh.token:
                    message = "GitHub token missing; publish calls unavailable"
                    if _publish_strict():
                        raise RuntimeError(message)
                    logger.warning(message)
                    analysis.warnings.append(message)
                elif ctx.pr_number:
                    try:
                        llm_engine_used = "disabled"
                        llm_model_used = "n/a"
                        if int(analysis.llm_count or 0) > 0:
                            if analysis.llm_usage:
                                llm_engine_used = str(
                                    analysis.llm_usage.get("engine")
                                    or analysis.llm_usage.get("provider")
                                    or "llm"
                                ).strip() or "llm"
                                llm_model_used = str(
                                    analysis.llm_usage.get("model") or config.model
                                ).strip() or config.model
                            else:
                                llm_engine_used = "llm"
                                llm_model_used = str(config.model).strip() or "unknown"

                        review_brief_md = None
                        try:
                            if analysis.review_brief_path and analysis.review_brief_path.exists():
                                review_brief_md = analysis.review_brief_path.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                        except Exception:
                            review_brief_md = None

                        comment_body = render_pr_comment(
                            result=gate_result,
                            run_id=run_id,
                            repo_full_name=ctx.repo_full_name,
                            pr_number=ctx.pr_number,
                            dashboard_url=dashboard_url,
                            artifacts_url=workflow_run_url,
                            estimated_cost_usd=estimated_cost,
                            version=ACTION_VERSION,
                            findings=analysis.findings,
                            codebase_snapshot=codebase_snapshot,
                            codebase_synopsis=codebase_synopsis,
                            warnings=analysis.warnings,
                            review_brief_md=review_brief_md,
                            scan_mode=config.scan_mode,
                            policy_pack=config.policy_pack,
                            policy_pack_version=config.policy_pack_version,
                            severity_gate=config.severity_gate,
                            duration_ms=summary_payload.get("duration_ms")
                            or scan_duration_ms,
                            files_scanned=collector.files_scanned,
                            llm_engine=llm_engine_used,
                            deterministic_count=analysis.deterministic_count,
                            llm_count=analysis.llm_count,
                            dedupe_key=gate_result.dedupe_key or idem_key,
                            llm_model=llm_model_used,
                            actual_cost_usd=cost_usd,
                            head_sha=ctx.head_sha,
                            server_url=server_url,
                        )
                        comment_url = gh.create_or_update_pr_comment(
                            ctx.pr_number,
                            comment_body,
                            marker_prefix(),
                        )
                        logger.info("PR comment upserted", url=comment_url)
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
                check_text = gate_result.reason
                try:
                    counts_marker = json.dumps(
                        {
                            "P0": int(counts.get("P0", 0) or 0),
                            "P1": int(counts.get("P1", 0) or 0),
                            "P2": int(counts.get("P2", 0) or 0),
                            "P3": int(counts.get("P3", 0) or 0),
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    check_text = f"{check_text}\n\n<!-- sentinelayer:counts:{counts_marker} -->"
                except Exception:
                    pass
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
                        check_url = gh.create_check_run(
                            name=CHECK_NAME,
                            head_sha=ctx.head_sha,
                            conclusion=conclusion_map.get(status_key, "failure"),
                            summary=summary_text,
                            title=f"Omar Gate: {status_key.upper()}",
                            text=check_text,
                            details_url=workflow_run_url or dashboard_url,
                            external_id=idem_key,
                            annotations=annotations,
                        )
                        logger.info("Check run created", url=check_url)
                    except Exception as exc:
                        if _publish_strict():
                            raise
                        logger.warning("Check run creation failed", error=str(exc))
                        analysis.warnings.append("Check run creation failed")

                try:
                    write_step_summary(
                        gate_result=gate_result,
                        summary=summary_payload,
                        findings=analysis.findings,
                        codebase_snapshot=codebase_snapshot,
                        codebase_synopsis=codebase_synopsis,
                        run_id=run_id,
                        version=ACTION_VERSION,
                    )
                except OSError as exc:
                    logger.warning("Step summary write failed", error=str(exc))
        except Exception as exc:
            publish_success = False
            collector.record_error("publish", str(exc))
            raise
        finally:
            collector.stage_end("publish", success=publish_success)

        # === OUTPUTS ===
        try:
            estimated_cost_usd = float(estimated_cost or 0.0)
            audit_report_path = run_dir / "AUDIT_REPORT.md"
            _write_github_outputs(
                run_id=run_id,
                idem_key=idem_key,
                findings_path=findings_path,
                pack_summary_path=pack_summary_path,
                gate_result=gate_result,
                estimated_cost_usd=estimated_cost_usd,
                review_brief_path=analysis.review_brief_path,
                audit_report_path=audit_report_path if audit_report_path.exists() else None,
                scan_mode=config.scan_mode,
                severity_gate=config.severity_gate,
                llm_provider=(collector.llm_provider or config.llm_provider),
                model=(collector.model_used or config.model),
                model_fallback=config.model_fallback,
                model_fallback_used=collector.model_fallback_used,
                policy_pack=config.policy_pack,
                policy_pack_version=config.policy_pack_version,
            )
        except OSError as exc:
            logger.warning("GitHub outputs write failed", error=str(exc))

        try:
            _emit_gate_annotation(
                gate_result=gate_result,
                severity_gate=config.severity_gate,
                run_id=run_id,
                run_dir=run_dir,
                workflow_run_url=workflow_run_url,
                dashboard_url=dashboard_url,
            )
        except Exception:
            pass

        exit_code = 1 if gate_result.block_merge else 0
        collector.exit_reason = "completed"
        collector.exit_code = exit_code
        return exit_code
    except Exception as exc:
        collector.record_error("unhandled", str(exc))
        if not collector.exit_reason:
            collector.exit_reason = "unhandled"
        collector.exit_code = int(exit_code)
        raise
    finally:
        collector.exit_code = int(exit_code)
        if not collector.exit_reason:
            collector.exit_reason = "unhandled" if exit_code == 2 else "completed"
        try:
            await _upload_telemetry_always(
                config=config,
                run_id=run_id,
                idem_key=idem_key,
                analysis=analysis,
                gate_result=gate_result,
                spec_compliance=spec_compliance,
                ctx=ctx,
                run_dir=run_dir,
                collector=collector,
                logger=logger,
            )
        except Exception:
            pass


async def _upload_telemetry(
    config: OmarGateConfig,
    run_id: str,
    idem_key: str,
    analysis,
    gate_result,
    spec_compliance: Optional[SpecComplianceTelemetry],
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
                spec_compliance=spec_compliance,
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


def _parse_bool_env(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _parse_int_env(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    try:
        return int(value.strip())
    except Exception:
        return default


def _resolve_consent_best_effort(config: Optional[OmarGateConfig]) -> ConsentConfig:
    if config is not None:
        return _resolve_consent(config)

    telemetry = _parse_bool_env(os.environ.get("INPUT_TELEMETRY"), True)
    share_metadata = _parse_bool_env(os.environ.get("INPUT_SHARE_METADATA"), False)
    share_artifacts = _parse_bool_env(os.environ.get("INPUT_SHARE_ARTIFACTS"), False)
    training_opt_in = _parse_bool_env(os.environ.get("INPUT_TRAINING_OPT_IN"), False)

    if share_metadata or share_artifacts or not telemetry:
        return ConsentConfig(
            telemetry=telemetry,
            share_metadata=share_metadata,
            share_artifacts=share_artifacts,
            training_consent=training_opt_in,
        )

    tier = _parse_int_env(os.environ.get("INPUT_TELEMETRY_TIER"), 1)
    tier = max(0, min(3, tier))
    return ConsentConfig(
        telemetry=telemetry and tier > 0,
        share_metadata=tier >= 2,
        share_artifacts=tier >= 3,
        training_consent=training_opt_in,
    )


async def _upload_telemetry_always(
    *,
    config: Optional[OmarGateConfig],
    run_id: str,
    idem_key: str,
    analysis,
    gate_result,
    spec_compliance: Optional[SpecComplianceTelemetry],
    ctx: Optional[GitHubContext],
    run_dir: Path,
    collector: TelemetryCollector,
    logger: OmarLogger,
) -> None:
    """Upload telemetry even on preflight exits (best effort)."""

    consent = _resolve_consent_best_effort(config)
    if get_max_tier(consent) <= 0:
        return

    telemetry_success = True
    collector.stage_start("telemetry")
    try:
        with logger.stage("telemetry"):
            try:
                # Full context path.
                if (
                    config is not None
                    and ctx is not None
                    and analysis is not None
                    and gate_result is not None
                ):
                    await _upload_telemetry(
                        config=config,
                        run_id=run_id,
                        idem_key=idem_key,
                        analysis=analysis,
                        gate_result=gate_result,
                        spec_compliance=spec_compliance,
                        ctx=ctx,
                        run_dir=run_dir,
                        collector=collector,
                        logger=logger,
                        consent=consent,
                    )
                else:
                    # Minimal Tier 1 path for early exits.
                    sentinelayer_token = (
                        config.sentinelayer_token.get_secret_value()
                        if config is not None
                        else (
                            os.environ.get("INPUT_SENTINELAYER_TOKEN")
                            or os.environ.get("SENTINELAYER_TOKEN")
                            or ""
                        )
                    )
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

                    # Best-effort Tier 2 path (share_metadata) when we have repo identity.
                    if config is not None and ctx is not None and should_upload_tier(2, consent):
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
                                findings_summary=[],
                                idempotency_key=idem_key,
                                severity_threshold=config.severity_gate,
                                spec_compliance=None,
                            )
                            if validate_payload_tier(tier2_payload, consent):
                                await upload_telemetry(
                                    tier2_payload,
                                    sentinelayer_token=sentinelayer_token,
                                    oidc_token=oidc_token,
                                    logger=logger,
                                )
            except Exception as exc:
                telemetry_success = False
                collector.record_error("telemetry", str(exc))
                logger.warning("Telemetry upload failed", error=str(exc))
    finally:
        collector.stage_end("telemetry", success=telemetry_success)


def _write_github_outputs(
    run_id: str,
    idem_key: str,
    findings_path: Path,
    pack_summary_path: Path,
    gate_result: GateResult,
    estimated_cost_usd: float = 0.0,
    *,
    review_brief_path: Optional[Path] = None,
    audit_report_path: Optional[Path] = None,
    scan_mode: Optional[str] = None,
    severity_gate: Optional[str] = None,
    llm_provider: Optional[str] = None,
    model: Optional[str] = None,
    model_fallback: Optional[str] = None,
    model_fallback_used: Optional[bool] = None,
    policy_pack: Optional[str] = None,
    policy_pack_version: Optional[str] = None,
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
        f.write(f"p0_count={gate_result.counts.p0}\n")
        f.write(f"p1_count={gate_result.counts.p1}\n")
        f.write(f"p2_count={gate_result.counts.p2}\n")
        f.write(f"p3_count={gate_result.counts.p3}\n")
        f.write(f"findings_artifact={_to_workspace_relative(findings_path)}\n")
        f.write(f"pack_summary_artifact={_to_workspace_relative(pack_summary_path)}\n")
        ingest_path = pack_summary_path.parent / "INGEST.json"
        if ingest_path.exists():
            f.write(f"ingest_artifact={_to_workspace_relative(ingest_path)}\n")
        codebase_ingest_path = pack_summary_path.parent / "CODEBASE_INGEST.json"
        if codebase_ingest_path.exists():
            f.write(
                f"codebase_ingest_artifact={_to_workspace_relative(codebase_ingest_path)}\n"
            )
        codebase_summary_json = pack_summary_path.parent / "CODEBASE_INGEST_SUMMARY.json"
        if codebase_summary_json.exists():
            f.write(
                f"codebase_ingest_summary_artifact={_to_workspace_relative(codebase_summary_json)}\n"
            )
        codebase_summary_md = pack_summary_path.parent / "CODEBASE_INGEST_SUMMARY.md"
        if codebase_summary_md.exists():
            f.write(
                f"codebase_ingest_summary_md_artifact={_to_workspace_relative(codebase_summary_md)}\n"
            )
        if review_brief_path and review_brief_path.exists():
            f.write(
                f"review_brief_artifact={_to_workspace_relative(review_brief_path)}\n"
            )
        if audit_report_path and audit_report_path.exists():
            f.write(
                f"audit_report_artifact={_to_workspace_relative(audit_report_path)}\n"
            )
        f.write(f"idempotency_key={idem_key}\n")
        f.write(f"estimated_cost_usd={estimated_cost_usd:.4f}\n")
        if scan_mode is not None:
            f.write(f"scan_mode={scan_mode}\n")
        if severity_gate is not None:
            f.write(f"severity_gate={severity_gate}\n")
        if llm_provider is not None:
            f.write(f"llm_provider={llm_provider}\n")
        if model is not None:
            f.write(f"model={model}\n")
        if model_fallback is not None:
            f.write(f"model_fallback={model_fallback}\n")
        if model_fallback_used is not None:
            f.write(f"model_fallback_used={'true' if model_fallback_used else 'false'}\n")
        if policy_pack is not None:
            f.write(f"policy_pack={policy_pack}\n")
        if policy_pack_version is not None:
            f.write(f"policy_pack_version={policy_pack_version}\n")


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
