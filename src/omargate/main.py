from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from .models import GateConfig, Finding, Counts, GateResult
from .config import OmarGateConfig
from .packaging import new_run_dir, write_findings_jsonl, write_pack_summary
from .gate import evaluate_gate
from .idempotency import compute_idempotency_key
from .github import GitHubClient
from .comment import render_pr_comment, marker
from .context import GitHubContext
from .logging import OmarLogger
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

def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

def load_event() -> dict:
    event_path = _env("GITHUB_EVENT_PATH")
    return json.loads(Path(event_path).read_text(encoding="utf-8"))

def _write_outputs(
    output_path: Path,
    result: GateResult,
    run_id: str,
    findings_path: Path | None,
    pack_summary_path: Path | None,
    estimated_cost: float,
    idempotency_key: str,
) -> None:
    with output_path.open("a", encoding="utf-8") as f:
        f.write(f"gate_status={result.status}\n")
        f.write(f"run_id={run_id}\n")
        f.write(f"p0_count={result.counts.p0}\n")
        f.write(f"p1_count={result.counts.p1}\n")
        f.write(f"p2_count={result.counts.p2}\n")
        f.write(f"p3_count={result.counts.p3}\n")
        f.write(f"findings_artifact={(str(findings_path) if findings_path else '')}\n")
        f.write(f"pack_summary_artifact={(str(pack_summary_path) if pack_summary_path else '')}\n")
        f.write(f"estimated_cost_usd={estimated_cost:.2f}\n")
        f.write(f"idempotency_key={idempotency_key}\n")

def _conclusion_for_result(result: GateResult) -> str:
    if result.status == "skipped":
        return "skipped"
    if result.block_merge:
        return "failure"
    return "success"

def main() -> int:
    config = OmarGateConfig()
    ctx = GitHubContext.from_environment()
    logger = OmarLogger(run_id="boot")

    repo = ctx.repo_full_name
    token = config.github_token.get_secret_value() or _env("GITHUB_TOKEN")
    event = load_event()

    scan_mode = config.scan_mode
    severity_gate = config.severity_gate
    policy_pack = config.policy_pack
    policy_pack_version = config.policy_pack_version

    # Pull request context (best-effort)
    pr = event.get("pull_request") or {}
    pr_number = ctx.pr_number or 0
    head_sha = ctx.head_sha

    # Run directory
    base = Path("/tmp/omar_runs")
    run_dir = new_run_dir(base)
    run_id = run_dir.name
    logger = OmarLogger(run_id=run_id)

    # Idempotency key (for check-run external_id, comment updates, telemetry)
    idem = compute_idempotency_key(
        repo=repo,
        pr_number=pr_number,
        head_sha=head_sha,
        scan_mode=scan_mode,
        policy_pack=policy_pack,
        policy_pack_version=policy_pack_version,
        action_major_version=ACTION_MAJOR_VERSION,
    )

    gh = GitHubClient(token=token, repo=repo)
    warnings: list[str] = []

    # Cost estimation (best-effort, based on PR stats when available)
    additions = int(pr.get("additions") or 0)
    deletions = int(pr.get("deletions") or 0)
    changed_files = int(pr.get("changed_files") or 0)
    estimated_cost = estimate_cost(changed_files, additions + deletions, config.model)

    def finalize(
        result: GateResult,
        conclusion: str | None = None,
        findings_path: Path | None = None,
        pack_summary_path: Path | None = None,
    ) -> int:
        dashboard_url = None
        comment_body = render_pr_comment(
            result,
            run_id,
            dashboard_url,
            estimated_cost,
            ACTION_VERSION,
            warnings=warnings or None,
        )
        if ctx.pr_number:
            gh.create_or_update_pr_comment(ctx.pr_number, comment_body, marker(run_id))
        gh.create_check_run(
            name=CHECK_NAME,
            head_sha=head_sha,
            conclusion=conclusion or _conclusion_for_result(result),
            summary=result.reason,
            details_url=dashboard_url,
            external_id=idem,
        )

        out_path = Path(_env("GITHUB_OUTPUT"))
        _write_outputs(out_path, result, run_id, findings_path, pack_summary_path, estimated_cost, idem)
        return 1 if result.block_merge else 0

    with logger.stage("preflight"):
        is_required, bp_status = check_branch_protection(gh, ctx, CHECK_NAME)
        if not is_required:
            warnings.append(
                "Branch protection does not require the Omar Gate check. "
                "Enable required status checks for enforcement."
            )
            logger.warning("branch_protection_missing", status=bp_status)

        allowed, mode, reason = check_fork_policy(ctx, config)
        if not allowed:
            result = GateResult(
                status="blocked",
                reason="Fork PR blocked by policy. Set fork_policy=limited or allow to proceed.",
                block_merge=True,
                counts=Counts(),
            )
            return finalize(result, conclusion="failure")

        async def run_preflight_checks():
            dedupe = await check_dedupe(gh, head_sha, idem, CHECK_NAME)
            rate = await check_rate_limits(gh, ctx.pr_number, config, logger)
            cost = await check_cost_approval(estimated_cost, config, ctx, gh)
            return dedupe, rate, cost

        (should_skip, existing_url), (rate_ok, rate_reason), (cost_ok, cost_status) = asyncio.run(
            run_preflight_checks()
        )

        if should_skip:
            reason = "Duplicate run detected for this commit."
            if existing_url:
                reason = f"{reason} Existing run: {existing_url}"
            result = GateResult(status="skipped", reason=reason, block_merge=False, counts=Counts())
            return finalize(result, conclusion="skipped")

        if not rate_ok:
            if rate_reason == "api_error_require_approval":
                result = GateResult(
                    status="blocked",
                    reason="Rate limit check failed due to API error; approval required.",
                    block_merge=True,
                    counts=Counts(),
                )
                return finalize(result, conclusion="action_required")
            result = GateResult(
                status="skipped",
                reason=f"Rate limit: {rate_reason}.",
                block_merge=False,
                counts=Counts(),
            )
            return finalize(result, conclusion="skipped")

        if not cost_ok:
            result = GateResult(
                status="blocked",
                reason=f"Cost approval required ({cost_status}).",
                block_merge=True,
                counts=Counts(),
            )
            return finalize(result, conclusion="action_required")

    # === SCANS (stub) ===
    findings = []  # type: list[Finding]
    findings_path = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, findings)

    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    pack_summary_path = write_pack_summary(
        run_dir=run_dir,
        run_id=run_id,
        writer_complete=True,
        findings_path=findings_path,
        counts=counts,
        tool_versions={"action": ACTION_VERSION, "policy_pack": policy_pack_version},
        stages_completed=["packaging", "gate_eval"],
        error=None,
    )

    # Gate eval (local)
    result = evaluate_gate(run_dir, GateConfig(severity_gate=severity_gate))
    return finalize(result, findings_path=findings_path, pack_summary_path=pack_summary_path)

if __name__ == "__main__":
    raise SystemExit(main())
