from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .models import GateConfig, Finding
from .config import OmarGateConfig
from .packaging import new_run_dir, write_findings_jsonl, write_pack_summary
from .gate import evaluate_gate
from .idempotency import compute_idempotency_key
from .github import GitHubClient
from .comment import render_pr_comment, marker

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

def main() -> int:
    config = OmarGateConfig()

    repo = _env("GITHUB_REPOSITORY")
    token = config.github_token.get_secret_value() or _env("GITHUB_TOKEN")
    event = load_event()

    scan_mode = config.scan_mode
    severity_gate = config.severity_gate
    policy_pack = config.policy_pack
    policy_pack_version = config.policy_pack_version

    # Pull request context (best-effort)
    pr = event.get("pull_request") or {}
    pr_number = int(event.get("number") or pr.get("number") or 0)
    head_sha = (pr.get("head") or {}).get("sha") or _env("GITHUB_SHA")

    # Run directory
    base = Path("/tmp/omar_runs")
    run_dir = new_run_dir(base)
    run_id = run_dir.name

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

    # TODO: preflight dedupe using existing check-runs by external_id/marker.

    # === SCANS (stub) ===
    findings = []  # type: list[Finding]
    findings_path = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, findings)

    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    write_pack_summary(
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

    # Publish
    gh = GitHubClient(token=token, repo=repo)
    dashboard_url = None
    cost_usd = None

    comment_body = render_pr_comment(result, run_id, dashboard_url, cost_usd, ACTION_VERSION)
    if pr_number:
        gh.create_or_update_pr_comment(pr_number, comment_body, marker(run_id))
    gh.create_check_run(
        name=CHECK_NAME,
        head_sha=head_sha,
        conclusion="failure" if result.block_merge else "success",
        summary=result.reason,
        details_url=dashboard_url,
        external_id=idem,
    )

    # Outputs
    out_path = Path(_env("GITHUB_OUTPUT"))
    with out_path.open("a", encoding="utf-8") as f:
        f.write(f"gate_status={result.status}\n")
        f.write(f"run_id={run_id}\n")
        f.write(f"p0_count={result.counts.p0}\n")
        f.write(f"p1_count={result.counts.p1}\n")
        f.write(f"p2_count={result.counts.p2}\n")
        f.write(f"p3_count={result.counts.p3}\n")
        f.write(f"findings_artifact={str(findings_path)}\n")
        f.write("estimated_cost_usd=0.00\n")

    return 1 if result.block_merge else 0

if __name__ == "__main__":
    raise SystemExit(main())
