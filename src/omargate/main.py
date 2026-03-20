from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ACTION_VERSION = "1.4.0"
SENTINELAYER_WEB_BASE = "https://sentinelayer.com"


@dataclass(frozen=True)
class BridgeConfig:
    token: str
    api_url: str
    repo_full_name: str
    event_path: Path
    event_name: str
    scan_mode: str
    severity_gate: str
    command_override: str
    provider_installation_id: int | None
    wait_for_completion: bool
    wait_timeout_seconds: int
    wait_poll_seconds: int
    pr_number_override: int | None


def _write_output(name: str, value: str) -> None:
    output_path = str(os.environ.get("GITHUB_OUTPUT", "")).strip()
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def _append_summary(markdown: str) -> None:
    summary_path = str(os.environ.get("GITHUB_STEP_SUMMARY", "")).strip()
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(markdown)
        if not markdown.endswith("\n"):
            handle.write("\n")


def _bool_input(name: str, default: bool) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _int_input(name: str, default: int) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _load_config() -> BridgeConfig:
    token = str(
        os.environ.get("INPUT_SENTINELAYER_TOKEN")
        or os.environ.get("SENTINELAYER_TOKEN")
        or ""
    ).strip()
    api_url = str(
        os.environ.get("INPUT_SENTINELAYER_API_URL")
        or "https://api.sentinelayer.com"
    ).strip().rstrip("/")
    repo_full_name = str(os.environ.get("GITHUB_REPOSITORY") or "").strip()
    event_path = Path(str(os.environ.get("GITHUB_EVENT_PATH") or ""))
    event_name = str(os.environ.get("GITHUB_EVENT_NAME") or "").strip()
    scan_mode = str(os.environ.get("INPUT_SCAN_MODE") or "deep").strip().lower()
    severity_gate = str(os.environ.get("INPUT_SEVERITY_GATE") or "P1").strip().upper()
    command_override = str(os.environ.get("INPUT_COMMAND") or "").strip()
    provider_installation_id_raw = str(
        os.environ.get("INPUT_PROVIDER_INSTALLATION_ID") or ""
    ).strip()
    provider_installation_id = (
        int(provider_installation_id_raw)
        if provider_installation_id_raw.isdigit()
        else None
    )
    wait_for_completion = _bool_input("INPUT_WAIT_FOR_COMPLETION", True)
    wait_timeout_seconds = max(30, _int_input("INPUT_WAIT_TIMEOUT_SECONDS", 900))
    wait_poll_seconds = max(5, _int_input("INPUT_WAIT_POLL_SECONDS", 10))
    pr_number_raw = str(os.environ.get("INPUT_PR_NUMBER") or "").strip()
    pr_number_override = int(pr_number_raw) if pr_number_raw.isdigit() else None

    missing = []
    if not token:
        missing.append("sentinelayer_token")
    if not api_url:
        missing.append("sentinelayer_api_url")
    if not repo_full_name:
        missing.append("GITHUB_REPOSITORY")
    if not event_path.exists():
        missing.append("GITHUB_EVENT_PATH")
    if missing:
        raise RuntimeError(f"Missing required configuration: {', '.join(missing)}")

    return BridgeConfig(
        token=token,
        api_url=api_url,
        repo_full_name=repo_full_name,
        event_path=event_path,
        event_name=event_name,
        scan_mode=scan_mode,
        severity_gate=severity_gate,
        command_override=command_override,
        provider_installation_id=provider_installation_id,
        wait_for_completion=wait_for_completion,
        wait_timeout_seconds=wait_timeout_seconds,
        wait_poll_seconds=wait_poll_seconds,
        pr_number_override=pr_number_override,
    )


def _api_json_request(
    *, method: str, url: str, token: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    body: bytes | None = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "sentinelayer-compat-action/1.4.0",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url=url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API request failed [{exc.code}] {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"API request failed [{url}]: {exc}") from exc


def _detect_pr_number(payload: dict[str, Any], *, fallback_pr_number: int | None = None) -> int:
    if fallback_pr_number and fallback_pr_number > 0:
        return fallback_pr_number

    pull_request = payload.get("pull_request")
    if isinstance(pull_request, dict):
        number = pull_request.get("number")
        if isinstance(number, int) and number > 0:
            return number

    issue = payload.get("issue")
    if isinstance(issue, dict) and isinstance(issue.get("pull_request"), dict):
        number = issue.get("number")
        if isinstance(number, int) and number > 0:
            return number

    check_run = payload.get("check_run")
    if isinstance(check_run, dict):
        prs = check_run.get("pull_requests")
        if isinstance(prs, list) and prs:
            first = prs[0] if isinstance(prs[0], dict) else {}
            number = first.get("number")
            if isinstance(number, int) and number > 0:
                return number

    workflow_dispatch_inputs = payload.get("inputs")
    if isinstance(workflow_dispatch_inputs, dict):
        raw = str(workflow_dispatch_inputs.get("pr_number") or "").strip()
        if raw.isdigit() and int(raw) > 0:
            return int(raw)

    raise RuntimeError("Unable to resolve PR number from event payload. Provide input 'pr_number'.")


def _command_for_scan_mode(scan_mode: str) -> str:
    normalized = str(scan_mode or "").strip().lower()
    if normalized in {"baseline", "baseline-only", "baseline_scan", "baseline-scan"}:
        return "/omar baseline"
    if normalized in {
        "full-depth",
        "full_depth",
        "full-depth-13",
        "full_depth_13",
        "full",
    }:
        return "/omar full-depth"
    return "/omar deep-scan"


def _blocking_count(*, severity_gate: str, counts: dict[str, int]) -> int:
    gate = str(severity_gate or "P1").strip().upper()
    p0 = int(counts.get("P0") or 0)
    p1 = int(counts.get("P1") or 0)
    p2 = int(counts.get("P2") or 0)
    if gate == "NONE":
        return 0
    if gate == "P0":
        return p0
    if gate == "P2":
        return p0 + p1 + p2
    return p0 + p1


def _terminal_status(status: str) -> bool:
    normalized = str(status or "").strip().lower()
    return normalized in {"completed", "failed", "error", "cancelled", "blocked"}


def _emit_outputs(
    *,
    gate_status: str,
    counts: dict[str, int],
    run_id: str,
    scan_mode: str,
    severity_gate: str,
) -> None:
    _write_output("gate_status", gate_status)
    _write_output("p0_count", str(int(counts.get("P0") or 0)))
    _write_output("p1_count", str(int(counts.get("P1") or 0)))
    _write_output("p2_count", str(int(counts.get("P2") or 0)))
    _write_output("p3_count", str(int(counts.get("P3") or 0)))
    _write_output("run_id", run_id)

    # Legacy outputs retained for compatibility.
    _write_output("findings_artifact", "")
    _write_output("pack_summary_artifact", "")
    _write_output("ingest_artifact", "")
    _write_output("codebase_ingest_artifact", "")
    _write_output("codebase_ingest_summary_artifact", "")
    _write_output("codebase_ingest_summary_md_artifact", "")
    _write_output("review_brief_artifact", "")
    _write_output("audit_report_artifact", "")
    _write_output("estimated_cost_usd", "")
    _write_output("idempotency_key", run_id)
    _write_output("scan_mode", scan_mode)
    _write_output("severity_gate", severity_gate)
    _write_output("llm_provider", "sentinelayer_managed")
    _write_output("model", "github_app_managed")
    _write_output("model_fallback", "")
    _write_output("model_fallback_used", "false")
    _write_output("policy_pack", "omar")
    _write_output("policy_pack_version", "v1")


def main() -> int:
    print(
        "::notice::Omar Gate Action v1 is now a thin compatibility bridge. "
        "Proprietary scan logic runs in Sentinelayer GitHub App backend."
    )

    try:
        config = _load_config()
        payload = json.loads(config.event_path.read_text(encoding="utf-8"))
        pr_number = _detect_pr_number(payload, fallback_pr_number=config.pr_number_override)
        command = config.command_override or _command_for_scan_mode(config.scan_mode)

        trigger_payload: dict[str, Any] = {
            "repository_full_name": config.repo_full_name,
            "pr_number": pr_number,
            "command": command,
        }
        if config.provider_installation_id and config.provider_installation_id > 0:
            trigger_payload["provider_installation_id"] = int(config.provider_installation_id)

        trigger_url = f"{config.api_url}/api/v1/github-app/trigger"
        trigger_response = _api_json_request(
            method="POST",
            url=trigger_url,
            token=config.token,
            payload=trigger_payload,
        )

        run_id = str(trigger_response.get("investigation_run_id") or "").strip()
        counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        status = str(trigger_response.get("status") or "accepted").strip().lower()
        progress = "queued"

        if config.wait_for_completion and run_id:
            deadline = time.time() + float(config.wait_timeout_seconds)
            while time.time() < deadline:
                status_url = f"{config.api_url}/api/v1/github-app/runs/{run_id}/status"
                status_payload = _api_json_request(method="GET", url=status_url, token=config.token)
                status = str(status_payload.get("status") or "queued").strip().lower()
                progress = str(status_payload.get("progress_label") or "").strip() or status
                payload_counts = status_payload.get("severity_counts")
                if isinstance(payload_counts, dict):
                    counts = {
                        "P0": int(payload_counts.get("P0") or 0),
                        "P1": int(payload_counts.get("P1") or 0),
                        "P2": int(payload_counts.get("P2") or 0),
                        "P3": int(payload_counts.get("P3") or 0),
                    }
                if _terminal_status(status):
                    break
                time.sleep(float(config.wait_poll_seconds))
            else:
                raise RuntimeError(
                    f"Timed out waiting for run completion after {config.wait_timeout_seconds}s (run_id={run_id})"
                )

        blocking = _blocking_count(severity_gate=config.severity_gate, counts=counts)
        gate_status = "passed"
        exit_code = 0
        if blocking > 0:
            gate_status = "blocked"
            exit_code = 1
        elif config.wait_for_completion and run_id and status in {"failed", "error", "cancelled"}:
            gate_status = "error"
            exit_code = 2

        _emit_outputs(
            gate_status=gate_status,
            counts=counts,
            run_id=run_id or str(trigger_response.get("delivery_id") or "manual-trigger"),
            scan_mode=config.scan_mode,
            severity_gate=config.severity_gate,
        )

        run_url = f"{SENTINELAYER_WEB_BASE}/runs/{run_id}" if run_id else ""
        evidence_url = f"{run_url}/evidence" if run_url else ""
        summary_lines = [
            "## Omar Gate Compatibility Bridge",
            f"- Action version: `{ACTION_VERSION}`",
            f"- Scan command: `{command}`",
            f"- Repository: `{config.repo_full_name}`",
            f"- PR: `#{pr_number}`",
            f"- Status: `{status}`",
            f"- Progress: `{progress}`",
            f"- Findings: `P0={counts['P0']} P1={counts['P1']} P2={counts['P2']} P3={counts['P3']}`",
            f"- Gate: `{gate_status}` (threshold `{config.severity_gate}`)",
        ]
        if run_url:
            summary_lines.append(f"- Run: {run_url}")
            summary_lines.append(f"- Evidence: {evidence_url}")
        _append_summary("\n".join(summary_lines) + "\n")

        if run_id:
            print(f"::notice::Sentinelayer run ready: {run_id}")
        return exit_code
    except Exception as exc:
        print(f"::error::{exc}")
        _emit_outputs(
            gate_status="error",
            counts={"P0": 0, "P1": 0, "P2": 0, "P3": 0},
            run_id="error",
            scan_mode=str(os.environ.get("INPUT_SCAN_MODE") or "deep"),
            severity_gate=str(os.environ.get("INPUT_SEVERITY_GATE") or "P1").strip().upper(),
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

