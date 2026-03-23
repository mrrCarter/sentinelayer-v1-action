from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ACTION_VERSION = "1.5.2"
SENTINELAYER_WEB_BASE = "https://sentinelayer.com"
_SPEC_DISCOVERY_MAX_FILES = 24
_SPEC_DISCOVERY_MAX_BYTES = 512_000
_SPEC_DISCOVERY_ALLOWED_SUFFIXES = {".md", ".markdown", ".txt", ".yml", ".yaml", ".json"}
_SPEC_DISCOVERY_EXACT_FILENAMES = {
    "spec.md",
    "specification.md",
    "requirements.md",
    "swe_excellence_framework.md",
}
_SPEC_DISCOVERY_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}


@dataclass(frozen=True)
class BridgeConfig:
    token: str
    status_poll_token: str
    api_url: str
    repo_full_name: str
    event_path: Path
    event_name: str
    scan_mode: str
    severity_gate: str
    command_override: str
    provider_installation_id: int | None
    spec_hash: str | None
    spec_id: str | None
    spec_binding_mode: str
    spec_sources: list[str]
    wait_for_completion: bool
    wait_timeout_seconds: int
    wait_poll_seconds: int
    pr_number_override: int | None
    playwright_mode: str
    playwright_base_url: str
    playwright_bootstrap: bool
    playwright_baseline_command: str
    playwright_audit_command: str


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


def _normalize_spec_hash(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if len(normalized) != 64:
        return None
    if any(ch not in "0123456789abcdef" for ch in normalized):
        return None
    return normalized


def _normalize_spec_binding_mode(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"explicit", "auto_discovered"}:
        return normalized
    return "none"


def _normalize_playwright_mode(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"baseline", "smoke", "pr"}:
        return "baseline"
    if normalized in {"audit", "deep", "full", "full-depth"}:
        return "audit"
    return "off"


def _normalize_spec_sources(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value or "").replace("\\", "/").strip()
        if not candidate:
            continue
        lowered = candidate.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(candidate)
    normalized.sort(key=lambda item: item.lower())
    return normalized


def _normalize_text_for_hash(content: str) -> str:
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    collapsed = "\n".join(lines).strip()
    return collapsed


def _spec_file_score(relative_path: str) -> tuple[int, str]:
    normalized = str(relative_path or "").replace("\\", "/").strip().lower()
    name = normalized.rsplit("/", 1)[-1]
    score = 90
    if name in _SPEC_DISCOVERY_EXACT_FILENAMES:
        score = 0
    elif normalized.startswith(".sentinelayer/"):
        score = 10
    elif "system designs and specifications/" in normalized:
        score = 20
    elif normalized.startswith("docs/") and "spec" in name:
        score = 30
    elif "spec" in name:
        score = 40
    elif "requirement" in name:
        score = 50
    elif "design" in normalized:
        score = 60
    return score, normalized


def _discover_spec_sources(workspace: Path) -> list[str]:
    if not workspace.exists():
        return []

    candidates: list[str] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [directory for directory in dirs if directory not in _SPEC_DISCOVERY_SKIP_DIRS]
        for file_name in files:
            suffix = Path(file_name).suffix.lower()
            if suffix not in _SPEC_DISCOVERY_ALLOWED_SUFFIXES:
                continue
            lowered_name = file_name.lower()
            if (
                lowered_name not in _SPEC_DISCOVERY_EXACT_FILENAMES
                and "spec" not in lowered_name
                and "requirement" not in lowered_name
                and "design" not in lowered_name
            ):
                continue

            absolute_path = Path(root) / file_name
            try:
                if absolute_path.stat().st_size > _SPEC_DISCOVERY_MAX_BYTES:
                    continue
            except OSError:
                continue

            try:
                relative = absolute_path.relative_to(workspace)
            except ValueError:
                continue
            candidates.append(str(relative).replace("\\", "/"))

    ranked = sorted(
        _normalize_spec_sources(candidates),
        key=_spec_file_score,
    )
    return ranked[:_SPEC_DISCOVERY_MAX_FILES]


def _compute_spec_hash_from_sources(workspace: Path, sources: list[str]) -> str | None:
    normalized_sources = _normalize_spec_sources(sources)
    if not normalized_sources:
        return None

    manifest: list[dict[str, str]] = []
    for relative_path in normalized_sources:
        file_path = workspace / relative_path
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        normalized_text = _normalize_text_for_hash(content)
        if not normalized_text:
            continue
        content_hash = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
        manifest.append({"path": relative_path, "content_hash": content_hash})

    if not manifest:
        return None
    payload = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_config() -> BridgeConfig:
    token = str(
        os.environ.get("INPUT_SENTINELAYER_TOKEN")
        or os.environ.get("SENTINELAYER_TOKEN")
        or ""
    ).strip()
    status_poll_token = str(
        os.environ.get("INPUT_STATUS_POLL_TOKEN")
        or os.environ.get("STATUS_POLL_TOKEN")
        or token
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
    workspace = Path(str(os.environ.get("GITHUB_WORKSPACE") or ".")).resolve()
    spec_hash = _normalize_spec_hash(
        str(os.environ.get("INPUT_SENTINELAYER_SPEC_HASH") or "").strip()
    )
    spec_id = str(os.environ.get("INPUT_SENTINELAYER_SPEC_ID") or "").strip() or None
    spec_binding_mode = _normalize_spec_binding_mode(
        str(os.environ.get("INPUT_SPEC_BINDING_MODE") or "").strip()
    )
    discovered_spec_sources: list[str] = []
    if spec_hash is None:
        discovered_spec_sources = _discover_spec_sources(workspace)
        discovered_hash = _compute_spec_hash_from_sources(workspace, discovered_spec_sources)
        if discovered_hash:
            spec_hash = discovered_hash
            if spec_binding_mode == "none":
                spec_binding_mode = "auto_discovered"
    if spec_binding_mode == "none" and (spec_hash or spec_id):
        spec_binding_mode = "explicit"
    wait_for_completion = _bool_input("INPUT_WAIT_FOR_COMPLETION", True)
    wait_timeout_seconds = max(30, _int_input("INPUT_WAIT_TIMEOUT_SECONDS", 900))
    wait_poll_seconds = max(5, _int_input("INPUT_WAIT_POLL_SECONDS", 10))
    pr_number_raw = str(os.environ.get("INPUT_PR_NUMBER") or "").strip()
    pr_number_override = int(pr_number_raw) if pr_number_raw.isdigit() else None
    playwright_mode = _normalize_playwright_mode(
        str(os.environ.get("INPUT_PLAYWRIGHT_MODE") or "").strip()
    )
    playwright_base_url = str(os.environ.get("INPUT_PLAYWRIGHT_BASE_URL") or "").strip()
    playwright_bootstrap = _bool_input("INPUT_PLAYWRIGHT_BOOTSTRAP", True)
    playwright_baseline_command = str(
        os.environ.get("INPUT_PLAYWRIGHT_BASELINE_COMMAND") or "npm run test:e2e:baseline"
    ).strip()
    playwright_audit_command = str(
        os.environ.get("INPUT_PLAYWRIGHT_AUDIT_COMMAND") or "npm run test:e2e:audit"
    ).strip()

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
        status_poll_token=status_poll_token,
        api_url=api_url,
        repo_full_name=repo_full_name,
        event_path=event_path,
        event_name=event_name,
        scan_mode=scan_mode,
        severity_gate=severity_gate,
        command_override=command_override,
        provider_installation_id=provider_installation_id,
        spec_hash=spec_hash,
        spec_id=spec_id,
        spec_binding_mode=spec_binding_mode,
        spec_sources=_normalize_spec_sources(discovered_spec_sources),
        wait_for_completion=wait_for_completion,
        wait_timeout_seconds=wait_timeout_seconds,
        wait_poll_seconds=wait_poll_seconds,
        pr_number_override=pr_number_override,
        playwright_mode=playwright_mode,
        playwright_base_url=playwright_base_url,
        playwright_bootstrap=playwright_bootstrap,
        playwright_baseline_command=playwright_baseline_command,
        playwright_audit_command=playwright_audit_command,
    )


def _api_json_request(
    *, method: str, url: str, token: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    body: bytes | None = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": f"sentinelayer-compat-action/{ACTION_VERSION}",
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
        "audit",
        "audit-full",
        "audit_full",
        "full-depth",
        "full_depth",
        "full-depth-13",
        "full_depth_13",
        "full",
    }:
        return "/omar full-depth"
    return "/omar deep-scan"


def _parse_safe_command(command: str) -> list[str]:
    raw = str(command or "").strip()
    if not raw:
        raise RuntimeError("Playwright command is empty.")
    try:
        args = shlex.split(raw, posix=os.name != "nt")
    except ValueError as exc:
        raise RuntimeError(f"Invalid Playwright command syntax: {exc}") from exc
    if not args:
        raise RuntimeError("Playwright command resolved to empty arguments.")
    forbidden_tokens = {"&&", "||", "|", ";", ">", "<"}
    if any(token in forbidden_tokens for token in args):
        raise RuntimeError(
            "Playwright command contains forbidden shell control tokens. "
            "Use a single executable command with arguments."
        )
    return args


def _run_command(command: str, *, env: dict[str, str] | None = None) -> int:
    args = _parse_safe_command(command)
    completed = subprocess.run(args, shell=False, env=env, check=False)
    return int(completed.returncode or 0)


def _run_command_args(args: list[str], *, env: dict[str, str] | None = None) -> int:
    completed = subprocess.run(args, shell=False, env=env, check=False)
    return int(completed.returncode or 0)


def _execute_playwright_gate(config: BridgeConfig) -> tuple[str, str]:
    mode = str(config.playwright_mode or "off").strip().lower()
    if mode == "off":
        return "skipped", "Playwright gate disabled."

    if mode == "audit":
        command = str(config.playwright_audit_command or "").strip()
    else:
        command = str(config.playwright_baseline_command or "").strip()
    if not command:
        raise RuntimeError(f"Playwright mode '{mode}' is enabled but command is empty.")

    env = os.environ.copy()
    if config.playwright_base_url:
        env["PLAYWRIGHT_TEST_BASE_URL"] = config.playwright_base_url
        env.setdefault("BASE_URL", config.playwright_base_url)

    started = time.time()
    if config.playwright_bootstrap:
        print("::notice::Playwright gate: bootstrapping npm dependencies and browser runtime.")
        install_code = _run_command_args(["npm", "ci", "--ignore-scripts"], env=env)
        if install_code != 0:
            raise RuntimeError(
                "Playwright bootstrap failed "
                f"(command=`npm ci --ignore-scripts`, exit_code={install_code})."
            )
        browser_code = _run_command_args(
            ["npx", "playwright", "install", "--with-deps", "chromium"],
            env=env,
        )
        if browser_code != 0:
            raise RuntimeError(
                "Playwright bootstrap failed "
                "(command=`npx playwright install --with-deps chromium`, "
                f"exit_code={browser_code})."
            )

    print(f"::notice::Playwright gate: executing mode={mode} command=`{command}`")
    run_code = _run_command(command, env=env)
    duration = int(round(time.time() - started))
    if run_code != 0:
        raise RuntimeError(
            "Playwright gate failed "
            f"(mode={mode}, exit_code={run_code}, command=`{command}`)."
        )
    detail = f"Playwright mode `{mode}` passed in `{duration}s` using `{command}`."
    return "passed", detail


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
    playwright_status: str,
    playwright_mode: str,
) -> None:
    _write_output("gate_status", gate_status)
    _write_output("p0_count", str(int(counts.get("P0") or 0)))
    _write_output("p1_count", str(int(counts.get("P1") or 0)))
    _write_output("p2_count", str(int(counts.get("P2") or 0)))
    _write_output("p3_count", str(int(counts.get("P3") or 0)))
    _write_output("run_id", run_id)
    _write_output("scan_mode", scan_mode)
    _write_output("severity_gate", severity_gate)
    _write_output("playwright_status", playwright_status)
    _write_output("playwright_mode", playwright_mode)


def main() -> int:
    print(
        "::notice::Omar Gate Action v1 is a thin GitHub App bridge. "
        "Scan adjudication runs in Sentinelayer backend services."
    )

    playwright_status = "skipped"
    playwright_mode = "off"
    try:
        config = _load_config()
        playwright_mode = config.playwright_mode
        playwright_status, playwright_detail = _execute_playwright_gate(config)
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
        if config.spec_hash:
            trigger_payload["spec_hash"] = config.spec_hash
        if config.spec_id:
            trigger_payload["spec_id"] = config.spec_id
        trigger_payload["spec_binding_mode"] = config.spec_binding_mode
        if config.spec_sources:
            trigger_payload["spec_sources"] = config.spec_sources

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
                status_payload = _api_json_request(
                    method="GET",
                    url=status_url,
                    token=config.status_poll_token,
                )
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
            playwright_status=playwright_status,
            playwright_mode=playwright_mode,
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
            f"- Spec binding: `{config.spec_binding_mode}`",
            (
                f"- Spec hash: `{config.spec_hash[:12]}...`"
                if config.spec_hash
                else "- Spec hash: `none`"
            ),
            f"- Spec sources: `{len(config.spec_sources)}`",
            f"- Findings: `P0={counts['P0']} P1={counts['P1']} P2={counts['P2']} P3={counts['P3']}`",
            f"- Gate: `{gate_status}` (threshold `{config.severity_gate}`)",
            f"- Playwright gate: `{playwright_status}` ({playwright_mode})",
            f"- Playwright detail: {playwright_detail}",
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
            playwright_status=playwright_status,
            playwright_mode=playwright_mode,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

