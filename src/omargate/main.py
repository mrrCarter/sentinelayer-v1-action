from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omargate.gates.budget import QuotaState, TokenBudgetTracker, parse_rate_limit_headers

ACTION_VERSION = "1.5.8"
SENTINELAYER_WEB_BASE = "https://sentinelayer.com"
_API_REQUEST_TIMEOUT_SECONDS = 120
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
_SBOM_DEFAULT_OUTPUT_DIR = ".sentinelayer/sbom"
_SBOM_PYTHON_REQUIREMENTS_FILES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
)
_OMAR_COMMENT_MARKER_PREFIX = "sentinelayer:omar-gate:"
_LOCAL_FINDINGS_RELATIVE_PATH = Path(".omargate/local/FINDINGS.jsonl")
_COMMENT_FINDING_LIMIT = 10


@dataclass(frozen=True)
class BridgeConfig:
    token: str
    status_poll_token: str
    github_token: str
    api_url: str
    repo_full_name: str
    event_path: Path
    event_name: str
    scan_mode: str
    severity_gate: str
    sentinelayer_managed_llm: bool
    model: str
    model_fallback: str
    use_codex: bool
    codex_only: bool
    codex_model: str
    llm_failure_policy: str
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
    sbom_mode: str
    sbom_bootstrap: bool
    sbom_output_dir: str
    sbom_baseline_command: str
    sbom_audit_command: str


class ApiRequestError(RuntimeError):
    """API request failure with response metadata preserved for budget accounting."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_headers = response_headers or {}


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


def _normalize_sbom_mode(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"baseline", "pr", "smoke"}:
        return "baseline"
    if normalized in {"audit", "deep", "full", "full-depth"}:
        return "audit"
    return "off"


def _normalize_model_id(value: str | None, *, default: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return default
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
    if len(normalized) > 128 or any(ch not in allowed for ch in normalized):
        return default
    return normalized


def _normalize_llm_failure_policy(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"block", "warn", "ignore", "deterministic_only"}:
        return normalized
    return "block"


def _normalize_spec_sources(values: list[str]) -> list[str]:
    """Normalize spec-source path strings, dropping any that fail safety checks.

    Hostile input classes rejected (per path_safety._validate_chars / _validate_prefix):
    null bytes, ASCII control chars 0x00-0x1F + 0x7F, BiDi override codepoints
    U+202A-202E + U+2066-2069, double-encoded percent, UNC `\\\\host\\share`
    prefixes, tilde variants (`~user`/`~+`/`~-`), shell-expansion (`$`/`%`/leading `=`),
    and bare Windows drive roots (`C:\\`).

    Rejected items are silently dropped; legitimate spec sources keep loading.
    """
    from .path_safety import (
        _validate_chars,
        _validate_double_encoded,
        _validate_prefix,
        PathSafetyError,
    )

    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        raw = str(value or "")
        if not raw.strip():
            continue
        try:
            _validate_chars(raw)
            _validate_double_encoded(raw)
            _validate_prefix(raw)
        except PathSafetyError:
            continue
        candidate = raw.replace("\\", "/").strip()
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
    github_token = str(
        os.environ.get("INPUT_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
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
    sentinelayer_managed_llm = _bool_input("INPUT_SENTINELAYER_MANAGED_LLM", True)
    model = _normalize_model_id(
        os.environ.get("INPUT_MODEL"),
        default="gpt-5.3-codex",
    )
    model_fallback = _normalize_model_id(
        os.environ.get("INPUT_MODEL_FALLBACK"),
        default="gpt-4.1-mini",
    )
    use_codex = _bool_input("INPUT_USE_CODEX", True)
    codex_only = _bool_input("INPUT_CODEX_ONLY", False)
    codex_model = _normalize_model_id(
        os.environ.get("INPUT_CODEX_MODEL"),
        default=model,
    )
    llm_failure_policy = _normalize_llm_failure_policy(
        os.environ.get("INPUT_LLM_FAILURE_POLICY")
    )
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
    sbom_mode = _normalize_sbom_mode(str(os.environ.get("INPUT_SBOM_MODE") or "").strip())
    sbom_bootstrap = _bool_input("INPUT_SBOM_BOOTSTRAP", True)
    sbom_output_dir = (
        str(os.environ.get("INPUT_SBOM_OUTPUT_DIR") or _SBOM_DEFAULT_OUTPUT_DIR).strip()
        or _SBOM_DEFAULT_OUTPUT_DIR
    )
    sbom_baseline_command = str(os.environ.get("INPUT_SBOM_BASELINE_COMMAND") or "").strip()
    sbom_audit_command = str(os.environ.get("INPUT_SBOM_AUDIT_COMMAND") or "").strip()

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
        github_token=github_token,
        api_url=api_url,
        repo_full_name=repo_full_name,
        event_path=event_path,
        event_name=event_name,
        scan_mode=scan_mode,
        severity_gate=severity_gate,
        sentinelayer_managed_llm=sentinelayer_managed_llm,
        model=model,
        model_fallback=model_fallback,
        use_codex=use_codex,
        codex_only=codex_only,
        codex_model=codex_model,
        llm_failure_policy=llm_failure_policy,
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
        sbom_mode=sbom_mode,
        sbom_bootstrap=sbom_bootstrap,
        sbom_output_dir=sbom_output_dir,
        sbom_baseline_command=sbom_baseline_command,
        sbom_audit_command=sbom_audit_command,
    )


def _headers_to_dict(headers: Any) -> dict[str, str]:
    if headers is None or not hasattr(headers, "items"):
        return {}
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        normalized[str(key)] = str(value)
    return normalized


def _capture_response_headers(
    target: dict[str, str] | None,
    headers: Any,
) -> dict[str, str]:
    captured = _headers_to_dict(headers)
    if target is not None:
        target.clear()
        target.update(captured)
    return captured


def _has_quota_headers(headers: dict[str, str]) -> bool:
    parsed = parse_rate_limit_headers(headers)
    return any(
        value is not None
        for value in (
            parsed.status,
            parsed.util_5h,
            parsed.util_7d,
            parsed.resets_at,
            parsed.overage_status,
        )
    )


def _quota_output_fields(tracker: TokenBudgetTracker) -> dict[str, str]:
    decision = tracker.should_allow_call(0)
    warn = decision.warn or tracker.state in {
        QuotaState.WARNING,
        QuotaState.THROTTLED,
        QuotaState.USING_OVERAGE,
    }
    reason = tracker.last_reason or decision.reason or tracker.state.value
    return {
        "quota_state": tracker.state.value,
        "quota_allow": "true" if decision.allow else "false",
        "quota_warn": "true" if warn else "false",
        "quota_reason": reason,
        "quota_resets_at": str(tracker.resets_at or ""),
        "quota_using_overage": "true" if tracker.using_overage else "false",
    }


def _print_quota_notice(tracker: TokenBudgetTracker) -> None:
    if tracker.state == QuotaState.NORMAL:
        return
    level = "warning" if tracker.state != QuotaState.EXHAUSTED else "error"
    reason = tracker.last_reason or tracker.state.value
    print(f"::{level}::Omar quota state {tracker.state.value}: {reason}")


def _api_json_request(
    *,
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
    response_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    body: bytes | None = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": f"sentinelayer-omar-action/{ACTION_VERSION}",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url=url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=_API_REQUEST_TIMEOUT_SECONDS) as response:
            _capture_response_headers(response_headers, getattr(response, "headers", None))
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        captured_headers = _capture_response_headers(response_headers, exc.headers)
        detail = exc.read().decode("utf-8", errors="replace")
        raise ApiRequestError(
            f"API request failed [{exc.code}] {url}: {detail}",
            status_code=int(exc.code),
            response_headers=captured_headers,
        ) from exc
    except urllib.error.URLError as exc:
        raise ApiRequestError(f"API request failed [{url}]: {exc}") from exc


def _build_trigger_payload(
    config: BridgeConfig,
    *,
    pr_number: int,
    command: str,
) -> dict[str, Any]:
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
    trigger_payload["llm_policy"] = {
        "sentinelayer_managed_llm": config.sentinelayer_managed_llm,
        "model": config.model,
        "model_fallback": config.model_fallback,
        "use_codex": config.use_codex,
        "codex_only": config.codex_only,
        "codex_model": config.codex_model,
        "llm_failure_policy": config.llm_failure_policy,
    }
    return trigger_payload


def _github_api_json_request(
    *,
    url: str,
    github_token: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> Any:
    body: bytes | None = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "Content-Type": "application/json",
        "User-Agent": f"sentinelayer-omar-action/{ACTION_VERSION}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url=url, method=method, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else None


def _github_api_repo_url(repo_full_name: str, path: str) -> str:
    repo = str(repo_full_name or "").strip()
    if repo.count("/") != 1:
        raise RuntimeError(f"Invalid GitHub repository name: {repo!r}")
    owner, name = repo.split("/", 1)
    allowed_repo_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if (
        not owner
        or not name
        or any(ch not in allowed_repo_chars for ch in owner)
        or any(ch not in allowed_repo_chars for ch in name)
    ):
        raise RuntimeError(f"Invalid GitHub repository name: {repo!r}")
    normalized_path = str(path or "").lstrip("/")
    return (
        "https://api.github.com/repos/"
        f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}/"
        f"{normalized_path}"
    )


def _omar_comment_marker(repo_full_name: str, pr_number: int) -> str:
    return f"<!-- {_OMAR_COMMENT_MARKER_PREFIX}{repo_full_name}:pr-{pr_number} -->"


def _resolve_pr_number_from_commit(
    *, repo_full_name: str | None, commit_sha: str | None, github_token: str | None
) -> int | None:
    repo = str(repo_full_name or "").strip()
    commit = str(commit_sha or "").strip()
    token = str(github_token or "").strip()
    if not repo or not commit or not token:
        return None
    if repo.count("/") != 1:
        return None
    owner, name = repo.split("/", 1)
    allowed_repo_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if (
        not owner
        or not name
        or any(ch not in allowed_repo_chars for ch in owner)
        or any(ch not in allowed_repo_chars for ch in name)
    ):
        return None
    allowed_commit_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if len(commit) > 128 or any(ch not in allowed_commit_chars for ch in commit):
        return None

    url = (
        "https://api.github.com/repos/"
        f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"
        f"/commits/{urllib.parse.quote(commit, safe='')}/pulls"
    )
    try:
        response = _github_api_json_request(url=url, github_token=token)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(response, list):
        return None
    for item in response:
        if not isinstance(item, dict):
            continue
        number = item.get("number")
        if isinstance(number, int) and number > 0:
            return number
    return None


def _detect_pr_number(
    payload: dict[str, Any],
    *,
    fallback_pr_number: int | None = None,
    repo_full_name: str | None = None,
    commit_sha: str | None = None,
    github_token: str | None = None,
) -> int:
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

    payload_commit_sha = (
        commit_sha
        or payload.get("after")
        or (payload.get("workflow_run") or {}).get("head_sha")
        or (payload.get("check_run") or {}).get("head_sha")
    )
    resolved_from_commit = _resolve_pr_number_from_commit(
        repo_full_name=repo_full_name,
        commit_sha=str(payload_commit_sha or "").strip(),
        github_token=github_token,
    )
    if resolved_from_commit:
        return resolved_from_commit

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


def _resolve_sbom_output_dir(workspace: Path, configured_output_dir: str) -> Path:
    raw = str(configured_output_dir or "").strip() or _SBOM_DEFAULT_OUTPUT_DIR
    output_dir = Path(raw)
    if not output_dir.is_absolute():
        output_dir = workspace / output_dir
    return output_dir.resolve()


def _discover_requirements_file(workspace: Path) -> Path | None:
    for file_name in _SBOM_PYTHON_REQUIREMENTS_FILES:
        candidate = workspace / file_name
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _run_default_sbom_collection(config: BridgeConfig) -> tuple[str, str]:
    workspace = Path(str(os.environ.get("GITHUB_WORKSPACE") or ".")).resolve()
    output_dir = _resolve_sbom_output_dir(workspace, config.sbom_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    mode = str(config.sbom_mode or "off").strip().lower()
    env = os.environ.copy()

    generated: list[Path] = []
    node_project = (workspace / "package.json").exists()
    node_lock = (workspace / "package-lock.json").exists() or (workspace / "npm-shrinkwrap.json").exists()
    requirements_file = _discover_requirements_file(workspace)
    pyproject_file = workspace / "pyproject.toml"
    python_project = requirements_file is not None or pyproject_file.exists()

    if not node_project and not python_project:
        return (
            "skipped",
            "SBOM mode enabled but no Node/Python manifests were discovered at repository root.",
        )

    if node_project:
        if config.sbom_bootstrap and node_lock:
            print("::notice::SBOM gate: bootstrapping Node dependencies with npm ci.")
            npm_ci_code = _run_command_args(["npm", "ci", "--ignore-scripts"], env=env)
            if npm_ci_code != 0:
                raise RuntimeError(
                    "SBOM bootstrap failed "
                    "(command=`npm ci --ignore-scripts`, "
                    f"exit_code={npm_ci_code})."
                )

        node_json = output_dir / (
            "sbom-node.audit.cdx.json" if mode == "audit" else "sbom-node.baseline.cdx.json"
        )
        node_command = [
            "npx",
            "--yes",
            "@cyclonedx/cyclonedx-npm",
            "--output-format",
            "JSON",
            "--spec-version",
            "1.5",
            "--output-file",
            str(node_json),
            "--validate",
        ]
        if node_lock:
            node_command.append("--package-lock-only")
        node_code = _run_command_args(node_command, env=env)
        if node_code != 0:
            raise RuntimeError(
                "SBOM generation failed for Node "
                "(command=`npx --yes @cyclonedx/cyclonedx-npm ...`, "
                f"exit_code={node_code})."
            )
        generated.append(node_json)

        if mode == "audit":
            node_xml = output_dir / "sbom-node.audit.cdx.xml"
            node_xml_command = [
                "npx",
                "--yes",
                "@cyclonedx/cyclonedx-npm",
                "--output-format",
                "XML",
                "--spec-version",
                "1.5",
                "--output-file",
                str(node_xml),
                "--validate",
            ]
            if node_lock:
                node_xml_command.append("--package-lock-only")
            node_xml_code = _run_command_args(node_xml_command, env=env)
            if node_xml_code != 0:
                raise RuntimeError(
                    "SBOM generation failed for Node XML output "
                    "(command=`npx --yes @cyclonedx/cyclonedx-npm ...`, "
                    f"exit_code={node_xml_code})."
                )
            generated.append(node_xml)

    if python_project:
        if config.sbom_bootstrap:
            print("::notice::SBOM gate: installing cyclonedx-bom for Python SBOM generation.")
            py_bootstrap_code = _run_command_args(
                ["python", "-m", "pip", "install", "--upgrade", "pip", "cyclonedx-bom"],
                env=env,
            )
            if py_bootstrap_code != 0:
                raise RuntimeError(
                    "SBOM bootstrap failed "
                    "(command=`python -m pip install --upgrade pip cyclonedx-bom`, "
                    f"exit_code={py_bootstrap_code})."
                )

        py_json = output_dir / (
            "sbom-python.audit.cdx.json" if mode == "audit" else "sbom-python.baseline.cdx.json"
        )
        if requirements_file is not None:
            py_command = [
                "cyclonedx-py",
                "requirements",
                str(requirements_file),
                "--output-format",
                "JSON",
                "--spec-version",
                "1.5",
                "--output-file",
                str(py_json),
                "--validate",
            ]
        else:
            py_command = [
                "cyclonedx-py",
                "environment",
                "--output-format",
                "JSON",
                "--spec-version",
                "1.5",
                "--output-file",
                str(py_json),
                "--validate",
            ]
        py_code = _run_command_args(py_command, env=env)
        if py_code != 0:
            raise RuntimeError(
                "SBOM generation failed for Python "
                "(command=`cyclonedx-py ...`, "
                f"exit_code={py_code})."
            )
        generated.append(py_json)

    if not generated:
        return (
            "skipped",
            "SBOM mode enabled but no SBOM files were generated for discovered manifests.",
        )

    relative_output_dir = str(output_dir)
    try:
        relative_output_dir = str(output_dir.relative_to(workspace)).replace("\\", "/")
    except ValueError:
        relative_output_dir = str(output_dir).replace("\\", "/")

    detail = (
        f"SBOM mode `{mode}` generated `{len(generated)}` file(s) in "
        f"`{relative_output_dir}`."
    )
    return "passed", detail


def _execute_sbom_gate(config: BridgeConfig) -> tuple[str, str]:
    mode = str(config.sbom_mode or "off").strip().lower()
    if mode == "off":
        return "skipped", "SBOM gate disabled."

    command = config.sbom_audit_command if mode == "audit" else config.sbom_baseline_command
    command = str(command or "").strip()
    if not command:
        print(f"::notice::SBOM gate: executing default profile mode={mode}.")
        return _run_default_sbom_collection(config)

    env = os.environ.copy()
    env["SENTINELAYER_SBOM_OUTPUT_DIR"] = str(config.sbom_output_dir or _SBOM_DEFAULT_OUTPUT_DIR)
    started = time.time()
    print(f"::notice::SBOM gate: executing mode={mode} command=`{command}`")
    run_code = _run_command(command, env=env)
    duration = int(round(time.time() - started))
    if run_code != 0:
        raise RuntimeError(
            "SBOM gate failed "
            f"(mode={mode}, exit_code={run_code}, command=`{command}`)."
        )
    detail = f"SBOM mode `{mode}` passed in `{duration}s` using `{command}`."
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
    model: str,
    model_fallback: str,
    codex_model: str,
    playwright_status: str,
    playwright_mode: str,
    sbom_status: str,
    sbom_mode: str,
    quota_state: str = QuotaState.NORMAL.value,
    quota_allow: str = "true",
    quota_warn: str = "false",
    quota_reason: str = "normal",
    quota_resets_at: str = "",
    quota_using_overage: str = "false",
) -> None:
    _write_output("gate_status", gate_status)
    _write_output("p0_count", str(int(counts.get("P0") or 0)))
    _write_output("p1_count", str(int(counts.get("P1") or 0)))
    _write_output("p2_count", str(int(counts.get("P2") or 0)))
    _write_output("p3_count", str(int(counts.get("P3") or 0)))
    _write_output("run_id", run_id)
    _write_output("scan_mode", scan_mode)
    _write_output("severity_gate", severity_gate)
    _write_output("model", model)
    _write_output("model_fallback", model_fallback)
    _write_output("codex_model", codex_model)
    _write_output("playwright_status", playwright_status)
    _write_output("playwright_mode", playwright_mode)
    _write_output("sbom_status", sbom_status)
    _write_output("sbom_mode", sbom_mode)
    _write_output("quota_state", quota_state)
    _write_output("quota_allow", quota_allow)
    _write_output("quota_warn", quota_warn)
    _write_output("quota_reason", quota_reason)
    _write_output("quota_resets_at", quota_resets_at)
    _write_output("quota_using_overage", quota_using_overage)


def _workspace_root() -> Path:
    raw = str(os.environ.get("GITHUB_WORKSPACE") or ".").strip() or "."
    return Path(raw).resolve()


def _safe_run_slug(run_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(run_id or "").strip()).strip(".-")
    return slug[:160] or "manual-trigger"


def _load_local_findings(workspace: Path) -> list[dict[str, Any]]:
    findings_path = workspace / _LOCAL_FINDINGS_RELATIVE_PATH
    if not findings_path.exists():
        return []
    findings: list[dict[str, Any]] = []
    with findings_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                findings.append(row)
    return findings


def _counts_for_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for row in findings:
        severity = str(row.get("severity") or "").strip().upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def _local_deterministic_run_id(
    *,
    config: BridgeConfig,
    pr_number: int,
    commit_sha: str,
    command: str,
) -> str:
    repo_slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", config.repo_full_name).strip(".-")
    repo_slug = repo_slug[:80] or "repo"
    payload = {
        "command": command,
        "commit_sha": commit_sha,
        "pr_number": pr_number,
        "repository_full_name": config.repo_full_name,
        "scan_mode": config.scan_mode,
        "source": "deterministic_only",
    }
    digest = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()[:24]
    return f"ghlocal_{repo_slug}_{digest}"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_counts(raw_counts: Any, fallback: dict[str, int] | None = None) -> dict[str, int]:
    base = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    if isinstance(fallback, dict):
        for severity in base:
            base[severity] = max(0, _safe_int(fallback.get(severity)))
    if isinstance(raw_counts, dict):
        for severity in base:
            base[severity] = max(0, _safe_int(raw_counts.get(severity)))
    return base


def _finding_scope(row: dict[str, Any]) -> tuple[str, int]:
    scope = row.get("scope") if isinstance(row.get("scope"), dict) else {}
    raw_path = (
        scope.get("path")
        or scope.get("file")
        or row.get("file")
        or row.get("path")
        or row.get("filename")
        or "repo"
    )
    raw_line = (
        scope.get("line_start")
        or scope.get("lineStart")
        or scope.get("line")
        or row.get("line")
        or row.get("line_start")
        or 0
    )
    return str(raw_path or "repo").strip() or "repo", max(0, _safe_int(raw_line))


def _finding_sort_key(row: dict[str, Any]) -> tuple[int, str, int]:
    sev_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    severity = str(row.get("severity") or "").upper()
    file_path, line = _finding_scope(row)
    return (sev_order.get(severity, 99), file_path, line)


def _truncate_markdown(value: str, *, limit: int = 320) -> str:
    clean = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 3)].rstrip() + "..."


def _github_blob_url(repo_full_name: str, commit_sha: str, file_path: str, line: int) -> str:
    repo = urllib.parse.quote(str(repo_full_name or "").strip(), safe="/")
    commit = urllib.parse.quote(str(commit_sha or "HEAD").strip() or "HEAD", safe="")
    path = urllib.parse.quote(str(file_path or "").lstrip("/"), safe="/")
    suffix = f"#L{line}" if line > 0 else ""
    return f"https://github.com/{repo}/blob/{commit}/{path}{suffix}"


def _fetch_backend_run_findings(
    *,
    config: BridgeConfig,
    run_id: str,
    run_read_token: str,
    api_json_request: Any = _api_json_request,
) -> dict[str, Any] | None:
    normalized_run_id = str(run_id or "").strip()
    if not normalized_run_id:
        return None
    url = (
        f"{config.api_url}/api/v1/github-app/runs/"
        f"{urllib.parse.quote(normalized_run_id, safe='')}/findings?limit=100"
    )
    try:
        payload = api_json_request(method="GET", url=url, token=run_read_token)
    except Exception as exc:
        print(f"::warning::Omar Gate backend findings fetch skipped: {exc}")
        return None
    return payload if isinstance(payload, dict) else None


def _backend_findings(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def _backend_counts(payload: dict[str, Any] | None, fallback: dict[str, int]) -> dict[str, int]:
    if not isinstance(payload, dict):
        return _normalize_counts(None, fallback)
    return _normalize_counts(payload.get("severity_counts"), fallback)


def _infer_stack(workspace: Path) -> list[str]:
    stack: list[str] = []

    def add(name: str) -> None:
        if name not in stack:
            stack.append(name)

    package_json = workspace / "package.json"
    package_text = ""
    if package_json.exists():
        add("Node.js")
        try:
            package_payload = json.loads(package_json.read_text(encoding="utf-8"))
            deps = {
                **(package_payload.get("dependencies") if isinstance(package_payload.get("dependencies"), dict) else {}),
                **(
                    package_payload.get("devDependencies")
                    if isinstance(package_payload.get("devDependencies"), dict)
                    else {}
                ),
            }
            package_text = " ".join(str(key).lower() for key in deps)
        except (OSError, json.JSONDecodeError):
            package_text = ""
    if "next" in package_text or (workspace / "next.config.js").exists() or (workspace / "next.config.mjs").exists():
        add("Next.js")
    if "react" in package_text:
        add("React")
    if (workspace / "tsconfig.json").exists() or list(workspace.glob("**/*.ts"))[:1]:
        add("TypeScript")
    if (workspace / "pyproject.toml").exists() or (workspace / "requirements.txt").exists():
        add("Python")
    if list(workspace.glob("**/*.tf"))[:1]:
        add("Terraform")
    if (workspace / "Dockerfile").exists() or list(workspace.glob("**/Dockerfile"))[:1]:
        add("Docker")
    return stack[:6] or ["unspecified"]


def _readme_label(workspace: Path) -> str:
    for name in ("README.md", "readme.md", "README.txt"):
        path = workspace / name
        if not path.exists():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                cleaned = line.strip().lstrip("#").strip()
                if cleaned:
                    return f"{name}: {_truncate_markdown(cleaned, limit=120)}"
        except OSError:
            continue
    return "README: not found"


def _architecture_label(workspace: Path) -> str:
    has_apps = (workspace / "apps").is_dir()
    has_packages = (workspace / "packages").is_dir()
    has_workspace = (workspace / "pnpm-workspace.yaml").exists() or (workspace / "turbo.json").exists()
    if has_workspace or (has_apps and has_packages):
        return "monorepo"
    if has_apps:
        return "apps workspace"
    return "single repository"


def _entry_points_label(workspace: Path) -> str:
    candidates: list[str] = []
    for rel in (
        "apps/web",
        "apps/api",
        "apps/dashboard",
        "server",
        "src",
        ".github/workflows",
        "infra",
        "packages",
    ):
        if (workspace / rel).exists():
            candidates.append(rel)
    return ", ".join(candidates[:6]) if candidates else "not inferred"


def _codebase_synopsis(workspace: Path) -> str:
    return (
        f"{_readme_label(workspace)}. "
        f"Architecture: {_architecture_label(workspace)}. "
        f"Stack: {', '.join(_infer_stack(workspace))}. "
        f"Entry points: {_entry_points_label(workspace)}."
    )


def _render_top_findings(
    *,
    repo_full_name: str,
    commit_sha: str,
    findings: list[dict[str, Any]],
) -> str:
    if not findings:
        return "No findings were returned for this run."

    lines: list[str] = []
    for idx, row in enumerate(sorted(findings, key=_finding_sort_key)[:_COMMENT_FINDING_LIMIT], start=1):
        severity = str(row.get("severity") or "P3").upper()
        file_path, line = _finding_scope(row)
        locator = f"{file_path}:{line}" if line > 0 else file_path
        title = _truncate_markdown(str(row.get("title") or row.get("description") or "Finding"))
        impact = _truncate_markdown(str(row.get("impact") or ""), limit=220)
        category = _truncate_markdown(
            str(row.get("category") or row.get("tool") or row.get("gateId") or "review"),
            limit=80,
        )
        link = _github_blob_url(repo_full_name, commit_sha, file_path, line)
        description = f"{title} {impact}".strip()
        lines.append(f"{idx}. **{severity}** [`{locator}`]({link}) - **{category}**: {description}")
        fix = _truncate_markdown(
            str(row.get("remediation_guidance") or row.get("recommendedFix") or ""),
            limit=240,
        )
        if fix:
            lines.append(f"   > Fix: {fix}")

    if len(findings) > _COMMENT_FINDING_LIMIT:
        remaining = len(findings) - _COMMENT_FINDING_LIMIT
        lines.append(f"\n_Additional findings omitted from this comment: {remaining}. See artifacts._")
    return "\n".join(lines)


def _severity_blocks_merge(severity: str, severity_gate: str) -> bool:
    gate = str(severity_gate or "P1").strip().upper()
    severity = str(severity or "").strip().upper()
    if gate == "NONE":
        return False
    if gate == "P0":
        return severity == "P0"
    if gate == "P2":
        return severity in {"P0", "P1", "P2"}
    return severity in {"P0", "P1"}


def _result_line(*, gate_status: str, severity_gate: str, counts: dict[str, int]) -> str:
    label = "Passed" if gate_status == "passed" else ("Blocked" if gate_status == "blocked" else "Errored")
    blocking_names = [
        severity
        for severity in ("P0", "P1", "P2", "P3")
        if _severity_blocks_merge(severity, severity_gate)
    ]
    blocking_total = sum(int(counts.get(severity) or 0) for severity in blocking_names)
    if gate_status == "passed" and blocking_names:
        detail = f"no {'/'.join(blocking_names)} findings"
    elif gate_status == "passed":
        detail = "severity gate disabled"
    else:
        detail = f"{blocking_total} blocking finding(s)"
    return (
        f"Result: {label} (severity_gate={severity_gate}): {detail}. "
        f"Counts: P0={counts['P0']}, P1={counts['P1']}, P2={counts['P2']}, P3={counts['P3']}"
    )


def _render_bridge_pr_comment(
    *,
    config: BridgeConfig,
    pr_number: int,
    run_id: str,
    command: str,
    status: str,
    progress: str,
    counts: dict[str, int],
    gate_status: str,
    run_url: str,
    evidence_url: str,
    playwright_status: str,
    playwright_mode: str,
    playwright_detail: str,
    sbom_status: str,
    sbom_mode: str,
    sbom_detail: str,
    local_findings: list[dict[str, Any]],
    backend_findings_payload: dict[str, Any] | None,
    workspace: Path,
    commit_sha: str,
) -> str:
    local_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for row in local_findings:
        severity = str(row.get("severity") or "").upper()
        if severity in local_counts:
            local_counts[severity] += 1

    backend_findings = _backend_findings(backend_findings_payload)
    display_findings = backend_findings if backend_findings else local_findings
    display_counts = _backend_counts(backend_findings_payload, counts)
    marker = _omar_comment_marker(config.repo_full_name, pr_number)
    counts_marker = json.dumps(display_counts, separators=(",", ":"), sort_keys=True)
    top_findings = _render_top_findings(
        repo_full_name=config.repo_full_name,
        commit_sha=commit_sha,
        findings=display_findings,
    )
    status_icon = "✅" if gate_status == "passed" else ("❌" if gate_status in {"blocked", "error"} else "⏳")
    findings_source = str((backend_findings_payload or {}).get("findings_source") or "").strip()
    if not findings_source:
        findings_source = (
            "skipped:deterministic_only"
            if config.llm_failure_policy == "deterministic_only"
            else "run"
        )

    lines = [
        marker,
        f"<!-- sentinelayer:counts:{counts_marker} -->",
        f"## 🛡️ Omar Gate: {status_icon} {gate_status.upper()}",
        "",
        f"Gate: {config.severity_gate}",
        _result_line(gate_status=gate_status, severity_gate=config.severity_gate, counts=display_counts),
        "",
        "| Severity | Count | Blocks Merge? |",
        "|---|---:|---|",
        f"| P0 (Critical) | {display_counts['P0']} | {'Yes' if _severity_blocks_merge('P0', config.severity_gate) else 'No'} |",
        f"| P1 (High) | {display_counts['P1']} | {'Yes' if _severity_blocks_merge('P1', config.severity_gate) else 'No'} |",
        f"| P2 (Medium) | {display_counts['P2']} | {'Yes' if _severity_blocks_merge('P2', config.severity_gate) else 'No'} |",
        f"| P3 (Low) | {display_counts['P3']} | {'Yes' if _severity_blocks_merge('P3', config.severity_gate) else 'No'} |",
        "",
        f"Codebase Synopsis: {_codebase_synopsis(workspace)}",
        "",
        "### Top Findings",
        top_findings,
        "",
        "### Run Details",
        f"- Run status: `{status}` / `{progress}`",
        f"- Scan: `{command}`",
        (
            "- LLM policy: "
            f"`managed={str(config.sentinelayer_managed_llm).lower()} "
            f"model={config.model} codex_model={config.codex_model} "
            f"fallback={config.model_fallback} failure_policy={config.llm_failure_policy}`"
        ),
        f"- Backend findings source: `{findings_source}`",
        f"- Action-local gates: `P0={local_counts['P0']} P1={local_counts['P1']} P2={local_counts['P2']} P3={local_counts['P3']}`",
    ]
    if run_url:
        lines.append(f"- Dashboard: {run_url}")
    if evidence_url:
        lines.append(f"- Evidence: {evidence_url}")
    lines.extend(
        [
            f"- Run id: `{run_id or 'manual-trigger'}`",
            f"- Playwright gate: `{playwright_status}` ({playwright_mode}) - {playwright_detail}",
            f"- SBOM gate: `{sbom_status}` ({sbom_mode}) - {sbom_detail}",
        ]
    )
    return "\n".join(lines)


def _upsert_omar_pr_comment(
    *,
    config: BridgeConfig,
    pr_number: int,
    body: str,
) -> str | None:
    token = str(config.github_token or "").strip()
    if not token:
        print("::warning::Omar Gate PR comment skipped: github_token input is empty.")
        return None

    marker = _omar_comment_marker(config.repo_full_name, pr_number)
    comments_url = _github_api_repo_url(
        config.repo_full_name,
        f"issues/{pr_number}/comments",
    )
    list_comments_url = f"{comments_url}?per_page=100"
    try:
        comments = _github_api_json_request(url=list_comments_url, github_token=token)
    except Exception as exc:
        print(f"::warning::Omar Gate PR comment skipped: unable to list PR comments: {exc}")
        return None

    if not isinstance(comments, list):
        comments = []

    for comment in comments:
        if not isinstance(comment, dict):
            continue
        existing_body = str(comment.get("body") or "")
        if marker not in existing_body and _OMAR_COMMENT_MARKER_PREFIX not in existing_body:
            continue
        comment_id = comment.get("id")
        if not isinstance(comment_id, int):
            continue
        update_url = _github_api_repo_url(config.repo_full_name, f"issues/comments/{comment_id}")
        try:
            response = _github_api_json_request(
                url=update_url,
                github_token=token,
                method="PATCH",
                payload={"body": body},
            )
        except Exception as exc:
            print(f"::warning::Omar Gate PR comment update skipped: {exc}")
            return None
        if isinstance(response, dict):
            return str(response.get("html_url") or "")
        return None

    try:
        response = _github_api_json_request(
            url=comments_url,
            github_token=token,
            method="POST",
            payload={"body": body},
        )
    except Exception as exc:
        print(f"::warning::Omar Gate PR comment create skipped: {exc}")
        return None
    if isinstance(response, dict):
        return str(response.get("html_url") or "")
    return None


def _write_bridge_artifacts(
    *,
    workspace: Path,
    run_id: str,
    summary: dict[str, Any],
    comment_body: str,
    local_findings: list[dict[str, Any]],
    backend_findings: list[dict[str, Any]] | None = None,
) -> None:
    slug = _safe_run_slug(run_id)
    run_dir = workspace / ".sentinelayer" / "runs" / slug
    artifacts_dir = workspace / ".sentinelayer" / "artifacts" / slug
    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    summary_json = json.dumps(summary, indent=2, sort_keys=True)
    (run_dir / "RUN_SUMMARY.json").write_text(summary_json + "\n", encoding="utf-8")
    (run_dir / "REVIEW_BRIEF.md").write_text(comment_body + "\n", encoding="utf-8")
    (run_dir / "AUDIT_REPORT.md").write_text(comment_body + "\n", encoding="utf-8")
    (artifacts_dir / "BRIDGE_SUMMARY.md").write_text(comment_body + "\n", encoding="utf-8")

    findings_path = run_dir / "FINDINGS.jsonl"
    merged_findings: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for row in list(backend_findings or []) + list(local_findings or []):
        if not isinstance(row, dict):
            continue
        fingerprint = str(
            row.get("finding_fingerprint")
            or row.get("fingerprint")
            or row.get("finding_id")
            or ""
        ).strip()
        if not fingerprint:
            file_path, line = _finding_scope(row)
            fingerprint = "|".join(
                [
                    str(row.get("severity") or ""),
                    str(row.get("category") or row.get("tool") or ""),
                    file_path,
                    str(line),
                    str(row.get("title") or row.get("message") or row.get("impact") or ""),
                ]
            )
        if fingerprint in seen_keys:
            continue
        seen_keys.add(fingerprint)
        merged_findings.append(row)

    with findings_path.open("w", encoding="utf-8") as handle:
        for row in merged_findings:
            handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
            handle.write("\n")


def main() -> int:
    print(
        "::notice::Omar Gate Action v1 is a thin GitHub App bridge. "
        "Scan adjudication runs in Sentinelayer backend services."
    )

    budget_tracker = TokenBudgetTracker()
    playwright_status = "skipped"
    playwright_mode = "off"
    playwright_detail = "Playwright gate disabled."
    sbom_status = "skipped"
    sbom_mode = "off"
    sbom_detail = "SBOM gate disabled."
    try:
        config = _load_config()
        def _tracked_api_json_request(
            *,
            method: str,
            url: str,
            token: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            response_headers: dict[str, str] = {}
            try:
                result = _api_json_request(
                    method=method,
                    url=url,
                    token=token,
                    payload=payload,
                    response_headers=response_headers,
                )
            except ApiRequestError as exc:
                if exc.status_code == 429:
                    budget_tracker.on_rate_limit_error(exc.response_headers)
                    _print_quota_notice(budget_tracker)
                raise
            if _has_quota_headers(response_headers):
                budget_tracker.on_response_headers(response_headers)
                _print_quota_notice(budget_tracker)
            return result

        playwright_mode = config.playwright_mode
        sbom_mode = config.sbom_mode
        try:
            playwright_status, playwright_detail = _execute_playwright_gate(config)
        except Exception as playwright_exc:
            playwright_status = "failed"
            playwright_detail = str(playwright_exc)
            raise
        try:
            sbom_status, sbom_detail = _execute_sbom_gate(config)
        except Exception as sbom_exc:
            sbom_status = "failed"
            sbom_detail = str(sbom_exc)
            raise
        payload = json.loads(config.event_path.read_text(encoding="utf-8"))
        commit_sha = str(os.environ.get("GITHUB_SHA") or payload.get("after") or "").strip()
        pr_number = _detect_pr_number(
            payload,
            fallback_pr_number=config.pr_number_override,
            repo_full_name=config.repo_full_name,
            commit_sha=commit_sha,
            github_token=config.github_token,
        )
        command = config.command_override or _command_for_scan_mode(config.scan_mode)
        workspace = _workspace_root()
        local_findings = _load_local_findings(workspace)
        deterministic_only = config.llm_failure_policy == "deterministic_only"

        trigger_response: dict[str, Any] = {}
        trigger_delivery_id = ""
        run_read_token = config.status_poll_token
        counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        backend_findings_payload: dict[str, Any] | None = None
        if deterministic_only:
            run_id = _local_deterministic_run_id(
                config=config,
                pr_number=pr_number,
                commit_sha=commit_sha,
                command=command,
            )
            counts = _counts_for_findings(local_findings)
            status = "completed"
            progress = "completed:deterministic-local"
            print(
                "::notice::Omar deterministic_only mode selected: "
                "using action-local findings without backend trigger."
            )
        else:
            trigger_url = f"{config.api_url}/api/v1/github-app/trigger"
            trigger_response = _tracked_api_json_request(
                method="POST",
                url=trigger_url,
                token=config.token,
                payload=_build_trigger_payload(
                    config,
                    pr_number=pr_number,
                    command=command,
                ),
            )

            run_id = str(trigger_response.get("investigation_run_id") or "").strip()
            trigger_delivery_id = str(trigger_response.get("delivery_id") or "").strip()
            run_read_token = (
                str(trigger_response.get("run_result_token") or "").strip()
                or config.status_poll_token
            )
            status = str(trigger_response.get("status") or "accepted").strip().lower()
            progress = "queued"

            if config.wait_for_completion and run_id:
                deadline = time.time() + float(config.wait_timeout_seconds)
                while time.time() < deadline:
                    status_url = f"{config.api_url}/api/v1/github-app/runs/{run_id}/status"
                    if trigger_delivery_id:
                        status_url = (
                            f"{status_url}?delivery_id="
                            f"{urllib.parse.quote(trigger_delivery_id, safe='')}"
                        )
                    status_payload = _tracked_api_json_request(
                        method="GET",
                        url=status_url,
                        token=run_read_token,
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

        backend_publish_error = ""
        if deterministic_only and exit_code == 0:
            trigger_url = f"{config.api_url}/api/v1/github-app/trigger"
            try:
                trigger_response = _tracked_api_json_request(
                    method="POST",
                    url=trigger_url,
                    token=config.token,
                    payload=_build_trigger_payload(
                        config,
                        pr_number=pr_number,
                        command=command,
                    ),
                )
                trigger_delivery_id = str(trigger_response.get("delivery_id") or "").strip()
                backend_run_id = str(
                    trigger_response.get("investigation_run_id") or ""
                ).strip()
                if backend_run_id:
                    print(
                        "::notice::Omar deterministic_only backend check publish queued: "
                        f"{backend_run_id}"
                    )
            except Exception as exc:
                backend_publish_error = str(exc)
                print(
                    "::warning::Omar deterministic_only backend check publish failed; "
                    f"local deterministic gate remains authoritative. {exc}"
                )

        _emit_outputs(
            gate_status=gate_status,
            counts=counts,
            run_id=run_id or str(trigger_response.get("delivery_id") or "manual-trigger"),
            scan_mode=config.scan_mode,
            severity_gate=config.severity_gate,
            model=config.model,
            model_fallback=config.model_fallback,
            codex_model=config.codex_model,
            playwright_status=playwright_status,
            playwright_mode=playwright_mode,
            sbom_status=sbom_status,
            sbom_mode=sbom_mode,
            **_quota_output_fields(budget_tracker),
        )

        run_url = f"{SENTINELAYER_WEB_BASE}/runs/{run_id}" if run_id and not deterministic_only else ""
        evidence_url = f"{run_url}/evidence" if run_url else ""
        if run_id and not deterministic_only:
            backend_findings_payload = _fetch_backend_run_findings(
                config=config,
                run_id=run_id,
                run_read_token=run_read_token,
                api_json_request=_tracked_api_json_request,
            )
        comment_body = _render_bridge_pr_comment(
            config=config,
            pr_number=pr_number,
            run_id=run_id or str(trigger_response.get("delivery_id") or "manual-trigger"),
            command=command,
            status=status,
            progress=progress,
            counts=counts,
            gate_status=gate_status,
            run_url=run_url,
            evidence_url=evidence_url,
            playwright_status=playwright_status,
            playwright_mode=playwright_mode,
            playwright_detail=playwright_detail,
            sbom_status=sbom_status,
            sbom_mode=sbom_mode,
            sbom_detail=sbom_detail,
            local_findings=local_findings,
            backend_findings_payload=backend_findings_payload,
            workspace=workspace,
            commit_sha=commit_sha,
        )
        bridge_summary = {
            "action_version": ACTION_VERSION,
            "repository_full_name": config.repo_full_name,
            "pr_number": pr_number,
            "run_id": run_id or str(trigger_response.get("delivery_id") or "manual-trigger"),
            "status": status,
            "progress": progress,
            "gate_status": gate_status,
            "severity_gate": config.severity_gate,
            "scan_command": command,
            "counts": counts,
            "backend_findings_count": len(_backend_findings(backend_findings_payload)),
            "local_findings_count": len(local_findings),
            "run_url": run_url,
            "evidence_url": evidence_url,
            "backend_check_publish": {
                "attempted": bool(deterministic_only and exit_code == 0),
                "delivery_id": trigger_delivery_id or None,
                "investigation_run_id": (
                    str(trigger_response.get("investigation_run_id") or "").strip()
                    or None
                ),
                "error": backend_publish_error or None,
            },
            "quota": _quota_output_fields(budget_tracker),
            "llm_policy": {
                "sentinelayer_managed_llm": config.sentinelayer_managed_llm,
                "model": config.model,
                "model_fallback": config.model_fallback,
                "use_codex": config.use_codex,
                "codex_only": config.codex_only,
                "codex_model": config.codex_model,
                "llm_failure_policy": config.llm_failure_policy,
            },
        }
        _write_bridge_artifacts(
            workspace=workspace,
            run_id=run_id or str(trigger_response.get("delivery_id") or "manual-trigger"),
            summary=bridge_summary,
            comment_body=comment_body,
            local_findings=local_findings,
            backend_findings=_backend_findings(backend_findings_payload),
        )
        comment_url = _upsert_omar_pr_comment(
            config=config,
            pr_number=pr_number,
            body=comment_body,
        )
        if comment_url:
            print(f"::notice::Omar Gate PR comment upserted: {comment_url}")

        summary_lines = [
            "## Omar Gate",
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
            f"- LLM policy: `managed={str(config.sentinelayer_managed_llm).lower()} model={config.model} codex_model={config.codex_model} fallback={config.model_fallback} failure_policy={config.llm_failure_policy}`",
            f"- Findings: `P0={counts['P0']} P1={counts['P1']} P2={counts['P2']} P3={counts['P3']}`",
            f"- Gate: `{gate_status}` (threshold `{config.severity_gate}`)",
            f"- Playwright gate: `{playwright_status}` ({playwright_mode})",
            f"- Playwright detail: {playwright_detail}",
            f"- SBOM gate: `{sbom_status}` ({sbom_mode})",
            f"- SBOM detail: {sbom_detail}",
        ]
        if run_url:
            summary_lines.append(f"- Run: {run_url}")
            summary_lines.append(f"- Evidence: {evidence_url}")
        if comment_url:
            summary_lines.append(f"- PR comment: {comment_url}")
        _append_summary("\n".join(summary_lines) + "\n")

        if run_id and deterministic_only:
            print(f"::notice::Omar deterministic run ready: {run_id}")
        elif run_id:
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
            model=_normalize_model_id(os.environ.get("INPUT_MODEL"), default="gpt-5.3-codex"),
            model_fallback=_normalize_model_id(
                os.environ.get("INPUT_MODEL_FALLBACK"),
                default="gpt-4.1-mini",
            ),
            codex_model=_normalize_model_id(
                os.environ.get("INPUT_CODEX_MODEL") or os.environ.get("INPUT_MODEL"),
                default="gpt-5.3-codex",
            ),
            playwright_status=playwright_status,
            playwright_mode=playwright_mode,
            sbom_status=sbom_status,
            sbom_mode=sbom_mode,
            **_quota_output_fields(budget_tracker),
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

