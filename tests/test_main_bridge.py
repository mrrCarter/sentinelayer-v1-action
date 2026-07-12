from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from omargate.main import (
    ApiRequestError,
    BridgeConfig,
    _API_REQUEST_TIMEOUT_SECONDS,
    _api_json_request,
    _blocking_count,
    _command_for_scan_mode,
    _compute_spec_hash_from_sources,
    _detect_pr_number,
    _execute_playwright_gate,
    _execute_sbom_gate,
    _normalize_llm_failure_policy,
    _normalize_model_id,
    _normalize_playwright_mode,
    _normalize_sbom_mode,
    _normalize_spec_binding_mode,
    _normalize_spec_hash,
    _normalize_spec_sources,
    _parse_safe_command,
    main,
)


def _bridge_config(
    tmp_path: Path,
    *,
    sentinelayer_managed_llm: bool = True,
    use_codex: bool = True,
    llm_failure_policy: str = "block",
    playwright_mode: str = "baseline",
    playwright_bootstrap: bool = True,
    playwright_base_url: str = "",
    sbom_mode: str = "off",
    sbom_bootstrap: bool = True,
    sbom_baseline_command: str = "",
    sbom_audit_command: str = "",
    wait_for_completion: bool = True,
) -> BridgeConfig:
    event_path = tmp_path / "event.json"
    event_path.write_text('{"pull_request":{"number":42}}', encoding="utf-8")
    return BridgeConfig(
        token="token",
        status_poll_token="token",
        github_token="github-token",
        api_url="https://api.sentinelayer.com",
        repo_full_name="owner/repo",
        event_path=event_path,
        event_name="pull_request",
        scan_mode="deep",
        severity_gate="P1",
        sentinelayer_managed_llm=sentinelayer_managed_llm,
        model="gpt-5.3-codex",
        model_fallback="gpt-4.1-mini",
        use_codex=use_codex,
        codex_only=False,
        codex_model="gpt-5.3-codex",
        llm_failure_policy=llm_failure_policy,
        command_override="",
        provider_installation_id=None,
        spec_hash=None,
        spec_id=None,
        spec_binding_mode="none",
        spec_sources=[],
        wait_for_completion=wait_for_completion,
        wait_timeout_seconds=900,
        wait_poll_seconds=10,
        pr_number_override=42,
        playwright_mode=playwright_mode,
        playwright_base_url=playwright_base_url,
        playwright_bootstrap=playwright_bootstrap,
        playwright_baseline_command="npm run test:e2e:baseline",
        playwright_audit_command="npm run test:e2e:audit",
        sbom_mode=sbom_mode,
        sbom_bootstrap=sbom_bootstrap,
        sbom_output_dir=".sentinelayer/sbom",
        sbom_baseline_command=sbom_baseline_command,
        sbom_audit_command=sbom_audit_command,
    )


def test_normalize_spec_hash_accepts_valid_sha256() -> None:
    value = "A" * 64
    assert _normalize_spec_hash(value) == ("a" * 64)


def test_normalize_spec_hash_rejects_invalid_values() -> None:
    assert _normalize_spec_hash("") is None
    assert _normalize_spec_hash("deadbeef") is None
    assert _normalize_spec_hash("z" * 64) is None


def test_normalize_spec_binding_mode_defaults_to_none() -> None:
    assert _normalize_spec_binding_mode("explicit") == "explicit"
    assert _normalize_spec_binding_mode("AUTO_DISCOVERED") == "auto_discovered"
    assert _normalize_spec_binding_mode("invalid-mode") == "none"


def test_normalize_spec_sources_dedupes_and_sorts_case_insensitive() -> None:
    values = ["docs/spec.md", "Docs/spec.md", "system/spec.md", " "]
    assert _normalize_spec_sources(values) == ["docs/spec.md", "system/spec.md"]


def test_compute_spec_hash_from_sources_is_stable_for_same_content(tmp_path: Path) -> None:
    spec = tmp_path / "spec.md"
    spec.write_text("line one  \r\nline two\r\n", encoding="utf-8")
    first = _compute_spec_hash_from_sources(tmp_path, ["spec.md"])
    spec.write_text("line one  \r\nline two\r\n", encoding="utf-8")
    second = _compute_spec_hash_from_sources(tmp_path, ["spec.md"])
    assert first is not None
    assert first == second


def test_detect_pr_number_supports_multiple_event_shapes() -> None:
    assert _detect_pr_number({"pull_request": {"number": 42}}) == 42
    assert _detect_pr_number({"issue": {"number": 7, "pull_request": {}}}) == 7
    assert _detect_pr_number({"check_run": {"pull_requests": [{"number": 15}]}}) == 15
    assert _detect_pr_number({}, fallback_pr_number=3) == 3


def test_detect_pr_number_resolves_push_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str | None] = {}

    def fake_resolve_pr_number_from_commit(
        *, repo_full_name: str | None, commit_sha: str | None, github_token: str | None
    ) -> int | None:
        captured["repo_full_name"] = repo_full_name
        captured["commit_sha"] = commit_sha
        captured["github_token"] = github_token
        return 88

    monkeypatch.setattr(
        "omargate.main._resolve_pr_number_from_commit",
        fake_resolve_pr_number_from_commit,
    )

    assert (
        _detect_pr_number(
            {"after": "abc123"},
            repo_full_name="owner/repo",
            github_token="ghs_test",
        )
        == 88
    )
    assert captured == {
        "repo_full_name": "owner/repo",
        "commit_sha": "abc123",
        "github_token": "ghs_test",
    }


def test_detect_pr_number_rejects_unresolved_payload() -> None:
    with pytest.raises(RuntimeError, match="Unable to resolve PR number"):
        _detect_pr_number({"after": "abc123"})


def test_command_for_scan_mode_defaults_to_deep_scan() -> None:
    assert _command_for_scan_mode("baseline") == "/omar baseline"
    assert _command_for_scan_mode("audit") == "/omar full-depth"
    assert _command_for_scan_mode("full-depth") == "/omar full-depth"
    assert _command_for_scan_mode("unknown") == "/omar deep-scan"


def test_normalize_playwright_mode() -> None:
    assert _normalize_playwright_mode("baseline") == "baseline"
    assert _normalize_playwright_mode("pr") == "baseline"
    assert _normalize_playwright_mode("audit") == "audit"
    assert _normalize_playwright_mode("full-depth") == "audit"
    assert _normalize_playwright_mode("off") == "off"
    assert _normalize_playwright_mode("invalid") == "off"


def test_normalize_sbom_mode() -> None:
    assert _normalize_sbom_mode("baseline") == "baseline"
    assert _normalize_sbom_mode("pr") == "baseline"
    assert _normalize_sbom_mode("audit") == "audit"
    assert _normalize_sbom_mode("full-depth") == "audit"
    assert _normalize_sbom_mode("off") == "off"
    assert _normalize_sbom_mode("invalid") == "off"


def test_normalize_model_policy_inputs() -> None:
    assert _normalize_model_id("gpt-5.3-codex", default="fallback") == "gpt-5.3-codex"
    assert _normalize_model_id("bad model; rm -rf /", default="fallback") == "fallback"
    assert _normalize_llm_failure_policy("warn") == "warn"
    assert _normalize_llm_failure_policy("deterministic_only") == "deterministic_only"
    assert _normalize_llm_failure_policy("invalid") == "block"


def test_parse_safe_command_blocks_shell_control_tokens() -> None:
    assert _parse_safe_command("npm run test:e2e:baseline") == [
        "npm",
        "run",
        "test:e2e:baseline",
    ]
    try:
        _parse_safe_command("npm run test:e2e:baseline && rm -rf /")
    except RuntimeError as exc:
        assert "forbidden shell control tokens" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError for forbidden shell control tokens")


def test_blocking_count_honors_severity_gate() -> None:
    counts = {"P0": 1, "P1": 2, "P2": 3, "P3": 4}
    assert _blocking_count(severity_gate="NONE", counts=counts) == 0
    assert _blocking_count(severity_gate="P0", counts=counts) == 1
    assert _blocking_count(severity_gate="P1", counts=counts) == 3
    assert _blocking_count(severity_gate="P2", counts=counts) == 6
    assert _blocking_count(severity_gate="P3", counts=counts) == 3


def test_execute_playwright_gate_baseline_with_bootstrap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _bridge_config(
        tmp_path,
        playwright_mode="baseline",
        playwright_bootstrap=True,
        playwright_base_url="http://127.0.0.1:4173",
    )
    bootstrap_calls: list[tuple[list[str], dict[str, str] | None]] = []
    run_calls: list[tuple[str, dict[str, str] | None]] = []

    def _fake_run_args(args: list[str], *, env: dict[str, str] | None = None) -> int:
        bootstrap_calls.append((args, env))
        return 0

    def _fake_run(command: str, *, env: dict[str, str] | None = None) -> int:
        run_calls.append((command, env))
        return 0

    monkeypatch.setattr("omargate.main._run_command_args", _fake_run_args)
    monkeypatch.setattr("omargate.main._run_command", _fake_run)

    status, detail = _execute_playwright_gate(config)
    assert status == "passed"
    assert "baseline" in detail
    assert bootstrap_calls[0][0] == ["npm", "ci", "--ignore-scripts"]
    assert bootstrap_calls[1][0] == ["npx", "playwright", "install", "--with-deps", "chromium"]
    assert run_calls[0][0] == "npm run test:e2e:baseline"
    assert run_calls[0][1]["PLAYWRIGHT_TEST_BASE_URL"] == "http://127.0.0.1:4173"


def test_execute_playwright_gate_audit_without_bootstrap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _bridge_config(tmp_path, playwright_mode="audit", playwright_bootstrap=False)
    run_calls: list[str] = []

    def _fake_run(command: str, *, env: dict[str, str] | None = None) -> int:
        run_calls.append(command)
        return 0

    monkeypatch.setattr("omargate.main._run_command", _fake_run)
    monkeypatch.setattr("omargate.main._run_command_args", lambda args, env=None: 0)

    status, detail = _execute_playwright_gate(config)
    assert status == "passed"
    assert "audit" in detail
    assert run_calls == ["npm run test:e2e:audit"]


def test_execute_playwright_gate_raises_on_command_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _bridge_config(tmp_path, playwright_mode="baseline", playwright_bootstrap=False)
    monkeypatch.setattr("omargate.main._run_command", lambda command, env=None: 7)
    monkeypatch.setattr("omargate.main._run_command_args", lambda args, env=None: 0)

    with pytest.raises(RuntimeError, match="Playwright gate failed"):
        _execute_playwright_gate(config)


def test_execute_sbom_gate_default_skips_when_no_supported_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _bridge_config(
        tmp_path,
        sbom_mode="baseline",
        sbom_bootstrap=False,
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    status, detail = _execute_sbom_gate(config)
    assert status == "skipped"
    assert "no Node/Python manifests" in detail


def test_execute_sbom_gate_uses_custom_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _bridge_config(
        tmp_path,
        sbom_mode="audit",
        sbom_bootstrap=False,
        sbom_audit_command="npm run sbom:audit",
    )
    run_calls: list[tuple[str, dict[str, str] | None]] = []

    def _fake_run(command: str, *, env: dict[str, str] | None = None) -> int:
        run_calls.append((command, env))
        return 0

    monkeypatch.setattr("omargate.main._run_command", _fake_run)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    status, detail = _execute_sbom_gate(config)
    assert status == "passed"
    assert "sbom:audit" in detail
    assert run_calls[0][0] == "npm run sbom:audit"
    assert run_calls[0][1]["SENTINELAYER_SBOM_OUTPUT_DIR"] == ".sentinelayer/sbom"


def test_execute_sbom_gate_default_node_and_python(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    config = _bridge_config(
        tmp_path,
        sbom_mode="audit",
        sbom_bootstrap=True,
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    command_calls: list[list[str]] = []

    def _fake_run_args(args: list[str], *, env: dict[str, str] | None = None) -> int:
        command_calls.append(args)
        return 0

    monkeypatch.setattr("omargate.main._run_command_args", _fake_run_args)
    status, detail = _execute_sbom_gate(config)
    assert status == "passed"
    assert "generated" in detail
    assert command_calls[0] == ["npm", "ci", "--ignore-scripts"]
    assert command_calls[1][:3] == ["npx", "--yes", "@cyclonedx/cyclonedx-npm"]
    assert command_calls[2][:3] == ["npx", "--yes", "@cyclonedx/cyclonedx-npm"]
    assert command_calls[3][:5] == ["python", "-m", "pip", "install", "--upgrade"]
    assert command_calls[4][0] == "cyclonedx-py"


def test_main_sets_playwright_status_failed_when_gate_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _bridge_config(tmp_path, playwright_mode="audit", playwright_bootstrap=False)
    output_path = tmp_path / "github_output.txt"
    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr(
        "omargate.main._execute_playwright_gate",
        lambda _config: (_ for _ in ()).throw(RuntimeError("playwright exploded")),
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("INPUT_SCAN_MODE", "deep")
    monkeypatch.setenv("INPUT_SEVERITY_GATE", "P1")

    exit_code = main()
    assert exit_code == 2

    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value

    assert outputs["gate_status"] == "error"
    assert outputs["playwright_status"] == "failed"
    assert outputs["playwright_mode"] == "audit"


def test_main_sets_sbom_status_failed_when_gate_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _bridge_config(tmp_path, sbom_mode="audit", sbom_bootstrap=False)
    output_path = tmp_path / "github_output.txt"
    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr(
        "omargate.main._execute_sbom_gate",
        lambda _config: (_ for _ in ()).throw(RuntimeError("sbom exploded")),
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("INPUT_SCAN_MODE", "deep")
    monkeypatch.setenv("INPUT_SEVERITY_GATE", "P1")

    exit_code = main()
    assert exit_code == 2

    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value

    assert outputs["gate_status"] == "error"
    assert outputs["sbom_status"] == "failed"
    assert outputs["sbom_mode"] == "audit"


def test_main_forwards_llm_policy_to_backend_trigger(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=False)
    output_path = tmp_path / "github_output.txt"
    captured_payloads: list[dict[str, object]] = []

    def _fake_request(**kwargs: object) -> dict[str, object]:
        payload = kwargs.get("payload")
        if isinstance(payload, dict):
            captured_payloads.append(payload)
        return {"status": "accepted", "investigation_run_id": "run-1"}

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_request)
    monkeypatch.setattr(
        "omargate.main._github_api_json_request",
        lambda **kwargs: [] if str(kwargs.get("method") or "GET") == "GET" else {"html_url": ""},
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    exit_code = main()
    assert exit_code == 0
    assert captured_payloads
    llm_policy = captured_payloads[0]["llm_policy"]
    assert isinstance(llm_policy, dict)
    assert llm_policy["sentinelayer_managed_llm"] is True
    assert llm_policy["model"] == "gpt-5.3-codex"
    assert llm_policy["codex_model"] == "gpt-5.3-codex"
    assert llm_policy["llm_failure_policy"] == "block"

    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    assert outputs["model"] == "gpt-5.3-codex"
    assert outputs["codex_model"] == "gpt-5.3-codex"


def test_main_exposes_quota_outputs_from_rate_limit_headers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=False)
    output_path = tmp_path / "github_output.txt"
    resets_at = int(time.time() + 2 * 3600)

    def _fake_request(**kwargs: object) -> dict[str, object]:
        response_headers = kwargs.get("response_headers")
        if isinstance(response_headers, dict):
            response_headers.update({
                "ratelimit-unified-status": "allowed",
                "ratelimit-unified-5h-utilization": "0.92",
                "ratelimit-unified-reset": str(resets_at),
            })
        return {"status": "accepted", "investigation_run_id": "run-1"}

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_request)
    monkeypatch.setattr(
        "omargate.main._github_api_json_request",
        lambda **kwargs: [] if str(kwargs.get("method") or "GET") == "GET" else {"html_url": ""},
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    exit_code = main()

    assert exit_code == 0
    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    assert outputs["quota_state"] == "warning"
    assert outputs["quota_warn"] == "true"
    assert outputs["quota_allow"] == "true"
    assert outputs["quota_resets_at"] == str(resets_at)
    assert "early_warning[5h]" in outputs["quota_reason"]


def test_main_exposes_throttled_quota_outputs_on_429(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=False)
    output_path = tmp_path / "github_output.txt"

    def _fake_request(**_kwargs: object) -> dict[str, object]:
        raise ApiRequestError(
            "rate limited",
            status_code=429,
            response_headers={"retry-after": "12"},
        )

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_request)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    exit_code = main()

    assert exit_code == 2
    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    assert outputs["gate_status"] == "error"
    assert outputs["quota_state"] == "throttled"
    assert outputs["quota_warn"] == "true"
    assert "retry_after=12s" in outputs["quota_reason"]


def test_main_deterministic_only_publishes_backend_check_without_polling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(
        tmp_path,
        wait_for_completion=True,
        sentinelayer_managed_llm=False,
        use_codex=False,
        llm_failure_policy="deterministic_only",
    )
    output_path = tmp_path / "github_output.txt"
    captured_requests: list[dict[str, object]] = []

    def _capture_api_request(**kwargs: object) -> dict[str, object]:
        captured_requests.append(dict(kwargs))
        assert kwargs["method"] == "POST"
        assert str(kwargs["url"]).endswith("/api/v1/github-app/trigger")
        payload = kwargs["payload"]
        assert isinstance(payload, dict)
        assert payload["repository_full_name"] == "owner/repo"
        assert payload["pr_number"] == 42
        llm_policy = payload["llm_policy"]
        assert isinstance(llm_policy, dict)
        assert llm_policy["llm_failure_policy"] == "deterministic_only"
        return {
            "status": "accepted",
            "delivery_id": "manual-deterministic",
            "investigation_run_id": "ghdeep_owner-repo_deterministic",
        }

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _capture_api_request)
    monkeypatch.setattr(
        "omargate.main._github_api_json_request",
        lambda **kwargs: [] if str(kwargs.get("method") or "GET") == "GET" else {"html_url": ""},
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_SHA", "abc123")

    exit_code = main()

    assert exit_code == 0
    assert len(captured_requests) == 1
    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    assert outputs["gate_status"] == "passed"
    assert outputs["run_id"].startswith("ghlocal_owner-repo_")
    run_dir = tmp_path / ".sentinelayer" / "runs" / outputs["run_id"]
    assert (run_dir / "RUN_SUMMARY.json").exists()
    summary = json.loads((run_dir / "RUN_SUMMARY.json").read_text(encoding="utf-8"))
    assert summary["backend_findings_count"] == 0
    assert summary["backend_check_publish"] == {
        "attempted": True,
        "delivery_id": "manual-deterministic",
        "investigation_run_id": "ghdeep_owner-repo_deterministic",
        "error": None,
    }
    assert summary["llm_policy"]["llm_failure_policy"] == "deterministic_only"
    assert summary["progress"] == "completed:deterministic-local"
    review_brief = (run_dir / "REVIEW_BRIEF.md").read_text(encoding="utf-8")
    assert "Backend findings source: `skipped:deterministic_only`" in review_brief
    assert "Dashboard:" not in review_brief


def test_main_deterministic_only_blocks_on_local_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(
        tmp_path,
        wait_for_completion=True,
        sentinelayer_managed_llm=False,
        use_codex=False,
        llm_failure_policy="deterministic_only",
    )
    output_path = tmp_path / "github_output.txt"
    local_dir = tmp_path / ".omargate" / "local"
    local_dir.mkdir(parents=True)
    (local_dir / "FINDINGS.jsonl").write_text(
        json.dumps(
            {
                "severity": "P1",
                "tool": "local",
                "file": "src/app.py",
                "line": 7,
                "title": "Local deterministic finding",
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    def _unexpected_api_request(**_kwargs: object) -> dict[str, object]:
        raise AssertionError(
            "deterministic_only must not publish a backend check when local findings block"
        )

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _unexpected_api_request)
    monkeypatch.setattr(
        "omargate.main._github_api_json_request",
        lambda **kwargs: [] if str(kwargs.get("method") or "GET") == "GET" else {"html_url": ""},
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_SHA", "abc123")

    exit_code = main()

    assert exit_code == 1
    outputs = {}
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    assert outputs["gate_status"] == "blocked"
    assert outputs["p1_count"] == "1"


def test_main_upserts_pr_comment_and_persistent_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=False)
    output_path = tmp_path / "github_output.txt"
    (tmp_path / "README.md").write_text("# AIdenID\n\nAgent access layer.\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "apps" / "api").mkdir(parents=True)
    (tmp_path / "apps" / "web").mkdir(parents=True)
    local_dir = tmp_path / ".omargate" / "local"
    local_dir.mkdir(parents=True)
    local_finding = {
        "gateId": "security",
        "tool": "semgrep",
        "severity": "P2",
        "file": "apps/api/app/routes/traffic.py",
        "line": 87,
        "title": "Example medium finding",
        "recommendedFix": "Tighten the route guard.",
    }
    (local_dir / "FINDINGS.jsonl").write_text(
        json.dumps(local_finding, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    api_requests: list[dict[str, object]] = []
    github_requests: list[dict[str, object]] = []

    def _fake_api_request(**kwargs: object) -> dict[str, object]:
        api_requests.append(dict(kwargs))
        if str(kwargs.get("method") or "GET") == "GET":
            return {
                "severity_counts": {"P0": 0, "P1": 0, "P2": 1, "P3": 1},
                "findings_source": "pack_executor",
                "findings": [
                    {
                        "severity": "P2",
                        "category": "cicd",
                        "title": "Release gate is not coupled to smoke evidence.",
                        "impact": "A deploy could promote without the expected smoke proof.",
                        "remediation_guidance": "Make the smoke job a required release input.",
                        "scope": {
                            "path": ".github/workflows/release.yml",
                            "line_start": 12,
                        },
                    }
                ],
            }
        return {
            "status": "accepted",
            "investigation_run_id": "run-1",
            "run_result_token": "run-read-token-1",
        }

    def _fake_github_request(**kwargs: object) -> object:
        github_requests.append(dict(kwargs))
        method = str(kwargs.get("method") or "GET")
        if method == "GET":
            return []
        if method == "POST":
            return {"html_url": "https://github.com/owner/repo/pull/42#issuecomment-new"}
        raise AssertionError(f"unexpected method: {method}")

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_api_request)
    monkeypatch.setattr("omargate.main._github_api_json_request", _fake_github_request)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_SHA", "abc123")

    exit_code = main()

    assert exit_code == 0
    findings_gets = [
        req
        for req in api_requests
        if str(req.get("method") or "GET") == "GET"
        and str(req.get("url") or "").endswith("/runs/run-1/findings?limit=100")
    ]
    assert findings_gets
    assert findings_gets[0]["token"] == "run-read-token-1"
    post_requests = [req for req in github_requests if req.get("method") == "POST"]
    assert len(post_requests) == 1
    comment_body = post_requests[0]["payload"]["body"]  # type: ignore[index]
    assert "sentinelayer:omar-gate:owner/repo:pr-42" in comment_body
    assert "## 🛡️ Omar Gate: ✅ PASSED" in comment_body
    assert "Result: Passed (severity_gate=P1): no P0/P1 findings" in comment_body
    assert "| P2 (Medium) | 1 | No |" in comment_body
    assert "Codebase Synopsis: README.md: AIdenID. Architecture: apps workspace. Stack: Node.js, Next.js, React." in comment_body
    assert "### Top Findings" in comment_body
    assert "**P2** [`.github/workflows/release.yml:12`]" in comment_body
    assert "Release gate is not coupled to smoke evidence." in comment_body
    assert "Compatibility Bridge" not in comment_body
    assert "run-1" in comment_body

    run_dir = tmp_path / ".sentinelayer" / "runs" / "run-1"
    artifacts_dir = tmp_path / ".sentinelayer" / "artifacts" / "run-1"
    assert (run_dir / "RUN_SUMMARY.json").exists()
    assert (run_dir / "REVIEW_BRIEF.md").exists()
    assert (run_dir / "AUDIT_REPORT.md").read_text(encoding="utf-8") == (
        run_dir / "REVIEW_BRIEF.md"
    ).read_text(encoding="utf-8")
    persisted_findings = [
        json.loads(line)
        for line in (run_dir / "FINDINGS.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(persisted_findings) == 2
    assert any(row.get("title") == "Example medium finding" for row in persisted_findings)
    assert any(
        row.get("title") == "Release gate is not coupled to smoke evidence."
        for row in persisted_findings
    )
    assert (artifacts_dir / "BRIDGE_SUMMARY.md").exists()


def test_main_polls_status_for_exact_trigger_delivery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=True)
    output_path = tmp_path / "github_output.txt"
    api_requests: list[dict[str, object]] = []
    github_requests: list[dict[str, object]] = []

    def _fake_api_request(**kwargs: object) -> dict[str, object]:
        api_requests.append(dict(kwargs))
        url = str(kwargs.get("url") or "")
        if str(kwargs.get("method") or "GET") == "POST":
            return {
                "status": "accepted",
                "delivery_id": "manual/current+1",
                "investigation_run_id": "run-1",
                "run_result_token": "run-read-token-1",
            }
        if url.endswith("/runs/run-1/status?delivery_id=manual%2Fcurrent%2B1"):
            return {
                "status": "completed",
                "progress_label": "completed:pack-executor",
                "severity_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
            }
        if url.endswith("/runs/run-1/findings?limit=100"):
            return {
                "findings": [],
                "severity_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
            }
        raise AssertionError(f"unexpected API URL: {url}")

    def _fake_github_request(**kwargs: object) -> object:
        github_requests.append(dict(kwargs))
        if str(kwargs.get("method") or "GET") == "GET":
            return []
        return {"html_url": "https://github.com/owner/repo/pull/42#issuecomment-new"}

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_api_request)
    monkeypatch.setattr("omargate.main._github_api_json_request", _fake_github_request)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_SHA", "abc123")

    exit_code = main()

    assert exit_code == 0
    status_gets = [
        req
        for req in api_requests
        if str(req.get("url") or "").endswith(
            "/runs/run-1/status?delivery_id=manual%2Fcurrent%2B1"
        )
    ]
    assert status_gets
    assert status_gets[0]["token"] == "run-read-token-1"


def test_main_updates_existing_omar_pr_comment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=False)
    github_requests: list[dict[str, object]] = []

    def _fake_api_request(**kwargs: object) -> dict[str, object]:
        return {"status": "accepted", "investigation_run_id": "run-2"}

    def _fake_github_request(**kwargs: object) -> object:
        github_requests.append(dict(kwargs))
        method = str(kwargs.get("method") or "GET")
        if method == "GET":
            return [
                {
                    "id": 123,
                    "body": "<!-- sentinelayer:omar-gate:owner/repo:pr-42 -->\nold",
                }
            ]
        if method == "PATCH":
            return {"html_url": "https://github.com/owner/repo/pull/42#issuecomment-123"}
        raise AssertionError(f"unexpected method: {method}")

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_api_request)
    monkeypatch.setattr("omargate.main._github_api_json_request", _fake_github_request)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    exit_code = main()

    assert exit_code == 0
    assert any(req.get("method") == "PATCH" for req in github_requests)
    assert not any(req.get("method") == "POST" for req in github_requests)


def test_main_comment_upsert_failure_is_fail_soft(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _bridge_config(tmp_path, wait_for_completion=False)

    def _fake_api_request(**kwargs: object) -> dict[str, object]:
        return {"status": "accepted", "investigation_run_id": "run-3"}

    def _fake_github_request(**kwargs: object) -> object:
        raise RuntimeError("resource not accessible by integration")

    monkeypatch.setattr("omargate.main._load_config", lambda: config)
    monkeypatch.setattr("omargate.main._execute_playwright_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._execute_sbom_gate", lambda _config: ("skipped", "ok"))
    monkeypatch.setattr("omargate.main._api_json_request", _fake_api_request)
    monkeypatch.setattr("omargate.main._github_api_json_request", _fake_github_request)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    exit_code = main()

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Omar Gate PR comment skipped" in captured.out
    assert "resource not accessible by integration" in captured.out
    assert (tmp_path / ".sentinelayer" / "runs" / "run-3" / "RUN_SUMMARY.json").exists()


def test_api_json_request_uses_long_enough_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_timeouts: list[int] = []

    class _FakeResponse:
        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"ok": true}'

    def _fake_urlopen(request: object, *, timeout: int) -> _FakeResponse:
        captured_timeouts.append(timeout)
        return _FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    payload = _api_json_request(
        method="GET",
        url="https://api.sentinelayer.test/api/v1/github-app/runs/run-1/status",
        token="token",
    )

    assert payload == {"ok": True}
    assert captured_timeouts == [_API_REQUEST_TIMEOUT_SECONDS]
    assert _API_REQUEST_TIMEOUT_SECONDS >= 120
