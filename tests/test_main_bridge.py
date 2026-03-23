from __future__ import annotations

from pathlib import Path

import pytest

from omargate.main import (
    BridgeConfig,
    _blocking_count,
    _command_for_scan_mode,
    _compute_spec_hash_from_sources,
    _detect_pr_number,
    _execute_playwright_gate,
    _normalize_playwright_mode,
    _normalize_spec_binding_mode,
    _normalize_spec_hash,
    _normalize_spec_sources,
    _parse_safe_command,
    main,
)


def _bridge_config(
    tmp_path: Path,
    *,
    playwright_mode: str = "baseline",
    playwright_bootstrap: bool = True,
    playwright_base_url: str = "",
) -> BridgeConfig:
    event_path = tmp_path / "event.json"
    event_path.write_text('{"pull_request":{"number":42}}', encoding="utf-8")
    return BridgeConfig(
        token="token",
        status_poll_token="token",
        api_url="https://api.sentinelayer.com",
        repo_full_name="owner/repo",
        event_path=event_path,
        event_name="pull_request",
        scan_mode="deep",
        severity_gate="P1",
        command_override="",
        provider_installation_id=None,
        spec_hash=None,
        spec_id=None,
        spec_binding_mode="none",
        spec_sources=[],
        wait_for_completion=True,
        wait_timeout_seconds=900,
        wait_poll_seconds=10,
        pr_number_override=42,
        playwright_mode=playwright_mode,
        playwright_base_url=playwright_base_url,
        playwright_bootstrap=playwright_bootstrap,
        playwright_baseline_command="npm run test:e2e:baseline",
        playwright_audit_command="npm run test:e2e:audit",
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
