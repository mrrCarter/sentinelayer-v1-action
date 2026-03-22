from __future__ import annotations

from pathlib import Path

from omargate.main import (
    _blocking_count,
    _command_for_scan_mode,
    _compute_spec_hash_from_sources,
    _detect_pr_number,
    _normalize_spec_binding_mode,
    _normalize_spec_hash,
    _normalize_spec_sources,
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
    assert _command_for_scan_mode("full-depth") == "/omar full-depth"
    assert _command_for_scan_mode("unknown") == "/omar deep-scan"


def test_blocking_count_honors_severity_gate() -> None:
    counts = {"P0": 1, "P1": 2, "P2": 3, "P3": 4}
    assert _blocking_count(severity_gate="NONE", counts=counts) == 0
    assert _blocking_count(severity_gate="P0", counts=counts) == 1
    assert _blocking_count(severity_gate="P1", counts=counts) == 3
    assert _blocking_count(severity_gate="P2", counts=counts) == 6
    assert _blocking_count(severity_gate="P3", counts=counts) == 3
