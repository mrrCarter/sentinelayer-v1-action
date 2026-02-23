from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

from omargate.harness.suites import dep_audit
from omargate.harness.suites.dep_audit import (
    DepAuditSuite,
    _parse_ignore_ids,
    _parse_pip_vulnerability_count,
)


def test_parse_pip_vulnerability_count_handles_no_vulns() -> None:
    payload = {
        "dependencies": [
            {"name": "requests", "version": "2.32.4", "vulns": []},
            {"name": "httpx", "version": "0.27.0", "vulns": []},
        ],
        "fixes": [],
    }
    assert _parse_pip_vulnerability_count(payload) == 0


def test_parse_pip_vulnerability_count_sums_nested_vulns() -> None:
    payload = {
        "dependencies": [
            {"name": "requests", "version": "2.31.0", "vulns": [{"id": "CVE-1"}, {"id": "CVE-2"}]},
            {"name": "foo", "version": "1.0.0", "vulns": [{"id": "CVE-3"}]},
        ]
    }
    assert _parse_pip_vulnerability_count(payload) == 3


def test_parse_ignore_ids_splits_and_deduplicates() -> None:
    raw = "CVE-1, CVE-2\nCVE-1 ; GHSA-abc"
    assert _parse_ignore_ids(raw) == ["CVE-1", "CVE-2", "GHSA-abc"]


@pytest.mark.anyio
async def test_pip_audit_no_vulns_does_not_emit_finding(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")

    async def _fake_run_command(*_args, **_kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout='{"dependencies":[{"name":"requests","version":"2.32.4","vulns":[]}],"fixes":[]}',
        )

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    suite = DepAuditSuite(tech_stack=[])

    finding = await suite._pip_audit(tmp_path)
    assert finding is None


@pytest.mark.anyio
async def test_pip_audit_passes_ignore_ids(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("python-jose==3.5.0\n", encoding="utf-8")

    captured_args: list[list[str]] = []

    async def _fake_run_command(args, *_unused, **_kwargs):
        captured_args.append(args)
        return SimpleNamespace(returncode=0, stdout='{"dependencies":[],"fixes":[]}')

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    suite = DepAuditSuite(tech_stack=[], pip_audit_ignore_ids="CVE-2024-23342,GHSA-test")

    finding = await suite._pip_audit(tmp_path)

    assert finding is None
    assert captured_args
    assert captured_args[0] == [
        "pip-audit",
        "-r",
        "requirements.txt",
        "-f",
        "json",
        "--ignore-vuln",
        "CVE-2024-23342",
        "--ignore-vuln",
        "GHSA-test",
    ]
