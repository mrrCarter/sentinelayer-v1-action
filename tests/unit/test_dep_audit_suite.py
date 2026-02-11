from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

from omargate.harness.suites import dep_audit
from omargate.harness.suites.dep_audit import DepAuditSuite, _parse_pip_vulnerability_count


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
