from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from omargate.harness.runner import HarnessRunner, SecuritySuite


def _touch(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_node_project_selects_expected_suites(tmp_path: Path) -> None:
    _touch(tmp_path / "package.json", '{"name":"x","dependencies":{}}')
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=["Node.js"])
    suites = runner._select_suites()
    names = {s.name for s in suites}
    assert "secrets_in_git" in names
    assert "dependency_audit" in names
    assert "config_hardening" in names
    assert "build_integrity" in names


def test_python_project_selects_expected_suites(tmp_path: Path) -> None:
    _touch(tmp_path / "pyproject.toml", "[project]\nname='x'\n")
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=["Python"])
    suites = runner._select_suites()
    names = {s.name for s in suites}
    assert "secrets_in_git" in names
    assert "dependency_audit" in names
    assert "config_hardening" in names
    assert "build_integrity" not in names


def test_empty_project_runs_only_secrets_in_git(tmp_path: Path) -> None:
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=[])
    suites = runner._select_suites()
    assert [s.name for s in suites] == ["secrets_in_git"]


@pytest.mark.anyio
async def test_suite_timeout_is_enforced(tmp_path: Path, monkeypatch) -> None:
    class SlowSuite(SecuritySuite):
        @property
        def name(self) -> str:
            return "slow"

        def applies_to(self, tech_stack: list[str]) -> bool:
            return True

        async def run(self, project_root: str):
            await asyncio.sleep(10)
            return []

    runner = HarnessRunner(
        project_root=str(tmp_path),
        tech_stack=[],
        per_suite_timeout_s=1,
        total_timeout_s=2,
    )
    monkeypatch.setattr(runner, "_select_suites", lambda: [SlowSuite()])
    findings = await runner.run()
    assert any(f.pattern_id == "HARNESS-TIMEOUT" for f in findings)
    assert all(f.source == "harness" for f in findings)


@pytest.mark.anyio
async def test_findings_are_harness_source(tmp_path: Path, monkeypatch) -> None:
    from omargate.analyze.deterministic.pattern_scanner import Finding

    class OneFindingSuite(SecuritySuite):
        @property
        def name(self) -> str:
            return "one"

        def applies_to(self, tech_stack: list[str]) -> bool:
            return True

        async def run(self, project_root: str):
            return [
                Finding(
                    id="X",
                    pattern_id="X",
                    severity="P3",
                    category="harness",
                    file_path="x",
                    line_start=1,
                    line_end=1,
                    snippet="",
                    message="x",
                    recommendation="x",
                    confidence=1.0,
                    source="harness",
                )
            ]

    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=[])
    monkeypatch.setattr(runner, "_select_suites", lambda: [OneFindingSuite()])
    findings = await runner.run()
    assert len(findings) == 1
    assert findings[0].source == "harness"

