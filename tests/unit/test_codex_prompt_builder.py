from __future__ import annotations

from pathlib import Path

from omargate.analyze.codex.codex_prompt_builder import CodexPromptBuilder
from omargate.ingest.quick_learn import QuickLearnSummary


def _ql(stack: list[str]) -> QuickLearnSummary:
    return QuickLearnSummary(
        project_name="demo",
        description="demo project",
        tech_stack=stack,
        architecture="monolith",
        entry_points=["src/"],
        source_doc="README.md",
        raw_excerpt="demo",
    )


def test_react_project_gets_frontend_checks(tmp_path: Path) -> None:
    builder = CodexPromptBuilder(max_tokens=2000)
    built = builder.build_prompt(
        repo_root=tmp_path,
        quick_learn=_ql(["React", "TypeScript"]),
        deterministic_findings=[],
        tech_stack=["React", "TypeScript"],
        scan_mode="pr-diff",
        diff_content="diff --git a/x b/x\n+ console.log('x')\n",
        hotspot_files=[],
    )
    assert "dangerouslySetInnerHTML" in built.prompt
    assert "useEffect" in built.prompt


def test_python_project_gets_backend_checks(tmp_path: Path) -> None:
    builder = CodexPromptBuilder(max_tokens=2000)
    built = builder.build_prompt(
        repo_root=tmp_path,
        quick_learn=_ql(["Python", "FastAPI"]),
        deterministic_findings=[],
        tech_stack=["Python", "FastAPI"],
        scan_mode="pr-diff",
        diff_content="diff --git a/x b/x\n+ eval('1')\n",
        hotspot_files=[],
    )
    assert "parameterized queries" in built.prompt
    assert "eval" in built.prompt


def test_pr_diff_mode_includes_diff(tmp_path: Path) -> None:
    diff = "diff --git a/a b/a\n+1\n"
    builder = CodexPromptBuilder(max_tokens=2000)
    built = builder.build_prompt(
        repo_root=tmp_path,
        quick_learn=_ql(["Node.js"]),
        deterministic_findings=[],
        tech_stack=["Node.js"],
        scan_mode="pr-diff",
        diff_content=diff,
        hotspot_files=[],
    )
    assert "Code to Review (PR Diff)" in built.prompt
    assert diff.strip() in built.prompt


def test_deep_mode_includes_hotspot_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "server.py").write_text("print('hi')\n")
    builder = CodexPromptBuilder(max_tokens=2000)
    built = builder.build_prompt(
        repo_root=tmp_path,
        quick_learn=_ql(["Python"]),
        deterministic_findings=[],
        tech_stack=["Python"],
        scan_mode="deep",
        diff_content=None,
        hotspot_files=["src/server.py"],
    )
    assert "Code to Review (Hotspot Files)" in built.prompt
    assert "File: src/server.py" in built.prompt
    assert "print('hi')" in built.prompt


def test_token_budget_respected(tmp_path: Path) -> None:
    diff = "A" * 20000
    builder = CodexPromptBuilder(max_tokens=200)
    built = builder.build_prompt(
        repo_root=tmp_path,
        quick_learn=_ql(["Node.js"]),
        deterministic_findings=[],
        tech_stack=["Node.js"],
        scan_mode="pr-diff",
        diff_content=diff,
        hotspot_files=[],
    )
    assert builder.estimate_tokens(built.prompt) <= 200

