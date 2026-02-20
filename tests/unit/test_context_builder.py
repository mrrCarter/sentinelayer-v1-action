from __future__ import annotations

from pathlib import Path

from omargate.analyze.llm.context_builder import ContextBuilder


def _make_ingest(files: list[str], hotspots: dict, categories: dict[str, str] | None = None) -> dict:
    categories = categories or {}
    return {
        "stats": {
            "total_files": len(files),
            "in_scope_files": len(files),
            "total_lines": 0,
        },
        "files": [
            {
                "path": path,
                "category": categories.get(path, "source"),
                "language": "python",
            }
            for path in files
        ],
        "hotspots": hotspots,
        "dependencies": {"package_manager": "pip"},
    }


def test_context_respects_token_budget(tmp_path: Path) -> None:
    """Context builder stops adding files when budget exhausted."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    file_path = repo_root / "a.py"
    file_path.write_text("a" * 500, encoding="utf-8")

    ingest = _make_ingest(["a.py"], hotspots={})
    builder = ContextBuilder(max_tokens=300, chars_per_token=1.0)

    result = builder.build_context(ingest, [], repo_root, scan_mode="deep")

    assert result.token_count <= 300
    assert result.files_truncated or result.files_skipped


def test_context_prioritizes_hotspots(tmp_path: Path) -> None:
    """Hotspot files included before regular files."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    hot_file = repo_root / "hot.py"
    regular_file = repo_root / "regular.py"
    hot_file.write_text("print('hot')\n", encoding="utf-8")
    regular_file.write_text("print('regular')\n", encoding="utf-8")

    ingest = _make_ingest(
        ["hot.py", "regular.py"],
        hotspots={"auth": ["hot.py"]},
    )
    builder = ContextBuilder(max_tokens=2000, chars_per_token=1.0)

    result = builder.build_context(ingest, [], repo_root, scan_mode="deep")

    assert result.files_included
    assert result.files_included[0] == "hot.py"


def test_context_prioritizes_cicd_files_before_hotspots(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    workflow_file = repo_root / ".github" / "workflows" / "deploy.yml"
    hot_file = repo_root / "hot.py"
    workflow_file.write_text("name: deploy\n", encoding="utf-8")
    hot_file.write_text("print('hot')\n", encoding="utf-8")

    ingest = _make_ingest(
        [".github/workflows/deploy.yml", "hot.py"],
        hotspots={"auth": ["hot.py"]},
        categories={".github/workflows/deploy.yml": "config"},
    )
    builder = ContextBuilder(max_tokens=2000, chars_per_token=1.0)

    result = builder.build_context(ingest, [], repo_root, scan_mode="deep")

    assert result.files_included
    assert result.files_included[0] == ".github/workflows/deploy.yml"


def test_context_includes_deterministic_findings(tmp_path: Path) -> None:
    """Deterministic scan results summarized in context."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "main.py").write_text("print('ok')\n", encoding="utf-8")

    ingest = _make_ingest(["main.py"], hotspots={})
    findings = [
        {
            "severity": "P1",
            "category": "XSS",
            "file_path": "main.py",
            "line_start": 1,
            "message": "Potential XSS",
        }
    ]

    builder = ContextBuilder(max_tokens=2000, chars_per_token=1.0)
    result = builder.build_context(ingest, findings, repo_root, scan_mode="deep")

    assert "Deterministic Scan Results" in result.content
    assert "Potential XSS" in result.content


def test_context_pr_diff_mode(tmp_path: Path) -> None:
    """PR diff mode prioritizes changed files."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    changed = repo_root / "changed.py"
    hot_file = repo_root / "hot.py"
    changed.write_text("print('changed')\n", encoding="utf-8")
    hot_file.write_text("print('hot')\n", encoding="utf-8")

    ingest = _make_ingest(
        ["changed.py", "hot.py"],
        hotspots={"auth": ["hot.py"]},
    )
    builder = ContextBuilder(max_tokens=2000, chars_per_token=1.0)

    result = builder.build_context(
        ingest,
        [],
        repo_root,
        scan_mode="pr-diff",
        diff_content="diff --git a/changed.py b/changed.py",
        changed_files=["changed.py"],
    )

    assert result.files_included
    assert result.files_included[0] == "changed.py"


def test_context_handles_empty_ingest(tmp_path: Path) -> None:
    """Graceful handling of empty ingest data."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    builder = ContextBuilder(max_tokens=1000, chars_per_token=1.0)
    result = builder.build_context({}, [], repo_root)

    assert "Repository Overview" in result.content
    assert result.token_count >= 0


def test_context_includes_spec_context_before_pr_diff(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "changed.py").write_text("print('changed')\n", encoding="utf-8")

    ingest = _make_ingest(["changed.py"], hotspots={})
    builder = ContextBuilder(max_tokens=4000, chars_per_token=1.0)

    result = builder.build_context(
        ingest=ingest,
        deterministic_findings=[],
        repo_root=repo_root,
        spec_context={
            "spec_hash": "a" * 64,
            "project_name": "Spec Aware App",
            "synopsis": "Sample synopsis",
            "tech_stack": ["Python", "FastAPI"],
            "security_rules": "- Validate inputs",
            "quality_gates": "- tests required",
            "domain_rules": "- enforce workflow state machine",
            "mode": "quick",
        },
        scan_mode="pr-diff",
        diff_content="diff --git a/changed.py b/changed.py",
        changed_files=["changed.py"],
    )

    spec_idx = result.content.find("## SENTINELAYER SPEC CONTEXT")
    diff_idx = result.content.find("## PR Diff")
    assert spec_idx != -1
    assert diff_idx != -1
    assert spec_idx < diff_idx
