from __future__ import annotations

import json
from pathlib import Path

from omargate.ingest.quick_learn import estimate_tokens, extract_quick_learn_summary


def test_quick_learn_readme_extracts_correctly(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text(
        "\n".join(
            [
                "# CoolApp",
                "",
                "A FastAPI service for secure scanning.",
                "",
                "Entry point: `src/main.py`",
                "",
                "## Installation",
                "pip install -r requirements.txt",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "src").mkdir()
    (repo / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")

    summary = extract_quick_learn_summary(repo)

    assert summary.source_doc == "README.md"
    assert summary.project_name == "CoolApp"
    assert summary.description.startswith("A FastAPI service")
    assert "FastAPI" in summary.tech_stack
    assert "Python" in summary.tech_stack
    assert "src/main.py" in summary.entry_points


def test_quick_learn_package_json_fallback(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "myapp",
                "description": "Test app",
                "scripts": {"dev": "node server.js", "build": "tsc"},
            }
        ),
        encoding="utf-8",
    )

    summary = extract_quick_learn_summary(repo)

    assert summary.source_doc == "package.json"
    assert summary.project_name == "myapp"
    assert summary.description == "Test app"
    assert "Node.js" in summary.tech_stack


def test_quick_learn_truncates_to_600_tokens(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    # 80 lines of dense text will exceed token budget without truncation.
    long_lines = ["# BigDoc"] + ["word " * 200 for _ in range(80)]
    (repo / "README.md").write_text("\n".join(long_lines), encoding="utf-8")

    summary = extract_quick_learn_summary(repo)

    assert estimate_tokens(summary.raw_excerpt) <= 600


def test_quick_learn_missing_docs_defaults(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    summary = extract_quick_learn_summary(repo)

    assert summary.project_name
    assert summary.architecture in {"unknown", "monorepo", "monolith", "microservices", "serverless"}
    assert summary.tech_stack == []
    assert summary.source_doc == ""
    assert summary.raw_excerpt == ""

