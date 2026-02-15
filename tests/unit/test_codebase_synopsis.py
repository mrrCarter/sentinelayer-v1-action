from __future__ import annotations

from omargate.ingest.codebase_snapshot import build_codebase_synopsis
from omargate.ingest.quick_learn import QuickLearnSummary


def test_codebase_synopsis_prefers_quick_learn_readme() -> None:
    quick_learn = QuickLearnSummary(
        project_name="sentinelayer",
        description="Policy-driven CI/CD security gate for pull requests",
        tech_stack=["Python", "TypeScript", "Docker"],
        architecture="monorepo",
        entry_points=["src/omargate/main.py"],
        source_doc="README.md",
        raw_excerpt="# Sentinelayer",
    )

    synopsis = build_codebase_synopsis(
        codebase_snapshot={"stats": {"in_scope_files": 180, "source_loc_total": 17058}},
        quick_learn=quick_learn,
    )

    assert synopsis
    assert "README:" in synopsis
    assert "Stack: Python, TypeScript, Docker." in synopsis


def test_codebase_synopsis_falls_back_to_snapshot() -> None:
    snapshot = {
        "stats": {"in_scope_files": 180, "source_loc_total": 17058},
        "languages": [
            {"language": "python", "files": 114, "loc": 13815},
            {"language": "typescript", "files": 61, "loc": 2748},
        ],
        "hotspots": [
            {"category": "auth", "count": 12, "examples": []},
            {"category": "infrastructure", "count": 30, "examples": []},
        ],
    }

    synopsis = build_codebase_synopsis(codebase_snapshot=snapshot, quick_learn=None)

    assert synopsis
    assert "Inferred:" in synopsis
    assert "Primary languages: python, typescript." in synopsis
