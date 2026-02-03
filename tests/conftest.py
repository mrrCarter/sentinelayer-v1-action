from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def event_pr_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "event_pr.json"


@pytest.fixture
def event_fork_pr_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "event_fork_pr.json"


@pytest.fixture
def event_push_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "event_push.json"
