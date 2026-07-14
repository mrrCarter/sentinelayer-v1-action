from pathlib import Path

from omargate import __version__
from omargate.main import ACTION_VERSION


def test_release_version_surfaces_match() -> None:
    readme = (Path(__file__).parents[2] / "README.md").read_text(encoding="utf-8")

    assert __version__ == ACTION_VERSION
    assert f"action-v{ACTION_VERSION}-blue" in readme
