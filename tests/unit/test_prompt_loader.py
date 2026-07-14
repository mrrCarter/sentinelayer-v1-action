from __future__ import annotations

import json
from pathlib import Path

from omargate.analyze.llm.prompt_loader import PromptLoader


def write_manifest(root: Path, prompt_file: str) -> None:
    manifest = {
        "schema_version": "1.0",
        "default_prompt": "review",
        "prompts": {
            "review": {
                "file": prompt_file,
                "scan_modes": ["pr-diff"],
                "max_context_tokens": 1234,
            }
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_prompt_loader_reads_file_inside_prompt_root(tmp_path: Path) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "review.txt").write_text("review safely", encoding="utf-8")
    write_manifest(prompts, "review.txt")

    loader = PromptLoader(prompts)

    assert loader.get_prompt(scan_mode="pr-diff") == "review safely"
    assert loader.get_max_context_tokens() == 1234


def test_prompt_loader_blocks_parent_traversal(tmp_path: Path) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (tmp_path / "secret.txt").write_text("do-not-read", encoding="utf-8")
    write_manifest(prompts, "../secret.txt")

    result = PromptLoader(prompts).get_prompt()

    assert "do-not-read" not in result
    assert result == PromptLoader.builtin_minimal_prompt()


def test_prompt_loader_falls_back_for_malformed_manifest(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text("not-json", encoding="utf-8")

    loader = PromptLoader(tmp_path)

    assert loader.get_prompt() == PromptLoader.builtin_minimal_prompt()


def test_prompt_loader_rejects_oversized_prompt(tmp_path: Path) -> None:
    prompt = tmp_path / "huge.txt"
    prompt.write_bytes(b"x" * 1_048_577)
    write_manifest(tmp_path, prompt.name)

    assert PromptLoader(tmp_path).get_prompt() == PromptLoader.builtin_minimal_prompt()
