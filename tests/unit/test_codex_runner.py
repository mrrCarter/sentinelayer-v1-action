from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from omargate.analyze.codex.codex_runner import CodexRunner, parse_codex_findings


def test_jsonl_parsing_valid() -> None:
    text = '\n'.join(
        [
            '{"severity":"P1","category":"auth","file_path":"src/a.py","line_start":3,"message":"x",'
            '"fix_plan":"Pseudo-code: enforce auth guard in this handler and add authorization tests."}',
            '{"no_findings": true}',
        ]
    )
    findings, errors, no_findings = parse_codex_findings(text)
    assert len(findings) == 1
    assert errors == []
    assert no_findings is True
    assert findings[0]["source"] == "codex"
    assert "auth guard" in findings[0]["fix_plan"]


def test_jsonl_parsing_malformed_lines() -> None:
    text = '\n'.join(
        [
            "{not json}",
            '{"severity":"P9","category":"x","file_path":"a","line_start":1,"message":"x"}',
            '{"severity":"P2","category":"x","file_path":"a","line_start":1,"message":"ok"}',
        ]
    )
    findings, errors, no_findings = parse_codex_findings(text)
    assert len(findings) == 1
    assert no_findings is False
    assert len(errors) >= 2
    assert findings[0]["fix_plan"].startswith("Pseudo-code:")


def test_jsonl_parsing_empty() -> None:
    findings, errors, no_findings = parse_codex_findings("")
    assert findings == []
    assert no_findings is False
    assert errors


def test_code_fenced_jsonl_is_stripped_cleanly() -> None:
    text = "\n".join(
        [
            "```jsonl",
            '{"severity":"P1","category":"auth","file_path":"src/a.py","line_start":3,"message":"x"}',
            '{"no_findings": true}',
            "```",
        ]
    )
    findings, errors, no_findings = parse_codex_findings(text)
    assert len(findings) == 1
    assert errors == []
    assert no_findings is True


@pytest.mark.anyio
async def test_timeout_handling(tmp_path: Path, monkeypatch) -> None:
    class FakeProc:
        def __init__(self) -> None:
            self.returncode = None

        async def communicate(self, input: bytes | None = None):  # noqa: A002
            await asyncio.sleep(10)
            return b"", b""

        def kill(self) -> None:
            self.returncode = -9

    async def fake_create(*args, **kwargs):  # noqa: ANN001
        return FakeProc()

    monkeypatch.setattr("shutil.which", lambda _: "codex")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    runner = CodexRunner(api_key="sk_test_dummy", model="gpt-5.2-codex")
    res = await runner.run_audit(prompt="x", working_dir=str(tmp_path), timeout=0.01)
    assert res.success is False
    assert res.error and "timed out" in res.error.lower()


@pytest.mark.anyio
async def test_missing_codex_cli_is_graceful(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    runner = CodexRunner(api_key="sk_test_dummy", model="gpt-5.2-codex")
    res = await runner.run_audit(prompt="x", working_dir=str(tmp_path))
    assert res.success is False
    assert res.error and "not found" in res.error.lower()
