"""Tests for omargate.fix_handoff_cli — the `/omar fix` command handler."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ACTION_SRC = Path(__file__).resolve().parent.parent / "src"


def write_findings(tmp: Path, entries: list[dict]) -> Path:
    path = tmp / "FINDINGS.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry) + "\n")
    return path


def write_comment(tmp: Path, body: str) -> Path:
    path = tmp / "comment.md"
    path.write_text(body, encoding="utf-8")
    return path


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "omargate.fix_handoff_cli", *args],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ACTION_SRC)},
    )


class FixHandoffCliTests(unittest.TestCase):
    def test_no_command_in_comment_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            findings = write_findings(tmp, [])
            comment = write_comment(tmp, "just a normal review comment")
            result = run_cli([
                "--path", tmp_str,
                "--findings-file", str(findings),
                "--comment-body-file", str(comment),
            ])
        self.assertEqual(result.returncode, 3, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIsNone(payload["command"])

    def test_rate_limited_command_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            findings = write_findings(tmp, [])
            comment = write_comment(tmp, "/omar fix crypto.md5")
            result = run_cli([
                "--path", tmp_str,
                "--findings-file", str(findings),
                "--comment-body-file", str(comment),
                "--fixes-in-build", "3",
                "--per-build-limit", "3",
            ])
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["decision"]["accepted"])
        self.assertTrue(payload["decision"]["rate_limited"])
        self.assertIsNone(payload["plan"])

    def test_finding_not_found_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            findings = write_findings(tmp, [
                {
                    "gateId": "security",
                    "tool": "semgrep",
                    "severity": "P0",
                    "file": "app/auth/login.ts",
                    "line": 10,
                    "title": "something else",
                    "ruleId": "sast.eval",
                },
            ])
            comment = write_comment(tmp, "/omar fix not-a-real-finding-id")
            result = run_cli([
                "--path", tmp_str,
                "--findings-file", str(findings),
                "--comment-body-file", str(comment),
            ])
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["decision"]["accepted"])
        self.assertIsNone(payload["plan"])
        self.assertIn("not found", payload["error"])

    def test_happy_path_emits_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            scaffold = tmp / ".sentinelayer" / "scaffold.yaml"
            scaffold.parent.mkdir(parents=True, exist_ok=True)
            scaffold.write_text(
                textwrap.dedent(
                    """
                    ownership_rules:
                      - pattern: app/auth/login.ts
                        persona: security
                    """
                ).strip(),
                encoding="utf-8",
            )
            findings = write_findings(tmp, [
                {
                    "gateId": "security",
                    "tool": "semgrep",
                    "severity": "P0",
                    "file": "app/auth/login.ts",
                    "line": 42,
                    "title": "MD5 used for session token",
                    "description": "md5 is collision-broken",
                    "ruleId": "crypto.md5",
                    "recommendedFix": "switch to SHA-256",
                },
            ])
            comment = write_comment(tmp, "Please /omar fix crypto.md5")
            result = run_cli([
                "--path", tmp_str,
                "--findings-file", str(findings),
                "--comment-body-file", str(comment),
            ])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["decision"]["accepted"])
        self.assertEqual(payload["plan"]["persona"], "security")
        self.assertEqual(payload["plan"]["files"], ["app/auth/login.ts"])
        self.assertTrue(payload["plan"]["branch_name"].startswith("omar-fix/security/"))
        self.assertIn("MD5 used for session token", payload["followup_pr_body"])

    def test_persona_override_applies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            findings = write_findings(tmp, [
                {
                    "gateId": "security",
                    "tool": "semgrep",
                    "severity": "P0",
                    "file": "app/api/users.ts",
                    "line": 10,
                    "title": "unvalidated input",
                    "ruleId": "sast.eval",
                },
            ])
            comment = write_comment(tmp, "/omar fix sast.eval --persona backend")
            result = run_cli([
                "--path", tmp_str,
                "--findings-file", str(findings),
                "--comment-body-file", str(comment),
            ])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["plan"]["persona"], "backend")


if __name__ == "__main__":
    unittest.main()
