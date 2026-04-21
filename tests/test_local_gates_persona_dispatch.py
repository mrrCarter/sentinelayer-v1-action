"""Tests for persona-dispatch wiring in local_gates.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from omargate.gates.findings import Finding
from omargate.local_gates import (
    _maybe_dispatch_personas,
    _parse_scaffold_ownership,
)


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        gate_id="security",
        tool="semgrep",
        severity="P1",
        file="app/auth/login.ts",
        line=42,
        title="unvalidated input",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class ParseScaffoldOwnershipTests(unittest.TestCase):
    def test_missing_file_returns_empty(self) -> None:
        result = _parse_scaffold_ownership(Path("/tmp/definitely-not-there.yaml"))
        self.assertEqual(result, {})

    def test_parses_literal_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.yaml"
            path.write_text(
                textwrap.dedent(
                    """
                    ownership_rules:
                      - pattern: "app/auth/login.ts"
                        persona: security
                      - pattern: app/api/users.ts
                        persona: backend
                    """
                ).strip(),
                encoding="utf-8",
            )
            result = _parse_scaffold_ownership(path)
        self.assertEqual(result.get("app/auth/login.ts"), "security")
        self.assertEqual(result.get("app/api/users.ts"), "backend")

    def test_drops_glob_patterns(self) -> None:
        # dispatch_personas needs file -> persona, not pattern -> persona,
        # so wildcard patterns are skipped by the minimal parser.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.yaml"
            path.write_text(
                textwrap.dedent(
                    """
                    ownership_rules:
                      - pattern: "**/*.ts"
                        persona: backend
                      - pattern: app/concrete.ts
                        persona: security
                    """
                ).strip(),
                encoding="utf-8",
            )
            result = _parse_scaffold_ownership(path)
        self.assertNotIn("**/*.ts", result)
        self.assertEqual(result.get("app/concrete.ts"), "security")

    def test_handles_quoted_and_unquoted_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.yaml"
            path.write_text(
                textwrap.dedent(
                    """
                    ownership_rules:
                      - pattern: 'single/quoted.ts'
                        persona: "security"
                    """
                ).strip(),
                encoding="utf-8",
            )
            result = _parse_scaffold_ownership(path)
        self.assertEqual(result.get("single/quoted.ts"), "security")


class MaybeDispatchPersonasTests(unittest.TestCase):
    def test_disabled_returns_none(self) -> None:
        summary = _maybe_dispatch_personas(
            baseline_findings=[make_finding()],
            repo_root=Path("/tmp"),
            enable=False,
            cli_override="",
            dry_run=False,
        )
        self.assertIsNone(summary)

    def test_missing_scaffold_marks_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = _maybe_dispatch_personas(
                baseline_findings=[make_finding()],
                repo_root=Path(tmp),
                enable=True,
                cli_override="",
                dry_run=True,
            )
        assert summary is not None
        self.assertEqual(summary["status"], "skipped")
        self.assertIn("no ownership map", summary["reason"])
        self.assertEqual(summary["persona_findings"], [])

    def test_dry_run_resolves_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scaffold = Path(tmp) / ".sentinelayer" / "scaffold.yaml"
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
            summary = _maybe_dispatch_personas(
                baseline_findings=[make_finding()],
                repo_root=Path(tmp),
                enable=True,
                cli_override="",
                dry_run=True,
            )
        assert summary is not None
        self.assertEqual(summary["status"], "dry_run")
        self.assertEqual(summary["personas_invoked"], ["security"])
        self.assertEqual(summary["persona_findings"], [])

    def test_missing_cli_marks_skipped_when_not_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scaffold = Path(tmp) / ".sentinelayer" / "scaffold.yaml"
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
            summary = _maybe_dispatch_personas(
                baseline_findings=[make_finding()],
                repo_root=Path(tmp),
                enable=True,
                # Point at a binary that definitely isn't on PATH.
                cli_override="/nonexistent/create-sentinelayer-for-test",
                dry_run=False,
            )
        assert summary is not None
        self.assertEqual(summary["status"], "skipped")
        self.assertIn("not resolvable", summary["reason"])


class LocalGatesCliPersonaFlagTests(unittest.TestCase):
    """Black-box smoke test via the module's CLI entry point."""

    def test_cli_accepts_persona_flags_without_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            output = Path(tmp) / "out"
            cmd = [
                sys.executable,
                "-m",
                "omargate.local_gates",
                "--path",
                str(repo),
                "--output-dir",
                str(output),
                "--no-static",
                "--no-security",
            ]
            # Without --no-static/--no-security, it would try to actually scan.
            # We expect exit code 2 for "no gates enabled" — but the flag
            # parsing itself should not crash on the new options.
            result = subprocess.run(
                cmd + ["--enable-persona-dispatch", "--persona-dispatch-dry-run"],
                capture_output=True,
                text=True,
                env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src")},
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            # Confirm argparse didn't reject the new flags.
            self.assertNotIn("unrecognized arguments", result.stderr)
            self.assertNotIn("error: argument", result.stderr)


if __name__ == "__main__":
    unittest.main()
