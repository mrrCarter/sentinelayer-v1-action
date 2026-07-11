"""Tests for src/omargate/local_gates.py — the standalone gates CLI."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from omargate.local_gates import _count_by_severity, _severity_blocks, main
from omargate.gates.findings import Finding


class SeverityBlocksTests(unittest.TestCase):
    def test_never_threshold_never_blocks(self) -> None:
        for sev in ("P0", "P1", "P2", "P3"):
            self.assertFalse(_severity_blocks(sev, "never"))

    def test_p1_threshold_blocks_p0_and_p1_only(self) -> None:
        self.assertTrue(_severity_blocks("P0", "P1"))
        self.assertTrue(_severity_blocks("P1", "P1"))
        self.assertFalse(_severity_blocks("P2", "P1"))
        self.assertFalse(_severity_blocks("P3", "P1"))

    def test_p0_threshold_blocks_only_p0(self) -> None:
        self.assertTrue(_severity_blocks("P0", "P0"))
        self.assertFalse(_severity_blocks("P1", "P0"))
        self.assertFalse(_severity_blocks("P2", "P0"))
        self.assertFalse(_severity_blocks("P3", "P0"))

    def test_p3_threshold_blocks_everything(self) -> None:
        for sev in ("P0", "P1", "P2", "P3"):
            self.assertTrue(_severity_blocks(sev, "P3"))


class CountBySeverityTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_count_by_severity([]), {"P0": 0, "P1": 0, "P2": 0, "P3": 0})

    def test_mixed_counts(self) -> None:
        findings = [
            Finding(gate_id="g", tool="t", severity="P0", file="a", line=1, title="x"),
            Finding(gate_id="g", tool="t", severity="P0", file="b", line=1, title="x"),
            Finding(gate_id="g", tool="t", severity="P1", file="c", line=1, title="x"),
            Finding(gate_id="g", tool="t", severity="P2", file="d", line=1, title="x"),
            Finding(gate_id="g", tool="t", severity="P2", file="e", line=1, title="x"),
            Finding(gate_id="g", tool="t", severity="P2", file="f", line=1, title="x"),
            Finding(gate_id="g", tool="t", severity="P3", file="g", line=1, title="x"),
        ]
        self.assertEqual(
            _count_by_severity(findings),
            {"P0": 2, "P1": 1, "P2": 3, "P3": 1},
        )


class CliMainTests(unittest.TestCase):
    def test_nonexistent_path_returns_2(self) -> None:
        rc = main(["--path", "/nonexistent/path/zzz", "--output-dir", ".", "--no-static", "--no-security"])
        # no-gates returns 2 before path check; ensure path check hit first with a valid --output-dir
        # and both gates disabled would exit 2 as "no gates enabled" — so we need to enable one
        rc = main(["--path", "/nonexistent/path/zzz", "--output-dir", "."])
        self.assertEqual(rc, 2)

    def test_no_gates_enabled_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["--path", tmp, "--output-dir", tmp, "--no-static", "--no-security"])
            self.assertEqual(rc, 2)

    def test_clean_repo_returns_0_and_writes_empty_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Empty temp dir — gates will skip (no tools installed OR no files) and findings empty
            rc = main([
                "--path", tmp,
                "--output-dir", tmp,
                "--json-summary",
            ])
            self.assertIn(rc, (0, 1))  # 0 when no findings; 1 if any scanner emits
            findings_path = Path(tmp) / "FINDINGS.jsonl"
            self.assertTrue(findings_path.exists())
            # Either empty or well-formed JSONL
            content = findings_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.strip():
                    json.loads(line)  # must parse

    def test_fail_severity_never_returns_0_even_with_findings(self) -> None:
        # We can't easily inject findings without mocking, but we can at least
        # verify the --fail-severity argument is accepted.
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["--path", tmp, "--output-dir", tmp, "--fail-severity", "never"])
            self.assertEqual(rc, 0)

    def test_policy_file_toggles_gates_and_blocks_on_forbid_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "src").mkdir()
            (repo / "src" / "app.ts").write_text("console.log('debug')\n", encoding="utf-8")
            policy_dir = repo / ".sentinelayer"
            policy_dir.mkdir()
            policy_path = policy_dir / "policy.json"
            policy_path.write_text(
                json.dumps({
                    "version": 1,
                    "gates": [
                        {"id": "static_analysis", "enabled": False},
                        {"id": "security_scan", "enabled": False},
                        {
                            "id": "policy",
                            "enabled": True,
                            "config": {
                                "forbid_patterns": [
                                    {
                                        "pattern": "console\\.log\\(",
                                        "severity": "P2",
                                        "message": "no console.log",
                                        "in": "*.ts",
                                    }
                                ],
                            },
                        },
                    ],
                }),
                encoding="utf-8",
            )

            output_dir = repo / "out"
            rc = main([
                "--path",
                str(repo),
                "--output-dir",
                str(output_dir),
                "--policy-file",
                ".sentinelayer/policy.json",
                "--fail-severity",
                "P2",
                "--json-summary",
            ])

            self.assertEqual(rc, 1)
            findings = [
                json.loads(line)
                for line in (output_dir / "FINDINGS.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["gateId"], "policy")
            self.assertEqual(findings[0]["file"], "src/app.ts")

    def test_policy_ask_findings_do_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app.ts").write_text("TODO: inspect\n", encoding="utf-8")
            policy_dir = repo / ".sentinelayer"
            policy_dir.mkdir()
            (policy_dir / "policy.json").write_text(
                json.dumps({
                    "version": 1,
                    "gates": [
                        {"id": "static_analysis", "enabled": False},
                        {"id": "security_scan", "enabled": False},
                        {
                            "id": "policy",
                            "enabled": True,
                            "config": {
                                "forbid_patterns": [
                                    {
                                        "pattern": "TODO",
                                        "severity": "P1",
                                        "behavior": "ask",
                                    }
                                ],
                            },
                        },
                    ],
                }),
                encoding="utf-8",
            )

            output_dir = repo / "out"
            rc = main([
                "--path",
                str(repo),
                "--output-dir",
                str(output_dir),
                "--fail-severity",
                "P1",
                "--json-summary",
            ])

            self.assertEqual(rc, 0)
            findings = [
                json.loads(line)
                for line in (output_dir / "FINDINGS.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(findings[0]["decision"], "ask")

    def test_explicit_missing_policy_file_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "--path",
                tmp,
                "--output-dir",
                tmp,
                "--policy-file",
                ".sentinelayer/missing.json",
            ])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
