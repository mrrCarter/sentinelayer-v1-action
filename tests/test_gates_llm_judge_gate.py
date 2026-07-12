"""Tests for src/omargate/gates/llm_judge.py (#A6 executable gate)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from omargate.gates import GateContext
from omargate.gates.llm_judge import LlmJudgeGate, LlmJudgeGateConfig


_VALID_FINDING = {
    "severity": "P1",
    "file": "src/app.py",
    "line": 12,
    "title": "SQL injection in query builder",
    "description": "User input is concatenated into raw SQL.",
    "category": "sql_injection",
    "confidence": 0.95,
    "recommended_fix": "Use parameterized queries.",
    "evidence": "query += request.args['id']",
}


class LlmJudgeGateTests(unittest.TestCase):
    def test_accepts_json_findings_and_applies_policy_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            findings_path = repo / ".sentinelayer" / "llm-findings.json"
            findings_path.parent.mkdir()
            findings_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            _VALID_FINDING,
                            {**_VALID_FINDING, "severity": "P3", "confidence": 0.7},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = LlmJudgeGate(
                LlmJudgeGateConfig(
                    findings_file=".sentinelayer/llm-findings.json",
                    behavior="deny",
                )
            ).run(GateContext(repo_root=repo))

            self.assertEqual(result.status, "ok")
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].gate_id, "llm_judge")
            self.assertEqual(result.findings[0].decision, "deny")
            self.assertEqual(result.metadata["accepted"], 1)
            self.assertEqual(result.metadata["rejected"], 1)
            self.assertEqual(result.metadata["rejections"]["confidence"], 1)

    def test_accepts_jsonl_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            findings_path = repo / "llm-findings.jsonl"
            findings_path.write_text(
                json.dumps(_VALID_FINDING) + "\n",
                encoding="utf-8",
            )

            result = LlmJudgeGate(
                LlmJudgeGateConfig(findings_file="llm-findings.jsonl")
            ).run(GateContext(repo_root=repo))

            self.assertEqual(result.status, "ok")
            self.assertEqual(len(result.findings), 1)

    def test_missing_configured_findings_file_blocks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            result = LlmJudgeGate(
                LlmJudgeGateConfig(findings_file=".sentinelayer/missing.json")
            ).run(GateContext(repo_root=repo))

            self.assertEqual(result.status, "error")
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].severity, "P1")
            self.assertEqual(result.findings[0].decision, "deny")
            self.assertEqual(result.findings[0].rule_id, "llm_judge:invalid-input")

    def test_findings_file_must_stay_inside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as outside_tmp:
            repo = Path(repo_tmp)
            outside = Path(outside_tmp) / "findings.json"
            outside.write_text(json.dumps([_VALID_FINDING]), encoding="utf-8")

            result = LlmJudgeGate(
                LlmJudgeGateConfig(findings_file=str(outside))
            ).run(GateContext(repo_root=repo))

            self.assertEqual(result.status, "error")
            self.assertEqual(result.findings[0].rule_id, "llm_judge:invalid-input")

    def test_no_findings_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = LlmJudgeGate(LlmJudgeGateConfig()).run(
                GateContext(repo_root=Path(tmp))
            )

            self.assertEqual(result.status, "skipped")
            self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
