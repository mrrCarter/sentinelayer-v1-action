"""Tests for src/omargate/gates/ package."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from omargate.gates import Gate, GateContext, GateResult, run_gates
from omargate.gates.findings import Finding, serialize_findings
from omargate.gates.static import (
    StaticAnalysisGate,
    _parse_eslint_output,
    _parse_prettier_output,
    _parse_tsc_output,
    _scrubbed_env,
)


class _StubGate:
    """Minimal Gate implementation for registry tests."""

    gate_id = "stub"

    def __init__(self, findings: list[Finding] | None = None, raise_exc: bool = False):
        self._findings = findings or []
        self._raise = raise_exc

    def run(self, ctx: GateContext) -> GateResult:
        if self._raise:
            raise RuntimeError("gate kaboom")
        return GateResult(gate_id=self.gate_id, findings=self._findings)


class RunGatesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = GateContext(
            repo_root=Path.cwd(),
            changed_files=("a.ts", "b.py"),
        )

    def test_empty_gate_list_returns_empty_results(self) -> None:
        self.assertEqual(run_gates([], self.ctx), [])

    def test_gate_result_includes_duration(self) -> None:
        results = run_gates([_StubGate()], self.ctx)
        self.assertEqual(len(results), 1)
        self.assertGreaterEqual(results[0].duration_ms, 0)
        self.assertEqual(results[0].status, "ok")

    def test_gate_exception_does_not_sink_subsequent_gates(self) -> None:
        finding = Finding(
            gate_id="stub",
            tool="mock",
            severity="P1",
            file="a.ts",
            line=5,
            title="ok",
        )
        results = run_gates(
            [_StubGate(raise_exc=True), _StubGate(findings=[finding])],
            self.ctx,
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].status, "error")
        self.assertIsNotNone(results[0].error_message)
        self.assertIn("RuntimeError", results[0].error_message or "")
        self.assertEqual(results[1].status, "ok")
        self.assertEqual(len(results[1].findings), 1)


class SerializeFindingsTests(unittest.TestCase):
    def test_shape_uses_camelcase_keys(self) -> None:
        finding = Finding(
            gate_id="static",
            tool="tsc",
            severity="P1",
            file="src/x.ts",
            line=10,
            title="type mismatch",
            rule_id="tsc:TS2345",
        )
        serialized = serialize_findings([finding])
        self.assertEqual(len(serialized), 1)
        row = serialized[0]
        self.assertEqual(row["gateId"], "static")
        self.assertEqual(row["tool"], "tsc")
        self.assertEqual(row["severity"], "P1")
        self.assertEqual(row["file"], "src/x.ts")
        self.assertEqual(row["line"], 10)
        self.assertEqual(row["ruleId"], "tsc:TS2345")
        self.assertEqual(row["confidence"], 1.0)
        self.assertIsNone(row["recommendedFix"])


class ScrubbedEnvTests(unittest.TestCase):
    def test_ld_preload_stripped(self) -> None:
        with patch.dict(os.environ, {"LD_PRELOAD": "/evil.so", "PATH": "/usr/bin"}, clear=True):
            env = _scrubbed_env()
            self.assertNotIn("LD_PRELOAD", env)
            self.assertEqual(env["PATH"], "/usr/bin")

    def test_dyld_insert_stripped(self) -> None:
        with patch.dict(
            os.environ,
            {"DYLD_INSERT_LIBRARIES": "/evil.dylib", "HOME": "/home/x"},
            clear=True,
        ):
            env = _scrubbed_env()
            self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
            self.assertIn("HOME", env)

    def test_bash_exported_function_stripped(self) -> None:
        with patch.dict(
            os.environ,
            {"BASH_FUNC_my_fn%%": "() { evil; }", "PATH": "/usr/bin"},
            clear=True,
        ):
            env = _scrubbed_env()
            self.assertNotIn("BASH_FUNC_my_fn%%", env)
            self.assertEqual(env["PATH"], "/usr/bin")


class ParseTscOutputTests(unittest.TestCase):
    def test_parses_error_diagnostic(self) -> None:
        stdout = "src/x.ts(10,4): error TS2345: Argument of type 'string' is not assignable.\n"
        findings = _parse_tsc_output(stdout, gate_id="static")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.file, "src/x.ts")
        self.assertEqual(f.line, 10)
        self.assertEqual(f.severity, "P1")
        self.assertEqual(f.rule_id, "tsc:TS2345")
        self.assertIn("Argument of type", f.title)

    def test_parses_warning_diagnostic(self) -> None:
        stdout = "src/y.ts(3,1): warning TS6059: A potential problem.\n"
        findings = _parse_tsc_output(stdout, gate_id="static")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "P2")

    def test_ignores_non_diagnostic_lines(self) -> None:
        stdout = "\nFound 0 errors.\n"
        findings = _parse_tsc_output(stdout, gate_id="static")
        self.assertEqual(findings, [])

    def test_skips_malformed_lines(self) -> None:
        stdout = "garbage): error TS9999: oops\n"
        findings = _parse_tsc_output(stdout, gate_id="static")
        # Malformed locator (no '(' before ')') should skip cleanly, not crash.
        self.assertEqual(findings, [])


class ParseEslintOutputTests(unittest.TestCase):
    def test_parses_empty_report(self) -> None:
        findings, err = _parse_eslint_output("[]", gate_id="static")
        self.assertFalse(err)
        self.assertEqual(findings, [])

    def test_parses_error_and_warning(self) -> None:
        payload = json.dumps(
            [
                {
                    "filePath": "/abs/src/a.ts",
                    "messages": [
                        {
                            "ruleId": "no-unused-vars",
                            "severity": 2,
                            "line": 5,
                            "message": "'x' is defined but never used.",
                        },
                        {
                            "ruleId": "prefer-const",
                            "severity": 1,
                            "line": 7,
                            "message": "Use const.",
                        },
                    ],
                }
            ]
        )
        findings, err = _parse_eslint_output(payload, gate_id="static")
        self.assertFalse(err)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "P1")
        self.assertEqual(findings[0].rule_id, "eslint:no-unused-vars")
        self.assertEqual(findings[1].severity, "P2")

    def test_malformed_json_returns_parse_error(self) -> None:
        findings, err = _parse_eslint_output("this is not json", gate_id="static")
        self.assertTrue(err)
        self.assertEqual(findings, [])


class ParsePrettierOutputTests(unittest.TestCase):
    def test_parses_warn_lines(self) -> None:
        stderr = "[warn] src/x.ts\n[warn] docs/y.md\n[warn] Code style issues found in the above files.\n"
        findings = _parse_prettier_output(stderr, gate_id="static")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].file, "src/x.ts")
        self.assertEqual(findings[0].severity, "P2")
        self.assertEqual(findings[0].rule_id, "prettier:unformatted")

    def test_ignores_empty_stderr(self) -> None:
        findings = _parse_prettier_output("", gate_id="static")
        self.assertEqual(findings, [])


class StaticAnalysisGateTests(unittest.TestCase):
    def test_all_tools_disabled_returns_empty_findings(self) -> None:
        gate = StaticAnalysisGate(tsc=False, eslint=False, prettier=False)
        ctx = GateContext(repo_root=Path.cwd(), changed_files=())
        result = gate.run(ctx)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.metadata["tools"], [])

    def test_gate_id_is_static(self) -> None:
        gate = StaticAnalysisGate()
        self.assertEqual(gate.gate_id, "static")


if __name__ == "__main__":
    unittest.main()
