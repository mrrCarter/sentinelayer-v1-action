"""Tests for src/omargate/gates/security.py — 6-scanner security gate.

These tests exercise the pure parser functions against representative
output samples from each scanner. The parsers are designed to be usable
without subprocess invocation, so CI can validate behavior without
requiring the scanner binaries to be installed.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from omargate.gates import GateContext
from omargate.gates.findings import Finding
from omargate.gates.security import (
    SecurityScanGate,
    _extract_cvss_numeric,
    _osv_max_severity,
    _parse_actionlint_output,
    _parse_checkov_output,
    _parse_gitleaks_output,
    _parse_osv_output,
    _parse_semgrep_output,
    _parse_tflint_output,
)


# ---------- gitleaks ----------


class ParseGitleaksTests(unittest.TestCase):
    def test_empty_stdout(self) -> None:
        self.assertEqual(_parse_gitleaks_output("", "security"), [])

    def test_empty_array(self) -> None:
        self.assertEqual(_parse_gitleaks_output("[]", "security"), [])

    def test_malformed_json(self) -> None:
        self.assertEqual(_parse_gitleaks_output("not json", "security"), [])

    def test_single_leak(self) -> None:
        stdout = json.dumps([
            {
                "Description": "AWS Access Key",
                "RuleID": "aws-access-key",
                "File": "src/config.ts",
                "StartLine": 12,
                "Secret": "AKIA...",
            }
        ])
        findings = _parse_gitleaks_output(stdout, "security")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "P0")
        self.assertEqual(f.tool, "gitleaks")
        self.assertEqual(f.file, "src/config.ts")
        self.assertEqual(f.line, 12)
        self.assertEqual(f.rule_id, "gitleaks:aws-access-key")
        self.assertIn("AWS Access Key", f.title)

    def test_multiple_leaks(self) -> None:
        stdout = json.dumps([
            {"Description": "A", "RuleID": "r1", "File": "a.env", "StartLine": 1},
            {"Description": "B", "RuleID": "r2", "File": "b.env", "StartLine": 5},
        ])
        findings = _parse_gitleaks_output(stdout, "security")
        self.assertEqual(len(findings), 2)
        self.assertEqual([f.severity for f in findings], ["P0", "P0"])

    def test_ignores_non_object_entries(self) -> None:
        stdout = json.dumps(["not an object", None, 42])
        self.assertEqual(_parse_gitleaks_output(stdout, "security"), [])


# ---------- semgrep ----------


class ParseSemgrepTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_parse_semgrep_output("", "security"), [])
        self.assertEqual(_parse_semgrep_output("{}", "security"), [])
        self.assertEqual(_parse_semgrep_output('{"results": []}', "security"), [])

    def test_severity_map(self) -> None:
        stdout = json.dumps({
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval.avoid-exec",
                    "path": "src/x.py",
                    "start": {"line": 10},
                    "extra": {"severity": "ERROR", "message": "avoid exec"},
                },
                {
                    "check_id": "python.style.plus-format",
                    "path": "src/y.py",
                    "start": {"line": 3},
                    "extra": {"severity": "WARNING", "message": "use f-string"},
                },
                {
                    "check_id": "info.rule",
                    "path": "src/z.py",
                    "start": {"line": 1},
                    "extra": {"severity": "INFO", "message": "nit"},
                },
            ],
        })
        findings = _parse_semgrep_output(stdout, "security")
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].severity, "P1")
        self.assertEqual(findings[0].rule_id, "semgrep:python.lang.security.audit.eval.avoid-exec")
        self.assertEqual(findings[1].severity, "P2")
        self.assertEqual(findings[2].severity, "P3")

    def test_malformed_falls_back_to_empty(self) -> None:
        self.assertEqual(_parse_semgrep_output("not json", "security"), [])


# ---------- osv-scanner ----------


class ParseOsvTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_parse_osv_output("", "security"), [])
        self.assertEqual(_parse_osv_output("{}", "security"), [])

    def test_nested_structure(self) -> None:
        stdout = json.dumps({
            "results": [
                {
                    "source": {"path": "/repo/package-lock.json"},
                    "packages": [
                        {
                            "package": {"name": "left-pad", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "CVE-2016-1337",
                                    "summary": "left-pad is evil",
                                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/9.8"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        })
        findings = _parse_osv_output(stdout, "security")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "P0")
        self.assertEqual(f.rule_id, "osv:CVE-2016-1337")
        self.assertIn("left-pad", f.title)

    def test_cvss_severity_mapping(self) -> None:
        self.assertEqual(_osv_max_severity([{"score": "9.8"}]), "P0")
        self.assertEqual(_osv_max_severity([{"score": "7.5"}]), "P1")
        self.assertEqual(_osv_max_severity([{"score": "5.0"}]), "P2")
        self.assertEqual(_osv_max_severity([{"score": "2.0"}]), "P3")
        self.assertEqual(_osv_max_severity([]), "P2")  # unknown → medium default
        self.assertEqual(_osv_max_severity(None), "P2")  # malformed → medium

    def test_cvss_vector_extraction(self) -> None:
        # Real OSV entries come as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"
        self.assertEqual(_extract_cvss_numeric("CVSS:3.1/AV:N/9.8"), 9.8)
        self.assertEqual(_extract_cvss_numeric("7.5"), 7.5)
        self.assertEqual(_extract_cvss_numeric("garbage"), 0.0)
        self.assertEqual(_extract_cvss_numeric(""), 0.0)


# ---------- actionlint ----------


class ParseActionlintTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_parse_actionlint_output("", "security"), [])

    def test_single_diagnostic(self) -> None:
        stdout = ".github/workflows/ci.yml:23:9: script injection of ${{ github.event.issue.title }} [expression]\n"
        findings = _parse_actionlint_output(stdout, "security")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.file, ".github/workflows/ci.yml")
        self.assertEqual(f.line, 23)
        self.assertEqual(f.severity, "P2")
        self.assertEqual(f.rule_id, "actionlint:expression")
        self.assertIn("script injection", f.title)

    def test_rule_missing_uses_unknown(self) -> None:
        stdout = ".github/workflows/deploy.yml:5:1: some message without brackets\n"
        findings = _parse_actionlint_output(stdout, "security")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "actionlint:unknown")
        self.assertEqual(findings[0].title, "some message without brackets")

    def test_malformed_lines_skipped(self) -> None:
        stdout = "not-a-diagnostic\nmissing:colons\n.github/x.yml:abc:def: malformed line\n"
        self.assertEqual(_parse_actionlint_output(stdout, "security"), [])

    def test_multiple_diagnostics(self) -> None:
        stdout = (
            ".github/workflows/a.yml:1:1: first issue [rule-a]\n"
            ".github/workflows/b.yml:10:5: second issue [rule-b]\n"
        )
        findings = _parse_actionlint_output(stdout, "security")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].rule_id, "actionlint:rule-a")
        self.assertEqual(findings[1].rule_id, "actionlint:rule-b")


# ---------- checkov ----------


class ParseCheckovTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_parse_checkov_output("", "security"), [])

    def test_severity_map(self) -> None:
        stdout = json.dumps({
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_1",
                        "check_name": "Ensure port 22 is not exposed",
                        "file_path": "/Dockerfile",
                        "file_line_range": [7, 7],
                        "severity": "HIGH",
                    },
                    {
                        "check_id": "CKV_AWS_24",
                        "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                        "file_path": "/main.tf",
                        "file_line_range": [42, 55],
                        "severity": "CRITICAL",
                    },
                    {
                        "check_id": "CKV_K8S_1",
                        "check_name": "Ensure that seccomp is used",
                        "file_path": "/deployment.yaml",
                        "file_line_range": [3, 3],
                        "severity": "LOW",
                    },
                ]
            }
        })
        findings = _parse_checkov_output(stdout, "security")
        self.assertEqual(len(findings), 3)
        # Severity map
        self.assertEqual(findings[0].severity, "P1")  # HIGH
        self.assertEqual(findings[1].severity, "P0")  # CRITICAL
        self.assertEqual(findings[2].severity, "P3")  # LOW
        # File path leading slash stripped
        self.assertEqual(findings[0].file, "Dockerfile")
        self.assertEqual(findings[1].file, "main.tf")
        # Line from range[0]
        self.assertEqual(findings[0].line, 7)
        self.assertEqual(findings[1].line, 42)

    def test_list_form_flattened(self) -> None:
        """Some checkov invocations emit a list of framework results."""
        stdout = json.dumps([
            {"results": {"failed_checks": [
                {"check_id": "CKV_1", "check_name": "A", "file_path": "a.tf", "file_line_range": [1, 1], "severity": "HIGH"}
            ]}},
            {"results": {"failed_checks": [
                {"check_id": "CKV_2", "check_name": "B", "file_path": "b.yaml", "file_line_range": [2, 2], "severity": "MEDIUM"}
            ]}},
        ])
        findings = _parse_checkov_output(stdout, "security")
        self.assertEqual(len(findings), 2)

    def test_missing_severity_defaults_to_medium(self) -> None:
        stdout = json.dumps({
            "results": {"failed_checks": [
                {"check_id": "CKV_X", "check_name": "Unspecified", "file_path": "x.yaml", "file_line_range": [1, 1]}
            ]}
        })
        findings = _parse_checkov_output(stdout, "security")
        self.assertEqual(findings[0].severity, "P2")


# ---------- tflint ----------


class ParseTflintTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_parse_tflint_output("", "security"), [])
        self.assertEqual(_parse_tflint_output('{"issues": []}', "security"), [])

    def test_issues_parsed(self) -> None:
        stdout = json.dumps({
            "issues": [
                {
                    "rule": {"name": "aws_instance_invalid_type", "severity": "error"},
                    "message": "invalid instance type",
                    "range": {"filename": "main.tf", "start": {"line": 10}},
                },
                {
                    "rule": {"name": "terraform_required_version", "severity": "warning"},
                    "message": "missing required version",
                    "range": {"filename": "versions.tf", "start": {"line": 1}},
                },
            ]
        })
        findings = _parse_tflint_output(stdout, "security")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "P1")
        self.assertEqual(findings[0].rule_id, "tflint:aws_instance_invalid_type")
        self.assertEqual(findings[1].severity, "P2")


# ---------- gate runner (structural) ----------


class SecurityScanGateTests(unittest.TestCase):
    def test_gate_id(self) -> None:
        gate = SecurityScanGate()
        self.assertEqual(gate.gate_id, "security")

    def test_all_disabled_empty(self) -> None:
        gate = SecurityScanGate(
            gitleaks=False,
            semgrep=False,
            osv_scanner=False,
            actionlint=False,
            checkov=False,
            tflint=False,
        )
        ctx = GateContext(repo_root=Path.cwd(), changed_files=())
        result = gate.run(ctx)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.findings, [])
        # All 6 tools appear in meta with invoked=False, reason=disabled
        tools = result.metadata["tools"]
        self.assertEqual(len(tools), 6)
        for meta in tools:
            self.assertFalse(meta["invoked"])
            self.assertEqual(meta["reason"], "disabled")

    def test_missing_binaries_skipped_silently(self) -> None:
        # Tools not on PATH are reported as skipped without raising.
        gate = SecurityScanGate()  # all True
        ctx = GateContext(repo_root=Path.cwd(), changed_files=())
        result = gate.run(ctx)
        self.assertEqual(result.status, "ok")
        # Either findings exist (tools installed) or every entry is skipped
        for meta in result.metadata["tools"]:
            if not meta.get("invoked"):
                self.assertIn(meta.get("reason"), {"disabled", "binary-not-on-path"})


if __name__ == "__main__":
    unittest.main()
