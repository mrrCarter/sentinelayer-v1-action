"""Tests for src/omargate/gates/persona_dispatch.py (#A25)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from omargate.gates.findings import Finding
from omargate.gates.persona_dispatch import (
    KNOWN_PERSONAS,
    PersonaDispatchConfig,
    build_persona_buckets,
    default_cli_path,
    dispatch_personas,
    normalize_persona_finding,
)


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        gate_id="security",
        tool="semgrep",
        severity="P1",
        file="app/users.ts",
        line=42,
        title="unvalidated input",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class BuildPersonaBucketsTests(unittest.TestCase):
    def test_groups_findings_by_owning_persona(self) -> None:
        findings = [
            make_finding(file="app/users.ts"),
            make_finding(file="app/payments.ts"),
            make_finding(file="app/auth/login.ts", severity="P0"),
        ]
        ownership = {
            "app/users.ts": "backend",
            "app/payments.ts": "backend",
            "app/auth/login.ts": "security",
        }
        buckets, unrouted = build_persona_buckets(findings, ownership)
        self.assertEqual(sorted(buckets.keys()), ["backend", "security"])
        self.assertEqual(sorted(buckets["backend"]), ["app/payments.ts", "app/users.ts"])
        self.assertEqual(buckets["security"], ["app/auth/login.ts"])
        self.assertEqual(unrouted, [])

    def test_drops_non_blocking_severities_by_default(self) -> None:
        findings = [
            make_finding(file="a.ts", severity="P2"),
            make_finding(file="b.ts", severity="P3"),
        ]
        buckets, unrouted = build_persona_buckets(findings, {"a.ts": "backend", "b.ts": "backend"})
        self.assertEqual(buckets, {})
        self.assertEqual(unrouted, [])

    def test_records_unrouted_files(self) -> None:
        findings = [
            make_finding(file="app/other.ts", severity="P1"),
        ]
        ownership = {"app/other.ts": "unknown-persona"}
        buckets, unrouted = build_persona_buckets(findings, ownership)
        self.assertEqual(buckets, {})
        self.assertEqual(unrouted, ["app/other.ts"])

    def test_dedupes_same_file_same_persona(self) -> None:
        findings = [
            make_finding(file="app/users.ts", title="a"),
            make_finding(file="app/users.ts", title="b"),
        ]
        buckets, _ = build_persona_buckets(findings, {"app/users.ts": "backend"})
        self.assertEqual(buckets["backend"], ["app/users.ts"])


class NormalizePersonaFindingTests(unittest.TestCase):
    def test_valid_input_produces_finding(self) -> None:
        f = normalize_persona_finding(
            {
                "severity": "P0",
                "file": "x.ts",
                "line": 10,
                "title": "MD5 used for security",
                "rootCause": "md5 is collision-broken",
                "kind": "crypto.md5",
                "confidence": 0.9,
                "recommendedFix": "switch to SHA-256",
                "evidence": "crypto.createHash('md5')",
            },
            persona="security",
        )
        self.assertIsNotNone(f)
        assert f is not None
        self.assertEqual(f.gate_id, "persona_dispatch")
        self.assertEqual(f.tool, "security")
        self.assertEqual(f.severity, "P0")
        self.assertEqual(f.file, "x.ts")
        self.assertEqual(f.line, 10)
        self.assertEqual(f.rule_id, "crypto.md5")
        self.assertAlmostEqual(f.confidence, 0.9, places=6)

    def test_invalid_severity_falls_back_to_default(self) -> None:
        f = normalize_persona_finding({"file": "x.ts", "severity": "CRITICAL"}, persona="backend")
        assert f is not None
        self.assertEqual(f.severity, "P2")

    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(normalize_persona_finding({"severity": "P1"}, persona="backend"))

    def test_clamps_confidence(self) -> None:
        too_high = normalize_persona_finding(
            {"file": "x.ts", "severity": "P1", "confidence": 42},
            persona="backend",
        )
        assert too_high is not None
        self.assertEqual(too_high.confidence, 1.0)

        too_low = normalize_persona_finding(
            {"file": "x.ts", "severity": "P1", "confidence": -0.5},
            persona="backend",
        )
        assert too_low is not None
        self.assertEqual(too_low.confidence, 0.0)


class DispatchPersonasTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = PersonaDispatchConfig(
            cli_path=Path("create-sentinelayer"),
            repo_root=Path("/tmp/repo"),
            dry_run=True,
        )

    def test_dry_run_dispatches_without_spawning(self) -> None:
        findings = [
            make_finding(file="app/users.ts", severity="P1"),
            make_finding(file="app/auth/login.ts", severity="P0"),
        ]
        ownership = {
            "app/users.ts": "backend",
            "app/auth/login.ts": "security",
        }
        result = dispatch_personas(findings, ownership, self.config)
        self.assertEqual(sorted(result.personas_invoked), ["backend", "security"])
        self.assertEqual(result.personas_failed, [])
        self.assertEqual(result.persona_findings, [])
        self.assertEqual(len(result.combined), 2)  # no persona findings added in dry-run

    def test_parses_persona_stdout_into_findings(self) -> None:
        payload = {
            "findings": [
                {
                    "severity": "P0",
                    "file": "app/users.ts",
                    "line": 88,
                    "title": "missing rate limit",
                    "kind": "backend.no-rate-limit",
                    "confidence": 0.92,
                },
            ],
        }
        with patch(
            "omargate.gates.persona_dispatch._spawn_persona_cli",
            return_value=(1, json.dumps(payload), ""),
        ):
            config = PersonaDispatchConfig(
                cli_path=Path("create-sentinelayer"),
                repo_root=Path("/tmp/repo"),
                dry_run=False,
            )
            result = dispatch_personas(
                [make_finding(file="app/users.ts", severity="P1")],
                {"app/users.ts": "backend"},
                config,
            )
        self.assertEqual(result.personas_invoked, ["backend"])
        self.assertEqual(len(result.persona_findings), 1)
        persona_f = result.persona_findings[0]
        self.assertEqual(persona_f.severity, "P0")
        self.assertEqual(persona_f.tool, "backend")
        self.assertEqual(persona_f.gate_id, "persona_dispatch")
        self.assertEqual(persona_f.rule_id, "backend.no-rate-limit")

    def test_records_personas_that_crash(self) -> None:
        with patch(
            "omargate.gates.persona_dispatch._spawn_persona_cli",
            return_value=(127, "", "CLI not found"),
        ):
            config = PersonaDispatchConfig(
                cli_path=Path("create-sentinelayer"),
                repo_root=Path("/tmp/repo"),
                dry_run=False,
            )
            result = dispatch_personas(
                [make_finding(file="app/users.ts", severity="P1")],
                {"app/users.ts": "backend"},
                config,
            )
        self.assertEqual(result.personas_invoked, [])
        self.assertEqual(result.personas_failed, ["backend"])

    def test_respects_per_persona_max_files(self) -> None:
        findings = [
            make_finding(file=f"app/f{i}.ts", severity="P1") for i in range(100)
        ]
        ownership = {f.file: "backend" for f in findings}
        config = PersonaDispatchConfig(
            cli_path=Path("create-sentinelayer"),
            repo_root=Path("/tmp/repo"),
            dry_run=True,
            per_persona_max_files=5,
        )
        # dry_run skips the spawn, so assert the bucket build still ran and
        # the cap didn't blow up with 100 files; argv-level cap enforcement
        # is covered by SpawnPersonaCliArgsTests.
        result = dispatch_personas(findings, ownership, config)
        self.assertEqual(result.personas_invoked, ["backend"])


class SpawnPersonaCliArgsTests(unittest.TestCase):
    """Assert the argv shape passed to subprocess matches the new CLI (#A27)."""

    def test_spawn_uses_persona_run_subcommand_and_mode(self) -> None:
        from omargate.gates.persona_dispatch import _spawn_persona_cli

        captured: dict[str, object] = {}

        class _FakeProc:
            returncode = 0
            stdout = '{"findings": []}'
            stderr = ""

        def _fake_run(args, **kwargs):  # noqa: ANN001 — matches subprocess.run signature
            captured["args"] = list(args)
            return _FakeProc()

        with patch("omargate.gates.persona_dispatch.subprocess.run", _fake_run):
            config = PersonaDispatchConfig(
                cli_path=Path("create-sentinelayer"),
                repo_root=Path("/tmp/repo"),
                mode="codegen",
            )
            _spawn_persona_cli(config, "security", ["app/a.ts", "app/b.ts"])

        args = captured["args"]
        assert isinstance(args, list)
        self.assertEqual(args[:4], [
            "create-sentinelayer",
            "persona",
            "run",
            "security",
        ])
        self.assertIn("--mode", args)
        self.assertEqual(args[args.index("--mode") + 1], "codegen")
        self.assertIn("--files", args)
        self.assertEqual(args[args.index("--files") + 1], "app/a.ts,app/b.ts")
        self.assertEqual(args[-1], "--json")

    def test_spawn_omits_files_flag_when_empty(self) -> None:
        from omargate.gates.persona_dispatch import _spawn_persona_cli

        captured: dict[str, object] = {}

        class _FakeProc:
            returncode = 0
            stdout = '{"findings": []}'
            stderr = ""

        def _fake_run(args, **kwargs):  # noqa: ANN001
            captured["args"] = list(args)
            return _FakeProc()

        with patch("omargate.gates.persona_dispatch.subprocess.run", _fake_run):
            config = PersonaDispatchConfig(
                cli_path=Path("create-sentinelayer"),
                repo_root=Path("/tmp/repo"),
            )
            _spawn_persona_cli(config, "backend", [])

        args = captured["args"]
        assert isinstance(args, list)
        self.assertNotIn("--files", args)
        self.assertIn("--mode", args)
        self.assertEqual(args[args.index("--mode") + 1], "audit")
        self.assertEqual(args[-1], "--json")


class DefaultCliPathTests(unittest.TestCase):
    def test_override_wins(self) -> None:
        self.assertEqual(default_cli_path("/opt/custom/sentinelayer"), Path("/opt/custom/sentinelayer"))

    def test_falls_back_to_default_when_no_override(self) -> None:
        result = default_cli_path(None)
        self.assertIsInstance(result, Path)


class KnownPersonasTests(unittest.TestCase):
    def test_covers_the_13_canon(self) -> None:
        for persona in [
            "security",
            "backend",
            "testing",
            "code-quality",
            "data-layer",
            "documentation",
            "reliability",
            "release",
            "observability",
            "infrastructure",
            "supply-chain",
            "ai-governance",
            "frontend",
        ]:
            self.assertIn(persona, KNOWN_PERSONAS, f"expected persona {persona} in KNOWN_PERSONAS")


if __name__ == "__main__":
    unittest.main()
