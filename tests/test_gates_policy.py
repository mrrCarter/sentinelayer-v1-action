"""Tests for src/omargate/gates/policy.py — policy YAML/JSON loader."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from omargate.gates.policy import (
    DEFAULT_POLICY,
    PolicyLoadError,
    SCHEMA_VERSION,
    load_policy,
    parse_policy,
)


class DefaultPolicyTests(unittest.TestCase):
    def test_default_policy_constants(self) -> None:
        self.assertEqual(DEFAULT_POLICY.version, SCHEMA_VERSION)
        self.assertIsNone(DEFAULT_POLICY.spec_id)
        self.assertTrue(DEFAULT_POLICY.spec_hash_auto_discover)
        self.assertEqual(DEFAULT_POLICY.severity_block_list, ("P0", "P1"))

    def test_default_gate_toggles(self) -> None:
        # Static + security on by default; others off
        self.assertTrue(DEFAULT_POLICY.gates.static_analysis.enabled)
        self.assertTrue(DEFAULT_POLICY.gates.security.enabled)
        self.assertFalse(DEFAULT_POLICY.gates.ownership.enabled)
        self.assertFalse(DEFAULT_POLICY.gates.llm_judge.enabled)


class ParsePolicyTests(unittest.TestCase):
    def test_empty_dict_yields_defaults(self) -> None:
        p = parse_policy({})
        self.assertEqual(p.version, SCHEMA_VERSION)
        self.assertTrue(p.gates.static_analysis.enabled)
        self.assertEqual(p.forbid_patterns, ())

    def test_non_dict_raises(self) -> None:
        with self.assertRaises(PolicyLoadError):
            parse_policy([])  # type: ignore[arg-type]

    def test_newer_version_raises(self) -> None:
        with self.assertRaises(PolicyLoadError):
            parse_policy({"version": SCHEMA_VERSION + 1})

    def test_invalid_version_type_raises(self) -> None:
        with self.assertRaises(PolicyLoadError):
            parse_policy({"version": "not-a-number"})

    def test_gates_list_parsed(self) -> None:
        p = parse_policy({
            "version": 1,
            "gates": [
                {"id": "security", "enabled": False, "hard": False, "config": {"gitleaks": True}},
                {"id": "ownership", "enabled": True, "hard": True},
            ],
        })
        self.assertFalse(p.gates.security.enabled)
        self.assertFalse(p.gates.security.hard)
        self.assertEqual(p.gates.security.config.get("gitleaks"), True)
        self.assertTrue(p.gates.ownership.enabled)

    def test_gate_hyphen_id_normalized_to_underscore(self) -> None:
        p = parse_policy({
            "gates": [{"id": "static-analysis", "enabled": False}],
        })
        self.assertFalse(p.gates.static_analysis.enabled)

    def test_unknown_gate_id_ignored(self) -> None:
        p = parse_policy({
            "gates": [{"id": "nonexistent-gate", "enabled": True}],
        })
        # Does not raise; unknown ignored
        self.assertEqual(p.gates, DEFAULT_POLICY.gates)

    def test_forbid_patterns_parsed(self) -> None:
        p = parse_policy({
            "gates": [
                {
                    "id": "policy",
                    "enabled": True,
                    "config": {},
                }
            ],
            "policy": {
                "forbid_patterns": [
                    {"pattern": "console\\.log", "severity": "P2", "message": "no console.log"},
                    {"pattern": ":\\s*any\\b", "severity": "P1", "in": "*.ts"},
                ],
                "coverage_min": 0.70,
            },
        })
        self.assertEqual(len(p.forbid_patterns), 2)
        self.assertEqual(p.forbid_patterns[0].pattern, "console\\.log")
        self.assertEqual(p.forbid_patterns[0].severity, "P2")
        self.assertEqual(p.forbid_patterns[1].in_glob, "*.ts")
        self.assertEqual(p.coverage_min, 0.70)

    def test_forbid_patterns_missing_pattern_skipped(self) -> None:
        p = parse_policy({
            "policy": {"forbid_patterns": [{"severity": "P1"}, {"pattern": ""}, {"pattern": "x"}]},
        })
        self.assertEqual(len(p.forbid_patterns), 1)
        self.assertEqual(p.forbid_patterns[0].pattern, "x")

    def test_severity_gate_parsed(self) -> None:
        p = parse_policy({
            "severity_gate": {
                "block_on": ["P0", "P1", "P2"],
                "soft_warn": ["P3"],
            },
        })
        self.assertEqual(p.severity_block_list, ("P0", "P1", "P2"))
        self.assertEqual(p.severity_warn_list, ("P3",))

    def test_spec_id_preserved(self) -> None:
        p = parse_policy({"spec_id": "sha256:abc123"})
        self.assertEqual(p.spec_id, "sha256:abc123")

    def test_raw_dict_preserved_for_forward_compat(self) -> None:
        raw = {"version": 1, "future_knob": "enabled", "another_future": {"x": 1}}
        p = parse_policy(raw)
        self.assertEqual(p.raw["future_knob"], "enabled")


class LoadPolicyJsonTests(unittest.TestCase):
    def test_load_json_file(self) -> None:
        policy_dict = {
            "version": 1,
            "gates": [{"id": "security", "enabled": False}],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as f:
            json.dump(policy_dict, f)
            path = Path(f.name)
        try:
            p = load_policy(path)
            self.assertFalse(p.gates.security.enabled)
        finally:
            path.unlink()

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(PolicyLoadError):
            load_policy("/nonexistent/policy.json")

    def test_unsupported_extension_raises(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False, mode="w", encoding="utf-8") as f:
            f.write("x = 1\n")
            path = Path(f.name)
        try:
            with self.assertRaises(PolicyLoadError) as cm:
                load_policy(path)
            self.assertIn(".toml", str(cm.exception))
        finally:
            path.unlink()

    def test_malformed_json_raises(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as f:
            f.write("{ not valid json }")
            path = Path(f.name)
        try:
            with self.assertRaises(PolicyLoadError):
                load_policy(path)
        finally:
            path.unlink()


class LoadPolicyYamlTests(unittest.TestCase):
    def test_yaml_without_pyyaml_raises_clear_error(self) -> None:
        # If PyYAML is installed in the test env, this test is effectively a no-op
        # — we only care that the error path has a clear message when unavailable.
        try:
            import yaml  # noqa: F401
            pyyaml_available = True
        except ImportError:
            pyyaml_available = False

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w", encoding="utf-8") as f:
            f.write("version: 1\n")
            path = Path(f.name)
        try:
            if pyyaml_available:
                # Verify loads cleanly when PyYAML is present.
                p = load_policy(path)
                self.assertEqual(p.version, 1)
            else:
                with self.assertRaises(PolicyLoadError) as cm:
                    load_policy(path)
                self.assertIn("PyYAML", str(cm.exception))
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
