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


class ThreeStateBehaviorTests(unittest.TestCase):
    """3-state allow/deny/ask DSL lifted from src/utils/permissions/PermissionRule.ts.

    Covers (a) default = "deny" preserves prior block-on-finding semantic,
    (b) explicit `behavior` field wins, (c) legacy `hard: bool` is converted
    for back-compat, (d) garbage values fall back to default, (e) ForbidPattern
    parses behavior too.
    """

    def test_gate_toggle_default_behavior_is_deny(self) -> None:
        self.assertEqual(DEFAULT_POLICY.gates.security.behavior, "deny")
        self.assertEqual(DEFAULT_POLICY.gates.static_analysis.behavior, "deny")
        # llm_judge is non-blocking by default → "allow" not "deny"
        self.assertEqual(DEFAULT_POLICY.gates.llm_judge.behavior, "allow")

    def test_explicit_behavior_overrides_hard(self) -> None:
        # behavior=ask trumps hard=true
        p = parse_policy({
            "gates": [{"id": "security", "enabled": True, "hard": True, "behavior": "ask"}],
        })
        self.assertEqual(p.gates.security.behavior, "ask")
        # hard derived to be False since ask is non-blocking
        self.assertFalse(p.gates.security.hard)

    def test_explicit_behavior_deny_keeps_hard_true(self) -> None:
        p = parse_policy({
            "gates": [{"id": "security", "enabled": True, "behavior": "deny"}],
        })
        self.assertEqual(p.gates.security.behavior, "deny")
        self.assertTrue(p.gates.security.hard)

    def test_back_compat_hard_true_means_deny(self) -> None:
        # No `behavior` field → fall back to legacy hard=true semantic
        p = parse_policy({
            "gates": [{"id": "ownership", "enabled": True, "hard": True}],
        })
        self.assertEqual(p.gates.ownership.behavior, "deny")
        self.assertTrue(p.gates.ownership.hard)

    def test_back_compat_hard_false_means_allow(self) -> None:
        p = parse_policy({
            "gates": [{"id": "llm_judge", "enabled": True, "hard": False}],
        })
        self.assertEqual(p.gates.llm_judge.behavior, "allow")
        self.assertFalse(p.gates.llm_judge.hard)

    def test_invalid_behavior_value_falls_back_to_default(self) -> None:
        # Garbage behavior string → default for that gate (security defaults to "deny")
        p = parse_policy({
            "gates": [{"id": "security", "enabled": True, "behavior": "totally-invalid"}],
        })
        self.assertEqual(p.gates.security.behavior, "deny")

    def test_behavior_case_insensitive(self) -> None:
        p = parse_policy({
            "gates": [{"id": "security", "behavior": "  ASK  "}],
        })
        self.assertEqual(p.gates.security.behavior, "ask")

    def test_forbid_pattern_default_behavior_is_deny(self) -> None:
        p = parse_policy({
            "policy": {"forbid_patterns": [{"pattern": "TODO", "severity": "P3"}]},
        })
        self.assertEqual(p.forbid_patterns[0].behavior, "deny")

    def test_forbid_pattern_ask_behavior_parses(self) -> None:
        # "annotate test fixture matches but don't block the gate"
        p = parse_policy({
            "policy": {
                "forbid_patterns": [
                    {"pattern": "TODO", "severity": "P3", "in": "*.test.ts", "behavior": "ask"},
                    {"pattern": "console\\.log", "severity": "P2", "behavior": "deny"},
                ],
            },
        })
        self.assertEqual(p.forbid_patterns[0].behavior, "ask")
        self.assertEqual(p.forbid_patterns[1].behavior, "deny")


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
