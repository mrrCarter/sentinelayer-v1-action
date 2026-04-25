"""Tests for src/omargate/gates/llm_judge_contract.py (#A6)."""

from __future__ import annotations

import unittest

from omargate.gates.llm_judge_contract import (
    CONFIDENCE_FLOOR,
    CONFIDENCE_FLOORS,
    HARD_EXCLUSIONS,
    PRECEDENTS,
    SUPPORTED_CATEGORIES,
    filter_llm_findings,
)


_BASE_FINDING = {
    "severity": "P1",
    "file": "src/x.py",
    "line": 10,
    "title": "SQL injection in query builder",
    "description": "User input concatenated into raw SQL string.",
    "category": "sql_injection",
    "confidence": 0.9,
    "recommended_fix": "Use parameterized queries.",
    "evidence": "query = 'SELECT * FROM users WHERE id=' + user_input",
}


class AcceptsValidFinding(unittest.TestCase):
    def test_happy_path(self) -> None:
        r = filter_llm_findings([_BASE_FINDING])
        self.assertEqual(len(r.accepted), 1)
        self.assertEqual(len(r.rejected), 0)
        f = r.accepted[0]
        self.assertEqual(f.severity, "P1")
        self.assertEqual(f.file, "src/x.py")
        self.assertEqual(f.rule_id, "llm:sql_injection")
        self.assertEqual(f.confidence, 0.9)

    def test_minimum_acceptable_confidence(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "confidence": 0.8}])
        self.assertEqual(len(r.accepted), 1)


class ConfidenceFloorTests(unittest.TestCase):
    def test_below_p3_floor_rejected(self) -> None:
        # P3 floor is 0.95 — 0.79 is well below.
        r = filter_llm_findings([
            {**_BASE_FINDING, "severity": "P3", "confidence": 0.79}
        ])
        self.assertEqual(len(r.accepted), 0)
        self.assertEqual(len(r.below_confidence_floor), 1)

    def test_non_numeric_confidence_rejected_as_schema(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "confidence": "high"}])
        self.assertEqual(len(r.accepted), 0)
        self.assertEqual(len(r.schema_failure), 1)

    def test_explicit_global_floor_overrides_tier(self) -> None:
        # When caller passes confidence_floor=0.90, that wins over the P1 tier (0.75).
        r = filter_llm_findings(
            [{**_BASE_FINDING, "confidence": 0.85}],
            confidence_floor=0.90,
        )
        self.assertEqual(len(r.accepted), 0)
        self.assertEqual(len(r.below_confidence_floor), 1)


class CalibratedTieredFloorsTests(unittest.TestCase):
    """PR 3: per-severity confidence floors lifted from src/commands/security-review.ts."""

    def test_floors_match_calibrated_tiers(self) -> None:
        self.assertEqual(CONFIDENCE_FLOORS["P0"], 0.60)
        self.assertEqual(CONFIDENCE_FLOORS["P1"], 0.75)
        self.assertEqual(CONFIDENCE_FLOORS["P2"], 0.85)
        self.assertEqual(CONFIDENCE_FLOORS["P3"], 0.95)

    def test_p0_critical_accepts_lower_confidence(self) -> None:
        # P0 floor is 0.60 — under the prior global 0.8, this would have been rejected.
        # Calibrated tiers preserve critical findings even at moderate confidence.
        r = filter_llm_findings([{**_BASE_FINDING, "severity": "P0", "confidence": 0.65}])
        self.assertEqual(len(r.accepted), 1, f"rejected: {[x.reason for x in r.rejected]}")

    def test_p1_high_accepts_above_p1_floor(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "severity": "P1", "confidence": 0.78}])
        self.assertEqual(len(r.accepted), 1)

    def test_p2_medium_floor_higher_than_p1(self) -> None:
        # 0.80 is below the P2 floor (0.85). Same confidence at P1 would accept.
        r_p2 = filter_llm_findings([{**_BASE_FINDING, "severity": "P2", "confidence": 0.80}])
        self.assertEqual(len(r_p2.accepted), 0)
        self.assertEqual(len(r_p2.below_confidence_floor), 1)

        r_p1 = filter_llm_findings([{**_BASE_FINDING, "severity": "P1", "confidence": 0.80}])
        self.assertEqual(len(r_p1.accepted), 1)

    def test_p3_low_requires_near_certain_confidence(self) -> None:
        # P3 noise control: anything below 0.95 drops.
        r_below = filter_llm_findings([{**_BASE_FINDING, "severity": "P3", "confidence": 0.90}])
        self.assertEqual(len(r_below.accepted), 0)
        self.assertEqual(len(r_below.below_confidence_floor), 1)

        r_above = filter_llm_findings([{**_BASE_FINDING, "severity": "P3", "confidence": 0.96}])
        self.assertEqual(len(r_above.accepted), 1)

    def test_custom_floors_override_tiers(self) -> None:
        # Caller can pass their own per-severity dict.
        r = filter_llm_findings(
            [{**_BASE_FINDING, "severity": "P0", "confidence": 0.55}],
            confidence_floors={"P0": 0.50},
        )
        self.assertEqual(len(r.accepted), 1)

    def test_partial_custom_floors_fall_back_to_default(self) -> None:
        # P1 in the custom dict, P2 finding falls back to the default tier (0.85).
        r = filter_llm_findings(
            [{**_BASE_FINDING, "severity": "P2", "confidence": 0.80}],
            confidence_floors={"P1": 0.50},
        )
        # P2 at 0.80 < 0.85 default → rejected
        self.assertEqual(len(r.accepted), 0)

    def test_rejection_message_names_severity_and_floor(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "severity": "P3", "confidence": 0.10}])
        self.assertEqual(len(r.below_confidence_floor), 1)
        self.assertIn("P3", r.below_confidence_floor[0].reason)
        self.assertIn("0.95", r.below_confidence_floor[0].reason)


class SchemaValidationTests(unittest.TestCase):
    def test_non_dict_rejected(self) -> None:
        r = filter_llm_findings(["not a dict", None, 42])
        self.assertEqual(len(r.accepted), 0)
        self.assertEqual(len(r.schema_failure), 3)

    def test_invalid_severity_rejected(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "severity": "CRITICAL"}])
        self.assertEqual(len(r.schema_failure), 1)

    def test_empty_title_rejected(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "title": ""}])
        self.assertEqual(len(r.schema_failure), 1)

    def test_missing_line_defaults_to_zero(self) -> None:
        raw = {**_BASE_FINDING}
        del raw["line"]
        r = filter_llm_findings([raw])
        self.assertEqual(len(r.accepted), 1)
        self.assertEqual(r.accepted[0].line, 0)

    def test_non_numeric_line_defaults_to_zero(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "line": "unknown"}])
        self.assertEqual(len(r.accepted), 1)
        self.assertEqual(r.accepted[0].line, 0)


class CategoryValidationTests(unittest.TestCase):
    def test_empty_category_accepted(self) -> None:
        raw = {**_BASE_FINDING}
        del raw["category"]
        r = filter_llm_findings([raw])
        self.assertEqual(len(r.accepted), 1)
        self.assertEqual(r.accepted[0].rule_id, "llm:unknown")

    def test_unsupported_category_rejected(self) -> None:
        r = filter_llm_findings([{**_BASE_FINDING, "category": "telepathy_attack"}])
        self.assertEqual(len(r.invalid_category), 1)

    def test_all_supported_categories_accepted(self) -> None:
        for cat in SUPPORTED_CATEGORIES:
            r = filter_llm_findings([{**_BASE_FINDING, "category": cat}])
            self.assertEqual(len(r.accepted), 1, f"category {cat} should be accepted")


class HardExclusionTests(unittest.TestCase):
    def test_denial_of_service_in_title_rejected(self) -> None:
        r = filter_llm_findings([{
            **_BASE_FINDING,
            "title": "Denial of Service via unbounded loop",
            "category": "",
        }])
        self.assertEqual(len(r.hard_exclusion), 1)

    def test_regex_injection_rejected(self) -> None:
        r = filter_llm_findings([{
            **_BASE_FINDING,
            "title": "Regex Injection in search",
            "category": "",
            "description": "User-supplied pattern.",
        }])
        self.assertEqual(len(r.hard_exclusion), 1)

    def test_unit_test_file_rejected_via_description(self) -> None:
        r = filter_llm_findings([{
            **_BASE_FINDING,
            "title": "Test bypass",
            "description": "In unit test file only",
        }])
        self.assertEqual(len(r.hard_exclusion), 1)


class PrecedentTests(unittest.TestCase):
    def test_react_auto_escape_precedent_rejected(self) -> None:
        r = filter_llm_findings([{
            **_BASE_FINDING,
            "title": "Potential XSS",
            "description": "Note: React auto-escapes XSS by default here.",
            "category": "xss",
        }])
        self.assertEqual(len(r.matched_precedent), 1)

    def test_uuid_unguessable_precedent_rejected(self) -> None:
        r = filter_llm_findings([{
            **_BASE_FINDING,
            "title": "Token enumeration",
            "description": "Attacker would need to guess a UUID but UUIDs are unguessable.",
            "category": "data_exposure",
        }])
        self.assertEqual(len(r.matched_precedent), 1)

    def test_client_side_permission_check_rejected(self) -> None:
        r = filter_llm_findings([{
            **_BASE_FINDING,
            "title": "Permission bypass via UI",
            "description": "Client-side permission check is not a vulnerability here.",
            "category": "auth_bypass",
        }])
        self.assertEqual(len(r.matched_precedent), 1)


class CombinedInputTests(unittest.TestCase):
    def test_mixed_inputs_bucketed_correctly(self) -> None:
        findings = [
            _BASE_FINDING,  # accepted
            {**_BASE_FINDING, "confidence": 0.5},  # below floor
            {**_BASE_FINDING, "category": "telepathy_attack"},  # invalid category
            {**_BASE_FINDING, "title": "Denial of Service in loop"},  # hard exclusion
            {**_BASE_FINDING, "description": "React auto-escapes XSS here."},  # precedent
            "not a dict",  # schema
        ]
        r = filter_llm_findings(findings)
        self.assertEqual(len(r.accepted), 1)
        self.assertEqual(len(r.below_confidence_floor), 1)
        self.assertEqual(len(r.invalid_category), 1)
        self.assertEqual(len(r.hard_exclusion), 1)
        self.assertEqual(len(r.matched_precedent), 1)
        self.assertEqual(len(r.schema_failure), 1)


class ConstantsTests(unittest.TestCase):
    def test_confidence_floor_is_point_eight(self) -> None:
        self.assertEqual(CONFIDENCE_FLOOR, 0.8)

    def test_hard_exclusions_non_empty(self) -> None:
        self.assertGreater(len(HARD_EXCLUSIONS), 5)

    def test_precedents_non_empty(self) -> None:
        self.assertGreater(len(PRECEDENTS), 3)

    def test_supported_categories_includes_canonical_set(self) -> None:
        for expected in (
            "sql_injection",
            "xss",
            "auth_bypass",
            "rce",
            "crypto_flaws",
            "data_exposure",
        ):
            self.assertIn(expected, SUPPORTED_CATEGORIES)


if __name__ == "__main__":
    unittest.main()
