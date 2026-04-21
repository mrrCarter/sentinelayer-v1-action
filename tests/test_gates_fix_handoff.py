"""Tests for src/omargate/gates/fix_handoff.py (#A26)."""

from __future__ import annotations

import unittest

from omargate.gates.findings import Finding
from omargate.gates.fix_handoff import (
    DEFAULT_PER_BUILD_FIX_LIMIT,
    build_fix_plan,
    compose_followup_pr_body,
    parse_fix_command,
    select_persona_for_finding,
    should_accept_fix,
)


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        gate_id="security",
        tool="security",
        severity="P0",
        file="app/auth/login.ts",
        line=42,
        title="MD5 used for session token",
        rule_id="crypto.md5",
        recommended_fix="use SHA-256 or crypto.randomUUID",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class ParseFixCommandTests(unittest.TestCase):
    def test_basic(self) -> None:
        cmd = parse_fix_command("Please /omar fix crypto.md5")
        self.assertIsNotNone(cmd)
        assert cmd is not None
        self.assertEqual(cmd.finding_id, "crypto.md5")
        self.assertIsNone(cmd.persona_override)
        self.assertIsNone(cmd.reason)

    def test_with_persona_override(self) -> None:
        cmd = parse_fix_command("/omar fix finding-42 --persona security")
        assert cmd is not None
        self.assertEqual(cmd.persona_override, "security")

    def test_with_reason(self) -> None:
        cmd = parse_fix_command(
            "/omar fix finding-42 --persona backend --reason needs retry budget"
        )
        assert cmd is not None
        self.assertEqual(cmd.persona_override, "backend")
        self.assertEqual(cmd.reason, "needs retry budget")

    def test_rejects_unrelated_comment(self) -> None:
        self.assertIsNone(parse_fix_command("ship it"))
        self.assertIsNone(parse_fix_command("Please fix this"))

    def test_rejects_missing_finding_id(self) -> None:
        self.assertIsNone(parse_fix_command("/omar fix"))

    def test_unknown_persona_is_stripped(self) -> None:
        # Unknown personas don't crash — we just drop the override and
        # leave it to the ownership-map lookup.
        cmd = parse_fix_command("/omar fix f-1 --persona not-a-real-persona")
        assert cmd is not None
        self.assertIsNone(cmd.persona_override)


class ShouldAcceptFixTests(unittest.TestCase):
    def test_accepts_fresh_request(self) -> None:
        decision = should_accept_fix("f-1")
        self.assertTrue(decision.accepted)
        self.assertFalse(decision.rate_limited)
        self.assertFalse(decision.already_attempted)

    def test_rejects_duplicate_in_same_build(self) -> None:
        decision = should_accept_fix(
            "f-1",
            already_attempted_finding_ids=["f-1"],
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(decision.already_attempted)

    def test_rejects_over_per_build_limit(self) -> None:
        decision = should_accept_fix(
            "f-2",
            fixes_in_current_build=DEFAULT_PER_BUILD_FIX_LIMIT,
        )
        self.assertFalse(decision.accepted)
        self.assertTrue(decision.rate_limited)


class SelectPersonaTests(unittest.TestCase):
    def test_override_wins(self) -> None:
        f = make_finding(tool="semgrep")
        persona = select_persona_for_finding(
            f,
            ownership_map={"app/auth/login.ts": "backend"},
            override="security",
        )
        self.assertEqual(persona, "security")

    def test_ownership_map_wins_over_tool(self) -> None:
        f = make_finding(tool="semgrep")
        persona = select_persona_for_finding(
            f,
            ownership_map={"app/auth/login.ts": "security"},
        )
        self.assertEqual(persona, "security")

    def test_tool_fallback_when_map_silent(self) -> None:
        f = make_finding(tool="backend")
        persona = select_persona_for_finding(f, ownership_map={})
        self.assertEqual(persona, "backend")

    def test_none_when_no_signal(self) -> None:
        f = make_finding(tool="semgrep", file="")
        persona = select_persona_for_finding(f, ownership_map={})
        self.assertIsNone(persona)


class BuildFixPlanTests(unittest.TestCase):
    def test_complete_plan(self) -> None:
        f = make_finding()
        plan = build_fix_plan(
            f,
            repo_root="/tmp/repo",
            ownership_map={"app/auth/login.ts": "security"},
        )
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.finding_id, "crypto.md5")
        self.assertEqual(plan.persona, "security")
        self.assertEqual(plan.repo_root, "/tmp/repo")
        self.assertEqual(plan.files, ("app/auth/login.ts",))
        self.assertTrue(plan.branch_name.startswith("omar-fix/security/"))
        self.assertIn("MD5 used for session token", plan.prompt_context)
        self.assertIn("RECOMMENDED FIX", plan.prompt_context)

    def test_none_when_no_persona_resolvable(self) -> None:
        f = make_finding(tool="semgrep", file="")
        plan = build_fix_plan(f, repo_root="/tmp/repo", ownership_map={})
        self.assertIsNone(plan)

    def test_branch_name_is_git_safe(self) -> None:
        f = make_finding(rule_id="some/really long!!id::with chars")
        plan = build_fix_plan(
            f,
            repo_root="/tmp/repo",
            ownership_map={"app/auth/login.ts": "security"},
        )
        assert plan is not None
        # Branch names shouldn't contain problematic chars for git
        for bad in [" ", ":", "!", "/"]:
            if bad == "/":
                # A single slash per path segment is fine (omar-fix/security/...)
                # but none of the others
                continue
            self.assertNotIn(bad, plan.branch_name)


class ComposeFollowupPRBodyTests(unittest.TestCase):
    def test_renders_expected_sections(self) -> None:
        f = make_finding()
        body = compose_followup_pr_body(
            finding=f,
            persona="security",
            summary="Replaced crypto.createHash('md5') with createHash('sha256').",
            tokens_used=1200,
            cost_usd=0.035,
        )
        self.assertIn("Fix attempt for `crypto.md5`", body)
        self.assertIn("Persona:** `security`", body)
        self.assertIn("Severity:** `P0`", body)
        self.assertIn("Tokens:** 1200", body)
        self.assertIn("$0.0350", body)
        self.assertIn("createHash('sha256')", body)

    def test_handles_empty_summary(self) -> None:
        f = make_finding()
        body = compose_followup_pr_body(
            finding=f,
            persona="security",
            summary="",
        )
        self.assertIn("did not provide a summary", body)


if __name__ == "__main__":
    unittest.main()
