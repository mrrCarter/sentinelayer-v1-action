"""Tests for omargate.scaffold.parse_scaffold_ownership."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from omargate.scaffold import parse_scaffold_ownership


class ParseScaffoldOwnershipTests(unittest.TestCase):
    def test_missing_file_returns_empty(self) -> None:
        self.assertEqual(
            parse_scaffold_ownership(Path("/tmp/definitely-not-there.yaml")), {}
        )

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
            result = parse_scaffold_ownership(path)
        self.assertEqual(result.get("app/auth/login.ts"), "security")
        self.assertEqual(result.get("app/api/users.ts"), "backend")

    def test_drops_glob_patterns(self) -> None:
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
            result = parse_scaffold_ownership(path)
        self.assertNotIn("**/*.ts", result)
        self.assertEqual(result.get("app/concrete.ts"), "security")

    def test_quoted_values(self) -> None:
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
            result = parse_scaffold_ownership(path)
        self.assertEqual(result.get("single/quoted.ts"), "security")

    def test_stops_on_next_top_level_key(self) -> None:
        # If another top-level key follows ownership_rules, the parser should
        # stop consuming rules and not gather entries from the next block.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.yaml"
            path.write_text(
                textwrap.dedent(
                    """
                    ownership_rules:
                      - pattern: app/a.ts
                        persona: security
                    unrelated_section:
                      - pattern: should/not/count.ts
                        persona: backend
                    """
                ).strip(),
                encoding="utf-8",
            )
            result = parse_scaffold_ownership(path)
        self.assertEqual(result, {"app/a.ts": "security"})

    def test_strips_leading_dot_slash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.yaml"
            path.write_text(
                textwrap.dedent(
                    """
                    ownership_rules:
                      - pattern: ./app/b.ts
                        persona: backend
                    """
                ).strip(),
                encoding="utf-8",
            )
            result = parse_scaffold_ownership(path)
        self.assertEqual(result.get("app/b.ts"), "backend")
        self.assertNotIn("./app/b.ts", result)


if __name__ == "__main__":
    unittest.main()
