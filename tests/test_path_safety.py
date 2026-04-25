"""Tests for src/omargate/path_safety.py — repo-path hardening module.

Each rejection class has at least one positive (rejected) and one negative
(accepted-but-similar) golden vector so future refactors can't relax the
filter without a visible test diff.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from omargate.path_safety import (
    EXCLUDED_PATH_PREFIXES,
    PathSafetyError,
    validate_repo_path,
    _validate_chars,
    _validate_double_encoded,
    _validate_prefix,
)


class CharValidationTests(unittest.TestCase):
    def test_null_byte_rejected(self) -> None:
        with self.assertRaises(PathSafetyError) as cm:
            _validate_chars("/tmp/repo\x00/.git")
        self.assertEqual(cm.exception.reason, "null_byte")

    def test_control_chars_rejected(self) -> None:
        # 0x01, 0x07 (BEL), 0x09 (TAB) — wait, TAB is 0x09 which is NOT in our
        # reject set (we exclude tab/newline/CR for compat with multiline yaml).
        # Actually the regex is [\x00-\x08\x0b\x0c\x0e-\x1f\x7f] which excludes
        # \x09 (TAB), \x0a (LF), \x0d (CR). So TAB/LF/CR pass through; 0x01/0x07/0x1f/0x7f reject.
        for bad in ["\x01", "\x07", "\x0b", "\x0c", "\x1f", "\x7f"]:
            with self.assertRaises(PathSafetyError) as cm:
                _validate_chars(f"/tmp/x{bad}y")
            self.assertEqual(cm.exception.reason, "control_character")

    def test_tab_lf_cr_allowed(self) -> None:
        # YAML-friendly compat: tab/newline/CR don't trip the control-char filter.
        for ok in ["\t", "\n", "\r"]:
            _validate_chars(f"/tmp/x{ok}y")  # must not raise

    def test_bidi_overrides_rejected_U202A_to_U202E(self) -> None:
        for cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E):
            with self.assertRaises(PathSafetyError) as cm:
                _validate_chars(f"/tmp/{chr(cp)}admin")
            self.assertEqual(cm.exception.reason, "bidi_override")

    def test_bidi_isolates_rejected_U2066_to_U2069(self) -> None:
        for cp in (0x2066, 0x2067, 0x2068, 0x2069):
            with self.assertRaises(PathSafetyError) as cm:
                _validate_chars(f"/tmp/{chr(cp)}admin")
            self.assertEqual(cm.exception.reason, "bidi_override")

    def test_normal_unicode_allowed(self) -> None:
        # Real internationalization: "/tmp/プロジェクト/repo" must not trip the BiDi filter.
        _validate_chars("/tmp/プロジェクト/repo")
        _validate_chars("/tmp/réseau/áé/projeto")


class DoubleEncodedPercentTests(unittest.TestCase):
    def test_double_encoded_traversal_rejected(self) -> None:
        # %252e%252e -> %2e%2e after one decode -> still has %xx triplet.
        with self.assertRaises(PathSafetyError) as cm:
            _validate_double_encoded("/repo/%252e%252e/etc/passwd")
        self.assertEqual(cm.exception.reason, "double_encoded_percent")

    def test_double_encoded_slash_rejected(self) -> None:
        with self.assertRaises(PathSafetyError) as cm:
            _validate_double_encoded("/api/%252fadmin")
        self.assertEqual(cm.exception.reason, "double_encoded_percent")

    def test_single_encoded_pass_through(self) -> None:
        # %20 (space) decodes once to ' ' and the result has no %xx — fine.
        _validate_double_encoded("/repo/My%20Project/.git")  # must not raise

    def test_no_percent_pass_through(self) -> None:
        _validate_double_encoded("/repo/regular/path")


class PrefixValidationTests(unittest.TestCase):
    def test_unc_path_rejected_backslash(self) -> None:
        with self.assertRaises(PathSafetyError) as cm:
            _validate_prefix("\\\\evil\\share\\admin")
        self.assertEqual(cm.exception.reason, "unc_path")

    def test_unc_path_rejected_forwardslash(self) -> None:
        with self.assertRaises(PathSafetyError) as cm:
            _validate_prefix("//evil/share/admin")
        self.assertEqual(cm.exception.reason, "unc_path")

    def test_tilde_user_rejected(self) -> None:
        for bad in ["~root/.ssh", "~/.bashrc", "~+/etc", "~-/etc", "~admin"]:
            with self.assertRaises(PathSafetyError) as cm:
                _validate_prefix(bad)
            self.assertEqual(cm.exception.reason, "tilde_prefix")

    def test_tilde_after_slash_rejected(self) -> None:
        # Leading slash variant: "/~user" should also reject.
        with self.assertRaises(PathSafetyError) as cm:
            _validate_prefix("/~root/.ssh")
        self.assertEqual(cm.exception.reason, "tilde_prefix")

    def test_shell_expansion_rejected(self) -> None:
        for bad in ["$HOME/repo", "${HOME}/repo", "%USERPROFILE%/repo", "=cmd-substitution/repo"]:
            with self.assertRaises(PathSafetyError) as cm:
                _validate_prefix(bad)
            self.assertEqual(cm.exception.reason, "shell_expansion")

    def test_windows_drive_root_rejected(self) -> None:
        for bad in ["C:", "C:/", "C:\\", "D:"]:
            with self.assertRaises(PathSafetyError) as cm:
                _validate_prefix(bad)
            self.assertEqual(cm.exception.reason, "windows_drive_root")

    def test_windows_drive_path_allowed(self) -> None:
        # C:/repo (drive + child) is fine; only bare drive roots reject.
        _validate_prefix("C:/Users/me/repo")  # must not raise
        _validate_prefix("C:\\Users\\me\\repo")  # must not raise

    def test_normal_paths_allowed(self) -> None:
        for ok in ["/tmp/repo", "./relative", "../parent", "repo", "repo/sub"]:
            _validate_prefix(ok)  # must not raise


class ValidateRepoPathTests(unittest.TestCase):
    def test_valid_directory_returns_resolved_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = validate_repo_path(td)
            self.assertIsNotNone(result)
            self.assertEqual(result, Path(td).resolve())

    def test_nonexistent_path_returns_none(self) -> None:
        self.assertIsNone(validate_repo_path("/tmp/definitely/does/not/exist/xyzqwerty"))

    def test_file_not_directory_returns_none(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        try:
            self.assertIsNone(validate_repo_path(path))
        finally:
            os.unlink(path)

    def test_empty_returns_none(self) -> None:
        self.assertIsNone(validate_repo_path(""))
        self.assertIsNone(validate_repo_path("   "))

    def test_non_string_returns_none(self) -> None:
        self.assertIsNone(validate_repo_path(None))  # type: ignore[arg-type]
        self.assertIsNone(validate_repo_path(123))  # type: ignore[arg-type]

    def test_hostile_input_returns_none(self) -> None:
        # Each attack class returns None (no exception escapes).
        for hostile in [
            "/tmp/repo\x00/.git",
            "/tmp/x\x07y",
            "‮/admin",
            "/repo/%252e%252e/etc",
            "\\\\evil\\share",
            "~root/.ssh",
            "$HOME/repo",
            "%USERPROFILE%/repo",
            "C:",
        ]:
            self.assertIsNone(validate_repo_path(hostile), f"should reject: {hostile!r}")

    def test_traversal_rejected_when_base_cwd_provided(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            # Create a sibling directory outside base
            sibling_parent = base.parent
            self.assertIsNone(validate_repo_path(str(sibling_parent), base_cwd=base))

    def test_traversal_check_skipped_when_no_base_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = validate_repo_path(td, base_cwd=None)
            self.assertIsNotNone(result)

    def test_require_directory_false_allows_files(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        try:
            result = validate_repo_path(path, require_directory=False)
            self.assertIsNotNone(result)
        finally:
            os.unlink(path)


class ExcludedPathPrefixesTests(unittest.TestCase):
    def test_known_noisy_dirs_excluded(self) -> None:
        # Spot-check that the most common scanner-noise sources are flagged.
        for noisy in ["node_modules", ".venv", ".git", "dist", "build", "__pycache__", "coverage"]:
            self.assertIn(noisy, EXCLUDED_PATH_PREFIXES)

    def test_legitimate_dirs_not_excluded(self) -> None:
        for legit in ["src", "tests", "apps", "packages", "docs"]:
            self.assertNotIn(legit, EXCLUDED_PATH_PREFIXES)


if __name__ == "__main__":
    unittest.main()
