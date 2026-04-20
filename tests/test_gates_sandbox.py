"""Tests for src/omargate/gates/sandbox.py (#A5)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from omargate.gates.sandbox import (
    SandboxConfig,
    SandboxResult,
    SandboxUnavailable,
    Violation,
    _build_sbpl_profile,
    _parse_violations,
    _wrap_bwrap,
    _wrap_sandbox_exec,
    detect_sandbox_platform,
    execute_in_sandbox,
)


class DetectSandboxPlatformTests(unittest.TestCase):
    def test_returns_one_of_expected_values(self) -> None:
        # Implementation-dependent on host, but must be in the expected set.
        self.assertIn(
            detect_sandbox_platform(),
            {"linux_bwrap", "macos_sandbox_exec", "unsandboxed"},
        )


class WrapBwrapTests(unittest.TestCase):
    def test_includes_core_flags(self) -> None:
        cmd = _wrap_bwrap(["echo", "hi"], cwd=Path("/tmp/x"), config=SandboxConfig())
        self.assertEqual(cmd[0], "bwrap")
        self.assertIn("--unshare-pid", cmd)
        self.assertIn("--unshare-net", cmd)  # allow_network default False
        self.assertIn("--tmpfs", cmd)

    def test_allow_network_removes_unshare_net(self) -> None:
        cmd = _wrap_bwrap(
            ["echo"],
            cwd=Path("/tmp/x"),
            config=SandboxConfig(allow_network=True),
        )
        self.assertNotIn("--unshare-net", cmd)

    def test_allow_read_binds_rotry(self) -> None:
        cmd = _wrap_bwrap(
            ["cat", "/etc/hosts"],
            cwd=Path("/tmp/x"),
            config=SandboxConfig(allow_read=("/etc/hosts",)),
        )
        ro_bind_idx = [i for i, v in enumerate(cmd) if v == "--ro-bind-try"]
        self.assertGreaterEqual(len(ro_bind_idx), 1)
        # The immediately-following path should be /etc/hosts
        self.assertIn("/etc/hosts", cmd)

    def test_cwd_bound_as_writeable(self) -> None:
        cmd = _wrap_bwrap(["echo"], cwd=Path("/work/repo"), config=SandboxConfig())
        self.assertIn("/work/repo", cmd)
        # --bind, not --ro-bind
        self.assertIn("--bind", cmd)

    def test_command_appended_after_separator(self) -> None:
        cmd = _wrap_bwrap(
            ["my-tool", "--flag"],
            cwd=Path("/tmp/x"),
            config=SandboxConfig(),
        )
        separator_idx = cmd.index("--")
        self.assertEqual(cmd[separator_idx + 1], "my-tool")
        self.assertEqual(cmd[separator_idx + 2], "--flag")


class WrapSandboxExecTests(unittest.TestCase):
    def test_deny_default_present(self) -> None:
        cmd = _wrap_sandbox_exec(["echo"], cwd=Path("/tmp/x"), config=SandboxConfig())
        self.assertEqual(cmd[0], "sandbox-exec")
        self.assertEqual(cmd[1], "-p")
        profile = cmd[2]
        self.assertIn("(deny default)", profile)
        self.assertIn("(version 1)", profile)

    def test_network_allow_when_enabled(self) -> None:
        profile = _build_sbpl_profile(
            cwd=Path("/tmp/x"),
            config=SandboxConfig(allow_network=True),
        )
        self.assertIn("(allow network*)", profile)

    def test_network_denied_when_disabled(self) -> None:
        profile = _build_sbpl_profile(cwd=Path("/tmp/x"), config=SandboxConfig())
        # No explicit allow; deny default covers it.
        self.assertNotIn("(allow network*)", profile)

    def test_cwd_path_allowed(self) -> None:
        profile = _build_sbpl_profile(
            cwd=Path("/Users/test/repo"),
            config=SandboxConfig(),
        )
        self.assertIn("/Users/test/repo", profile)
        self.assertIn("(allow file-write*", profile)
        self.assertIn("(allow file-read-data", profile)

    def test_deny_rules_included(self) -> None:
        profile = _build_sbpl_profile(
            cwd=Path("/tmp/x"),
            config=SandboxConfig(
                deny_write=("/Users/test/secret",),
                deny_read=("/Users/test/otherconf",),
            ),
        )
        self.assertIn('(deny file-write* (subpath "/Users/test/secret"))', profile)
        self.assertIn('(deny file-read-data (subpath "/Users/test/otherconf"))', profile)


class ParseViolationsTests(unittest.TestCase):
    def test_linux_op_not_permitted(self) -> None:
        v = _parse_violations("bwrap: Operation not permitted\n", "linux_bwrap")
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].kind, "fs_write")

    def test_linux_network_unreachable(self) -> None:
        v = _parse_violations(
            "connect: Network is unreachable\n", "linux_bwrap",
        )
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].kind, "network")

    def test_macos_deny_file_write(self) -> None:
        v = _parse_violations(
            "sandbox: deny file-write-create /Users/test/hack.txt\n",
            "macos_sandbox_exec",
        )
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].kind, "fs_write")

    def test_empty_stderr(self) -> None:
        self.assertEqual(_parse_violations("", "linux_bwrap"), [])

    def test_multiple_violations(self) -> None:
        stderr = (
            "deny file-write /tmp/bad\n"
            "deny network\n"
            "unrelated error message\n"
        )
        v = _parse_violations(stderr, "macos_sandbox_exec")
        self.assertEqual(len(v), 2)
        self.assertEqual([x.kind for x in v], ["fs_write", "network"])


class ExecuteInSandboxTests(unittest.TestCase):
    def test_strict_raises_when_unavailable(self) -> None:
        with patch("omargate.gates.sandbox.detect_sandbox_platform", return_value="unsandboxed"):
            with self.assertRaises(SandboxUnavailable):
                execute_in_sandbox(
                    ["echo", "hi"],
                    cwd=Path.cwd(),
                    strict=True,
                )

    def test_non_strict_falls_through_unsandboxed(self) -> None:
        with patch("omargate.gates.sandbox.detect_sandbox_platform", return_value="unsandboxed"):
            result = execute_in_sandbox(
                [sys.executable, "-c", "print('hello')"],
                cwd=Path.cwd(),
                strict=False,
            )
            self.assertEqual(result.platform, "unsandboxed")
            self.assertTrue(result.skipped)

    def test_empty_command_raises(self) -> None:
        with self.assertRaises(ValueError):
            execute_in_sandbox([], cwd=Path.cwd())

    def test_non_list_command_raises(self) -> None:
        with self.assertRaises(ValueError):
            execute_in_sandbox("echo hi", cwd=Path.cwd())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
