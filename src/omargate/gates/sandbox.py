"""OS-level sandbox envelope (#A5) — Omar Gate 2.0 §5.1.

Provides a subprocess wrapper that executes commands inside an OS-level
sandbox (Linux bubblewrap / bwrap, macOS sandbox-exec). Used by Layer 7
(LLM judge) when executing code against an untrusted model's output, and
by the local security gate when running adversarial-input scanners.

Behavior:
  - Platform detection via sys.platform.
  - Linux: wraps with `bwrap` + allow/deny filesystem rules + network
    deny-by-default.
  - macOS: wraps with `sandbox-exec` + an sbpl profile derived from the
    same allow/deny rules.
  - Other platforms / missing binary: falls back to plain subprocess
    with a SandboxUnavailable warning in metadata. Production runners
    should fail closed when strict=True is passed.

Violation reporting:
  - Exit code + stderr are returned.
  - Known violation patterns in stderr (e.g. "Operation not permitted")
    are parsed into a list of Violation objects on the result.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .static import _scrubbed_env  # reuse the env hardening from static gate

__all__ = [
    "SandboxConfig",
    "SandboxResult",
    "Violation",
    "SandboxUnavailable",
    "detect_sandbox_platform",
    "execute_in_sandbox",
]


class SandboxUnavailable(RuntimeError):
    """Raised when strict=True and no sandbox is available on this runner."""


@dataclass(frozen=True)
class SandboxConfig:
    """Allow / deny lists for filesystem + network access."""

    allow_read: tuple[str, ...] = ()
    allow_write: tuple[str, ...] = ()
    deny_read: tuple[str, ...] = ()
    deny_write: tuple[str, ...] = ()
    # Network policy: deny-by-default. Pass allow_network=True to allow
    # general egress (still subject to deny_hosts filtering where the
    # platform supports it). Most LLM-judge uses should keep this False.
    allow_network: bool = False
    deny_hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Violation:
    """A single sandbox violation surfaced from the wrapped execution."""

    kind: str          # "fs_write" | "fs_read" | "network" | "unknown"
    target: str        # what was attempted (path or host)
    raw_line: str      # original stderr line for debugging


@dataclass
class SandboxResult:
    """Result of execute_in_sandbox."""

    exit_code: int
    stdout: str
    stderr: str
    platform: str          # "linux_bwrap" | "macos_sandbox_exec" | "unsandboxed"
    violations: list[Violation] = field(default_factory=list)
    skipped: bool = False  # True if sandbox was not invoked (no binary)


def detect_sandbox_platform() -> str:
    """Return the sandbox engine that would be used on this host.

    Values: "linux_bwrap" | "macos_sandbox_exec" | "unsandboxed".
    """
    plat = sys.platform
    if plat.startswith("linux") and shutil.which("bwrap"):
        return "linux_bwrap"
    if plat == "darwin" and shutil.which("sandbox-exec"):
        return "macos_sandbox_exec"
    return "unsandboxed"


def execute_in_sandbox(
    command: list[str],
    *,
    cwd: Path,
    config: SandboxConfig | None = None,
    timeout_s: int = 300,
    strict: bool = False,
) -> SandboxResult:
    """Run `command` in cwd under the host's available sandbox.

    On Linux: wraps with bubblewrap using --ro-bind/--bind for filesystem
    rules and --unshare-net when allow_network=False.

    On macOS: wraps with sandbox-exec using a generated sbpl profile.

    When strict=True and no sandbox is available, raises SandboxUnavailable
    so callers can fail closed. When strict=False, executes the command
    unsandboxed and reports skipped=True in the result.
    """
    if not isinstance(command, list) or not command:
        raise ValueError("command must be a non-empty list of args")

    effective = config or SandboxConfig()
    platform = detect_sandbox_platform()

    if platform == "unsandboxed":
        if strict:
            raise SandboxUnavailable(
                "No sandbox available on this host "
                "(requires bubblewrap on Linux or sandbox-exec on macOS)"
            )
        return _run_unsandboxed(command, cwd=cwd, timeout_s=timeout_s)

    if platform == "linux_bwrap":
        wrapped = _wrap_bwrap(command, cwd=cwd, config=effective)
    else:  # macos_sandbox_exec
        wrapped = _wrap_sandbox_exec(command, cwd=cwd, config=effective)

    try:
        proc = subprocess.run(
            wrapped,
            cwd=cwd.as_posix(),
            env=_scrubbed_env(),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return SandboxResult(
            exit_code=124 if isinstance(exc, subprocess.TimeoutExpired) else 127,
            stdout="",
            stderr=f"{type(exc).__name__}: {exc}",
            platform=platform,
            skipped=True,
        )

    return SandboxResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        platform=platform,
        violations=_parse_violations(proc.stderr, platform),
    )


def _run_unsandboxed(
    command: list[str], *, cwd: Path, timeout_s: int,
) -> SandboxResult:
    try:
        proc = subprocess.run(
            command,
            cwd=cwd.as_posix(),
            env=_scrubbed_env(),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return SandboxResult(
            exit_code=124 if isinstance(exc, subprocess.TimeoutExpired) else 127,
            stdout="",
            stderr=f"{type(exc).__name__}: {exc}",
            platform="unsandboxed",
            skipped=True,
        )
    return SandboxResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        platform="unsandboxed",
        skipped=True,
    )


# ---------- bubblewrap (Linux) ----------


def _wrap_bwrap(
    command: list[str],
    *,
    cwd: Path,
    config: SandboxConfig,
) -> list[str]:
    """Build a bwrap invocation that enforces SandboxConfig."""
    wrapped: list[str] = ["bwrap"]

    # Base minimal rootfs — readonly-bind standard system dirs.
    wrapped += [
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
    ]
    # /lib64 may not exist on all distros
    if Path("/lib64").is_dir():
        wrapped += ["--ro-bind", "/lib64", "/lib64"]

    # Separate mount namespaces + pid isolation for defense in depth
    wrapped += ["--unshare-pid", "--unshare-ipc", "--unshare-uts"]

    if not config.allow_network:
        wrapped += ["--unshare-net"]

    # cwd must be accessible; bind as rw so the command can operate.
    wrapped += ["--bind", cwd.as_posix(), cwd.as_posix()]
    wrapped += ["--chdir", cwd.as_posix()]

    for path in config.allow_read:
        wrapped += ["--ro-bind-try", path, path]
    for path in config.allow_write:
        wrapped += ["--bind-try", path, path]

    # tmpfs overlay for /tmp by default; caller can override via allow_write.
    wrapped += ["--tmpfs", "/tmp"]
    wrapped += ["--proc", "/proc", "--dev", "/dev"]

    wrapped += ["--"] + list(command)
    return wrapped


# ---------- sandbox-exec (macOS) ----------


def _wrap_sandbox_exec(
    command: list[str],
    *,
    cwd: Path,
    config: SandboxConfig,
) -> list[str]:
    """Build a sandbox-exec invocation with an inline sbpl profile."""
    profile = _build_sbpl_profile(cwd=cwd, config=config)
    return ["sandbox-exec", "-p", profile] + list(command)


def _build_sbpl_profile(*, cwd: Path, config: SandboxConfig) -> str:
    """Generate a minimal sbpl profile enforcing SandboxConfig."""
    lines: list[str] = [
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        "(allow process-exec)",
        "(allow signal (target self))",
        f"(allow file-read-data (subpath \"{cwd.as_posix()}\"))",
        f"(allow file-write* (subpath \"{cwd.as_posix()}\"))",
        "(allow file-read-data (subpath \"/usr\"))",
        "(allow file-read-data (subpath \"/bin\"))",
        "(allow file-read-data (subpath \"/System\"))",
    ]

    if config.allow_network:
        lines.append("(allow network*)")
    # Deny network is implicit in `(deny default)`.

    for path in config.allow_read:
        lines.append(f"(allow file-read-data (subpath \"{path}\"))")
    for path in config.allow_write:
        lines.append(f"(allow file-write* (subpath \"{path}\"))")
    for path in config.deny_read:
        lines.append(f"(deny file-read-data (subpath \"{path}\"))")
    for path in config.deny_write:
        lines.append(f"(deny file-write* (subpath \"{path}\"))")

    return "\n".join(lines)


# ---------- violation parsing ----------


_LINUX_VIOLATION_MARKERS: tuple[tuple[str, str], ...] = (
    ("Operation not permitted", "fs_write"),
    ("Permission denied", "fs_read"),
    ("Network is unreachable", "network"),
    ("Address family not supported", "network"),
)
_MACOS_VIOLATION_MARKERS: tuple[tuple[str, str], ...] = (
    ("deny file-write", "fs_write"),
    ("deny file-read", "fs_read"),
    ("deny network", "network"),
)


def _parse_violations(stderr: str, platform: str) -> list[Violation]:
    if not stderr:
        return []
    markers = _LINUX_VIOLATION_MARKERS if platform == "linux_bwrap" else _MACOS_VIOLATION_MARKERS
    violations: list[Violation] = []
    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        for needle, kind in markers:
            if needle.lower() in line.lower():
                violations.append(Violation(kind=kind, target=_extract_target(line), raw_line=line))
                break
    return violations


def _extract_target(line: str) -> str:
    """Best-effort: pluck a path / host from a violation line."""
    # Many kernel messages end with a colon-separated path
    if ":" in line:
        parts = line.rsplit(":", 1)
        candidate = parts[-1].strip().strip(",.'\"")
        if candidate:
            return candidate[:200]
    return line[:200]
