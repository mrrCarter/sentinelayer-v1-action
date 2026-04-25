"""Path safety / hardening for Omar Gate inputs.

Lifted as a clean-room re-implementation of the defensive patterns from
src/utils/permissions/pathValidation.ts:373-485 (Claude Code CLI internals,
gitignored, study-only — no source-import). Adapted for filesystem repo paths
(not URL paths — that's already handled in aidenid-clearance's pathNormalize.ts).

Why this exists
---------------
Omar Gate's main.py and local_gates.py historically only did
`replace("\\\\", "/").strip().lower()` and `Path(p).resolve()` on the --path
input. Hostile input via that surface can:

  - smuggle null bytes that confuse downstream string handling
  - smuggle BiDi override characters that confuse PR-comment rendering
  - sneak past directory guards via tilde / shell-expansion prefixes (~user, $X)
  - sneak past directory guards via double-encoded percent (%252e%252e/etc/)
  - reach internal Windows shares via UNC \\\\host\\share prefix
  - escape into root or drive children via .. traversal that the resolver lets through

This module rejects (returns None) any of those classes BEFORE the path
becomes a Path object that scanners walk.

Also exports `EXCLUDED_PATH_PREFIXES` — folders that should never be
walked by deterministic scanners (gitleaks, semgrep, etc.). Today this is
informational; future PRs will plumb it into individual gate scanners.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

__all__ = [
    "RejectedPathReason",
    "PathSafetyError",
    "validate_repo_path",
    "EXCLUDED_PATH_PREFIXES",
]

RejectedPathReason = Literal[
    "null_byte",
    "control_character",
    "bidi_override",
    "double_encoded_percent",
    "unc_path",
    "tilde_prefix",
    "shell_expansion",
    "windows_drive_root",
    "traversal_above_base",
    "not_a_directory",
    "empty",
]


@dataclass(frozen=True)
class PathSafetyError(Exception):
    """Raised internally when a path fails validation. Public API returns None."""

    reason: RejectedPathReason
    detail: str = ""

    def __str__(self) -> str:
        return f"path rejected ({self.reason}): {self.detail}" if self.detail else f"path rejected ({self.reason})"


# Folders that MUST NOT be walked by deterministic scanners. Directly
# adapted from sentinelayer-api's EXCLUDED_PATH_PREFIXES intuition plus
# the build/coverage/__pycache__ noise that gitleaks and semgrep famously
# trip on.
EXCLUDED_PATH_PREFIXES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "out",
        "coverage",
        ".coverage",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".next",
        ".nuxt",
        ".turbo",
        ".cache",
        "target",  # Rust / Maven
        "bin",
        "obj",  # .NET
    }
)


# Char classes
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI_OVERRIDE_RE = re.compile(r"[‪-‮⁦-⁩]")
# After one decode, if any %xx triplet remains, that's a double-encode.
_PERCENT_TRIPLET_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _validate_chars(raw: str) -> None:
    """Reject null bytes, ASCII control chars, DEL, and BiDi overrides."""
    if "\x00" in raw:
        raise PathSafetyError(reason="null_byte", detail="path contains \\x00")
    m = _CONTROL_CHAR_RE.search(raw)
    if m:
        raise PathSafetyError(
            reason="control_character",
            detail=f"path contains 0x{ord(m.group(0)):02x} at position {m.start()}",
        )
    m = _BIDI_OVERRIDE_RE.search(raw)
    if m:
        raise PathSafetyError(
            reason="bidi_override",
            detail=f"path contains BiDi override U+{ord(m.group(0)):04X} at position {m.start()}",
        )


def _validate_double_encoded(raw: str) -> None:
    """Reject %xx that survives a single percent-decode round.

    Filesystem paths shouldn't be percent-encoded at all in our input surface,
    but if a caller percent-encodes once (e.g. URL-style), single-decoding is
    fine. Anything that REMAINS percent-encoded after one decode is double-
    encoded — almost always an attacker's traversal smuggling vector
    (`%252e%252e/etc/passwd` -> `%2e%2e/etc/passwd` after one decode).
    """
    try:
        from urllib.parse import unquote
    except ImportError:  # pragma: no cover
        return
    decoded = unquote(raw)
    if decoded != raw and _PERCENT_TRIPLET_RE.search(decoded):
        raise PathSafetyError(
            reason="double_encoded_percent",
            detail="path remains percent-encoded after one decode round",
        )


def _validate_prefix(raw: str) -> None:
    """Reject UNC paths, tilde variants, shell expansion, and Windows drive roots."""
    if raw.startswith(("\\\\", "//")):
        raise PathSafetyError(reason="unc_path", detail="UNC-style host\\share prefix")
    # Strip a single leading slash for prefix checks (so "/~user" is caught too)
    head = raw.lstrip("/").lstrip("\\")
    if head.startswith("~"):
        # Reject ~, ~user, ~+, ~-, ~N — anything that shells could expand
        raise PathSafetyError(reason="tilde_prefix", detail=f"tilde prefix '{head[:8]}'")
    if head.startswith(("$", "%", "=")):
        raise PathSafetyError(reason="shell_expansion", detail=f"shell-expansion prefix '{head[:1]}'")
    # Windows drive-root rejection: 'C:\' / 'C:/' / 'C:' alone
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        rest = raw[2:].lstrip("/").lstrip("\\")
        if not rest:
            raise PathSafetyError(reason="windows_drive_root", detail=f"bare drive root '{raw[:3]}'")


def _validate_within_base(resolved: Path, base_cwd: Path) -> None:
    """If a base_cwd is provided, resolved must be inside or equal to it.

    base_cwd defaults to None (skip check). When provided, this prevents the
    --path arg from escaping CI's working directory via .. or symlink resolution.
    """
    if base_cwd is None:
        return
    try:
        base_resolved = base_cwd.resolve()
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise PathSafetyError(
            reason="traversal_above_base",
            detail=f"resolved path {resolved} is not inside base {base_resolved}",
        ) from exc


def validate_repo_path(
    raw: str,
    *,
    base_cwd: Path | None = None,
    require_directory: bool = True,
) -> Path | None:
    """Validate a repo-path input and return a resolved Path, or None on rejection.

    Parameters
    ----------
    raw
        The raw string from CLI args, env vars, or YAML config.
    base_cwd
        If given, the resolved path must be inside this directory. Use
        Path.cwd() to enforce "inside the GitHub Actions workspace" in CI.
        Pass None (default) to skip the inside-base check (e.g., for
        unit tests where the resolved path may legitimately be in /tmp).
    require_directory
        If True (default), the resolved path must exist and be a directory.

    Returns
    -------
    Path | None
        Resolved path on success. None on any rejection. The caller should
        treat None as "fail closed" — emit a clear `error:` and exit non-zero,
        do not fall back to scanning a partially-validated path.
    """
    if not isinstance(raw, str):
        return None
    if not raw or not raw.strip():
        return None

    try:
        _validate_chars(raw)
        _validate_double_encoded(raw)
        _validate_prefix(raw)

        # Normalize separators only AFTER prefix/char validation so we
        # don't lose attack signal (e.g., \\\\?\\C:\\ would become //?/C:/).
        normalized = raw.replace("\\", "/").strip()

        resolved = Path(normalized).resolve()
        _validate_within_base(resolved, base_cwd)

        if require_directory and not resolved.is_dir():
            raise PathSafetyError(
                reason="not_a_directory",
                detail=f"resolved path is not a directory: {resolved}",
            )

        return resolved

    except PathSafetyError:
        return None
    except (OSError, ValueError):
        # Path resolution can throw on extremely malformed input — treat as rejection.
        return None
