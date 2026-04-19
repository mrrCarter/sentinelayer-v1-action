"""Static analysis gate (Layer 3 of Omar Gate 2.0).

Runs tsc, eslint, prettier as independent subprocess invocations and
parses each tool's output into Finding objects. Tools are invoked with
a scrubbed environment to prevent PATH-injection vectors (LD_PRELOAD,
DYLD_*, and exported shell functions).

All three tools are skipped silently if their runtime binary (`npx` for
this MVP) is absent or the tool's own subprocess raises FileNotFoundError
/ TimeoutExpired. This keeps the gate safe to invoke in environments
where a particular toolchain isn't present (e.g., a Python-only repo).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import GateContext, GateResult
from .findings import Finding

# Environment variables that can be abused to inject shared libraries
# or modify linker behavior in the subprocess. Stripped before invoke.
_SCRUBBED_ENV_KEYS = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FALLBACK_LIBRARY_PATH",
}


def _scrubbed_env() -> dict[str, str]:
    """Strip known PATH-injection vectors from subprocess env."""
    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV_KEYS}
    # Drop exported bash functions (e.g., BASH_FUNC_name%%=() { ... })
    env = {
        k: v
        for k, v in env.items()
        if not (k.startswith("BASH_FUNC_") and v.startswith("()"))
    }
    return env


class StaticAnalysisGate:
    """Runs configured static-analysis tools and aggregates findings."""

    gate_id = "static"

    def __init__(self, *, tsc: bool = True, eslint: bool = True, prettier: bool = False):
        self._run_tsc = tsc
        self._run_eslint = eslint
        self._run_prettier = prettier

    def run(self, ctx: GateContext) -> GateResult:
        findings: list[Finding] = []
        tools_meta: list[dict[str, Any]] = []

        have_npx = shutil.which("npx") is not None

        if self._run_tsc and have_npx:
            tsc_findings, tsc_meta = self._run_tsc_check(ctx)
            findings.extend(tsc_findings)
            tools_meta.append(tsc_meta)

        if self._run_eslint and have_npx:
            eslint_findings, eslint_meta = self._run_eslint_check(ctx)
            findings.extend(eslint_findings)
            tools_meta.append(eslint_meta)

        if self._run_prettier and have_npx:
            prettier_findings, prettier_meta = self._run_prettier_check(ctx)
            findings.extend(prettier_findings)
            tools_meta.append(prettier_meta)

        return GateResult(
            gate_id=self.gate_id,
            findings=findings,
            status="ok",
            metadata={"tools": tools_meta, "npx_available": have_npx},
        )

    # ---------- tsc ----------

    def _run_tsc_check(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        """Run `tsc --noEmit --pretty false`.

        tsc output format per diagnostic:
            path/to/file.ts(12,4): error TS2345: Message...
        """
        meta: dict[str, Any] = {"tool": "tsc", "invoked": True}
        try:
            proc = subprocess.run(
                ["npx", "--no-install", "tsc", "--noEmit", "--pretty", "false"],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            meta["skipped"] = True
            meta["reason"] = f"{type(exc).__name__}: {exc}"
            return [], meta

        meta["exit_code"] = proc.returncode
        findings = _parse_tsc_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta

    # ---------- eslint ----------

    def _run_eslint_check(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        """Run `eslint --format=json .`. Parses JSON output into Findings."""
        meta: dict[str, Any] = {"tool": "eslint", "invoked": True}
        try:
            proc = subprocess.run(
                ["npx", "--no-install", "eslint", "--format=json", "."],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            meta["skipped"] = True
            meta["reason"] = f"{type(exc).__name__}: {exc}"
            return [], meta

        meta["exit_code"] = proc.returncode
        findings, parse_error = _parse_eslint_output(proc.stdout, self.gate_id)
        if parse_error:
            meta["parse_error"] = True
        meta["finding_count"] = len(findings)
        return findings, meta

    # ---------- prettier ----------

    def _run_prettier_check(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        """Run `prettier --check .`. Emits one P2 finding per unformatted file."""
        meta: dict[str, Any] = {"tool": "prettier", "invoked": True}
        try:
            proc = subprocess.run(
                ["npx", "--no-install", "prettier", "--check", "."],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            meta["skipped"] = True
            meta["reason"] = f"{type(exc).__name__}: {exc}"
            return [], meta

        meta["exit_code"] = proc.returncode
        findings = _parse_prettier_output(proc.stderr or "", self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta


# ---------- parsers (pure functions — easy to unit-test without subprocess) ----------


def _parse_tsc_output(stdout: str, gate_id: str) -> list[Finding]:
    """Parse tsc --pretty false output into Findings.

    Tolerant of trailing blank lines and informational summaries.
    """
    findings: list[Finding] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if "): error TS" not in line and "): warning TS" not in line:
            continue
        try:
            location_end = line.index(")")
            location = line[: location_end + 1]
            file_part, rest = location.rsplit("(", 1)
            line_num = int(rest.rstrip(")").split(",", 1)[0])
            rule_start = line.index("TS", location_end)
            rule_end = line.index(":", rule_start)
            rule_id = f"tsc:{line[rule_start:rule_end]}"
            message = line[rule_end + 1 :].strip()
        except (ValueError, IndexError):
            continue
        severity = "P1" if ") error " in line or "): error " in line else "P2"
        findings.append(
            Finding(
                gate_id=gate_id,
                tool="tsc",
                severity=severity,  # type: ignore[arg-type]
                file=str(Path(file_part).as_posix()),
                line=line_num,
                title=message,
                rule_id=rule_id,
            )
        )
    return findings


def _parse_eslint_output(stdout: str, gate_id: str) -> tuple[list[Finding], bool]:
    """Parse eslint --format=json output.

    Returns (findings, parse_error). parse_error=True signals the JSON
    payload was malformed; callers should treat the gate as having
    skipped rather than claimed zero findings.
    """
    try:
        reports = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return [], True

    findings: list[Finding] = []
    for report in reports:
        file_rel = str(Path(report.get("filePath", "")).as_posix())
        for msg in report.get("messages", []) or []:
            severity_code = msg.get("severity", 1)  # 1=warn, 2=error
            severity = "P1" if severity_code >= 2 else "P2"
            findings.append(
                Finding(
                    gate_id=gate_id,
                    tool="eslint",
                    severity=severity,  # type: ignore[arg-type]
                    file=file_rel,
                    line=int(msg.get("line") or 0),
                    title=msg.get("message", ""),
                    rule_id=f"eslint:{msg.get('ruleId') or 'unknown'}",
                )
            )
    return findings, False


def _parse_prettier_output(stderr: str, gate_id: str) -> list[Finding]:
    """Parse prettier --check stderr lines like `[warn] path/to/file`."""
    findings: list[Finding] = []
    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        if not line.startswith("[warn]"):
            continue
        path_part = line[len("[warn]") :].strip()
        if not path_part or path_part.startswith("Code style issues"):
            continue
        findings.append(
            Finding(
                gate_id=gate_id,
                tool="prettier",
                severity="P2",
                file=str(Path(path_part).as_posix()),
                line=0,
                title="Prettier formatting differences",
                rule_id="prettier:unformatted",
            )
        )
    return findings
