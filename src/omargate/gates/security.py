"""Security scan gate (Layer 4 of Omar Gate 2.0).

Runs six deterministic scanners in sequence (concurrency can be added
later if runtime pressure warrants it). Each scanner is skipped silently
when its runtime binary isn't on PATH — callers can invoke this gate in
mixed-language / partial-toolchain environments without failure.

Scanners (per CODEX_OMARGATE_COMBINE_SPEC.md §5 + §7):
  gitleaks        — secret scanning (high-signal, zero-auth, OSS)
  semgrep         — SAST with --config=auto ruleset
  osv-scanner     — dependency CVE lookup against OSV database
  actionlint      — GitHub Actions workflow YAML validation
  checkov         — IaC policy scanning (Dockerfile / Terraform)
  tflint          — Terraform linting

Carter's audit finding: "most of our problems are in yml and infra." This
gate specifically closes that gap — actionlint + checkov + tflint are the
three YAML/IaC-focused scanners. Plus gitleaks + semgrep + osv-scanner to
cover code + secrets + dependencies.

All tools run via subprocess with a scrubbed env (LD_PRELOAD, DYLD_*,
BASH_FUNC_* stripped) per the hardening baked into `static.py`. Parser
functions are pure + unit-testable without subprocess calls.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import GateContext, GateResult
from .findings import Finding
from .static import _scrubbed_env


__all__ = ["SecurityScanGate"]


# ---------- public gate class ----------


class SecurityScanGate:
    """Runs up to six deterministic security scanners and aggregates findings."""

    gate_id = "security"

    def __init__(
        self,
        *,
        gitleaks: bool = True,
        semgrep: bool = True,
        osv_scanner: bool = True,
        actionlint: bool = True,
        checkov: bool = True,
        tflint: bool = True,
    ) -> None:
        self._tools: list[tuple[str, bool]] = [
            ("gitleaks", gitleaks),
            ("semgrep", semgrep),
            ("osv-scanner", osv_scanner),
            ("actionlint", actionlint),
            ("checkov", checkov),
            ("tflint", tflint),
        ]

    def run(self, ctx: GateContext) -> GateResult:
        findings: list[Finding] = []
        tools_meta: list[dict[str, Any]] = []

        for tool_name, enabled in self._tools:
            if not enabled:
                tools_meta.append({"tool": tool_name, "invoked": False, "reason": "disabled"})
                continue
            if shutil.which(tool_name) is None:
                tools_meta.append({"tool": tool_name, "invoked": False, "reason": "binary-not-on-path"})
                continue

            runner = getattr(self, f"_run_{tool_name.replace('-', '_')}")
            tool_findings, meta = runner(ctx)
            findings.extend(tool_findings)
            tools_meta.append(meta)

        return GateResult(
            gate_id=self.gate_id,
            findings=findings,
            status="ok",
            metadata={"tools": tools_meta},
        )

    # ---------- per-tool runners ----------

    def _run_gitleaks(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        meta: dict[str, Any] = {"tool": "gitleaks", "invoked": True}
        try:
            proc = subprocess.run(
                ["gitleaks", "detect", "--no-git", "--report-format", "json", "--report-path", "-", "--source", "."],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return [], {**meta, "skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
        meta["exit_code"] = proc.returncode
        findings = _parse_gitleaks_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta

    def _run_semgrep(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        meta: dict[str, Any] = {"tool": "semgrep", "invoked": True}
        try:
            proc = subprocess.run(
                ["semgrep", "--config", "auto", "--json", "--quiet", "--error", "--timeout", "60", "."],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return [], {**meta, "skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
        meta["exit_code"] = proc.returncode
        findings = _parse_semgrep_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta

    def _run_osv_scanner(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        meta: dict[str, Any] = {"tool": "osv-scanner", "invoked": True}
        try:
            proc = subprocess.run(
                ["osv-scanner", "--format", "json", "--recursive", "."],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=240,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return [], {**meta, "skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
        meta["exit_code"] = proc.returncode
        findings = _parse_osv_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta

    def _run_actionlint(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        meta: dict[str, Any] = {"tool": "actionlint", "invoked": True}
        # actionlint scans .github/workflows/**/*.yml by default when run at repo root
        workflows_dir = ctx.repo_root / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return [], {**meta, "skipped": True, "reason": "no-workflows-dir"}
        try:
            proc = subprocess.run(
                ["actionlint", "-format", "{{range $err := .}}{{$err.Filepath}}:{{$err.Line}}:{{$err.Column}}: {{$err.Message}} [{{$err.Kind}}]\n{{end}}"],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return [], {**meta, "skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
        meta["exit_code"] = proc.returncode
        findings = _parse_actionlint_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta

    def _run_checkov(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        meta: dict[str, Any] = {"tool": "checkov", "invoked": True}
        try:
            proc = subprocess.run(
                ["checkov", "--quiet", "--compact", "-o", "json", "-d", "."],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return [], {**meta, "skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
        meta["exit_code"] = proc.returncode
        findings = _parse_checkov_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta

    def _run_tflint(self, ctx: GateContext) -> tuple[list[Finding], dict[str, Any]]:
        meta: dict[str, Any] = {"tool": "tflint", "invoked": True}
        # tflint only runs against Terraform files
        has_tf = any(p.suffix == ".tf" for p in ctx.repo_root.rglob("*.tf"))
        if not has_tf:
            return [], {**meta, "skipped": True, "reason": "no-terraform-files"}
        try:
            proc = subprocess.run(
                ["tflint", "--format", "json", "--recursive"],
                cwd=str(ctx.repo_root),
                env=_scrubbed_env(),
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return [], {**meta, "skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
        meta["exit_code"] = proc.returncode
        findings = _parse_tflint_output(proc.stdout, self.gate_id)
        meta["finding_count"] = len(findings)
        return findings, meta


# ---------- pure parsers (testable without subprocess) ----------


def _parse_gitleaks_output(stdout: str, gate_id: str) -> list[Finding]:
    """gitleaks --report-format json emits a JSON array of leak records.

    Every secret exposure is P0 — we deliberately do not soften this.
    """
    if not stdout.strip():
        return []
    try:
        records = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(records, list):
        return []

    findings: list[Finding] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        file_rel = str(rec.get("File", "")).strip()
        line = int(rec.get("StartLine", 0) or 0)
        rule_id = str(rec.get("RuleID", "")).strip() or "unknown"
        title = str(rec.get("Description", "Potential secret")).strip()
        findings.append(
            Finding(
                gate_id=gate_id,
                tool="gitleaks",
                severity="P0",
                file=file_rel,
                line=line,
                title=title,
                rule_id=f"gitleaks:{rule_id}",
            )
        )
    return findings


_SEMGREP_SEVERITY_MAP = {
    "ERROR": "P1",
    "WARNING": "P2",
    "INFO": "P3",
}


def _parse_semgrep_output(stdout: str, gate_id: str) -> list[Finding]:
    """semgrep --json emits {"results": [...], "errors": [...]}."""
    if not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id", "unknown")).strip()
        path = str(item.get("path", "")).strip()
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        line = int(start.get("line", 0) or 0)
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        severity_raw = str(extra.get("severity", "WARNING")).upper()
        severity = _SEMGREP_SEVERITY_MAP.get(severity_raw, "P2")
        message = str(extra.get("message", check_id)).strip()
        findings.append(
            Finding(
                gate_id=gate_id,
                tool="semgrep",
                severity=severity,  # type: ignore[arg-type]
                file=path,
                line=line,
                title=message,
                rule_id=f"semgrep:{check_id}",
            )
        )
    return findings


def _parse_osv_output(stdout: str, gate_id: str) -> list[Finding]:
    """osv-scanner --format json emits nested {results: [{packages: [{vulnerabilities: [...]}]}]}."""
    if not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        source_path = str((result.get("source") or {}).get("path", "")).strip()
        for package_block in result.get("packages", []) or []:
            if not isinstance(package_block, dict):
                continue
            package_name = str((package_block.get("package") or {}).get("name", "")).strip()
            for vuln in package_block.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id", "")).strip() or "unknown"
                summary = str(vuln.get("summary", vuln_id)).strip()
                severity = _osv_max_severity(vuln.get("severity"))
                findings.append(
                    Finding(
                        gate_id=gate_id,
                        tool="osv-scanner",
                        severity=severity,
                        file=source_path,
                        line=0,
                        title=f"{package_name}: {summary}" if package_name else summary,
                        rule_id=f"osv:{vuln_id}",
                    )
                )
    return findings


def _osv_max_severity(severity_entries: Any) -> str:
    """Map OSV CVSS severity list → our P0/P1/P2/P3 scale.

    Unknown severity (empty / non-list / all zero scores) defaults to P2
    (medium) — defensive default. Only explicit low CVSS scores (< 4.0)
    map to P3.
    """
    if not isinstance(severity_entries, list) or not severity_entries:
        return "P2"
    highest_score = 0.0
    saw_numeric = False
    for entry in severity_entries:
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("score", "")).strip()
        score = _extract_cvss_numeric(raw)
        if score > 0.0:
            saw_numeric = True
        if score > highest_score:
            highest_score = score
    if highest_score >= 9.0:
        return "P0"
    if highest_score >= 7.0:
        return "P1"
    if highest_score >= 4.0:
        return "P2"
    if saw_numeric:
        return "P3"
    return "P2"


def _extract_cvss_numeric(raw: str) -> float:
    """Best-effort CVSS score parsing ('CVSS:3.1/AV:N/... / 9.8' and variants)."""
    if not raw:
        return 0.0
    # Some entries are a bare number, others a CVSS vector string
    parts = raw.split("/")
    for part in reversed(parts):
        part = part.strip()
        try:
            value = float(part)
            if 0.0 <= value <= 10.0:
                return value
        except ValueError:
            continue
    # Direct numeric
    try:
        return float(raw)
    except ValueError:
        return 0.0


def _parse_actionlint_output(stdout: str, gate_id: str) -> list[Finding]:
    """actionlint default text format: `file:line:col: message [rule]`."""
    findings: list[Finding] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        # Expect at least "path:line:col: message"
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue
        file_part, line_part, col_part, rest = parts
        try:
            line_num = int(line_part)
        except ValueError:
            continue
        # rest = " message [rule]"
        rest = rest.strip()
        rule_id = "unknown"
        title = rest
        if rest.endswith("]") and "[" in rest:
            bracket_open = rest.rfind("[")
            rule_id = rest[bracket_open + 1 : -1].strip() or "unknown"
            title = rest[:bracket_open].strip()
        findings.append(
            Finding(
                gate_id=gate_id,
                tool="actionlint",
                severity="P2",
                file=str(Path(file_part).as_posix()),
                line=line_num,
                title=title,
                rule_id=f"actionlint:{rule_id}",
            )
        )
    return findings


_CHECKOV_SEVERITY_MAP = {
    "CRITICAL": "P0",
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P3",
}


def _parse_checkov_output(stdout: str, gate_id: str) -> list[Finding]:
    """checkov -o json emits {"results": {"failed_checks": [...]}} (or a list of such objects).

    checkov sometimes emits a list of frameworks when -d is used; we
    flatten across all of them.
    """
    if not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payloads: list[dict[str, Any]] = [payload]
    elif isinstance(payload, list):
        payloads = [p for p in payload if isinstance(p, dict)]
    else:
        return []

    findings: list[Finding] = []
    for pl in payloads:
        results = pl.get("results") if isinstance(pl.get("results"), dict) else {}
        failed = results.get("failed_checks", []) if isinstance(results, dict) else []
        if not isinstance(failed, list):
            continue
        for chk in failed:
            if not isinstance(chk, dict):
                continue
            check_id = str(chk.get("check_id", "unknown")).strip()
            check_name = str(chk.get("check_name", check_id)).strip()
            file_path = str(chk.get("file_path", "")).lstrip("/").strip()
            rng = chk.get("file_line_range")
            line = 0
            if isinstance(rng, list) and len(rng) >= 1 and isinstance(rng[0], int):
                line = rng[0]
            severity_raw = str(chk.get("severity", "MEDIUM") or "MEDIUM").upper()
            severity = _CHECKOV_SEVERITY_MAP.get(severity_raw, "P2")
            findings.append(
                Finding(
                    gate_id=gate_id,
                    tool="checkov",
                    severity=severity,  # type: ignore[arg-type]
                    file=file_path,
                    line=line,
                    title=check_name,
                    rule_id=f"checkov:{check_id}",
                )
            )
    return findings


_TFLINT_SEVERITY_MAP = {
    "error": "P1",
    "warning": "P2",
    "notice": "P3",
    "info": "P3",
}


def _parse_tflint_output(stdout: str, gate_id: str) -> list[Finding]:
    """tflint --format json emits {"issues": [...], "errors": [...]}."""
    if not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    issues = payload.get("issues") if isinstance(payload, dict) else None
    if not isinstance(issues, list):
        return []

    findings: list[Finding] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        rule = issue.get("rule") if isinstance(issue.get("rule"), dict) else {}
        rule_name = str(rule.get("name", "unknown")).strip()
        severity_raw = str(rule.get("severity", "warning") or "warning").lower()
        severity = _TFLINT_SEVERITY_MAP.get(severity_raw, "P2")
        message = str(issue.get("message", rule_name)).strip()
        rng = issue.get("range") if isinstance(issue.get("range"), dict) else {}
        file_rel = str(rng.get("filename", "")).strip()
        start = rng.get("start") if isinstance(rng.get("start"), dict) else {}
        line = int(start.get("line", 0) or 0)
        findings.append(
            Finding(
                gate_id=gate_id,
                tool="tflint",
                severity=severity,  # type: ignore[arg-type]
                file=file_rel,
                line=line,
                title=message,
                rule_id=f"tflint:{rule_name}",
            )
        )
    return findings
