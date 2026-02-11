from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ...analyze.deterministic.pattern_scanner import Finding, _truncate_snippet
from ..runner import SecuritySuite, run_command


def _parse_pip_vulnerability_count(payload: Any) -> int:
    """
    Parse pip-audit JSON output and return total vulnerability count.

    pip-audit returns:
      {"dependencies":[{"name":"x","version":"1.0","vulns":[...]}], "fixes":[...]}
    Older versions may return a list directly.
    """
    deps: list[Any] = []
    if isinstance(payload, dict):
        dependencies = payload.get("dependencies")
        if isinstance(dependencies, list):
            deps = dependencies
    elif isinstance(payload, list):
        deps = payload

    total = 0
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        vulns = dep.get("vulns")
        if isinstance(vulns, list):
            total += len(vulns)
    return total


def _parse_npm_critical_count(payload: dict[str, Any]) -> int:
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    vulns_meta = meta.get("vulnerabilities") if isinstance(meta.get("vulnerabilities"), dict) else {}
    critical = vulns_meta.get("critical")
    if isinstance(critical, int):
        return critical

    vulnerabilities = payload.get("vulnerabilities")
    if isinstance(vulnerabilities, dict):
        return sum(
            1
            for v in vulnerabilities.values()
            if isinstance(v, dict) and str(v.get("severity", "")).lower() == "critical"
        )

    advisories = payload.get("advisories")
    if isinstance(advisories, dict):
        return sum(
            1
            for adv in advisories.values()
            if isinstance(adv, dict) and str(adv.get("severity", "")).lower() == "critical"
        )

    return 0


@dataclass
class DepAuditSuite(SecuritySuite):
    tech_stack: list[str]

    @property
    def name(self) -> str:
        return "dependency_audit"

    def applies_to(self, tech_stack: list[str]) -> bool:
        return True

    async def _npm_audit(self, root: Path) -> Optional[Finding]:
        if not (root / "package.json").is_file():
            return None

        res = await run_command(
            ["npm", "audit", "--audit-level=critical", "--json", "--ignore-scripts"],
            cwd=root,
            timeout_s=50,
        )
        if res.returncode == 127:
            return None
        if not res.stdout.strip():
            return None
        try:
            payload = json.loads(res.stdout)
        except json.JSONDecodeError:
            return None

        critical_count = _parse_npm_critical_count(payload)
        if critical_count <= 0:
            return None

        snippet = _truncate_snippet(f"critical={critical_count}", max_chars=200)
        return Finding(
            id="HARNESS-NPM-AUDIT",
            pattern_id="HARNESS-NPM-AUDIT",
            severity="P1",
            category="supply-chain",
            file_path="package.json",
            line_start=1,
            line_end=1,
            snippet=snippet,
            message=f"npm audit reported {critical_count} critical vulnerabilities",
            recommendation="Update dependencies and re-run npm audit; consider npm audit fix and lockfile updates",
            confidence=0.9,
            source="harness",
        )

    async def _pip_audit(self, root: Path) -> Optional[Finding]:
        if not (root / "requirements.txt").is_file():
            return None

        res = await run_command(
            ["pip-audit", "-r", "requirements.txt", "-f", "json"],
            cwd=root,
            timeout_s=50,
        )
        if res.returncode == 127:
            return None
        if not res.stdout.strip():
            return None
        try:
            payload = json.loads(res.stdout)
        except json.JSONDecodeError:
            return None
        vuln_count = _parse_pip_vulnerability_count(payload)
        if vuln_count <= 0:
            return None

        snippet = _truncate_snippet(f"vulnerabilities={vuln_count}", max_chars=200)
        return Finding(
            id="HARNESS-PIP-AUDIT",
            pattern_id="HARNESS-PIP-AUDIT",
            severity="P1",
            category="supply-chain",
            file_path="requirements.txt",
            line_start=1,
            line_end=1,
            snippet=snippet,
            message="pip-audit reported known vulnerabilities in Python dependencies",
            recommendation="Upgrade vulnerable dependencies and re-run pip-audit",
            confidence=0.8,
            source="harness",
        )

    async def _cargo_audit(self, root: Path) -> Optional[Finding]:
        if not (root / "Cargo.toml").is_file():
            return None

        res = await run_command(["cargo", "audit", "--json"], cwd=root, timeout_s=50)
        if res.returncode == 127:
            return None
        if not res.stdout.strip():
            return None

        try:
            payload = json.loads(res.stdout)
        except json.JSONDecodeError:
            return None
        vulns = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), dict) else {}
        listed = vulns.get("list") if isinstance(vulns.get("list"), list) else []
        if not listed:
            return None

        snippet = _truncate_snippet(f"count={len(listed)}", max_chars=200)
        return Finding(
            id="HARNESS-CARGO-AUDIT",
            pattern_id="HARNESS-CARGO-AUDIT",
            severity="P1",
            category="supply-chain",
            file_path="Cargo.toml",
            line_start=1,
            line_end=1,
            snippet=snippet,
            message="cargo audit reported known vulnerabilities in Rust dependencies",
            recommendation="Update vulnerable crates and re-run cargo audit",
            confidence=0.8,
            source="harness",
        )

    async def run(self, project_root: str) -> list[Finding]:
        root = Path(project_root)
        findings: list[Finding] = []

        for f in (
            await self._npm_audit(root),
            await self._pip_audit(root),
            await self._cargo_audit(root),
        ):
            if f:
                findings.append(f)

        return findings

