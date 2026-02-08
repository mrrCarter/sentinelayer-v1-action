from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...analyze.deterministic.pattern_scanner import Finding, _truncate_snippet
from ..detectors import read_text_best_effort
from ..runner import SecuritySuite


def _is_floating_version(spec: str) -> bool:
    s = (spec or "").strip().lower()
    if not s:
        return True
    if s in ("*", "latest"):
        return True
    if " x" in s or s.endswith("x") or ".x" in s:
        return True
    if any(op in s for op in (">", "<", "||")):
        return True
    return False


@dataclass
class BuildIntegritySuite(SecuritySuite):
    tech_stack: list[str]

    @property
    def name(self) -> str:
        return "build_integrity"

    def applies_to(self, tech_stack: list[str]) -> bool:
        return True

    async def run(self, project_root: str) -> list[Finding]:
        root = Path(project_root)
        pkg_path = root / "package.json"
        if not pkg_path.is_file():
            return []

        raw = read_text_best_effort(pkg_path)
        try:
            data: dict[str, Any] = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []

        lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
        if not any((root / lf).is_file() for lf in lockfiles):
            findings.append(
                Finding(
                    id="HARNESS-BUILD-LOCKFILE",
                    pattern_id="HARNESS-BUILD-LOCKFILE",
                    severity="P2",
                    category="supply-chain",
                    file_path="package.json",
                    line_start=1,
                    line_end=1,
                    snippet="",
                    message="No lockfile detected for Node dependencies",
                    recommendation="Commit a lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml) to ensure reproducible builds",
                    confidence=0.9,
                    source="harness",
                )
            )

        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        postinstall = scripts.get("postinstall") if isinstance(scripts, dict) else None
        if isinstance(postinstall, str) and postinstall.strip():
            snippet = _truncate_snippet(postinstall.strip(), max_chars=200)
            findings.append(
                Finding(
                    id="HARNESS-BUILD-POSTINSTALL",
                    pattern_id="HARNESS-BUILD-POSTINSTALL",
                    severity="P2",
                    category="supply-chain",
                    file_path="package.json",
                    line_start=1,
                    line_end=1,
                    snippet=snippet,
                    message="postinstall script present (supply-chain risk)",
                    recommendation="Ensure postinstall is required, audited, and does not fetch/execute remote code",
                    confidence=0.8,
                    source="harness",
                )
            )

        deps_sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
        floating: list[str] = []
        for section in deps_sections:
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, ver in deps.items():
                if not isinstance(ver, str):
                    continue
                if _is_floating_version(ver):
                    floating.append(f"{name}@{ver}")

        if floating:
            floating_preview = ", ".join(floating[:10])
            snippet = _truncate_snippet(floating_preview, max_chars=300)
            findings.append(
                Finding(
                    id="HARNESS-BUILD-FLOATING-VERSIONS",
                    pattern_id="HARNESS-BUILD-FLOATING-VERSIONS",
                    severity="P2",
                    category="supply-chain",
                    file_path="package.json",
                    line_start=1,
                    line_end=1,
                    snippet=snippet,
                    message="Floating/wildcard dependency versions detected",
                    recommendation="Pin versions to reduce supply-chain risk and improve build determinism",
                    confidence=0.7,
                    source="harness",
                )
            )

        return findings

