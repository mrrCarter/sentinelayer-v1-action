from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from .pattern_scanner import Finding, PatternScanner, mask_secret_in_snippet

MAX_SNIPPET_CHARS = 500


def _truncate_snippet(snippet: str, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    if len(snippet) <= max_chars:
        return snippet
    if max_chars <= 3:
        return snippet[:max_chars]
    return f"{snippet[: max_chars - 3]}..."


def _build_finding_id(pattern_id: str, file_path: str, line_start: int) -> str:
    return f"{pattern_id}-{file_path}-{line_start}"


class ConfigScanner:
    def __init__(self, patterns_dir: Path):
        self._pattern_scanner = PatternScanner(patterns_dir)
        self._cicd_patterns = [
            pattern for pattern in self._pattern_scanner.patterns if str(pattern.get("id", "")).startswith("CICD-")
        ]

    def scan_file(self, file_path: Path, content: str) -> List[Finding]:
        rel_path = file_path.as_posix()
        normalized = rel_path.replace("\\", "/")
        name = file_path.name.lower()
        findings: List[Finding] = []

        if name.startswith(".env"):
            findings.extend(self._scan_env(rel_path, content))

        if name == "package.json":
            findings.extend(self._scan_package_json(rel_path, content))

        if name in {"tsconfig.json", "jsconfig.json"}:
            findings.extend(self._scan_tsconfig(rel_path, content))

        if name in {"docker-compose.yml", "docker-compose.yaml"}:
            findings.extend(self._scan_docker_compose(rel_path, content))

        if normalized.startswith(".github/workflows/") or "/.github/workflows/" in normalized:
            findings.extend(
                self._pattern_scanner.scan_file_with_patterns(Path(rel_path), content, self._cicd_patterns)
            )

        return findings

    def scan_files(self, files: List[dict], repo_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        for entry in sorted(files, key=lambda item: item.get("path") or ""):
            rel_path = entry.get("path")
            if not rel_path:
                continue
            full_path = repo_root / rel_path
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.scan_file(Path(rel_path), content))
        return findings

    def _scan_env(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            _, value = stripped.split("=", 1)
            value = value.strip().strip("'\"")
            if not value or len(value) < 8:
                continue
            snippet = mask_secret_in_snippet(line, "secrets")
            snippet = _truncate_snippet(snippet)
            findings.append(
                Finding(
                    id=_build_finding_id("CONF-ENV-001", file_path, line_no),
                    pattern_id="CONF-ENV-001",
                    severity="P1",
                    category="secrets",
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    snippet=snippet,
                    message="Potential secret in .env file",
                    recommendation="Do not commit .env files; use a secrets manager or local overrides",
                    confidence=1.0,
                )
            )
        return findings

    def _scan_package_json(self, file_path: str, content: str) -> List[Finding]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        findings: List[Finding] = []
        for section_name in ("dependencies", "devDependencies", "optionalDependencies"):
            section = data.get(section_name)
            if not isinstance(section, dict):
                continue
            for dep_name, version in section.items():
                if isinstance(version, str) and "http://" in version:
                    snippet = _truncate_snippet(f'\"{dep_name}\": \"{version}\"')
                    findings.append(
                        Finding(
                            id=_build_finding_id("CONF-PKG-001", file_path, 1),
                            pattern_id="CONF-PKG-001",
                            severity="P2",
                            category="supply-chain",
                            file_path=file_path,
                            line_start=1,
                            line_end=1,
                            snippet=snippet,
                            message="Insecure HTTP dependency source detected",
                            recommendation="Use HTTPS or a registry version instead of HTTP URLs",
                            confidence=1.0,
                        )
                    )
        return findings

    def _scan_tsconfig(self, file_path: str, content: str) -> List[Finding]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        compiler = data.get("compilerOptions") if isinstance(data, dict) else None
        strict_value = None
        if isinstance(compiler, dict):
            strict_value = compiler.get("strict")
        if strict_value is True:
            return []
        snippet = "\"strict\": false" if strict_value is False else "strict mode not enabled"
        snippet = _truncate_snippet(snippet)
        return [
            Finding(
                id=_build_finding_id("CONF-TS-001", file_path, 1),
                pattern_id="CONF-TS-001",
                severity="P2",
                category="quality",
                file_path=file_path,
                line_start=1,
                line_end=1,
                snippet=snippet,
                message="TypeScript strict mode is disabled",
                recommendation="Enable compilerOptions.strict for safer type checking",
                confidence=1.0,
            )
        ]

    def _scan_docker_compose(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        privileged_re = re.compile(r"^\\s*privileged:\\s*true\\b", re.IGNORECASE)
        ports_re = re.compile(r"^\\s*-\\s*['\\\"]?\\d{1,5}:\\d{1,5}(?:/(tcp|udp))?['\\\"]?\\s*$")

        for line_no, line in enumerate(content.splitlines(), start=1):
            if privileged_re.search(line):
                snippet = _truncate_snippet(line.strip())
                findings.append(
                    Finding(
                        id=_build_finding_id("CONF-DC-001", file_path, line_no),
                        pattern_id="CONF-DC-001",
                        severity="P1",
                        category="misconfig",
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        message="Docker Compose privileged mode enabled",
                        recommendation="Avoid privileged containers unless absolutely required",
                        confidence=1.0,
                    )
                )
            if ports_re.search(line):
                snippet = _truncate_snippet(line.strip())
                findings.append(
                    Finding(
                        id=_build_finding_id("CONF-DC-002", file_path, line_no),
                        pattern_id="CONF-DC-002",
                        severity="P2",
                        category="exposure",
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        message="Docker Compose exposes host ports",
                        recommendation="Limit exposed ports and bind to localhost where possible",
                        confidence=1.0,
                    )
                )
        return findings
