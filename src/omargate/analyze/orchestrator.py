from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..config import OmarGateConfig
from ..ingest import run_ingest
from ..logging import OmarLogger
from .deterministic import ConfigScanner, PatternScanner, scan_for_secrets
from .llm import ContextBuilder, LLMClient, PromptLoader, ResponseParser, handle_llm_failure
from .llm.response_parser import ParsedFinding


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    findings: List[dict]
    counts: dict
    ingest_stats: dict
    deterministic_count: int
    llm_count: int
    llm_success: bool
    llm_usage: Optional[dict]
    warnings: List[str]
    scan_mode: str
    total_files_scanned: int
    hotspots_found: List[str]


@dataclass
class LLMAnalysisResult:
    findings: List[dict]
    success: bool
    usage: Optional[dict]
    warning: Optional[str]


class AnalysisOrchestrator:
    """Orchestrates the complete analysis pipeline."""

    def __init__(
        self,
        config: OmarGateConfig,
        logger: OmarLogger,
        repo_root: Path,
        allow_llm: bool = True,
    ) -> None:
        self.config = config
        self.logger = logger
        self.repo_root = repo_root
        self.allow_llm = allow_llm

        patterns_dir = Path(__file__).parent / "deterministic" / "patterns"
        self.pattern_scanner = PatternScanner(patterns_dir=patterns_dir)
        self.config_scanner = ConfigScanner(patterns_dir=patterns_dir)

        prompts_dir = Path(__file__).resolve().parents[3] / "prompts"
        self.prompt_loader = PromptLoader(prompts_dir=prompts_dir)

        self.context_builder = ContextBuilder(max_tokens=config.max_input_tokens)
        self.response_parser = ResponseParser()

    async def run(
        self,
        scan_mode: str = "pr-diff",
        diff_content: Optional[str] = None,
        changed_files: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """
        Run complete analysis pipeline.

        Steps:
        1. Ingest codebase
        2. Run deterministic scans
        3. Build LLM context
        4. Run LLM analysis (with fallback)
        5. Merge and dedupe findings
        6. Return results
        """
        warnings: List[str] = []

        # Step 1: Ingest
        with self.logger.stage("ingest"):
            ingest = run_ingest(
                self.repo_root,
                max_files=1000,
                max_file_size_bytes=1_000_000,
                logger=self.logger,
            )
            stats = ingest.get("stats", {})
            self.logger.info(
                "Ingest complete",
                total_files=stats.get("total_files"),
                in_scope=stats.get("in_scope_files"),
            )

        # Step 2: Deterministic scans
        with self.logger.stage("deterministic_scan"):
            det_findings = self._run_deterministic_scans(ingest)
            self.logger.info(
                "Deterministic scan complete",
                findings_count=len(det_findings),
            )

        # Step 3-4: LLM analysis (skip if no API key or limited mode)
        llm_findings: List[dict] = []
        llm_success = False
        llm_usage: Optional[dict] = None

        if self._should_run_llm():
            with self.logger.stage("llm_analysis"):
                llm_result = await self._run_llm_analysis(
                    ingest=ingest,
                    deterministic_findings=det_findings,
                    scan_mode=scan_mode,
                    diff_content=diff_content,
                    changed_files=changed_files,
                )
                llm_findings = llm_result.findings
                llm_success = llm_result.success
                llm_usage = llm_result.usage

                if llm_result.warning:
                    warnings.append(llm_result.warning)

                self.logger.info(
                    "LLM analysis complete",
                    success=llm_success,
                    findings_count=len(llm_findings),
                )
        else:
            warnings.append("LLM analysis skipped (no API key or limited mode)")

        # Step 5: Merge findings
        all_findings = self._merge_findings(det_findings, llm_findings)
        counts = self._count_by_severity(all_findings)

        hotspots_with_findings = self._identify_hotspots_with_findings(
            all_findings, ingest.get("hotspots", {})
        )

        stats = ingest.get("stats", {})

        return AnalysisResult(
            findings=all_findings,
            counts=counts,
            ingest_stats=stats,
            deterministic_count=len(det_findings),
            llm_count=len(llm_findings),
            llm_success=llm_success,
            llm_usage=llm_usage,
            warnings=warnings,
            scan_mode=scan_mode,
            total_files_scanned=int(stats.get("in_scope_files", 0) or 0),
            hotspots_found=hotspots_with_findings,
        )

    def _should_run_llm(self) -> bool:
        """Check if LLM analysis should run."""
        if not self.allow_llm:
            return False
        api_key = self.config.openai_api_key.get_secret_value()
        if not api_key:
            return False
        return True

    def _run_deterministic_scans(self, ingest: dict) -> List[dict]:
        """Run all deterministic scanners."""
        findings: List[dict] = []

        pattern_findings = self.pattern_scanner.scan_files(
            ingest.get("files", []),
            self.repo_root,
        )
        findings.extend(self._finding_to_dict(f) for f in pattern_findings)

        for file_info in ingest.get("files", []):
            if file_info.get("category") != "source":
                continue
            rel_path = file_info.get("path")
            if not rel_path:
                continue
            try:
                content = (self.repo_root / rel_path).read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except OSError:
                continue
            secret_findings = scan_for_secrets(content, rel_path)
            findings.extend(self._finding_to_dict(f) for f in secret_findings)

        config_findings = self.config_scanner.scan_files(
            ingest.get("files", []),
            self.repo_root,
        )
        findings.extend(self._finding_to_dict(f) for f in config_findings)

        return findings

    async def _run_llm_analysis(
        self,
        ingest: dict,
        deterministic_findings: List[dict],
        scan_mode: str,
        diff_content: Optional[str],
        changed_files: Optional[List[str]],
    ) -> LLMAnalysisResult:
        """Run LLM analysis with fallback handling."""
        context = self.context_builder.build_context(
            ingest=ingest,
            deterministic_findings=deterministic_findings,
            repo_root=self.repo_root,
            scan_mode=scan_mode,
            diff_content=diff_content,
            changed_files=changed_files,
        )

        system_prompt = self.prompt_loader.get_prompt(scan_mode=scan_mode)

        client = LLMClient(
            api_key=self.config.openai_api_key.get_secret_value(),
            primary_model=self.config.model,
            fallback_model=self.config.model_fallback,
        )

        response = await client.analyze(
            system_prompt=system_prompt,
            user_content=context.content,
            max_tokens=4096,
        )

        if not response.success:
            fallback_result = handle_llm_failure(
                llm_response=response,
                deterministic_findings=deterministic_findings,
                policy=self.config.llm_failure_policy,
            )
            warning = fallback_result.warning_message or (
                f"LLM analysis failed ({response.error})."
            )
            non_det_findings = [
                f for f in fallback_result.findings if f.source != "deterministic"
            ]
            return LLMAnalysisResult(
                findings=[self._parsed_finding_to_dict(f) for f in non_det_findings],
                success=False,
                usage=None,
                warning=warning,
            )

        parse_result = self.response_parser.parse(response.content)
        if parse_result.parse_errors:
            self.logger.warning(
                "llm_parse_errors",
                count=len(parse_result.parse_errors),
            )

        return LLMAnalysisResult(
            findings=[self._parsed_finding_to_dict(f) for f in parse_result.findings],
            success=True,
            usage={
                "model": response.usage.model,
                "tokens_in": response.usage.tokens_in,
                "tokens_out": response.usage.tokens_out,
                "cost_usd": response.usage.cost_usd,
                "latency_ms": response.usage.latency_ms,
            }
            if response.usage
            else None,
            warning=None,
        )

    def _merge_findings(self, deterministic: List[dict], llm: List[dict]) -> List[dict]:
        """Merge findings, dedupe by file+line+category."""
        seen = set()
        merged: List[dict] = []

        for finding in deterministic:
            key = (
                finding.get("file_path"),
                finding.get("line_start"),
                finding.get("category"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)

        for finding in llm:
            key = (
                finding.get("file_path"),
                finding.get("line_start"),
                finding.get("category"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)

        severity_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        merged.sort(
            key=lambda f: (
                severity_order.get(f.get("severity"), 4),
                f.get("file_path") or "",
            )
        )

        return merged

    def _count_by_severity(self, findings: List[dict]) -> dict:
        """Count findings by severity."""
        counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "total": len(findings)}
        for finding in findings:
            sev = finding.get("severity", "P3")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _identify_hotspots_with_findings(self, findings: List[dict], hotspots: dict) -> List[str]:
        """Return hotspot files that have findings."""
        if not hotspots:
            return []
        hotspot_files = set()
        for files in hotspots.values():
            if isinstance(files, list):
                hotspot_files.update(files)
        if not hotspot_files:
            return []
        finding_files = {
            finding.get("file_path")
            for finding in findings
            if finding.get("file_path")
        }
        return sorted(hotspot_files.intersection(finding_files))

    def _finding_to_dict(self, finding) -> dict:
        """Convert Finding dataclass to dict."""
        return {
            "id": finding.id,
            "severity": finding.severity,
            "category": finding.category,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "snippet": finding.snippet,
            "message": finding.message,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
            "source": finding.source,
        }

    def _parsed_finding_to_dict(self, finding: ParsedFinding) -> dict:
        """Convert ParsedFinding to dict."""
        return {
            "id": f"{finding.category}-{finding.file_path}-{finding.line_start}",
            "severity": finding.severity,
            "category": finding.category,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "snippet": "",
            "message": finding.message,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
            "source": finding.source,
        }
