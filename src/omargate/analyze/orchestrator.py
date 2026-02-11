from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..artifacts import generate_review_brief
from ..config import OmarGateConfig
from ..ingest import QuickLearnSummary, extract_quick_learn_summary, run_ingest
from ..harness import HarnessRunner
from ..logging import OmarLogger
from ..package.fingerprint import add_fingerprints_to_findings
from .codex import CodexPromptBuilder, CodexRunner
from .deterministic import ConfigScanner, EngQualityScanner, PatternScanner, scan_for_secrets
from .llm import ContextBuilder, LLMClient, PromptLoader, ResponseParser, handle_llm_failure
from .llm.providers import detect_provider_from_model
from .llm.response_parser import ParsedFinding


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    findings: List[dict]
    ingest: dict
    counts: dict
    ingest_stats: dict
    deterministic_count: int
    llm_count: int
    llm_success: bool
    llm_usage: Optional[dict]
    warnings: List[str]
    review_brief_path: Optional[Path]
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
        self._quick_learn: Optional[QuickLearnSummary] = None

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
        run_dir: Optional[Path] = None,
        run_id: Optional[str] = None,
        version: Optional[str] = None,
        dashboard_url: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Run complete analysis pipeline.

        Steps:
        1. Ingest codebase
        2. Run harness suites (optional)
        3. Run deterministic scans
        4. Build LLM context
        5. Run LLM analysis (with fallback)
        6. Merge and dedupe findings
        7. Return results
        """
        warnings: List[str] = []

        # Step 0: Quick Learn
        quick_learn: Optional[QuickLearnSummary] = None
        with self.logger.stage("quick_learn"):
            quick_learn = await asyncio.to_thread(extract_quick_learn_summary, self.repo_root)
            self.logger.info(
                "Quick learn complete",
                source_doc=quick_learn.source_doc,
                tech_stack=quick_learn.tech_stack,
                architecture=quick_learn.architecture,
            )
        self._quick_learn = quick_learn

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

        # Step 2: Harness (portable suites)
        harness_findings: List[dict] = []
        if self.config.run_harness:
            with self.logger.stage("harness"):
                try:
                    runner = HarnessRunner(
                        project_root=str(self.repo_root),
                        tech_stack=quick_learn.tech_stack if quick_learn else [],
                    )
                    harness_results = await runner.run()
                    harness_findings = [self._finding_to_dict(f) for f in harness_results]
                    self.logger.info(
                        "Harness complete",
                        findings_count=len(harness_findings),
                    )
                except Exception as exc:
                    self.logger.warning("Harness failed", error=str(exc))
                    warnings.append("Harness failed")
        else:
            warnings.append("Harness skipped (run_harness=false)")

        # Step 3: Deterministic scans
        with self.logger.stage("deterministic_scan"):
            det_findings = self._run_deterministic_scans(ingest)
            self.logger.info(
                "Deterministic scan complete",
                findings_count=len(det_findings),
            )

        # Step 4-5: Codex audit (optional) and/or LLM analysis
        llm_findings: List[dict] = []
        llm_success = False
        llm_usage: Optional[dict] = None

        ran_codex = False
        if self.allow_llm and self.config.use_codex:
            ran_codex = True
            with self.logger.stage("codex_audit"):
                codex_result = await self._run_codex_audit(
                    ingest=ingest,
                    deterministic_findings=det_findings,
                    quick_learn=quick_learn,
                    scan_mode=scan_mode,
                    diff_content=diff_content,
                )
                llm_findings = codex_result.findings
                llm_success = codex_result.success
                llm_usage = codex_result.usage
                if codex_result.warning:
                    warnings.append(codex_result.warning)
                self.logger.info(
                    "Codex audit complete",
                    success=llm_success,
                    findings_count=len(llm_findings),
                )

        if (not ran_codex or not llm_success) and self._should_run_llm():
            with self.logger.stage("llm_analysis"):
                llm_result = await self._run_llm_analysis(
                    ingest=ingest,
                    deterministic_findings=det_findings,
                    quick_learn=quick_learn,
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
        elif not ran_codex:
            warnings.append("LLM analysis skipped (no API key or limited mode)")

        # Step 6: Merge findings
        base_findings = harness_findings + det_findings
        all_findings = self._merge_findings(base_findings, llm_findings)
        add_fingerprints_to_findings(
            all_findings,
            policy_version=self.config.policy_pack_version,
            tenant_salt="",
        )
        counts = self._count_by_severity(all_findings)

        review_brief_path: Optional[Path] = None
        if run_dir and run_id:
            try:
                review_brief_path = generate_review_brief(
                    run_dir=run_dir,
                    run_id=run_id,
                    findings=all_findings,
                    ingest=ingest,
                    scan_mode=scan_mode,
                    version=version or "unknown",
                    dashboard_url=dashboard_url,
                )
            except Exception as exc:
                self.logger.warning("Review brief generation failed", error=str(exc))
                warnings.append("Review brief generation failed")

        hotspots_with_findings = self._identify_hotspots_with_findings(
            all_findings, ingest.get("hotspots", {})
        )

        stats = ingest.get("stats", {})

        return AnalysisResult(
            findings=all_findings,
            ingest=ingest,
            counts=counts,
            ingest_stats=stats,
            deterministic_count=len(det_findings),
            llm_count=len(llm_findings),
            llm_success=llm_success,
            llm_usage=llm_usage,
            warnings=warnings,
            review_brief_path=review_brief_path,
            scan_mode=scan_mode,
            total_files_scanned=int(stats.get("in_scope_files", 0) or 0),
            hotspots_found=hotspots_with_findings,
        )

    def _should_run_llm(self) -> bool:
        """Check if LLM analysis should run."""
        if not self.allow_llm:
            return False
        primary_provider = detect_provider_from_model(
            self.config.model, default_provider=self.config.llm_provider
        )
        api_key = self._get_provider_api_key(primary_provider)
        return bool(api_key)

    def _get_provider_api_key(self, provider: str) -> str:
        if provider == "openai":
            return self.config.openai_api_key.get_secret_value()
        if provider == "anthropic":
            return self.config.anthropic_api_key.get_secret_value()
        if provider == "google":
            return self.config.google_api_key.get_secret_value()
        if provider == "xai":
            return self.config.xai_api_key.get_secret_value()
        return ""

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

        # Stack-aware engineering quality checks (inline rules).
        tech_stack = self._quick_learn.tech_stack if self._quick_learn else []
        eng_files = self._load_files_for_quality_scans(ingest)
        eng_scanner = EngQualityScanner(tech_stack=tech_stack)
        eng_findings = eng_scanner.scan(eng_files)
        findings.extend(self._finding_to_dict(f) for f in eng_findings)

        return findings

    def _load_files_for_quality_scans(self, ingest: dict) -> dict[str, str]:
        """
        Load a bounded set of file contents for stack-aware quality scanning.

        Uses ingest's in-scope file list; avoids reading huge files.
        """
        files: dict[str, str] = {}
        for file_info in ingest.get("files", []) or []:
            rel_path = file_info.get("path")
            if not rel_path:
                continue
            size_bytes = file_info.get("size_bytes")
            if isinstance(size_bytes, int) and size_bytes > 1_000_000:
                continue
            try:
                content = (self.repo_root / rel_path).read_text(
                    encoding="utf-8", errors="ignore"
                )
            except OSError:
                continue
            files[rel_path] = content
        # Ensure key infra files are included if present.
        for rel_path in ("Dockerfile", ".env"):
            if rel_path in files:
                continue
            try:
                p = self.repo_root / rel_path
                if p.is_file():
                    files[rel_path] = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass
        return files

    async def _run_llm_analysis(
        self,
        ingest: dict,
        deterministic_findings: List[dict],
        quick_learn: Optional[QuickLearnSummary],
        scan_mode: str,
        diff_content: Optional[str],
        changed_files: Optional[List[str]],
    ) -> LLMAnalysisResult:
        """Run LLM analysis with fallback handling."""
        context = self.context_builder.build_context(
            ingest=ingest,
            deterministic_findings=deterministic_findings,
            repo_root=self.repo_root,
            quick_learn=quick_learn,
            scan_mode=scan_mode,
            diff_content=diff_content,
            changed_files=changed_files,
        )

        system_prompt = self.prompt_loader.get_prompt(scan_mode=scan_mode)

        client = LLMClient(
            api_key=self.config.openai_api_key.get_secret_value(),
            primary_model=self.config.model,
            fallback_model=self.config.model_fallback,
            llm_provider=self.config.llm_provider,
            anthropic_api_key=self.config.anthropic_api_key.get_secret_value(),
            google_api_key=self.config.google_api_key.get_secret_value(),
            xai_api_key=self.config.xai_api_key.get_secret_value(),
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
                "provider": getattr(response.usage, "provider", None),
                "tokens_in": response.usage.tokens_in,
                "tokens_out": response.usage.tokens_out,
                "cost_usd": response.usage.cost_usd,
                "latency_ms": response.usage.latency_ms,
            }
            if response.usage
            else None,
            warning=None,
        )

    async def _run_codex_audit(
        self,
        *,
        ingest: dict,
        deterministic_findings: List[dict],
        quick_learn: Optional[QuickLearnSummary],
        scan_mode: str,
        diff_content: Optional[str],
    ) -> LLMAnalysisResult:
        """
        Run Codex CLI agentic audit and parse JSONL findings.

        Returns: LLMAnalysisResult (findings, success, usage, warning_message)
        """
        api_key = self.config.openai_api_key.get_secret_value()
        if not api_key:
            return LLMAnalysisResult(
                findings=[],
                success=False,
                usage=None,
                warning="Codex skipped (missing openai_api_key)",
            )

        tech_stack = quick_learn.tech_stack if quick_learn else []
        hotspots = self._flatten_hotspots(ingest.get("hotspots", {}) or {})

        builder = CodexPromptBuilder(max_tokens=self.config.max_input_tokens)
        built = builder.build_prompt(
            repo_root=self.repo_root,
            quick_learn=quick_learn,
            deterministic_findings=deterministic_findings,
            tech_stack=tech_stack,
            scan_mode=scan_mode,
            diff_content=diff_content,
            hotspot_files=hotspots,
            ingest=ingest,
        )

        runner = CodexRunner(api_key=api_key, model=self.config.codex_model)
        result = await runner.run_audit(
            prompt=built.prompt,
            working_dir=str(self.repo_root),
            sandbox="read-only",
            timeout=int(self.config.codex_timeout),
        )
        if not result.success:
            warn = result.error or "Codex audit failed"
            return LLMAnalysisResult(
                findings=[],
                success=False,
                usage=None,
                warning=f"Codex audit failed ({warn}). Falling back to LLM analysis.",
            )

        # Codex CLI currently doesn't provide token/cost accounting. Keep cost unknown.
        return LLMAnalysisResult(
            findings=result.findings,
            success=True,
            usage={
                "engine": "codex",
                "provider": "openai",
                "model": self.config.codex_model,
                "tokens_in": None,
                "tokens_out": None,
                "cost_usd": None,
                "latency_ms": int(result.duration_ms),
            },
            warning=None,
        )

    def _flatten_hotspots(self, hotspots: dict) -> List[str]:
        files: List[str] = []
        seen = set()
        for group in hotspots.values():
            if not isinstance(group, list):
                continue
            for rel_path in group:
                if not rel_path or rel_path in seen:
                    continue
                seen.add(rel_path)
                files.append(rel_path)
        return files

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
