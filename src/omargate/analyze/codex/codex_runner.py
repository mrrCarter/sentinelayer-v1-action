from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Optional


_VALID_SEVERITIES = {"P0", "P1", "P2", "P3"}
_REQUIRED_FIELDS = {"severity", "category", "file_path", "line_start", "message"}


@dataclass(frozen=True)
class CodexResult:
    findings: list[dict]
    raw_output: str
    success: bool
    duration_ms: int
    error: Optional[str] = None
    parse_errors: Optional[list[str]] = None


def _strip_code_fence(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"```(?:json|jsonl)?\s*\r?\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def _validate_obj(obj: dict[str, Any]) -> bool:
    if not all(k in obj for k in _REQUIRED_FIELDS):
        return False
    if obj.get("severity") not in _VALID_SEVERITIES:
        return False
    if not isinstance(obj.get("line_start"), int):
        return False
    return True


def _normalize_obj(obj: dict[str, Any]) -> dict[str, Any]:
    file_path = str(obj.get("file_path") or "").replace("\\", "/")
    line_start = int(obj.get("line_start") or 1)
    line_end = obj.get("line_end")
    if not isinstance(line_end, int):
        line_end = line_start
    category = str(obj.get("category") or "unknown")
    message = str(obj.get("message") or "").strip()
    recommendation = str(obj.get("recommendation") or "")
    confidence_raw = obj.get("confidence", 0.8)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.8
    return {
        "id": f"{category}-{file_path}-{line_start}",
        "severity": obj.get("severity"),
        "category": category,
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "snippet": "",
        "message": message,
        "recommendation": recommendation,
        "confidence": confidence,
        "source": "codex",
    }


def parse_codex_findings(text: str) -> tuple[list[dict], list[str], bool]:
    """
    Parse Codex final output as JSON, JSON array, or JSONL.

    Returns: (findings, parse_errors, no_findings_reported)
    """
    raw = _strip_code_fence(text or "")
    if not raw:
        return [], ["Empty response"], False

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None

    findings: list[dict] = []
    errors: list[str] = []
    no_findings = False

    if isinstance(parsed, dict):
        if parsed.get("no_findings") is True:
            return [], [], True
        if _validate_obj(parsed):
            findings.append(_normalize_obj(parsed))
        else:
            errors.append("Object: Missing required fields or invalid values")
        return findings, errors, no_findings

    if isinstance(parsed, list):
        for idx, item in enumerate(parsed):
            if not isinstance(item, dict):
                errors.append(f"Item {idx + 1}: Not an object")
                continue
            if item.get("no_findings") is True:
                no_findings = True
                continue
            if _validate_obj(item):
                findings.append(_normalize_obj(item))
            else:
                errors.append(f"Item {idx + 1}: Missing required fields or invalid values")
        return findings, errors, no_findings

    for i, line in enumerate(raw.splitlines()):
        ln = line.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError as exc:
            errors.append(f"Line {i + 1}: Invalid JSON - {exc}")
            continue
        if isinstance(obj, dict) and obj.get("no_findings") is True:
            no_findings = True
            continue
        if not isinstance(obj, dict) or not _validate_obj(obj):
            errors.append(f"Line {i + 1}: Missing required fields or invalid values")
            continue
        findings.append(_normalize_obj(obj))

    if re.search(r'"no_findings"\s*:\s*true', raw, re.IGNORECASE):
        no_findings = True

    return findings, errors, no_findings


class CodexRunner:
    def __init__(self, api_key: str, model: str = "gpt-5.2-codex") -> None:
        self.api_key = api_key
        self.model = model

    def _resolve_codex_bin(self, working_dir: Path) -> Optional[str]:
        path = shutil.which("codex")
        if path:
            return path

        # Allow local installs in the repo (e.g. npm i -D @openai/codex).
        candidates = [
            working_dir / "node_modules" / ".bin" / "codex",
            working_dir / "node_modules" / ".bin" / "codex.cmd",
            working_dir / "node_modules" / ".bin" / "codex.ps1",
        ]
        for cand in candidates:
            if cand.exists():
                return str(cand)
        return None

    async def run_audit(
        self,
        prompt: str,
        working_dir: str,
        sandbox: str = "read-only",
        timeout: int = 300,
    ) -> CodexResult:
        """
        Execute `codex exec` with the given prompt.

        Returns parsed findings from Codex output.
        """
        start = time.monotonic()
        wd = Path(working_dir).resolve()

        codex_bin = self._resolve_codex_bin(wd)
        if not codex_bin:
            return CodexResult(
                findings=[],
                raw_output="",
                success=False,
                duration_ms=int((time.monotonic() - start) * 1000),
                error="Codex CLI not found in PATH",
                parse_errors=None,
            )

        fd, last_msg_path_str = tempfile.mkstemp(prefix="codex_last_", suffix=".txt")
        os.close(fd)
        last_msg_path = Path(last_msg_path_str)

        cmd = [
            codex_bin,
            "exec",
            "--sandbox",
            sandbox,
            "--model",
            self.model,
            "--cd",
            str(wd),
            "--output-last-message",
            str(last_msg_path),
            "-",
        ]

        env = os.environ.copy()
        env["OPENAI_API_KEY"] = self.api_key
        env["CODEX_API_KEY"] = self.api_key
        env["CODEX_MODEL"] = self.model

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            return CodexResult(
                findings=[],
                raw_output="",
                success=False,
                duration_ms=int((time.monotonic() - start) * 1000),
                error="Codex CLI not found",
                parse_errors=None,
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=(prompt or "").encode("utf-8")),
                timeout=float(timeout),
            )
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            stdout_b, stderr_b = await proc.communicate()
            raw_output = (
                (stdout_b or b"").decode("utf-8", errors="ignore")
                + "\n"
                + (stderr_b or b"").decode("utf-8", errors="ignore")
            ).strip()
            return CodexResult(
                findings=[],
                raw_output=raw_output,
                success=False,
                duration_ms=int((time.monotonic() - start) * 1000),
                error=f"Codex timed out after {timeout}s",
                parse_errors=None,
            )
        finally:
            # Best-effort cleanup; keep file around if read fails for debugging.
            pass

        raw_output = (
            (stdout_b or b"").decode("utf-8", errors="ignore")
            + "\n"
            + (stderr_b or b"").decode("utf-8", errors="ignore")
        ).strip()

        duration_ms = int((time.monotonic() - start) * 1000)

        if int(proc.returncode or 0) != 0:
            return CodexResult(
                findings=[],
                raw_output=raw_output,
                success=False,
                duration_ms=duration_ms,
                error=f"Codex exited with code {proc.returncode}",
                parse_errors=None,
            )

        last_message = ""
        try:
            last_message = last_msg_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            last_message = ""
        try:
            last_msg_path.unlink(missing_ok=True)
        except OSError:
            pass

        findings, parse_errors, no_findings = parse_codex_findings(last_message)
        if findings or no_findings:
            return CodexResult(
                findings=findings,
                raw_output=raw_output,
                success=True,
                duration_ms=duration_ms,
                error=None,
                parse_errors=parse_errors or [],
            )

        return CodexResult(
            findings=[],
            raw_output=raw_output,
            success=False,
            duration_ms=duration_ms,
            error="Codex output was not parseable as findings JSONL",
            parse_errors=parse_errors or [],
        )
