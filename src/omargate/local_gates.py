"""Standalone runner for the Omar Gate local gates package.

Invoked as:
    python -m omargate.local_gates --path <repo> --output-dir <path> [--enable-X]

Writes findings to FINDINGS.jsonl inside the output directory and prints
a compact summary to stdout. Exit code:
    0 — no blocking findings
    1 — at least one P0 or P1 finding (configurable via --fail-severity)
    2 — runner error (argparse / IO / unexpected exception)

Kept deliberately simple so the composite action can invoke it as a
single-shot bash step without needing to plumb additional glue. Wiring
into the Action happens in action.yml; this file is the CLI surface.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from .gates import GateContext, run_gates
from .gates.findings import Finding, serialize_findings
from .path_safety import validate_repo_path
from .gates.persona_dispatch import (
    PersonaDispatchConfig,
    default_cli_path,
    dispatch_personas,
)
from .gates.security import SecurityScanGate
from .gates.static import StaticAnalysisGate
from .scaffold import parse_scaffold_ownership

# Kept as a module-level alias so existing test imports
# (from omargate.local_gates import _parse_scaffold_ownership) keep working.
_parse_scaffold_ownership = parse_scaffold_ownership


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omargate.local_gates",
        description="Run Omar Gate 2.0 local gates (static + security) and emit FINDINGS.jsonl.",
    )
    parser.add_argument("--path", default=".", help="Repository root to scan (default: cwd)")
    parser.add_argument("--output-dir", default=".omargate", help="Directory for FINDINGS.jsonl output (default: .omargate/)")
    parser.add_argument("--enable-static", dest="enable_static", action="store_true", default=True, help="Run StaticAnalysisGate (default: on)")
    parser.add_argument("--no-static", dest="enable_static", action="store_false", help="Skip StaticAnalysisGate")
    parser.add_argument("--enable-security", dest="enable_security", action="store_true", default=True, help="Run SecurityScanGate (default: on)")
    parser.add_argument("--no-security", dest="enable_security", action="store_false", help="Skip SecurityScanGate")
    parser.add_argument(
        "--fail-severity",
        choices=["P0", "P1", "P2", "P3", "never"],
        default="P1",
        help="Lowest severity that should cause a non-zero exit. Default: P1.",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Emit a single-line JSON summary to stdout instead of human text.",
    )
    parser.add_argument(
        "--enable-persona-dispatch",
        dest="enable_persona_dispatch",
        action="store_true",
        default=False,
        help=(
            "After base gates run, dispatch create-sentinelayer personas "
            "via the CLI for each baseline P0/P1 finding (requires "
            "create-sentinelayer on PATH and a .sentinelayer/scaffold.yaml "
            "ownership map). Persona findings are merged into FINDINGS.jsonl "
            "with gate_id=persona_dispatch. No-op when preconditions miss."
        ),
    )
    parser.add_argument(
        "--persona-cli-path",
        dest="persona_cli_path",
        default="",
        help=(
            "Optional explicit path to the create-sentinelayer binary used "
            "by --enable-persona-dispatch. Defaults to whichever "
            "create-sentinelayer / sentinelayer-cli is on PATH."
        ),
    )
    parser.add_argument(
        "--persona-dispatch-dry-run",
        dest="persona_dispatch_dry_run",
        action="store_true",
        default=False,
        help=(
            "Run persona dispatch in planning mode — resolve buckets but do "
            "not spawn the CLI. Useful for CI smoke tests."
        ),
    )
    return parser


def _severity_blocks(sev: str, threshold: str) -> bool:
    """Return True if a finding at `sev` should block when threshold=`threshold`."""
    if threshold == "never":
        return False
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    return order.get(sev, 99) <= order.get(threshold, -1)


def _count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _write_findings_jsonl(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in serialize_findings(findings):
            f.write(json.dumps(row, separators=(",", ":")))
            f.write("\n")


def _maybe_dispatch_personas(
    *,
    baseline_findings: list[Finding],
    repo_root: Path,
    enable: bool,
    cli_override: str,
    dry_run: bool,
) -> dict | None:
    if not enable:
        return None

    scaffold_path = repo_root / ".sentinelayer" / "scaffold.yaml"
    ownership_map = _parse_scaffold_ownership(scaffold_path)
    if not ownership_map:
        return {
            "status": "skipped",
            "reason": f"no ownership map at {scaffold_path}",
            "persona_findings": [],
        }

    cli_path = default_cli_path(cli_override or None)
    # If the binary isn't resolvable and we're not in dry-run, skip gracefully.
    if not dry_run:
        import shutil

        if not shutil.which(str(cli_path)):
            return {
                "status": "skipped",
                "reason": f"persona CLI not resolvable on PATH: {cli_path}",
                "persona_findings": [],
            }

    config = PersonaDispatchConfig(
        cli_path=cli_path,
        repo_root=repo_root,
        scaffold_path=scaffold_path,
        dry_run=dry_run,
    )
    result = dispatch_personas(baseline_findings, ownership_map, config)
    return {
        "status": "completed" if not dry_run else "dry_run",
        "reason": None,
        "persona_findings": result.persona_findings,
        "personas_invoked": result.personas_invoked,
        "personas_failed": result.personas_failed,
        "unrouted_files": result.unrouted_files,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:
        # argparse calls sys.exit on --help / bad input. Preserve that code.
        return int(exc.code or 2)

    # Validate --path through the hardening module: rejects null bytes, control
    # chars, BiDi overrides, double-encoded percent, UNC, tilde/$/%/= prefixes,
    # and Windows drive roots BEFORE the path becomes a Path() that scanners walk.
    repo_root = validate_repo_path(args.path)
    if repo_root is None:
        print(
            f"error: --path failed safety validation or is not a directory: {args.path!r}",
            file=sys.stderr,
        )
        return 2

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = (Path.cwd() / output_dir).resolve()

    gates = []
    if args.enable_static:
        gates.append(StaticAnalysisGate())
    if args.enable_security:
        gates.append(SecurityScanGate())

    if not gates:
        print("error: no gates enabled (pass --enable-static and/or --enable-security)", file=sys.stderr)
        return 2

    ctx = GateContext(repo_root=repo_root, changed_files=())
    results = run_gates(gates, ctx)

    all_findings = [f for result in results for f in result.findings]

    dispatch_summary = _maybe_dispatch_personas(
        baseline_findings=all_findings,
        repo_root=repo_root,
        enable=args.enable_persona_dispatch,
        cli_override=args.persona_cli_path,
        dry_run=args.persona_dispatch_dry_run,
    )
    if dispatch_summary is not None and dispatch_summary.get("persona_findings"):
        all_findings.extend(dispatch_summary["persona_findings"])

    findings_path = output_dir / "FINDINGS.jsonl"
    try:
        _write_findings_jsonl(all_findings, findings_path)
    except OSError as exc:
        print(f"error: failed to write FINDINGS.jsonl: {exc}", file=sys.stderr)
        return 2

    counts = _count_by_severity(all_findings)
    summary = {
        "findings_path": str(findings_path),
        "counts": counts,
        "gates": [
            {
                "gate_id": r.gate_id,
                "status": r.status,
                "finding_count": len(r.findings),
                "duration_ms": r.duration_ms,
                "error_message": r.error_message,
            }
            for r in results
        ],
    }
    if dispatch_summary is not None:
        summary["persona_dispatch"] = {
            "status": dispatch_summary["status"],
            "reason": dispatch_summary.get("reason"),
            "personas_invoked": dispatch_summary.get("personas_invoked", []),
            "personas_failed": dispatch_summary.get("personas_failed", []),
            "unrouted_files": dispatch_summary.get("unrouted_files", []),
            "persona_findings_count": len(
                dispatch_summary.get("persona_findings", [])
            ),
        }

    # 3-state DSL: findings tagged decision="ask" are annotated but never block.
    # decision="allow" or None falls through to severity-based blocking.
    blocking = any(
        f.decision != "ask" and _severity_blocks(f.severity, args.fail_severity)
        for f in all_findings
    )
    ask_count = sum(1 for f in all_findings if f.decision == "ask")
    summary["blocking"] = blocking
    summary["fail_severity"] = args.fail_severity
    summary["ask_count"] = ask_count

    if args.json_summary:
        print(json.dumps(summary, separators=(",", ":")))
    else:
        print(f"Omar Gate local — wrote {len(all_findings)} findings to {findings_path}")
        print(f"  P0={counts['P0']}  P1={counts['P1']}  P2={counts['P2']}  P3={counts['P3']}")
        for g in summary["gates"]:
            print(f"  gate {g['gate_id']:<10} status={g['status']:<7} findings={g['finding_count']:<4} duration_ms={g['duration_ms']}")
        if blocking:
            print(f"BLOCKED: at least one finding at or above {args.fail_severity}")

    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
