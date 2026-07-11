# Sentinelayer Full Omar Gate Action Spec

## Purpose

`sentinelayer-v1-action` is the self-contained Omar Gate GitHub Action. It runs
deterministic analysis, optional Codex/LLM review, packaging, PR comments, check
runs, telemetry, and evidence artifacts from the checked-out repository.

## Required Behavior

- The action entrypoint is `python -m omargate.main` through `action.yml`.
- Pull requests must produce a merge-consumable gate status, severity counts,
  run id, scan mode, model metadata, and artifact paths.
- Findings at or above `severity_gate` must block the action unless the caller
  explicitly selects a supported nonblocking policy.
- `llm_failure_policy=block` must fail closed with a synthetic system finding
  when Codex/API/managed analysis cannot complete.
- BYO provider failures may fall back across configured providers and managed
  capacity only according to `src/omargate/analyze/llm/llm_client.py`.
- Fork PRs must not receive repository secrets; workflow fallback coverage must
  remain deterministic and read-only.
- PR comments and reports must remain stable and idempotent for downstream
  automation.
- `.github/workflows/security-review.yml` is the canonical pull-request gate
  for tests, provenance, and Omar Review. `.github/workflows/omar-gate.yml`
  is a manual fail-closed deep-scan entrypoint and must not duplicate PR
  gating.

## Security Constraints

- Never expose raw provider credentials, API-key-like material, project numbers,
  provider consumer IDs, bearer tokens, or authorization headers in comments,
  step summaries, telemetry, logs, `FINDINGS.jsonl`, `REVIEW_BRIEF.md`, or
  `AUDIT_REPORT.md`.
- Public provider failures must preserve actionable class/status context
  (`429`, `insufficient_quota`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`) while
  redacting tenant/provider identifiers.
- GitHub writes must use the provided `github_token`; Sentinelayer calls must
  use `sentinelayer_token` or OIDC as configured.
- Any exception-to-warning path must sanitize before rendering.

## Implementation Surface

- `src/omargate/main.py`
- `src/omargate/analyze/orchestrator.py`
- `src/omargate/analyze/llm/llm_client.py`
- `src/omargate/analyze/llm/fallback_handler.py`
- `src/omargate/comment.py`
- `src/omargate/artifacts/*.py`
- `src/omargate/redaction.py`
- `.github/workflows/security-review.yml`
- `.github/workflows/omar-gate.yml`

## Validation

- `ruff check src tests`
- `python -m pytest -q`
- `python -m compileall -q src`
- `sentinelayer-cli review scan --path . --mode diff --json`
- `sentinelayer-cli /omargate deep --path . --json`
