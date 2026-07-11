# Sentinelayer Omar Gate Action Spec

## Purpose

`sentinelayer-v1-action` is the GitHub Action wrapper for Omar Gate. It runs
action-local deterministic gates, delegates managed review orchestration to the
Sentinelayer backend, returns merge-blocking outputs, posts a PR-visible review
comment, and writes downloadable evidence artifacts.

## Required Behavior

- Primary implementation lives in `src/omargate/main.py`. Action behavior is
  covered by `tests/test_main_bridge.py`; action metadata and upload visibility
  are covered by `tests/test_action_yml_visibility.py`.
- The action must fail closed when Sentinelayer orchestration fails or when
  findings at or above the configured `severity_gate` are present.
- The action must preserve the historical PR visibility surface: an idempotent
  Omar Gate PR comment containing `sentinelayer:omar-gate:`, the original
  severity table, codebase synopsis, and backend top findings.
- When the backend trigger response includes `run_result_token`, the action must
  use that run-bound token for subsequent status and findings reads. It may fall
  back to `status_poll_token` only for older backends that do not return a
  per-run token.
- The action must write persistent evidence under `.sentinelayer/runs/**` and
  `.sentinelayer/artifacts/**` so the composite upload step has real files.
- The action must keep `gate_status`, severity counts, run id, scan mode, model,
  and optional Playwright/SBOM status outputs stable for callers.
- GitHub API writes must use the caller-provided `github_token`; Sentinelayer API
  requests must use `sentinelayer_token`.
- The optional `/omar fix <finding_id>` handoff workflow must verify the
  commenter has write, maintain, or admin permission before checking out PR
  code, download the current run-scoped `omar-gate-findings-*` artifact, and
  distinguish declined/no-op fix requests from runner errors so the PR still
  receives a decision acknowledgement.

## Security Constraints

- Do not include tokens, raw secrets, or provider credentials in comments,
  summaries, or artifacts.
- PR-comment updates must be idempotent and scoped to the current PR.
- PR-comment permission or GitHub API failures must be fail-soft warnings:
  they must not convert a passing Sentinelayer scan into a failed Omar Gate.
- Fork PRs must not receive repository secrets through the dogfooding workflow.
- Local findings are advisory unless their configured severity threshold blocks;
  backend severity counts remain the bridge output contract.
- The `/omar fix <finding_id>` handoff must be opt-in and deny-by-default for
  unauthorized commenters. It must not trust author association as a substitute
  for repository permission.

## Validation

- `PYTHONPATH=src python -m pytest -q`
- `python -m ruff check src tests`
- `python -m compileall -q src`
- `sentinelayer-cli review --path . --staged --json`
