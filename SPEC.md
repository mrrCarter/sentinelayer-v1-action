# Sentinelayer Omar Gate Action Spec

## Purpose

`sentinelayer-v1-action` is the GitHub Action wrapper for Omar Gate. It runs
action-local deterministic gates, delegates managed review orchestration to the
Sentinelayer backend, returns merge-blocking outputs, posts a PR-visible review
comment, and writes downloadable evidence artifacts.

## Required Behavior

- Primary implementation lives in `src/omargate/main.py`. Bridge behavior is
  covered by `tests/test_main_bridge.py`; action metadata and upload visibility
  are covered by `tests/test_action_yml_visibility.py`.
- The action must fail closed when Sentinelayer orchestration fails or when
  findings at or above the configured `severity_gate` are present.
- The compatibility bridge must preserve the historical PR visibility surface:
  an idempotent PR comment containing `sentinelayer:omar-gate:` and enough
  finding context for downstream scoped-count scripts.
- The bridge must write persistent evidence under `.sentinelayer/runs/**` and
  `.sentinelayer/artifacts/**` so the composite upload step has real files.
- The action must keep `gate_status`, severity counts, run id, scan mode, model,
  and optional Playwright/SBOM status outputs stable for callers.
- GitHub API writes must use the caller-provided `github_token`; Sentinelayer API
  requests must use `sentinelayer_token`.

## Security Constraints

- Do not include tokens, raw secrets, or provider credentials in comments,
  summaries, or artifacts.
- PR-comment updates must be idempotent and scoped to the current PR.
- Fork PRs must not receive repository secrets through the dogfooding workflow.
- Local findings are advisory unless their configured severity threshold blocks;
  backend severity counts remain the bridge output contract.

## Validation

- `PYTHONPATH=src python -m pytest -q`
- `python -m ruff check src tests`
- `python -m compileall -q src`
- `sentinelayer-cli review --path . --staged --json`
