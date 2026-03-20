# Omar Gate Action (GitHub App Bridge)

Sentinelayer is a reproducible PR governance layer for AI-generated and human-written changes.
This public Action is intentionally thin: it triggers and reads scan status from Sentinelayer's
GitHub App backend instead of embedding private scanner internals in this repository.

## What this Action does

- Detects repository + PR context from the GitHub event.
- Calls `POST /api/v1/github-app/trigger`.
- Optionally waits for completion via `GET /api/v1/github-app/runs/{run_id}/status`.
- Applies merge gate thresholds from returned severity counts (`P0/P1/P2/P3`).

## Positioning (fair and clear)

- **CodeQL / Semgrep / Snyk**: strong scanners that produce findings.
- **Sentinelayer**: governance layer that turns findings + PR context + evidence
  into a release decision workflow with reproducibility artifacts.

This Action is the CI bridge. Core adjudication logic runs in the backend GitHub App pipeline.

## Required setup

- Install the Sentinelayer GitHub App on the target repository/org.
- Provide `sentinelayer_token` (bearer token) to the workflow.

## Minimal usage

```yaml
name: Omar Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  omar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Omar Gate (Bridge)
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
          scan_mode: deep
          severity_gate: P1
```

## Inputs

- `sentinelayer_token` (required): bearer token for Sentinelayer API.
- `sentinelayer_api_url` (optional): defaults to `https://api.sentinelayer.com`.
- `scan_mode` (optional): `baseline`, `deep`, `full-depth`.
- `severity_gate` (optional): `P0`, `P1`, `P2`, `none`.
- `provider_installation_id` (optional): explicit installation id override.
- `command` (optional): explicit slash command override, example `/omar baseline`.
- `wait_for_completion` (optional): `true` by default.
- `wait_timeout_seconds` (optional): `900` by default.
- `wait_poll_seconds` (optional): `10` by default.
- `pr_number` (optional): manual PR number override.

## Outputs

- `gate_status`
- `p0_count`, `p1_count`, `p2_count`, `p3_count`
- `run_id`
- `scan_mode`
- `severity_gate`
