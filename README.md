# Omar Gate Action (Compatibility Bridge)

This Action is now a thin compatibility layer. It no longer runs proprietary ingest, deterministic scanners, or prompt orchestration in-repo.

All scan execution runs in Sentinelayer GitHub App backend.

## What changed

- Local scan internals were removed from this public Action.
- The Action now:
  - detects repo + PR context from the GitHub event,
  - calls `POST /api/v1/github-app/trigger`,
  - optionally waits for run completion via `GET /api/v1/github-app/runs/{run_id}/status`,
  - applies gate threshold from returned severity counts.

## Required setup

- Install the Sentinelayer GitHub App on the target repository.
- Provide a Sentinelayer bearer token to the workflow (`sentinelayer_token` input).

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

- `sentinelayer_token` (required): Bearer token for Sentinelayer API.
- `sentinelayer_api_url` (optional): defaults to `https://api.sentinelayer.com`.
- `scan_mode` (optional): `baseline`, `deep`, `full-depth` (mapped to slash commands).
- `severity_gate` (optional): `P0`, `P1`, `P2`, `none`.
- `provider_installation_id` (optional): explicit installation id override.
- `command` (optional): explicit slash command override (example `/omar baseline`).
- `wait_for_completion` (optional): `true` by default.
- `wait_timeout_seconds` (optional): `900` by default.
- `wait_poll_seconds` (optional): `10` by default.
- `pr_number` (optional): manual PR number override.

## Outputs

- `gate_status`, `p0_count`, `p1_count`, `p2_count`, `p3_count`, `run_id`
- `scan_mode`, `severity_gate`
