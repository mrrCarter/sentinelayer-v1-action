# Workflow Examples

This document provides practical GitHub Actions workflows for SentinelLayer.

## Basic PR Scanning

```yaml
name: SentinelLayer Security Review
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      issues: write
    steps:
      - uses: actions/checkout@v4

      - name: SentinelLayer Scan
        id: sentinelayer
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          severity_gate: P1
          scan_mode: pr-diff

      - name: Upload SentinelLayer Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sentinelayer-${{ steps.sentinelayer.outputs.run_id }}
          path: .sentinelayer/runs/${{ steps.sentinelayer.outputs.run_id }}
```

## Nightly Full Scan With Slack Notification

```yaml
name: SentinelLayer Nightly Audit
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

jobs:
  nightly:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
      issues: write
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: SentinelLayer Nightly Scan
        id: sentinelayer
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          scan_mode: nightly
          severity_gate: P2
          telemetry_tier: 1

      - name: Upload SentinelLayer Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sentinelayer-nightly-${{ steps.sentinelayer.outputs.run_id }}
          path: .sentinelayer/runs/${{ steps.sentinelayer.outputs.run_id }}

      - name: Slack Notify (failure only)
        if: failure()
        uses: slackapi/slack-github-action@v1.27.0
        with:
          payload: |
            {
              "text": "SentinelLayer nightly scan failed for ${{ github.repository }} (run_id=${{ steps.sentinelayer.outputs.run_id }}, gate_status=${{ steps.sentinelayer.outputs.gate_status }})."
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Monorepo Setup With Path Filters

Use `paths` to scan only relevant parts of a monorepo. Pair this with `.sentinelayerignore` for additional scope control.

```yaml
name: SentinelLayer (Monorepo)
on:
  pull_request:
    paths:
      - "services/api/**"
      - "services/web/**"
      - ".github/workflows/**"

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          scan_mode: pr-diff
```

## Custom Severity Gate Per Environment

Example policy:
- Main branch PRs: block on `P1`
- Non-main PRs: block on `P0` (report lower severities, but do not block)

```yaml
name: SentinelLayer (Env Gates)
on:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      issues: write
    steps:
      - uses: actions/checkout@v4

      - uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          severity_gate: ${{ github.base_ref == 'main' && 'P1' || 'P0' }}
          scan_mode: pr-diff
```

## Fork PR Policy For Open Source Projects

GitHub does not provide repository secrets to workflows triggered from fork PRs under `pull_request`. Since SentinelLayer currently requires `openai_api_key`, the safest default is to skip forks and require maintainer-triggered scans.

Option A (recommended): skip forks on `pull_request`

```yaml
name: SentinelLayer (Skip Forks)
on:
  pull_request:

jobs:
  security:
    if: ${{ github.event.pull_request.head.repo.fork == false }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          fork_policy: block
```

Option B (advanced): use `pull_request_target` to scan fork PRs

Security warning: `pull_request_target` runs with base-repo permissions and has access to secrets. Only use this pattern if you are confident no step executes untrusted code from the fork. SentinelLayer is designed to read and analyze files, not execute them, but you are responsible for your workflow hardening.

```yaml
name: SentinelLayer (Forks via pull_request_target)
on:
  pull_request_target:
    types: [opened, synchronize, reopened]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      issues: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          fork_policy: allow
          scan_mode: pr-diff
```

