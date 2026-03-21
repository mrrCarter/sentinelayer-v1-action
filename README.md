# Omar Gate

**AI-powered security gate for pull requests, with 7-layer analysis and policy-based merge control.**

[![Action Version](https://img.shields.io/badge/action-v1-blue)](https://github.com/mrrCarter/sentinelayer-v1-action)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Omar Gate reviews pull requests and enforces severity gates before merge. It combines deterministic checks and deeper multi-agent review through Sentinelayer's managed GitHub App execution layer, while keeping this public action surface minimal and stable.

## Why this action is thin

This repository intentionally exposes a compatibility bridge only. The bridge handles PR context, run orchestration, and gate outputs; Sentinelayer-managed services handle deeper adjudication and evidence assembly.

This keeps public action setup simple and avoids exposing proprietary scanner internals.

## Quick start (2-3 minutes)

### 1) Install Sentinelayer GitHub App

Install the Sentinelayer GitHub App on your repository or organization.

### 2) Add workflow secret

Add `SENTINELAYER_TOKEN` in:

`Settings` -> `Secrets and variables` -> `Actions`

### 3) Add workflow

Create `.github/workflows/omar-gate.yml`:

```yaml
name: Omar Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  omar:
    name: Omar Gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Omar Gate
        id: omar
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
          scan_mode: deep
          severity_gate: P1

      - name: Print gate result
        if: always()
        run: |
          echo "gate=${{ steps.omar.outputs.gate_status }}"
          echo "p0=${{ steps.omar.outputs.p0_count }} p1=${{ steps.omar.outputs.p1_count }} p2=${{ steps.omar.outputs.p2_count }} p3=${{ steps.omar.outputs.p3_count }}"
```

### 4) Enforce branch protection

Require the `Omar Gate` check on your protected branch so blocked runs prevent merge.

## 7-layer security model (public overview)

Omar Gate follows a layered review model so one weak signal cannot dominate merge policy:

| Layer | Purpose |
|-------|---------|
| 1 | Repository and pull request context normalization |
| 2 | Deterministic secret and unsafe pattern checks |
| 3 | Configuration and workflow hardening checks |
| 4 | Dependency and supply-chain risk signals |
| 5 | Multi-agent deep review on high-risk code paths |
| 6 | Cross-signal corroboration and consistency checks |
| 7 | Severity-gated release decision and evidence output |

## Scan modes

| Mode | Use case |
|------|----------|
| `baseline` | Fast baseline checks and policy smoke validation |
| `deep` | Default pull request enforcement mode |
| `full-depth` | Maximum review depth for high-risk changes |

## Severity gates

| Gate | Behavior |
|------|----------|
| `P0` | Block only critical findings |
| `P1` | Block critical and high findings (recommended default) |
| `P2` | Block critical, high, and medium findings |
| `none` | Report-only mode; does not block by severity |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `sentinelayer_token` | Yes | - | Sentinelayer service token used for run orchestration. |
| `status_poll_token` | No | falls back to `sentinelayer_token` | Optional separate token for status polling. |
| `sentinelayer_api_url` | No | `https://api.sentinelayer.com` | Sentinelayer API base URL. |
| `scan_mode` | No | `deep` | `baseline`, `deep`, or `full-depth`. |
| `severity_gate` | No | `P1` | `P0`, `P1`, `P2`, or `none`. |
| `provider_installation_id` | No | empty | Optional GitHub App installation override. |
| `command` | No | empty | Optional explicit slash-command override (for advanced control). |
| `wait_for_completion` | No | `true` | Wait for run completion before step exits. |
| `wait_timeout_seconds` | No | `900` | Maximum wait time in seconds. |
| `wait_poll_seconds` | No | `10` | Poll interval while waiting for completion. |
| `pr_number` | No | empty | Manual PR override for non-PR-triggered workflows. |

## Outputs

| Output | Description |
|--------|-------------|
| `gate_status` | `passed`, `blocked`, `error` (or queued in async flows). |
| `p0_count` | Number of P0 findings. |
| `p1_count` | Number of P1 findings. |
| `p2_count` | Number of P2 findings. |
| `p3_count` | Number of P3 findings. |
| `run_id` | Correlation id for the run. |
| `scan_mode` | Effective scan mode for this run. |
| `severity_gate` | Effective severity threshold for this run. |

## Common configurations

### Strict production gate

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    scan_mode: deep
    severity_gate: P1
```

### Report-only

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    scan_mode: deep
    severity_gate: none
```

### Full-depth release gate

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    scan_mode: full-depth
    severity_gate: P2
```

## Troubleshooting

### Missing token

If the run fails immediately, confirm `SENTINELAYER_TOKEN` exists and is mapped to `sentinelayer_token`.

### Wrong gate behavior

Confirm `severity_gate` is set to the expected value and branch protection is requiring the Omar check.

### PR context not detected

For manual or dispatch runs, set `pr_number` explicitly.

## FAQ

### Is this still the same Omar Gate?

Yes. The delivery architecture moved to a managed GitHub App execution layer, but the pull request governance goal is unchanged: deterministic evidence, deep review, and enforceable merge policy.

### Does this action expose private scanner code?

No. The public action remains a compatibility/control surface and intentionally does not ship proprietary scanner internals.
