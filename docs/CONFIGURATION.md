# SentinelLayer Action Configuration

SentinelLayer is configured entirely via GitHub Action inputs (see `action.yml`). Inputs are passed via `with:` in your workflow.

Notes:
- GitHub Actions provides inputs as strings; the action parses booleans (`true`/`false`) and numbers automatically.
- `openai_api_key` is currently required (even if you intend to run deterministic-only scans).

## Inputs At A Glance

Authentication

| Input | Type | Default | Purpose |
|---|---|---|---|
| `openai_api_key` | secret string | (required) | OpenAI API key for LLM analysis (BYO). |
| `github_token` | secret string | `""` | GitHub token for PR comments and Check Runs. |
| `sentinelayer_token` | secret string | `""` | SentinelLayer token for Tier 2/3 uploads (optional). |

Scan Settings

| Input | Type | Default | Purpose |
|---|---|---|---|
| `scan_mode` | string | `pr-diff` | `pr-diff`, `deep`, or `nightly`. |
| `policy_pack` | string | `omar` | Policy pack identifier. |
| `policy_pack_version` | string | `v1` | Policy pack version identifier. |
| `model` | string | `gpt-5.3-codex` | Primary OpenAI model. |
| `model_fallback` | string | `gpt-4.1` | Fallback OpenAI model. |
| `max_input_tokens` | int | `100000` | Maximum LLM context budget (cost control). |
| `llm_failure_policy` | string | `block` | `block`, `deterministic_only`, or `allow_with_warning`. |

Gate Control

| Input | Type | Default | Purpose |
|---|---|---|---|
| `severity_gate` | string | `P1` | Block threshold: `P0`, `P1`, `P2`, `none`. |
| `fork_policy` | string | `block` | Fork PR handling: `block`, `limited`, `allow`. |
| `run_deterministic_fix` | bool | `false` | Reserved (currently no-op). |
| `run_llm_fix` | bool | `false` | Reserved (currently no-op). |
| `auto_commit_fixes` | bool | `false` | Reserved (currently no-op). |

Cost Control

| Input | Type | Default | Purpose |
|---|---|---|---|
| `max_daily_scans` | int | `20` | Rate limit: cap check-run executions per PR head SHA per 24 hours. |
| `min_scan_interval_minutes` | int | `5` | Rate limit: cooldown between scans per PR head SHA. |
| `require_cost_confirmation` | float | `5.00` | If estimated cost exceeds this USD threshold, require approval. |
| `approval_mode` | string | `pr_label` | `pr_label`, `workflow_dispatch`, `none`. |
| `approval_label` | string | `sentinelayer:approved` | PR label that approves high-cost scans (when `approval_mode=pr_label`). |

Telemetry

| Input | Type | Default | Purpose |
|---|---|---|---|
| `telemetry_tier` | int | `1` | `0`=off, `1`=aggregate, `2`=metadata, `3`=full artifacts. |
| `telemetry` | bool | `true` | Enable anonymous telemetry (opt-out). |
| `share_metadata` | bool | `false` | Explicit opt-in to Tier 2 metadata (overrides `telemetry_tier`). |
| `share_artifacts` | bool | `false` | Explicit opt-in to Tier 3 artifacts upload (overrides `telemetry_tier`). |
| `training_opt_in` | bool | `false` | Optional training consent (de-identified). |

## Authentication

### `openai_api_key` (required)

Used for LLM analysis. The action will send a bounded context (diff + prioritized files) to OpenAI using your API key.

Example:

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

### `github_token` (recommended)

Used to:
- Post an idempotent PR comment (updates the same comment on re-runs)
- Create a GitHub Check Run with inline annotations (up to 50)
- Fetch PR diff and changed files for `scan_mode=pr-diff`

If `github_token` is not provided, the action also checks the `GITHUB_TOKEN` environment variable.

Recommended:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
  issues: write
```

Example:

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    github_token: ${{ github.token }}
```

### `sentinelayer_token` (optional)

Enables SentinelLayer dashboard uploads for higher telemetry tiers (especially Tier 3 artifacts).

Example:

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    github_token: ${{ github.token }}
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    telemetry_tier: 3
```

## Scan Settings

### `scan_mode`

- `pr-diff`: includes the PR diff in LLM context (when running on a PR) and prioritizes changed files.
- `deep`: omits the PR diff and prioritizes hotspots and general source coverage.
- `nightly`: intended for scheduled runs; behavior is similar to `deep` but may use a different prompt selection strategy as the product evolves.

Example:

```yaml
with:
  scan_mode: deep
```

### `policy_pack` and `policy_pack_version`

Used for:
- Finding fingerprinting/deduplication stability
- Reporting and telemetry metadata

Example:

```yaml
with:
  policy_pack: omar
  policy_pack_version: v1
```

### `model` / `model_fallback`

If the primary model fails, the action retries using the fallback model.

Example:

```yaml
with:
  model: gpt-5.3-codex
  model_fallback: gpt-4.1
```

### `max_input_tokens`

Hard cap on the LLM context budget used to build the analysis prompt. Lowering this reduces cost at the expense of coverage (more files will be skipped or truncated in context).

Example:

```yaml
with:
  max_input_tokens: 80000
```

### `.sentinelayerignore`

The action respects a `.sentinelayerignore` file at repo root (gitignore-style patterns). This is the primary control for reducing scan scope in monorepos or large repositories.

Example `.sentinelayerignore`:

```text
node_modules/**
dist/**
**/*.min.js
vendor/**
```

## Gate Control

### `severity_gate`

Defines the minimum severity that blocks the workflow:
- `P0`: block on any P0
- `P1`: block on any P0/P1
- `P2`: block on any P0/P1/P2
- `none`: never block (report-only)

Example:

```yaml
with:
  severity_gate: P0
```

### `fork_policy`

Controls how fork PRs are handled:
- `block`: do not proceed (intended to fail closed on forks)
- `limited`: proceed but disable LLM analysis (deterministic-only)
- `allow`: full scan (use with care)

Important: GitHub does not provide secrets to workflows triggered from fork PRs under `pull_request`. Since `openai_api_key` is required, the practical options today are:
- Skip running the action on forks (recommended for open source), or
- Use `pull_request_target` with strict safeguards (see `docs/EXAMPLES.md`).

Example:

```yaml
with:
  fork_policy: limited
```

### Fix options (`run_deterministic_fix`, `run_llm_fix`, `auto_commit_fixes`)

These inputs exist for forward compatibility but are currently no-ops in this repository revision. Do not rely on them for remediation workflows yet.

## Cost Control And Rate Limiting

### `max_daily_scans` and `min_scan_interval_minutes`

These limits are enforced using GitHub Check Run history for the PR head SHA. Practical implications:
- Pushing a new commit (new head SHA) resets the window.
- The limits apply to the Check Run named `Omar Gate` on that commit.

Examples:

```yaml
with:
  max_daily_scans: 10
  min_scan_interval_minutes: 15
```

Disable limits:

```yaml
with:
  max_daily_scans: 0
  min_scan_interval_minutes: 0
```

### `require_cost_confirmation`, `approval_mode`, `approval_label`

Before analysis, SentinelLayer estimates LLM cost from PR stats and blocks the run when the estimate exceeds `require_cost_confirmation` unless approved.

Approval modes:
- `pr_label`: requires `approval_label` on the PR (requires `issues: read` permission to check labels)
- `workflow_dispatch`: only allows runs triggered by `workflow_dispatch`
- `none`: disables approval checks

Example:

```yaml
with:
  require_cost_confirmation: 2.50
  approval_mode: pr_label
  approval_label: sentinelayer:approved
```

## Telemetry

Telemetry is best-effort: upload failures do not block the gate.

### Consent resolution (`telemetry_tier` vs explicit flags)

Consent is resolved as follows:
- If you set `share_metadata` or `share_artifacts`, or you set `telemetry: false`, those explicit flags control upload behavior.
- Otherwise, `telemetry_tier` controls behavior.

Examples:

Disable all telemetry:

```yaml
with:
  telemetry_tier: 0
```

Explicitly opt in to metadata:

```yaml
with:
  share_metadata: true
```

Tier 3 artifacts upload (requires `sentinelayer_token`):

```yaml
with:
  share_artifacts: true
  sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
```

### OIDC authentication (optional)

The action can use GitHub OIDC for telemetry authentication when available.

Workflow permissions:

```yaml
permissions:
  id-token: write
```

Optional audience override:
- Set `SENTINELAYER_OIDC_AUDIENCE` as an environment variable in your workflow or runner.

## Outputs

The action sets outputs (see `action.yml`), including:
- `gate_status`: `passed`, `blocked`, `bypassed`, `needs_approval`, `error`
- `p0_count` / `p1_count` / `p2_count` / `p3_count`
- `run_id`
- `estimated_cost_usd`
- `idempotency_key`

## Artifact Locations

By default, artifacts are written under:
- `.sentinelayer/runs/<run_id>/` in your workspace

Environment override:
- `SENTINELAYER_RUNS_DIR`: sets the base directory for run artifacts.
