# SentinelLayer GitHub Action

AI-powered security scanning for every pull request

[![Action Version](https://img.shields.io/badge/action-v1-blue)](https://github.com/mrrCarter/sentinelayer-v1-action)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/mrrCarter/sentinelayer-v1-action/quality-gates.yml?branch=main)](https://github.com/mrrCarter/sentinelayer-v1-action/actions/workflows/quality-gates.yml)
[![Marketplace](https://img.shields.io/badge/marketplace-GitHub-blue)](https://github.com/marketplace?query=sentinelayer)

SentinelLayer (policy pack: `Omar Gate`) analyzes pull requests for security vulnerabilities (P0-P3), posts PR comments with findings, creates GitHub Check Runs, and can optionally send telemetry to the SentinelLayer dashboard.

## Quick Start (30-second setup)

```yaml
# .github/workflows/security.yml
name: SentinelLayer Security Review
on: [pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - uses: actions/checkout@v4
      - uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

Notes:
- If `@v1` is not available yet, use `@main` or pin to a commit SHA.
- PR comments use the Issues API; if comment publishing fails, add `issues: write` to workflow permissions.

## What It Scans For (P0-P3)

SentinelLayer produces findings with severities `P0` (highest) through `P3` (lowest).

- 🔴 P0: Hardcoded secrets, CI/CD workflow injection, critical injection/execution paths (SQL injection, RCE primitives)
  - Example: committed cloud credentials (AWS keys, GitHub tokens)
  - Example: unsafe workflow contexts in CI
- 🟠 P1: Auth bypasses, missing rate limits, insecure crypto, unsafe code execution primitives
  - Example: permissive CORS + credentials
  - Example: `eval()` usage
- 🟡 P2: Missing security headers, verbose errors, CSRF weaknesses, supply-chain and exposure misconfigs
  - Example: dependencies fetched over `http://`
  - Example: Docker Compose `privileged: true`
- ⚪ P3: Logging PII, debug leftovers, minor config issues
  - Example: `console.log(...)` in production code

## Configuration Reference

All inputs come from `action.yml`. Full detail is in `docs/CONFIGURATION.md`.

Authentication

| Input | Default | Description | Example |
|---|---|---|---|
| `openai_api_key` | (required) | OpenAI API key for LLM calls (BYO). | `${{ secrets.OPENAI_API_KEY }}` |
| `github_token` | `""` | GitHub token for PR comments and check runs (use `github.token`). | `${{ github.token }}` |
| `sentinelayer_token` | `""` | SentinelLayer API token for Tier 2/3 uploads (optional). | `${{ secrets.SENTINELAYER_TOKEN }}` |

Scan Settings

| Input | Default | Description | Example |
|---|---|---|---|
| `scan_mode` | `pr-diff` | `pr-diff` (fast), `deep` (full repo), `nightly` (scheduled). | `deep` |
| `model` | `gpt-4.1` | Primary OpenAI model. | `gpt-4.1` |
| `model_fallback` | `gpt-4.1-mini` | Fallback OpenAI model. | `gpt-4.1-mini` |
| `max_input_tokens` | `100000` | Max context budget per run (cost control). | `80000` |
| `llm_failure_policy` | `block` | On LLM failure: `block`, `deterministic_only`, `allow_with_warning`. | `deterministic_only` |
| `policy_pack` | `omar` | Policy pack identifier. | `omar` |
| `policy_pack_version` | `v1` | Policy pack version. | `v1` |

Gate Control

| Input | Default | Description | Example |
|---|---|---|---|
| `severity_gate` | `P1` | Minimum severity to block: `P0`, `P1`, `P2`, `none`. | `P0` |
| `fork_policy` | `block` | Fork PR handling: `block`, `limited` (deterministic only), `allow`. | `limited` |
| `run_deterministic_fix` | `false` | Deterministic autofix (reserved; currently no-op). | `true` |
| `run_llm_fix` | `false` | LLM fix patches (reserved; currently no-op). | `true` |
| `auto_commit_fixes` | `false` | Auto-commit deterministic fixes (reserved; currently no-op). | `false` |

Cost Control

| Input | Default | Description | Example |
|---|---|---|---|
| `max_daily_scans` | `20` | Maximum scans per repo per day (0 = unlimited). | `0` |
| `min_scan_interval_minutes` | `5` | Minimum minutes between scans for same PR head SHA. | `15` |
| `require_cost_confirmation` | `5.00` | If estimated cost exceeds this USD threshold, require approval. | `2.50` |
| `approval_mode` | `pr_label` | High-cost scan approval: `pr_label`, `workflow_dispatch`, `none`. | `workflow_dispatch` |
| `approval_label` | `sentinelayer:approved` | PR label that approves high-cost scan. | `security:cost-approved` |

Telemetry

| Input | Default | Description | Example |
|---|---|---|---|
| `telemetry_tier` | `1` | `0`=off, `1`=aggregate, `2`=metadata, `3`=full artifacts. | `0` |
| `telemetry` | `true` | Enable anonymous telemetry (opt-out). | `false` |
| `share_metadata` | `false` | Opt-in to Tier 2 metadata. | `true` |
| `share_artifacts` | `false` | Opt-in to Tier 3 artifact upload. | `true` |
| `training_opt_in` | `false` | Optional training consent (de-identified). | `true` |

## Scan Modes

- `pr-diff` (default): Fast scan optimized for PR review; includes PR diff in LLM context when available.
- `deep`: Full repo scan using the ingest map and hotspot prioritization.
- `nightly`: Scheduled comprehensive scans (use with cron).

Example nightly workflow:

```yaml
name: SentinelLayer Nightly Scan
on:
  schedule:
    - cron: "0 3 * * *"
jobs:
  nightly:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ github.token }}
          scan_mode: nightly
          severity_gate: P2
```

## Output Artifacts

Artifacts are written under `.sentinelayer/runs/<run_id>/` (or the directory specified by `SENTINELAYER_RUNS_DIR`).

- `FINDINGS.jsonl`: machine-readable findings (JSONL)
- `AUDIT_REPORT.md`: human-readable detailed report
- `REVIEW_BRIEF.md`: quick summary for reviewers
- `PACK_SUMMARY.json`: metadata and counts (includes checksum for fail-closed gating)

## Gate Behavior

Severity gates:
- `severity_gate: P0` blocks on any P0
- `severity_gate: P1` blocks on any P0 or P1
- `severity_gate: P2` blocks on any P0, P1, or P2
- `severity_gate: none` never blocks (report-only)

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Passed |
| `1` | Blocked |
| `10` | Dedupe (already analyzed) |
| `11` | Rate limited |
| `12` | Fork blocked |
| `13` | Cost approval needed |

## PR Comment Screenshot Placeholder

The PR comment includes:
- A status header (PASSED/BLOCKED/NEEDS APPROVAL/ERROR)
- A severity counts table (P0-P3)
- A collapsible "Top Findings" section (up to 5)
- "Next Steps" guidance
- Links to `AUDIT_REPORT.md` and `REVIEW_BRIEF.md` when artifacts are uploaded

## Dashboard

SentinelLayer dashboard: https://sentinelayer.com

- Login with GitHub
- View run history, findings, and trends
- Optional telemetry and artifact uploads by tier

## FAQ

**Do you store my code?**
Your repository is analyzed in your GitHub runner. SentinelLayer dashboard telemetry is opt-in by tier; Tier 1 is aggregate-only, Tier 2 includes metadata, and Tier 3 can include uploaded artifacts. LLM analysis sends a bounded context to OpenAI using your `openai_api_key`.

**What LLM models are used?**
Default primary model is `gpt-4.1`, with `gpt-4.1-mini` as fallback (configurable). When Codex models (e.g. `gpt-5.2-codex`) become available via the Chat Completions API, you can override via the `model` input.

**What about false positives?**
SentinelLayer combines deterministic rules with LLM review and includes a `confidence` field per finding. Tune enforcement via `severity_gate`, and consider `llm_failure_policy=deterministic_only` for stricter determinism.

**Is it free?**
See https://sentinelayer.com for current tier limits and pricing.

## Contributing

Run the same checks as CI:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest ruff mypy

ruff check src tests
python -m pytest tests/unit tests/integration -q
```

## Documentation Maintenance

Repo doc inventory script:

```bash
python scripts/doc_inventory.py
```

Search for TODO/FIXME in docs:

```bash
rg -n "\\b(TODO|FIXME)\\b" docs
```

## License

MIT. See `LICENSE`.
