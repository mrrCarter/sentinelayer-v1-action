# Omar Gate

**AI-powered security gate that blocks P0/P1 vulnerabilities before merge.**

[![Action Version](https://img.shields.io/badge/action-v1-blue)](https://github.com/mrrCarter/sentinelayer-v1-action)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests: 186 passing](https://img.shields.io/badge/tests-186%20passing-brightgreen)](https://github.com/mrrCarter/sentinelayer-v1-action/actions/workflows/quality-gates.yml)
[![Marketplace](https://img.shields.io/badge/GitHub-Marketplace-blue)](https://github.com/marketplace?query=sentinelayer)

Omar Gate runs a 7-layer security analysis on every pull request — combining deterministic pattern scanning, codebase-aware ingestion, and deep AI-powered code review — then blocks the merge if critical vulnerabilities are found.

Built by engineers, for engineers. No vendor lock-in. Bring your own LLM.

---

## Quick Start

Create `.github/workflows/security-review.yml` in your repository:

```yaml
name: Security Review

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Omar Gate
        id: omar
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}

      - name: Upload Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sentinelayer-${{ steps.omar.outputs.run_id }}
          path: .sentinelayer/runs/${{ steps.omar.outputs.run_id }}
          if-no-files-found: warn
```

That's it. Open a PR and Omar Gate will:
1. Scan your codebase for secrets, vulnerabilities, and misconfigurations
2. Run AI-powered deep analysis on high-risk files
3. Post a detailed security report as a PR comment
4. Block the merge if P0/P1 issues are found
5. Upload full audit artifacts for download

> **Required inputs:** `github_token` and an API key for your chosen LLM provider. Without `github_token`, the action cannot fetch your PR diff and will fail. Without an API key, only deterministic scanning runs (no AI analysis).

---

## Setup (3 Steps)

### Step 1: Add the workflow file

Copy the Quick Start YAML above into `.github/workflows/security-review.yml` in your repository.

### Step 2: Add your API key as a repository secret

1. Go to your repo **Settings** > **Secrets and variables** > **Actions**
2. Click **New repository secret**
3. Add your API key (see [Choose Your LLM](#choose-your-llm) below for which key to add)

> `GITHUB_TOKEN` is provided automatically by GitHub Actions — you do not need to create it as a secret. Just pass it as `${{ secrets.GITHUB_TOKEN }}`.

### Step 3: Open a pull request

That's it. Omar Gate triggers automatically on every PR.

---

## Choose Your LLM

Omar Gate supports multiple LLM providers. Pick one based on your needs:

### Model Comparison

| Model | Provider | Quality | Cost | Speed | Best For |
|-------|----------|:-------:|:----:|:-----:|----------|
| `gpt-5.2-codex` | OpenAI | ★★★★★ | $$$ | Medium | Deep agentic audit, full codebase understanding |
| `claude-opus-4-6` | Anthropic | ★★★★★ | $$$ | Medium | Nuanced analysis, architectural review |
| `claude-sonnet-4-5` | Anthropic | ★★★★ | $$ | Fast | Strong balance of quality and cost |
| `gpt-4.1` | OpenAI | ★★★★ | $$ | Fast | Reliable all-rounder, great default |
| `gemini-2.5-pro` | Google | ★★★★ | $$ | Fast | Large context window, good for big repos |
| `gpt-4.1-mini` | OpenAI | ★★★ | $ | Very Fast | Budget-friendly, frequent scans |
| `gemini-2.5-flash` | Google | ★★★ | $ | Very Fast | Cheapest option with decent quality |

**Cost estimates by codebase size:**

| Repo Size | Files | Premium Model ($$$/scan) | Standard Model ($$/scan) | Budget Model ($/scan) |
|-----------|------:|:------------------------:|:------------------------:|:---------------------:|
| Small | <100 | ~$0.50 | ~$0.20 | ~$0.05 |
| Medium | 100-500 | ~$2-5 | ~$1-2 | ~$0.25-0.50 |
| Large | 500-2000 | ~$5-15 | ~$3-8 | ~$1-3 |
| Monorepo | 2000+ | ~$15-30 | ~$8-15 | ~$3-8 |

> Use budget models for frequent PR scans during development. Use premium models for release gates and security audits.

### Provider Configuration

**OpenAI (default)**
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    llm_provider: openai
    model: gpt-4.1              # or gpt-5.2-codex for deepest analysis
    model_fallback: gpt-4.1-mini
```

**Anthropic**
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    llm_provider: anthropic
    model: claude-sonnet-4-5     # or claude-opus-4-6 for deepest analysis
```

**Google**
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    google_api_key: ${{ secrets.GOOGLE_API_KEY }}
    llm_provider: google
    model: gemini-2.5-pro        # or gemini-2.5-flash for budget
```

---

## How It Works

Omar Gate runs a two-phase analysis pipeline:

### Phase 1: Deterministic Analysis (free, fast, always runs)

| Layer | Engine | Time | What It Catches |
|:-----:|--------|:----:|-----------------|
| 1 | Codebase ingest | ~1s | File tree, LOC counts, god components, complexity metrics |
| 2 | Regex scanner | ~7s | Hardcoded secrets, `eval()`, known-bad patterns, leaked credentials |
| 3 | Config scanner | ~2s | Insecure `.env` files, weak TypeScript config, HTTP dependencies |
| 4 | CI/CD scanner | ~1s | Workflow injection, script injection, privilege escalation |

### Phase 2: AI-Powered Analysis (uses your LLM, runs after Phase 1)

| Layer | Engine | Time | What It Catches |
|:-----:|--------|:----:|-----------------|
| 5 | Codex / Claude / Gemini | ~30-120s | RCE, SQLi, auth bypass, business logic flaws, broken references |
| 6 | Security test harness | ~5s | Portable security tests |
| 7 | Fail-closed gate | ~1s | Blocks merge if P0/P1 found, posts findings to PR |

**How the AI phase works:**
- Phase 1 produces structured data (file metrics, hotspot files, ingest summary)
- The AI receives this data + the PR diff + your README — it does NOT crawl the codebase blindly
- The AI targets specific files identified as high-risk by the deterministic scan
- This dramatically reduces token usage and cost while maintaining deep analysis quality

### First Run vs Subsequent Runs

**First PR on your repo:** Omar Gate generates a detailed codebase summary — tech stack, architecture, LOC breakdown, key entry points, dependency analysis. This context is used to make all future scans smarter.

**Subsequent PRs:** A 3-sentence summary referencing the cached profile. Faster, cheaper, focused on what changed.

---

## What You Get

### PR Comment
Every scan posts a detailed report to your PR:
- **Gate status** (passed/blocked) with severity breakdown
- **Top findings** with file paths, line numbers, and GitHub permalinks
- **Risk hotspots** ranked by severity and category
- **Suggested review order** by category (Auth, Payment, Database, etc.)
- **Codebase metrics** — LOC, god components, complexity scores
- **Quick commands** to find related patterns in your codebase

### Check Run
A GitHub check run appears on the PR with pass/fail status and a link to the full report.

### Downloadable Artifacts
Full audit artifacts available for download from the Actions tab:
- `AUDIT_REPORT.md` — complete findings report
- `REVIEW_BRIEF.md` — reviewer summary with priority order
- `FINDINGS.jsonl` — machine-readable findings (for CI integration)
- `PACK_SUMMARY.json` — counts, integrity hash, metadata
- `CODEBASE_INGEST.json` — codebase metrics and file inventory

---

## Outputs

Use these in subsequent workflow steps:

| Output | Description |
|--------|-------------|
| `gate_status` | `passed`, `blocked`, `bypassed`, or `error` |
| `p0_count` / `p1_count` / `p2_count` / `p3_count` | Finding counts by severity |
| `run_id` | Unique run identifier |
| `estimated_cost_usd` | Estimated LLM cost for the run |
| `findings_artifact` | Path to findings JSONL |

---

## Configuration Reference

### Required Inputs

| Input | Description |
|-------|-------------|
| `github_token` | GitHub token for fetching PR diffs and posting comments. Use `${{ secrets.GITHUB_TOKEN }}`. |
| API key | At least one of: `openai_api_key`, `anthropic_api_key`, `google_api_key`. Without this, only deterministic scanning runs. |

### Scan Settings

| Input | Default | Description |
|-------|---------|-------------|
| `severity_gate` | `P1` | Block threshold. `P0` = only criticals, `P1` = criticals + high, `P2` = medium+, `none` = report only |
| `scan_mode` | `pr-diff` | `pr-diff` (fast, scans changed files + context), `deep` (full repo scan) |
| `llm_failure_policy` | `block` | What happens if the LLM fails: `block` (fail-closed), `deterministic_only` (fall back to regex), `allow_with_warning` |

### LLM Settings

| Input | Default | Description |
|-------|---------|-------------|
| `llm_provider` | `openai` | `openai`, `anthropic`, `google`, `xai` |
| `model` | `gpt-4.1` | Primary LLM model |
| `model_fallback` | `gpt-4.1-mini` | Fallback if primary fails or exceeds quota |
| `use_codex` | `true` | Enable Codex CLI for deep agentic audit (OpenAI only) |
| `codex_model` | `gpt-5.2-codex` | Model for Codex CLI |
| `codex_timeout` | `300` | Codex CLI timeout in seconds |

### Rate Limiting

| Input | Default | Description |
|-------|---------|-------------|
| `max_daily_scans` | `20` | Maximum scans per repo per day |
| `min_scan_interval_minutes` | `2` | Cooldown between scans |
| `rate_limit_fail_mode` | `closed` | `closed` (block on limit) or `open` (allow on limit) |

### Security

| Input | Default | Description |
|-------|---------|-------------|
| `fork_policy` | `block` | How to handle PRs from forks: `block`, `limited` (deterministic only), `allow` |
| `approval_mode` | `pr_label` | Require label for scanning: `pr_label`, `always`, `manual` |
| `approval_label` | `sentinelayer:approved` | Label that triggers scanning (when `approval_mode: pr_label`) |

### Telemetry

| Input | Default | Description |
|-------|---------|-------------|
| `telemetry` | `true` | Send anonymous usage metrics |
| `telemetry_tier` | `1` | `1` = anonymous aggregates, `2` = includes repo metadata, `3` = includes finding summaries |
| `share_metadata` | `false` | Share repo metadata with Sentinelayer |
| `training_opt_in` | `false` | Allow findings to improve the model (never shares your code) |

See [action.yml](action.yml) for all 30+ configuration options.

---

## Advanced Examples

### Strict Security Gate (Recommended for Production)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    severity_gate: P1
    scan_mode: pr-diff
    llm_failure_policy: block
    fork_policy: block
```

### Report-Only Mode (No Blocking)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    severity_gate: none
    scan_mode: pr-diff
```

### Budget Mode (Deterministic + Cheap LLM)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    model: gpt-4.1-mini
    model_fallback: gpt-4.1-mini
    use_codex: false
```

### Deep Scan (Nightly / Release Gate)
```yaml
name: Nightly Security Audit
on:
  schedule:
    - cron: '0 3 * * *'

jobs:
  deep-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Omar Gate (Deep)
        id: omar
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          scan_mode: deep
          model: gpt-5.2-codex
          severity_gate: P2
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nightly-audit-${{ steps.omar.outputs.run_id }}
          path: .sentinelayer/runs/${{ steps.omar.outputs.run_id }}
```

### With Claude (Anthropic)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    llm_provider: anthropic
    model: claude-sonnet-4-5
```

---

## Troubleshooting

### "Illegal header value b'Bearer '"
**Cause:** `github_token` was not passed to the action.
**Fix:** Add `github_token: ${{ secrets.GITHUB_TOKEN }}` to your `with:` block.

### "Codex skipped (missing openai_api_key)"
**Cause:** No LLM API key was provided. Only deterministic scanning ran.
**Fix:** Add your API key as a repository secret and pass it in the `with:` block.

### 15,000+ findings on first run
**Cause:** The deterministic scanner runs regex patterns across your entire codebase. Many findings are informational (P3) or low severity.
**Fix:** This is expected on the first scan. Focus on P0/P1 findings. Use `severity_gate: P1` to only block on critical issues. Subsequent scans on PRs will focus on changed files.

### Action doesn't trigger on PR
**Cause:** The workflow file must exist on the PR branch. If you're adding it for the first time, it needs to be part of the PR itself.
**Fix:** Commit the workflow file to your branch, push, and open the PR. The action will trigger.

---

## FAQ

**Do you store my code?**
Your repository is analyzed in your GitHub runner. SentinelLayer dashboard telemetry is opt-in by tier; Tier 1 is aggregate-only, Tier 2 includes metadata, and Tier 3 can include uploaded artifacts. LLM analysis sends a bounded context to your LLM provider using your own API key.

**What LLM models are used?**
Primary analysis uses Codex CLI with `gpt-5.2-codex` for deep agentic audit. If Codex CLI is unavailable, falls back to `gpt-4.1` via the Responses API, then `gpt-4.1-mini` as secondary fallback. All models are configurable via `codex_model`, `model`, and `model_fallback` inputs.

**What about false positives?**
SentinelLayer combines deterministic rules with LLM review and includes a `confidence` field per finding. Tune enforcement via `severity_gate`, and consider `llm_failure_policy=deterministic_only` for stricter determinism.

**Is it free?**
See https://sentinelayer.com for current tier limits and pricing.

---

## Test Coverage

**186 tests** (unit + integration) — all passing. Covers deterministic scanners, Codex CLI, LLM fallback, telemetry, rate limiting, gate logic, and config validation.

---

## License

MIT License — Copyright (c) 2026 PlexAura Inc.

---

**Built by [PlexAura](https://plexaura.com) | [Sentinelayer](https://sentinelayer.com) — Stop vulnerabilities before they ship.**
