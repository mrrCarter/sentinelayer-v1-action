# Omar Gate

**AI-powered security gate that blocks P0/P1 vulnerabilities before merge.**

[![Action Version](https://img.shields.io/badge/action-v1-blue)](https://github.com/mrrCarter/sentinelayer-v1-action)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests: 204 passing](https://img.shields.io/badge/tests-204%20passing-brightgreen)](https://github.com/mrrCarter/sentinelayer-v1-action/actions/workflows/quality-gates.yml)
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
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read

jobs:
  quality-gates:
    name: Quality Gates
    runs-on: ubuntu-latest
    env:
      PYTHONPATH: src
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"
          cache-dependency-path: requirements.lock.txt
      - run: python -m pip install --require-hashes -r requirements.lock.txt
      - run: python -m pip install --disable-pip-version-check ruff==0.15.0
      - run: ruff check src tests
      - run: python -m pytest tests/unit tests/integration -q

  secret-scanning:
    name: Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install gitleaks
        run: |
          curl -fsSLo gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_linux_x64.tar.gz
          echo "fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e  gitleaks.tar.gz" | sha256sum --check --strict
          tar -xzf gitleaks.tar.gz
          sudo mv gitleaks /usr/local/bin/
      - run: gitleaks detect --source . --report-format json --report-path gitleaks-report.json --redact --no-git
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gitleaks-${{ github.run_id }}
          path: gitleaks-report.json

  omar-review:
    name: Omar Review
    needs: [quality-gates, secret-scanning]
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install LLM CLIs
        run: |
          npm install -g @openai/codex@0.98.0
          npm install -g @anthropic-ai/claude-code || true
          npm install -g @google/gemini-cli || npm install -g @google-ai/gemini-cli || true

      - name: Verify LLM CLIs
        run: |
          codex --version || true
          claude --version || true
          gemini --version || true

      - name: Omar Gate
        id: omar
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          sentinelayer_managed_llm: ${{ secrets.OPENAI_API_KEY == '' && secrets.SENTINELAYER_TOKEN != '' }}

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

The workflow above intentionally runs **Quality Gates** and **Secret Scanning** in parallel, then runs **Omar Review** only after both pass.

> **Required inputs:** `github_token` and either (a) an API key for your chosen LLM provider, or (b) `sentinelayer_token` with managed proxy enabled. The Quick Start enables managed mode automatically when `OPENAI_API_KEY` is empty and `SENTINELAYER_TOKEN` is set.

---

## Setup (3 Steps)

### Step 1: Add the workflow file

Copy the Quick Start YAML above into `.github/workflows/security-review.yml` in your repository.

### Step 2: Add your LLM secret(s) as repository secrets

1. Go to your repo **Settings** > **Secrets and variables** > **Actions**
2. Click **New repository secret**
3. Add either:
   - `OPENAI_API_KEY` for BYO OpenAI billing, or
   - `SENTINELAYER_TOKEN` to use Sentinelayer-managed proxy mode (48-hour onboarding window)
4. You can set both secrets; the workflow uses BYO key when present and auto-falls back to managed mode when it is not.

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

**Managed-first with BYO fallback (recommended for onboarding)**
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    sentinelayer_managed_llm: ${{ secrets.OPENAI_API_KEY == '' && secrets.SENTINELAYER_TOKEN != '' }}
    llm_provider: openai
    model: gpt-4.1
    model_fallback: gpt-4.1-mini
```

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
- `CODEBASE_INGEST_SUMMARY.md` — deterministic snapshot (LOC, languages, god components)
- `CODEBASE_INGEST_SUMMARY.json` — same snapshot (machine-readable)

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
| `pack_summary_artifact` | Path to `PACK_SUMMARY.json` |
| `ingest_artifact` | Path to `INGEST.json` |
| `codebase_ingest_artifact` | Path to `CODEBASE_INGEST.json` |
| `codebase_ingest_summary_artifact` | Path to `CODEBASE_INGEST_SUMMARY.json` |
| `codebase_ingest_summary_md_artifact` | Path to `CODEBASE_INGEST_SUMMARY.md` |
| `review_brief_artifact` | Path to `REVIEW_BRIEF.md` (if generated) |
| `audit_report_artifact` | Path to `AUDIT_REPORT.md` (if generated) |
| `idempotency_key` | Idempotency key used for dedupe |

---

## Configuration Reference

### Required Inputs

| Input | Description |
|-------|-------------|
| `github_token` | GitHub token for fetching PR diffs and posting comments. Use `${{ secrets.GITHUB_TOKEN }}`. |
| API key / managed proxy | Either provide a BYO key (`openai_api_key`, `anthropic_api_key`, `google_api_key`) or use managed mode with `sentinelayer_token` + `sentinelayer_managed_llm=true` (or auto-detect when OpenAI key is empty). |

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
| `sentinelayer_managed_llm` | `false` | Route OpenAI calls through Sentinelayer-managed proxy. If `false`, auto-enables when `openai_api_key` is empty and `sentinelayer_token` is set |
| `use_codex` | `true` | Enable Codex CLI for deep agentic audit (OpenAI only) |
| `codex_only` | `false` | If `true`, disable API fallback and use Codex CLI only |
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

## False Positive Defense

Omar Gate uses three independent layers so that **LLM analysis can never unilaterally block a merge**:

### Layer 1 — AST & Syntax-Aware Deterministic Analysis
- Python `eval()`/`exec()` detected via `ast.parse` + `ast.walk`, not regex — eliminates self-referential matches in comments, strings, and docs.
- JS/TS comment and string literals are blanked before pattern matching.
- Entropy-based secret detection requires context keywords nearby, minimum length (32), and high Shannon entropy (>4.7) to flag.

### Layer 2 — Git-Aware Diff Scoping
- Only **added** lines can produce blocking (P0/P1) findings.
- Removed lines are scanned separately at P3 (advisory only).
- Entropy matches in doc files (`.md`, `.rst`, `.txt`) and historical commits are auto-downgraded to P3.

### Layer 3 — LLM Guardrails (Corroboration Required)
- LLM-sourced P0/P1 findings are automatically **downgraded to P2** unless a deterministic finding in the *same file*, *same category*, and within *5 lines* corroborates them.
- Findings referencing files not in the scanned diff are dropped entirely.
- Line numbers are clamped to valid ranges; hallucinated locations are discarded.

| Finding Source | Can Block Merge? |
|---|:---:|
| Deterministic scanner (regex, AST, config) | Yes |
| Harness (pip-audit, gitleaks) | Yes |
| LLM/Codex **with** deterministic corroboration | Yes |
| LLM/Codex **without** corroboration | No (advisory P2) |

> See [docs/CONFIGURATION.md](docs/CONFIGURATION.md#false-positive-defense) for the full technical breakdown of each layer.

---

## Troubleshooting

### "Illegal header value b'Bearer '"
**Cause:** `github_token` was not passed to the action.
**Fix:** Add `github_token: ${{ secrets.GITHUB_TOKEN }}` to your `with:` block.

### "Codex skipped (missing openai_api_key)"
**Cause:** No BYO LLM key was provided, and managed proxy auth was not available.
**Fix:** Add your API key as a repository secret, or configure managed mode with `sentinelayer_token` (and `id-token: write`) so the action can use the Sentinelayer proxy.

### 15,000+ findings on first run
**Cause:** The deterministic scanner runs regex patterns across your entire codebase. Many findings are informational (P3) or low severity.
**Fix:** This is expected on the first scan. Focus on P0/P1 findings. Use `severity_gate: P1` to only block on critical issues. Subsequent scans on PRs will focus on changed files.

### Action doesn't trigger on PR
**Cause:** The workflow file must exist on the PR branch. If you're adding it for the first time, it needs to be part of the PR itself.
**Fix:** Commit the workflow file to your branch, push, and open the PR. The action will trigger.

---

## FAQ

**Do you store my code?**
Your repository is analyzed in your GitHub runner. SentinelLayer dashboard telemetry is opt-in by tier; Tier 1 is aggregate-only, Tier 2 includes metadata, and Tier 3 can include uploaded artifacts. LLM analysis sends a bounded context to your LLM provider using your own API key, or through Sentinelayer-managed proxy mode when enabled.

**What LLM models are used?**
Primary analysis uses Codex CLI with `gpt-5.2-codex` for deep agentic audit. If Codex CLI is unavailable, falls back to `gpt-4.1` via the Responses API, then `gpt-4.1-mini` as secondary fallback. All models are configurable via `codex_model`, `model`, and `model_fallback` inputs.

**What about false positives?**
Omar Gate has a 3-layer defense against false positives: AST-aware deterministic analysis, git-aware diff scoping, and LLM guardrails that require deterministic corroboration. LLM-only P0/P1 findings without corroboration are automatically downgraded to advisory P2 — they can't block your merge. See [False Positive Defense](#false-positive-defense) for details.

**Is it free?**
See https://sentinelayer.com for current tier limits and pricing.

---

## Test Coverage

**204 tests** (unit + integration) — all passing. Covers deterministic scanners, Codex CLI, LLM fallback, telemetry, rate limiting, gate logic, and config validation.

---

## License

MIT License — Copyright (c) 2026 PlexAura Inc.

---

**Built by [PlexAura](https://plexaura.com) | [Sentinelayer](https://sentinelayer.com) — Stop vulnerabilities before they ship.**
