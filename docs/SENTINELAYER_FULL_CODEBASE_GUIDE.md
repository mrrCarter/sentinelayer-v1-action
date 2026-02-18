# SentinelLayer Full Codebase Guide (Action + API + Web)

**Last updated:** February 18, 2026

## 1) What this document is

This is one end-to-end guide for the current SentinelLayer system across three sibling repositories:

- `sentinellayer-v1-action` (GitHub Action engine)
- `sentinelayer-api` (FastAPI backend)
- `sentinelayer-web` (React dashboard + marketing/docs UI)

It explains:

- how the codebases are structured
- how they work together
- how marketplace install + secrets setup works
- how scans are triggered
- how to contribute and open PRs
- what changes when the GitHub App + 13 personas ships
- how to run free without an API key

Additional planning sources used for roadmap context:

- `sentinellayer_implementation_requirements_v1.2.1.md`
- `my-sentinellayerXteam-backup/pack_assignment_rules.json`

---

## 2) High-level architecture

```text
Developer opens PR on customer repo
    ->
GitHub Actions workflow runs `mrrCarter/sentinelayer-v1-action@v1`
    ->
Action preflight (dedupe, fork policy, rate/cost checks)
    ->
Ingest + deterministic scanners + optional harness
    ->
Optional LLM analysis (BYO key OR managed proxy)
    ->
Gate evaluates local artifacts (fail-closed)
    ->
PR comment + Check Run + artifacts
    ->
Optional telemetry/artifact upload to SentinelLayer API
    ->
SentinelLayer Web dashboard reads API data for user-facing views
```

Key point: merge blocking is decided locally from generated artifacts, not from a network callback.

---

## 3) Repo-by-repo breakdown

### 3.1 `sentinellayer-v1-action` (core gate engine)

Purpose: this is the marketplace action customers add to their workflow.

Core entry files:

- `action.yml`: inputs, outputs, Docker action definition.
- `Dockerfile`: builds runtime image, installs Python deps + pinned Codex CLI (`@openai/codex@0.98.0`).
- `entrypoint.sh`: maps `INPUT_*` to env and executes `python -m omargate.main`.
- `src/omargate/main.py`: end-to-end orchestration.

Main pipeline in `src/omargate/main.py`:

1. Parse config/context.
2. Preflight:
   - dedupe (`src/omargate/idempotency.py`, `src/omargate/preflight/dedupe.py`)
   - fork policy (`src/omargate/preflight/fork_policy.py`)
   - rate limits + cost approval checks (`src/omargate/preflight/rate_limit.py`, `src/omargate/preflight/cost.py`)
3. Ingest and analysis (`src/omargate/analyze/orchestrator.py`):
   - quick learn
   - codebase ingest
   - harness (optional)
   - deterministic scanners
   - Codex/LLM analysis (optional)
   - LLM guardrails and merge of findings
4. Packaging/artifacts:
   - findings JSONL
   - pack summary
   - audit report and brief
5. Gate decision:
   - `src/omargate/gate.py` validates `PACK_SUMMARY.json` integrity and applies severity threshold.
6. Publish:
   - PR comment
   - check run annotations
   - GitHub outputs
   - optional telemetry upload

Key files/folders:

- `src/omargate/analyze/orchestrator.py`: ingest + deterministic + LLM/Codex pipeline
- `src/omargate/analyze/deterministic/*`: static/security/engineering scanners
- `src/omargate/gate.py`: fail-closed gate evaluation from artifacts
- `src/omargate/comment.py`: PR comment rendering
- `src/omargate/github.py`: check run + PR comment publishing
- `src/omargate/ingest/*`: deterministic codebase map/snapshot
- `src/omargate/telemetry/*`: telemetry payloads/upload
- `prompts/*`: baseline/security prompt files and manifest
- `.github/workflows/*`: this repo's own CI/security workflows

Important behavior:

- Fail-closed gate if summary is missing/corrupt or hash mismatch.
- LLM-only P0/P1 findings are guardrailed and downgraded without deterministic corroboration.
- Deterministic mode works without any LLM key.
- Managed LLM mode auto-enables if `OPENAI_API_KEY` is absent but `SENTINELAYER_TOKEN` is present (OpenAI provider path only).

Key artifacts:

- `.sentinelayer/runs/<run_id>/FINDINGS.jsonl`
- `.sentinelayer/runs/<run_id>/PACK_SUMMARY.json`
- `.sentinelayer/runs/<run_id>/AUDIT_REPORT.md`
- `.sentinelayer/runs/<run_id>/REVIEW_BRIEF.md`
- `.sentinelayer/runs/<run_id>/CODEBASE_INGEST_SUMMARY.md`

### 3.2 `sentinelayer-api` (backend service)

Purpose: receives telemetry, provides public stats, manages auth, and provides managed LLM proxy.

Core entry files:

- `src/main.py`: FastAPI app + middleware + route registration.
- `src/config.py`: runtime config and managed LLM limits.
- `src/db/connection.py`: Postgres/Timescale + Redis setup.

Implemented/active routes:

- `GET /health`, `GET /ready`
- `GET /api/v1/auth/github/state`
- `POST /api/v1/auth/github/callback`
- `GET /api/v1/auth/me`
- `POST /api/v1/telemetry`
- `POST /api/v1/proxy/llm`
- `GET /api/v1/public/stats`

Managed LLM proxy (`src/routes/proxy_llm.py`) enforces:

- `Authorization: Bearer <SENTINELAYER_TOKEN>`
- `X-Sentinelayer-OIDC-Token` validation
- model allowlist (`gpt-4.1`, `gpt-4.1-mini`)
- trial window and daily limits
- 402 errors on trial/budget exhaustion

Partially implemented/stub routes (currently return 501):

- `GET /api/v1/runs` (`src/routes/runs.py`)
- `POST /api/v1/artifacts/upload-urls` (`src/routes/artifacts.py`)
- `DELETE /api/v1/runs/{run_id}` (`src/routes/deletion.py`)

Deployment pipeline:

- `.github/workflows/deploy_api_to_ecs.yml` deploys on push to `main` (with path filters) and on manual dispatch.

### 3.3 `sentinelayer-web` (frontend app)

Purpose: marketing pages, docs pages, auth screens, and dashboard UI.

Core app files:

- `src/App.tsx`: route map, lazy-loaded pages, protected dashboard routes.
- `src/lib/api.ts`: API client (default `https://api.sentinelayer.com`).
- `src/lib/auth.ts`: GitHub OAuth flow.

Key user-facing sections:

- Landing/docs/pricing pages.
- Login + OAuth callback.
- Dashboard pages (`/dashboard/...`) for overview, repos, runs, settings, billing.

Current integration state:

- Web client expects `/api/v1/repos`, `/api/v1/runs/:id`, `/api/v1/runs/summary`.
- API currently only has partial run APIs and no repos endpoint yet, so some dashboard surfaces are roadmap-dependent.
- Web docs still reference `mrrCarter/sentinelayer-action@v1`; action repo currently uses `mrrCarter/sentinelayer-v1-action@v1`.

---

## 4) How these components work together in practice

### 4.1 Standard BYO-key flow

1. User opens PR in their own repository.
2. Workflow step calls `mrrCarter/sentinelayer-v1-action@v1`.
3. Action scans code locally and optionally calls OpenAI with `OPENAI_API_KEY`.
4. Action posts PR comment + check run.
5. Gate blocks or passes based on `severity_gate`.
6. Optional telemetry uploads to SentinelLayer API.
7. Web dashboard can show aggregate stats/runs where backend support exists.

### 4.2 Managed LLM flow (no user OpenAI key)

1. Workflow passes `SENTINELAYER_TOKEN` and enables managed mode.
2. Action sends bounded prompt context to `POST /api/v1/proxy/llm`.
3. API verifies Sentinelayer token + GitHub OIDC + trial/budget limits.
4. API calls OpenAI using server-side key and returns response.
5. Action continues normally and gates the PR.

### 4.3 Deterministic-only flow (fully no LLM)

1. Workflow sets `llm_failure_policy: deterministic_only` and disables Codex.
2. Action runs ingest, pattern/config/secret scanning, harness checks.
3. No LLM network call is made.
4. PR is still gated by deterministic findings.

---

## 5) Marketplace install guide (with GitHub + OpenAI setup)

There is no manual binary download. Installing from Marketplace means adding a workflow that references the action.

### 5.1 GitHub setup

1. Open your target repository on GitHub.
2. Go to `Settings -> Secrets and variables -> Actions`.
3. Add secrets:
   - `OPENAI_API_KEY` (if using BYO OpenAI)
   - `SENTINELAYER_TOKEN` (if using managed mode/dashboard linking)
   - optional provider keys (`ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `XAI_API_KEY`)
4. Create workflow file: `.github/workflows/security-review.yml`.
5. Commit and push this workflow.
6. Open a pull request to trigger first run.

### 5.2 Required GitHub workflow permissions

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write
```

Notes:

- `id-token: write` is required for managed LLM mode and OIDC-backed telemetry.
- `github_token` should be passed as `${{ secrets.GITHUB_TOKEN }}` or `${{ github.token }}`.

### 5.3 Recommended workflow (supports BYO key + managed fallback)

```yaml
name: Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Omar Gate
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
          sentinelayer_managed_llm: ${{ secrets.OPENAI_API_KEY == '' && secrets.SENTINELAYER_TOKEN != '' }}
          severity_gate: P1
          scan_mode: pr-diff
```

### 5.4 Minimal BYO OpenAI example

```yaml
name: Security Review
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Omar Gate
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          severity_gate: P1
```

### 5.5 Branch protection (required for real enforcement)

In GitHub branch protection for `main` (or target branch):

- Require pull request before merge.
- Require status checks to pass.
- Add required check: `Omar Gate`.

Without branch protection, comments still appear but merge blocking is not enforced.

---

## 6) Trigger matrix

### 6.1 Customer repository (where action is consumed)

- Trigger source: your workflow `on: pull_request` (or your selected events).
- Action trigger: workflow reaches the `uses: mrrCarter/sentinelayer-v1-action@v1` step.
- Outputs available: `gate_status`, severity counts, run/artifact paths.

Common trigger events:

- `pull_request` (opened, synchronize, reopened, ready_for_review)
- optional `push`, `schedule`, `workflow_dispatch`

### 6.2 Action repo internal workflows (`sentinellayer-v1-action/.github/workflows`)

- `security-review.yml`:
  - triggers: push (except dependabot branch pattern), pull_request (`opened`, `synchronize`, `reopened`, `ready_for_review`)
  - includes quality gates, secret scanning, then host-runner Omar review
- `deterministic-scan.yml`:
  - trigger: push (except dependabot branch pattern)
  - deterministic-only Omar run + gitleaks
- `quality-gates.yml`:
  - triggers: pull_request and push to `main`
  - lint + mypy checks + unit/integration tests

### 6.3 API repo internal workflow (`sentinelayer-api/.github/workflows`)

- `deploy_api_to_ecs.yml`:
  - triggers: push to `main` with path filters, and `workflow_dispatch`
  - builds/pushes image, registers ECS task definition, deploys, then smoke-checks endpoints

### 6.4 Web repo

- No GitHub workflows currently present in `sentinelayer-web`.

---

## 7) How to ship a feature update and open a PR

Use this process for any repo (`sentinellayer-v1-action`, `sentinelayer-api`, `sentinelayer-web`).

1. Pull latest main:
   - `git checkout main`
   - `git pull`
2. Create branch:
   - `git checkout -b feat/<short-feature-name>`
3. Implement changes.
4. Run local quality checks.
5. Commit:
   - `git add .`
   - `git commit -m "feat: <summary>"`
6. Push:
   - `git push -u origin feat/<short-feature-name>`
7. Open PR on GitHub.
8. Verify checks and artifacts.
9. Merge once required checks pass.

Suggested local checks by repo:

- Action repo (`sentinellayer-v1-action`):
  - `python -m pytest tests/unit tests/integration -q`
  - `ruff check src tests`
- API repo (`sentinelayer-api`):
  - `pytest`
  - optionally run `uvicorn src.main:app --reload` for local validation
- Web repo (`sentinelayer-web`):
  - `npm run lint`
  - `npm run test`
  - `npm run build`

If one feature spans action + api + web, open separate PRs per repo and link them in each PR description.

---

## 8) Free usage without providing an API key

There are two practical no-key paths:

### 8.1 Fully free deterministic-only mode

No `OPENAI_API_KEY`, no managed proxy required.

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    use_codex: false
    llm_failure_policy: deterministic_only
```

What you still get:

- secrets/config/pattern/harness scanning
- gate pass/block decisions
- PR comment + check run

What you do not get:

- deep LLM reasoning for business-logic vulnerabilities

### 8.2 Managed trial mode (no user OpenAI key)

Use a Sentinelayer token and OIDC permissions:

```yaml
permissions:
  id-token: write

- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    sentinelayer_managed_llm: true
```

Behavior:

- API enforces trial window and daily limits.
- When trial/budget is exhausted, API returns 402 and messaging to add BYO key.

---

## 9) Future GitHub App with all 13 personas (Model 3)

Current planning documents clearly position multi-persona execution as Model 3 (server-side), not full Model 2 container action behavior.

### 9.1 Strategic change (Model 2 -> Model 3)

Today (Model 2):

- action runs in customer runner/container
- prompts and logic are inspectable by advanced users

Planned GitHub App model:

- webhook/server-side execution under PlexAura control
- multi-persona orchestration runs in managed backend
- higher-value prompts/packs remain server-side

Result:

- better IP protection
- centralized policy/version governance
- cleaner org-level onboarding (install app once, not per-repo YAML)
- orchestration can scale beyond action time limits
- stronger governance over multi-pack analysis and HITL workflows

### 9.2 The 13 persona lineup (human-facing model)

1. Nora Kline: dependency and supply chain
2. Ethan Park: code quality and complexity
3. Priya Raman: testing and correctness
4. Samir Okafor: docs and knowledge risk
5. Jules Tanaka: frontend excellence
6. Maya Volkov: backend excellence
7. Dr. Linh Tran: data layer excellence
8. Sofia Alvarez: observability and debuggability
9. Omar Singh: CI/CD and release engineering
10. Kat Hughes: infra and IaC consistency
11. Noah Ben-David: reliability/SRE
12. Amina Chen: AI pipeline and evals
13. Nina Patel: security overlay

Implementation note:

- In `pack_assignment_rules.json`, Maya is split into backend sub-packs (`api`, `jobs`, `integrations`, and core backend) to improve routing precision.
- Current public action uses a single embedded Omar persona in Codex prompt builder. Full multi-persona assignment is roadmap/planning and not yet the active production flow.

### 9.3 Expected GitHub App behavior when complete

1. Org installs SentinelLayer GitHub App.
2. PR webhook triggers server-side orchestrator.
3. Deterministic assignment maps files/findings to persona packs.
4. Persona agents run in parallel and produce evidence bundles.
5. Cross-pack conflict resolution and escalation run.
6. One consolidated gate/check + scorecard is posted back to PR.
7. Dashboard shows per-persona findings, trends, and fix tracking.
8. HITL workflows can be launched from richer evidence sets.

### 9.4 How teams will use it

- Security and platform teams enforce one app-level policy baseline.
- Feature teams get persona-scoped remediation guidance (frontend, backend, infra, AI safety, etc.).
- Leadership gets aggregated quality/risk scorecards over time.

---

## 10) Known gaps and alignment tasks (current snapshot)

1. Web references old action slug (`mrrCarter/sentinelayer-action@v1`) while action repo is `mrrCarter/sentinelayer-v1-action@v1`.
2. Web dashboard expects repo/run detail APIs that are not fully implemented in API yet.
3. API run/artifact/deletion endpoints are still placeholders (501 responses).
4. Full 13-persona pack execution remains roadmap/model-3 work, not production-complete in this codebase state.
5. Add CI workflow to `sentinelayer-web` for lint/test/build parity.
6. Keep this guide updated whenever endpoint contracts or install flows change.

---

## 11) Practical quick-reference

Paths:

- Action engine: `sentinellayer-v1-action/src/omargate`
- API service: `sentinelayer-api/src`
- Web app: `sentinelayer-web/src`

Most important files:

- Action runtime: `sentinellayer-v1-action/src/omargate/main.py`
- Action config contract: `sentinellayer-v1-action/action.yml`
- Gate logic: `sentinellayer-v1-action/src/omargate/gate.py`
- API app wiring: `sentinelayer-api/src/main.py`
- Managed LLM route: `sentinelayer-api/src/routes/proxy_llm.py`
- Web API client: `sentinelayer-web/src/lib/api.ts`
- Web OAuth flow: `sentinelayer-web/src/lib/auth.ts`
