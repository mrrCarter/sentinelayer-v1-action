# SentinelLayer Action Architecture

This document explains how the SentinelLayer GitHub Action executes, what artifacts it produces, and where the main trust boundaries are.

## Execution Model

- Packaging: Docker-based GitHub Action (`runs.using: docker` in `action.yml`).
- Runtime: Python entrypoint executes the analysis pipeline.
- Ingest helper: a Node script is used to map the codebase (file listing + basic stats).

## Pipeline Stages

The action is structured as a staged pipeline. Some stages are fail-closed (they intentionally block merges on unexpected conditions).

| Stage | Purpose | Typical Output | Failure Behavior |
|---|---|---|---|
| Config + Context | Parse inputs and GitHub event context | (in memory) | Exit `2` on invalid config/context |
| Preflight | Dedupe, fork policy, rate limits, cost approval | (in memory) | Exit `10/11/12/13` depending on outcome |
| Ingest | Build a repo map, apply `.sentinelayerignore` | Ingest stats (in memory) | Error if ingest mapping fails |
| Deterministic Scan | Run pattern/config/secret scanners | Finding list (in memory) | Non-fatal findings; scanner errors are handled best-effort |
| LLM Analysis | Build context and call OpenAI | Finding list + usage | Controlled by `llm_failure_policy` |
| Artifact Write | Write findings + reports + manifest + summary | `FINDINGS.jsonl`, `REVIEW_BRIEF.md`, `AUDIT_REPORT.md`, `ARTIFACT_MANIFEST.json`, `PACK_SUMMARY.json` | Best-effort for reports; summary is intended to be present for gating |
| Gate Evaluation | Decide pass/block from local artifacts only | Gate result | Fail-closed on missing/corrupt artifacts |
| Publish | Post PR comment + create Check Run | PR comment + Check Run annotations | Best-effort unless publish is configured strict |
| Telemetry | Optional upload to SentinelLayer API | Tier 1/2 telemetry; Tier 3 artifact upload | Best-effort; does not block gate |

## Artifact Contract (Fail-Closed)

All run artifacts are written under a deterministic run directory. Default location:
- `.sentinelayer/runs/<run_id>/`

Core contract files:
- `FINDINGS.jsonl`: JSONL findings; one object per line.
- `PACK_SUMMARY.json`: includes `writer_complete` and a SHA-256 checksum of `FINDINGS.jsonl`.

Gate evaluation reads `PACK_SUMMARY.json` and validates:
- `writer_complete` is `true`
- required fields exist
- `FINDINGS.jsonl` exists
- SHA-256 checksum matches

If any of these checks fail, the gate returns `error` and blocks (fail-closed).

## Idempotency and Dedupe

The action computes an idempotency key using stable inputs (repo, PR number, head SHA, scan mode, policy pack/version, action major version). That key is used to:
- Skip re-analysis for identical inputs (exit `10`)
- Mark Check Runs for lookup (`external_id` on the Check Run)
- Embed a short marker in PR comments to update the same comment on re-runs

## Rate Limiting and Cost Approval

Preflight checks can prevent analysis before any scanning begins:
- Rate limiting/cooldown returns exit `11`.
- Cost approval requirements return exit `13` until approved.

Implementation detail: rate limits are currently enforced using Check Run history for the PR head SHA. Pushing a new commit changes the head SHA and effectively resets the counters.

## Trust Boundaries and Data Flows

Data that can leave the GitHub runner:

- OpenAI API (required): LLM analysis sends a bounded context (diff + prioritized files) to OpenAI using `openai_api_key`.
- GitHub API (recommended): PR diff fetch, comment publishing, Check Run creation (requires `github_token` and permissions).
- SentinelLayer API (optional): telemetry and artifact uploads when enabled by tier and consent settings.

## Forks and Secrets

GitHub does not provide repository secrets to workflows triggered by fork PRs under `pull_request`.

Practical implications:
- The action requires `openai_api_key`, so it cannot run on fork PRs in a plain `pull_request` workflow.
- For open source projects, prefer skipping forks and requiring maintainer-triggered review.
- If you use `pull_request_target` to scan forks, harden your workflow to avoid executing untrusted code with secret-bearing permissions.

