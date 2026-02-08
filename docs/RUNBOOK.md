# SentinelLayer Action Runbook

This runbook is for responders and maintainers who need to debug SentinelLayer runs quickly (including during incident response).

## Fast Triage

1. Identify the workflow run and the failing step.
2. Record the action exit code (see "Exit Codes").
3. Open the PR comment and the GitHub Check Run named `Omar Gate` (if enabled).
4. Locate run artifacts under `.sentinelayer/runs/<run_id>/` (or uploaded job artifacts if configured).
5. Decide the response: fix code, approve cost, adjust configuration, or enforce fork policy.

## Exit Codes

| Code | Meaning | Response |
|---:|---|---|
| `0` | Passed | No action required. |
| `1` | Blocked by severity gate | Fix blocking findings or adjust `severity_gate` per policy. |
| `2` | Configuration/context error | Fix missing/invalid inputs or missing GitHub context. |
| `10` | Dedupe skip | Confirm whether a re-scan is expected; if yes, change inputs that affect idempotency (or push a new commit). |
| `11` | Rate limited / cooldown | Wait, or adjust `min_scan_interval_minutes` / `max_daily_scans`. |
| `12` | Fork blocked | Use fork-safe workflow patterns or skip fork PRs. |
| `13` | Cost approval required | Add approval label, re-run via approved trigger, or raise the threshold. |

## Where Artifacts Live

Default run directory:
- `.sentinelayer/runs/<run_id>/`

Primary artifacts:
- `FINDINGS.jsonl` (machine-readable findings)
- `REVIEW_BRIEF.md` (high-level summary)
- `AUDIT_REPORT.md` (detailed report)
- `PACK_SUMMARY.json` (counts, checksums, and run metadata)

If you want artifacts preserved outside the runner, add an upload step:

```yaml
- name: Upload SentinelLayer Artifacts
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: sentinelayer-${{ steps.sentinelayer.outputs.run_id }}
    path: .sentinelayer/runs/${{ steps.sentinelayer.outputs.run_id }}
```

## Common Scenarios

### Gate blocked (exit `1`)

1. Read the PR comment summary (severity counts, top findings).
2. Open `REVIEW_BRIEF.md` and `AUDIT_REPORT.md` for full context.
3. Fix the findings and push a commit.
4. Re-run the workflow. If the run is deduped unexpectedly (exit `10`), confirm the head SHA changed.

### Dedupe skip (exit `10`)

Dedupe means the same PR head SHA and the same idempotency inputs were already analyzed successfully.

Actions:
- If you expected a different result, verify that the workflow is running on the latest commit SHA.
- If you intentionally want to force re-analysis without code changes, change an idempotency input (for example `scan_mode`, `policy_pack_version`). Do this only if you understand the operational impact.

### Rate limited / cooldown (exit `11`)

1. Check whether reruns were triggered repeatedly (manual reruns, bot retriggers).
2. Adjust rate limit settings if needed:

```yaml
with:
  min_scan_interval_minutes: 0
  max_daily_scans: 0
```

Implementation note: rate limits are enforced via Check Run history for the PR head SHA. A new commit SHA resets the counters.

### Fork blocked (exit `12`) and open source repos

Root cause:
- `pull_request` workflows do not get access to secrets on fork PRs.

Recommended responses:
- Skip forks using `if: github.event.pull_request.head.repo.fork == false`.
- If you must scan forks, use `pull_request_target` with strict workflow hardening (see `docs/EXAMPLES.md`).

### Cost approval required (exit `13`)

Typical triggers:
- Large diffs or large repositories increase context and estimated tokens.
- Lowering `require_cost_confirmation` can make approvals more frequent.

Actions:
- Add the approval label to the PR (default: `sentinelayer:approved`), or
- Switch approval policy:

```yaml
with:
  approval_mode: none
```

### PR comment or Check Run missing

Common causes:
- `github_token` not provided
- Missing workflow permissions

Recommended permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
  issues: write
```

### Gate fails closed with `PACK_SUMMARY.json` errors

Gate evaluation validates `PACK_SUMMARY.json` and the checksum of `FINDINGS.jsonl`.

Actions:
1. Confirm `.sentinelayer/runs/<run_id>/PACK_SUMMARY.json` exists.
2. Check `writer_complete` is `true`.
3. Confirm `FINDINGS.jsonl` exists and the SHA-256 matches the summary.
4. If artifacts are missing, inspect earlier stages (ingest, deterministic scan, LLM) in the job logs.

## Security and Privacy Notes

- LLM analysis sends a bounded code context to OpenAI using your `openai_api_key`.
- SentinelLayer dashboard uploads are opt-in; Tier 3 artifact uploads may include redacted snippets.
- Treat PRs from forks as untrusted. Prefer skip-forks by default unless you have a hardened `pull_request_target` workflow.

