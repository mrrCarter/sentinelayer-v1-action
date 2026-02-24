# Rollback Runbook

## Scope
This runbook covers rollback for `mrrCarter/sentinelayer-v1-action` CI and action-runtime changes.

## Trigger Conditions
- New release causes failed GitHub Action runs on customer repositories.
- Security scan false positives create merge blockage at scale.
- Regression in deterministic scan or artifact generation.

## Rollback Procedure
1. Identify the last known good tag or commit on `main`.
2. Repoint consumers to the last stable immutable action SHA.
3. Revert the broken commit(s) in `main` with `git revert` and open an emergency PR.
4. Verify `quality-gates`, `deterministic-scan`, and `security-review` pass on the revert PR.
5. Merge revert PR and publish an incident note with root cause + prevention.

## Verification Checklist
- Action resolves at previous stable SHA in a smoke test workflow.
- Omar Gate and deterministic scan return expected pass/fail behavior.
- No missing artifacts in `.sentinelayer/runs/*` output.

## Post-Rollback
- Document customer impact window.
- Track forward-fix PR with added regression tests.
