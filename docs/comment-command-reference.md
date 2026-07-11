# Omar Comment Command Reference

This reference documents public command behavior for PR comments without exposing proprietary orchestration internals.

## Trigger Model

- Automatic PR gate: `mrrCarter/sentinelayer-v1-action@v1` runs on pull request events and enforces `severity_gate`.
- Manual deep actions: operators post `/omar ...` comments on a PR when they want additional depth.

## Supported PR Comment Commands

| Command | Purpose | Typical use |
|---|---|---|
| `/omar baseline` | Refresh baseline context and deterministic memory map for current scope. | First run on a repo, or after major refactors. |
| `/omar deep-scan` | Run standard deep review profile for changed + related high-risk scope. | Default manual follow-up when gate blocks or risk is unclear. |
| `/omar full-depth` | Run full-depth audit profile with broader persona/domain coverage. | Release-candidate reviews, high-risk areas, or diligence runs. |
| `/omar fix-plan` | Generate remediation plan package from current findings. | After findings are confirmed and work needs to be assigned. |
| `/omar fix <finding_id>` | Dispatch a reviewed finding into a persona codegen handoff workflow. | Maintainers want a draft follow-up PR for one specific finding. |
| `/omar report` | Generate dashboard-linked report package for HITL/reviewer handoff. | Evidence export and executive/security review. |

## CLI Invocation

```bash
gh pr comment <pr-number> --body "/omar baseline"
gh pr comment <pr-number> --body "/omar deep-scan"
gh pr comment <pr-number> --body "/omar full-depth"
gh pr comment <pr-number> --body "/omar fix-plan"
gh pr comment <pr-number> --body "/omar fix crypto.md5"
gh pr comment <pr-number> --body "/omar report"
```

## Expected Outputs

- PR thread updates with command acknowledgement and outcome summary.
- Dashboard run timeline with linked artifacts.
- Artifact package for reproducibility and HITL handoff.
- For `/omar fix <finding_id>`, the optional reference workflow in
  [examples/workflows/omar-fix-comment.yml](../examples/workflows/omar-fix-comment.yml)
  verifies the commenter has write/maintain/admin permission, downloads the
  latest run-scoped `omar-gate-findings-*` artifact, and opens a draft follow-up
  PR carrying the persona codegen envelope.

## Operational Guidance

- Keep branch protection bound to Omar Gate check run for merge safety.
- Use manual comment commands for deeper investigations to avoid automatic PR noise.
- Prefer `/omar deep-scan` before `/omar full-depth` unless release policy requires full-depth.
