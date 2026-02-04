# Omar Gate (Scaffold)

This is a **starter scaffold** for the Sentinelayer Model 2 GitHub Action described in
`sentinellayer_implementation_requirements_v1.2.x.md`.

✅ What's implemented (foundation):
- Deterministic run directory + artifact contract
- Idempotency key computation (`sha256`)
- Always writes `PACK_SUMMARY.json`
- Gate evaluation reads `PACK_SUMMARY.json` (**no network calls**)

🚧 What's intentionally stubbed (you will implement next):
- GitHub API publishing (PR comment + check run)
- Rate limiting, cooldown, daily caps, cost approval
- Deterministic scanners (rules) + LLM review + cost estimation
- Sentinelayer telemetry/artifact upload

## Quick start (workflow)

> Minimal copy/paste example. Branch protection is required for real enforcement.

```yaml
name: Omar Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  checks: write
  issues: write       # required for label-based cost approval
  actions: read       # required for daily cap via workflow runs
  id-token: write     # optional: enables OIDC auth to Sentinelayer (no stored token)

jobs:
  omar-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: ./
        with:
          github_token: ${{ github.token }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          # Optional: link to Sentinelayer for Tier 2/3
          # sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
          telemetry_tier: "1"
```

## Notes

- This scaffold is not production-ready. Use it to bootstrap repo structure and the
  **fail-closed artifact contract**.
- Implement rate limiting, fork policy, cost estimation/approval, PR publishing, and uploads per the requirements doc.

---

*Sentinelayer is a product of PlexAura Inc.*
