import { DocsLayout } from "@/pages/DocsLayout";

export function DocsInstall() {
  return (
    <DocsLayout
      title="Install Sentinelayer"
      description="Add the GitHub Action to your repository in minutes."
    >
      <p>
        Create a workflow file in <code>.github/workflows</code> and add the
        Sentinelayer action. Branch protection is required to enforce the gate.
      </p>

      <pre className="rounded-2xl border border-border/60 bg-card p-6 text-xs text-foreground">
        <code>{`name: Sentinelayer Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  sentinelayer:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mrrCarter/sentinelayer-action@v1
        with:
          openai_api_key: \${{ secrets.OPENAI_API_KEY }}`}</code>
      </pre>

      <p>
        Once merged, open a pull request and Sentinelayer will comment with
        findings and block the merge on critical issues.
      </p>
    </DocsLayout>
  );
}
