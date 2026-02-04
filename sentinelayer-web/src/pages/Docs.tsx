import { DocsLayout } from "@/pages/DocsLayout";

export function Docs() {
  return (
    <DocsLayout
      title="Sentinelayer Documentation"
      description="Everything you need to protect pull requests with AI-first security reviews."
    >
      <p>
        Sentinelayer runs inside GitHub Actions, reviewing every pull request with
        deterministic scanners and LLM-driven analysis. Use the tabs on the left
        to get installed and configure your gate.
      </p>

      <div className="rounded-2xl border border-border/60 bg-card p-6">
        <h3 className="text-base font-semibold text-foreground">What you get</h3>
        <ul className="mt-4 space-y-2">
          <li>Real-time security findings posted on PRs.</li>
          <li>Merge blocking for critical issues.</li>
          <li>Action-level telemetry for run history and trends.</li>
        </ul>
      </div>

      <div className="rounded-2xl border border-border/60 bg-muted/40 p-6">
        <h3 className="text-base font-semibold text-foreground">Next steps</h3>
        <p className="mt-2">
          Start with the install guide, then configure policy packs and gate
          thresholds based on your team risk profile.
        </p>
      </div>
    </DocsLayout>
  );
}
