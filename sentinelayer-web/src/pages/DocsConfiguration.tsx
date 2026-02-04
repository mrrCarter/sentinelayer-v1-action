import { DocsLayout } from "@/pages/DocsLayout";

export function DocsConfiguration() {
  return (
    <DocsLayout
      title="Configuration"
      description="Tune the gate behavior, telemetry, and policy packs."
    >
      <p>
        Sentinelayer supports optional inputs in the workflow file to control
        telemetry tiers, rate limits, and policy behavior. The most common inputs
        are listed below.
      </p>

      <div className="rounded-2xl border border-border/60 bg-card p-6">
        <div className="grid gap-4 text-xs">
          <div className="grid grid-cols-3 font-semibold text-foreground">
            <span>Input</span>
            <span>Type</span>
            <span>Description</span>
          </div>
          <div className="grid grid-cols-3">
            <span>telemetry_tier</span>
            <span>"1" | "2" | "3"</span>
            <span>Controls data sharing and dashboard visibility.</span>
          </div>
          <div className="grid grid-cols-3">
            <span>sentinelayer_token</span>
            <span>string</span>
            <span>Connects runs to the Sentinelayer dashboard.</span>
          </div>
          <div className="grid grid-cols-3">
            <span>fail_closed</span>
            <span>boolean</span>
            <span>Blocks merge on analysis errors.</span>
          </div>
        </div>
      </div>

      <p>
        For advanced configuration, reach out to the Sentinelayer team for
        policy pack guidance and org-wide telemetry setup.
      </p>
    </DocsLayout>
  );
}
