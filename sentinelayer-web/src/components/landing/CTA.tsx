import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

export function CTA() {
  return (
    <section className="py-24">
      <div className="container">
        <div className="relative overflow-hidden rounded-[32px] border border-border/60 bg-gradient-to-br from-[#fff3e8] via-white to-[#e8f6f6] p-12 shadow-soft">
          <div className="absolute inset-0 bg-grid opacity-40" />
          <div className="relative flex flex-col items-start justify-between gap-8 lg:flex-row lg:items-center">
            <div className="max-w-2xl space-y-4">
              <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                Start Free
              </p>
              <h2 className="text-3xl font-semibold md:text-4xl">
                Secure every PR before it ships
              </h2>
              <p className="text-muted-foreground">
                Install the Sentinelayer Action in minutes. Upgrade when you need
                advanced telemetry, custom policy packs, and org-wide insights.
              </p>
            </div>
            <Button size="lg" asChild>
              <a href="https://github.com/marketplace/actions/sentinelayer">
                Add to GitHub
                <ArrowRight className="h-4 w-4" />
              </a>
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
}
