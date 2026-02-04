import { Link } from "react-router-dom";
import { ArrowRight, CheckCircle2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PublicStats } from "@/components/landing/Stats";

export function Hero() {
  return (
    <section className="relative overflow-hidden bg-hero">
      <div className="absolute inset-0 bg-grid opacity-60" />
      <div className="container relative py-24">
        <div className="grid items-center gap-12 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="space-y-8">
            <div className="inline-flex items-center gap-2 rounded-full border border-border/60 bg-white/70 px-4 py-2 text-xs font-semibold uppercase tracking-widest text-muted-foreground shadow-soft">
              <ShieldCheck className="h-4 w-4 text-primary" />
              AI-Driven Security Gate
            </div>

            <div className="space-y-6">
              <h1 className="text-4xl font-semibold leading-tight md:text-6xl">
                AI-Powered Security Review
                <br />
                <span className="text-gradient">For Every Pull Request</span>
              </h1>
              <p className="max-w-2xl text-lg text-muted-foreground md:text-xl">
                Sentinelayer adapts to your codebase. Not a million static rules -
                intelligent analysis that understands your domain, then blocks risky
                merges before they ship.
              </p>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <Button size="lg" asChild>
                <a href="https://github.com/marketplace/actions/sentinelayer">
                  Add to Your Repo
                  <ArrowRight className="h-4 w-4" />
                </a>
              </Button>
              <Button size="lg" variant="outline" asChild>
                <Link to="/docs">View Docs</Link>
              </Button>
            </div>

            <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
              {[
                "Runs inside GitHub Actions",
                "Fail-closed by default",
                "Works with any language",
              ].map((item) => (
                <div key={item} className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-success" />
                  <span>{item}</span>
                </div>
              ))}
            </div>

            <PublicStats className="pt-6" />
          </div>

          <div className="relative">
            <div className="absolute -left-6 -top-6 h-40 w-40 rounded-full bg-primary/20 blur-3xl" />
            <div className="absolute -bottom-10 right-0 h-40 w-40 rounded-full bg-accent/20 blur-3xl" />
            <div className="relative rounded-[32px] border border-border/60 bg-white/80 p-6 shadow-glow backdrop-blur">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                  Latest Gate
                </p>
                <span className="rounded-full bg-success/10 px-3 py-1 text-xs font-semibold text-success">
                  Passed
                </span>
              </div>
              <div className="mt-6 space-y-4">
                <div>
                  <p className="text-sm font-semibold">api/payments/charge.ts</p>
                  <p className="text-xs text-muted-foreground">
                    LLM cross-checked domain guardrails
                  </p>
                </div>
                <div className="rounded-2xl border border-border/60 bg-background/80 p-4 font-mono text-xs text-muted-foreground">
                  <p>security.review</p>
                  <p className="text-foreground">- confidence: 0.91</p>
                  <p>- policy: "pci-2025"</p>
                  <p>- findings: 0 critical</p>
                </div>
                <div className="grid grid-cols-3 gap-3 text-center">
                  {[
                    { label: "Duration", value: "38s" },
                    { label: "Tokens", value: "18k" },
                    { label: "Cost", value: "$0.42" },
                  ].map((metric) => (
                    <div key={metric.label} className="rounded-2xl bg-muted/60 p-3">
                      <p className="text-sm font-semibold">{metric.value}</p>
                      <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                        {metric.label}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
