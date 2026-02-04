import {
  Brain,
  Code,
  Gauge,
  GitPullRequest,
  Lock,
  Shield,
} from "lucide-react";

const features = [
  {
    icon: Brain,
    title: "Adapts to Your Codebase",
    description:
      "Uses current LLMs to understand your domain, not static rules from 2019.",
  },
  {
    icon: GitPullRequest,
    title: "PR-Native Workflow",
    description:
      "Runs on every pull request. Blocks merges when critical issues are found.",
  },
  {
    icon: Lock,
    title: "Fail-Closed Security",
    description: "If analysis fails, the gate blocks. No silent failures.",
  },
  {
    icon: Gauge,
    title: "Fast Feedback",
    description: "Results in under 60 seconds. Developers stay in flow.",
  },
  {
    icon: Code,
    title: "Any Language",
    description: "TypeScript, Python, Go, Rust, Java - LLMs understand them all.",
  },
  {
    icon: Shield,
    title: "Privacy-First Telemetry",
    description: "Tier 1 is anonymous. You control what data you share.",
  },
];

export function Features() {
  return (
    <section className="py-24">
      <div className="container space-y-12">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            Why Sentinelayer
          </p>
          <h2 className="mt-3 text-3xl font-semibold md:text-4xl">
            Stop shipping unknown security risks
          </h2>
          <p className="mt-4 text-muted-foreground">
            Sentinelayer combines deterministic scanners with model-driven reviews
            to surface what static tooling misses.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <FeatureCard key={feature.title} {...feature} />
          ))}
        </div>
      </div>
    </section>
  );
}

function FeatureCard({
  icon: Icon,
  title,
  description,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
}) {
  return (
    <div className="group relative overflow-hidden rounded-3xl border border-border/60 bg-card p-6 shadow-soft transition hover:-translate-y-1">
      <div className="absolute inset-0 opacity-0 transition group-hover:opacity-100">
        <div className="absolute -right-16 -top-16 h-40 w-40 rounded-full bg-primary/10 blur-3xl" />
      </div>
      <div className="relative space-y-4">
        <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-muted text-primary">
          <Icon className="h-6 w-6" />
        </span>
        <h3 className="text-lg font-semibold">{title}</h3>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
    </div>
  );
}
