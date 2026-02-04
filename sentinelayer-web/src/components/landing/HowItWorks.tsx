const steps = [
  {
    step: 1,
    title: "Add the Action",
    description: "One YAML file in your repo. 2 minutes to set up.",
    code: `- uses: mrrCarter/sentinelayer-action@v1\n  with:\n    openai_api_key: \${{ secrets.OPENAI_API_KEY }}`,
  },
  {
    step: 2,
    title: "Push Code",
    description: "Open a PR or push to a protected branch.",
    visual: "pr-created",
  },
  {
    step: 3,
    title: "Get Results",
    description: "Findings appear inline. Critical issues block the merge.",
    visual: "pr-comment",
  },
];

export function HowItWorks() {
  return (
    <section className="py-24">
      <div className="container">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            Workflow
          </p>
          <h2 className="mt-3 text-3xl font-semibold md:text-4xl">
            Three steps to safer code
          </h2>
        </div>

        <div className="mt-16 grid gap-10 lg:grid-cols-3">
          {steps.map((step) => (
            <StepCard key={step.step} {...step} />
          ))}
        </div>
      </div>
    </section>
  );
}

function StepCard({
  step,
  title,
  description,
  code,
}: {
  step: number;
  title: string;
  description: string;
  code?: string;
}) {
  return (
    <div className="relative rounded-3xl border border-border/60 bg-card p-6 shadow-soft">
      <div className="absolute -top-5 left-6 rounded-full bg-primary px-3 py-1 text-xs font-semibold uppercase tracking-widest text-primary-foreground">
        Step {step}
      </div>
      <div className="space-y-4 pt-4">
        <h3 className="text-xl font-semibold">{title}</h3>
        <p className="text-sm text-muted-foreground">{description}</p>
        {code ? (
          <pre className="rounded-2xl border border-border/60 bg-muted/60 p-4 text-xs text-foreground">
            <code>{code}</code>
          </pre>
        ) : (
          <div className="rounded-2xl border border-dashed border-border/80 bg-background/60 p-6 text-xs uppercase tracking-widest text-muted-foreground">
            Visual preview
          </div>
        )}
      </div>
    </div>
  );
}
