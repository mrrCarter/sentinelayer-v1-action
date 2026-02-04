import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Footer } from "@/components/layout/Footer";
import { Header } from "@/components/layout/Header";

const tiers = [
  {
    name: "Free",
    price: "$0",
    description: "Ship safer PRs for solo maintainers and small teams.",
    features: [
      "Unlimited public repos",
      "Community policy pack",
      "Fail-closed gate",
      "Anonymous telemetry",
    ],
    cta: "Install Action",
    href: "https://github.com/marketplace/actions/sentinelayer",
    highlight: false,
  },
  {
    name: "Pro",
    price: "$49",
    description: "Advanced telemetry and org-wide insights.",
    features: [
      "Private repos + org access",
      "Custom policy packs",
      "Slack + Jira alerts",
      "SLA + priority support",
    ],
    cta: "Talk to Sales",
    href: "mailto:hello@sentinelayer.com",
    highlight: true,
  },
];

export function Pricing() {
  return (
    <div className="min-h-screen">
      <Header />
      <main className="bg-hero">
        <section className="container py-20">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Pricing
            </p>
            <h1 className="mt-3 text-4xl font-semibold md:text-5xl">
              Plans that scale with your security needs
            </h1>
            <p className="mt-4 text-muted-foreground">
              Start free and upgrade when you need deeper telemetry and custom
              policy controls.
            </p>
          </div>

          <div className="mt-14 grid gap-8 lg:grid-cols-2">
            {tiers.map((tier) => (
              <Card
                key={tier.name}
                className={tier.highlight ? "border-primary shadow-glow" : ""}
              >
                <CardHeader className="space-y-3">
                  <CardTitle className="text-2xl font-semibold">
                    {tier.name}
                  </CardTitle>
                  <p className="text-4xl font-semibold">{tier.price}</p>
                  <p className="text-sm text-muted-foreground">
                    {tier.description}
                  </p>
                </CardHeader>
                <CardContent className="space-y-6">
                  <ul className="space-y-3 text-sm text-muted-foreground">
                    {tier.features.map((feature) => (
                      <li key={feature} className="flex items-center gap-2">
                        <Check className="h-4 w-4 text-success" />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                  <Button asChild size="lg" className="w-full">
                    <a href={tier.href}>{tier.cta}</a>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
