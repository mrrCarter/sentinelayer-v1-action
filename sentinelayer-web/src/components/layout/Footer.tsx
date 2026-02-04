import { Link } from "react-router-dom";
import { Shield } from "lucide-react";

const footerLinks = [
  { label: "Docs", href: "/docs" },
  { label: "Pricing", href: "/pricing" },
  { label: "GitHub Action", href: "https://github.com/marketplace/actions/sentinelayer" },
];

export function Footer() {
  return (
    <footer className="border-t border-border/60 bg-background">
      <div className="container flex flex-col gap-6 py-10 md:flex-row md:items-center md:justify-between">
        <Link to="/" className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-base font-semibold">Sentinelayer</span>
        </Link>

        <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
          {footerLinks.map((link) => (
            <a key={link.href} href={link.href} className="hover:text-foreground">
              {link.label}
            </a>
          ))}
        </div>

        <p className="text-xs text-muted-foreground">
          PlexAura Inc. All rights reserved.
        </p>
      </div>
    </footer>
  );
}
