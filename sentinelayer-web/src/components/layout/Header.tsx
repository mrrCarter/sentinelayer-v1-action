import { Link, NavLink } from "react-router-dom";
import { Shield, Menu, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";

const navLinks = [
  { label: "Docs", href: "/docs" },
  { label: "Pricing", href: "/pricing" },
  { label: "GitHub", href: "https://github.com/marketplace/actions/sentinelayer" },
];

export function Header() {
  const { user, login, logout } = useAuth();

  return (
    <header className="sticky top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur">
      <div className="container flex h-16 items-center justify-between">
        <Link to="/" className="flex items-center gap-2">
          <Shield className="h-7 w-7 text-primary" />
          <span className="font-display text-lg font-semibold">Sentinelayer</span>
        </Link>

        <nav className="hidden items-center gap-6 text-sm font-medium md:flex">
          {navLinks.map((link) =>
            link.href.startsWith("/") ? (
              <NavLink
                key={link.href}
                to={link.href}
                className={({ isActive }) =>
                  cn(
                    "text-muted-foreground transition-colors hover:text-foreground",
                    isActive && "text-foreground"
                  )
                }
              >
                {link.label}
              </NavLink>
            ) : (
              <a
                key={link.href}
                href={link.href}
                className="text-muted-foreground transition-colors hover:text-foreground"
              >
                {link.label}
              </a>
            )
          )}
        </nav>

        <div className="hidden items-center gap-3 md:flex">
          {user ? (
            <>
              <Button asChild variant="outline" size="sm">
                <Link to="/dashboard">Dashboard</Link>
              </Button>
              <Button variant="ghost" size="sm" onClick={logout}>
                <LogOut className="h-4 w-4" />
                Sign out
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={login}>
              Sign in with GitHub
            </Button>
          )}
        </div>

        <Button variant="ghost" size="icon" className="md:hidden" aria-label="Menu">
          <Menu className="h-5 w-5" />
        </Button>
      </div>
    </header>
  );
}
