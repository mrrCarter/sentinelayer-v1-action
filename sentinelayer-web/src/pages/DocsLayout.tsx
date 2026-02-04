import { NavLink } from "react-router-dom";
import { Footer } from "@/components/layout/Footer";
import { Header } from "@/components/layout/Header";
import { cn } from "@/lib/utils";

const docsLinks = [
  { label: "Overview", href: "/docs" },
  { label: "Install", href: "/docs/install" },
  { label: "Configuration", href: "/docs/configuration" },
];

export function DocsLayout({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container py-12">
        <div className="grid gap-10 lg:grid-cols-[240px_1fr]">
          <aside className="space-y-3">
            <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Docs
            </p>
            <nav className="space-y-1">
              {docsLinks.map((link) => (
                <NavLink
                  key={link.href}
                  to={link.href}
                  className={({ isActive }) =>
                    cn(
                      "block rounded-2xl px-4 py-2 text-sm font-medium text-muted-foreground transition",
                      isActive && "bg-muted text-foreground"
                    )
                  }
                >
                  {link.label}
                </NavLink>
              ))}
            </nav>
          </aside>

          <section className="space-y-6">
            <div>
              <h1 className="text-3xl font-semibold md:text-4xl">{title}</h1>
              {description && (
                <p className="mt-2 text-muted-foreground">{description}</p>
              )}
            </div>
            <div className="space-y-6 text-sm text-muted-foreground">
              {children}
            </div>
          </section>
        </div>
      </main>
      <Footer />
    </div>
  );
}
