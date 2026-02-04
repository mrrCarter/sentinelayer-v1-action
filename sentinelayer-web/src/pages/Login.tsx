import { useLocation } from "react-router-dom";
import { useState } from "react";
import { ArrowRight } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

const REDIRECT_KEY = "post_login_redirect";

export function Login() {
  const { login } = useAuth();
  const location = useLocation();
  const [error, setError] = useState<string | null>(null);

  const handleLogin = () => {
    const from =
      (location.state as { from?: { pathname?: string } })?.from?.pathname ||
      "/dashboard";
    sessionStorage.setItem(REDIRECT_KEY, from);
    try {
      login();
    } catch (err) {
      setError((err as Error).message || "Unable to start OAuth");
    }
  };

  return (
    <div className="min-h-screen">
      <Header />
      <main className="container flex min-h-[70vh] items-center justify-center py-16">
        <div className="w-full max-w-lg rounded-3xl border border-border/60 bg-card p-10 text-center shadow-soft">
          <h1 className="text-3xl font-semibold">Sign in to Sentinelayer</h1>
          <p className="mt-3 text-muted-foreground">
            Connect your GitHub account to view repo insights and run history.
          </p>
          {error && (
            <p className="mt-4 text-sm text-destructive">{error}</p>
          )}
          <Button size="lg" className="mt-8 w-full" onClick={handleLogin}>
            Continue with GitHub
            <ArrowRight className="h-4 w-4" />
          </Button>
        </div>
      </main>
      <Footer />
    </div>
  );
}
