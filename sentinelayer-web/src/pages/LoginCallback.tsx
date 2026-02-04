import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { handleOAuthCallback } from "@/lib/auth";
import { useAuth } from "@/hooks/useAuth";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { Button } from "@/components/ui/button";

const REDIRECT_KEY = "post_login_redirect";

export function LoginCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const { setUser } = useAuth();
  const { code, state } = useMemo(() => {
    const params = new URLSearchParams(location.search);
    return {
      code: params.get("code"),
      state: params.get("state"),
    };
  }, [location.search]);
  const [error, setError] = useState<string | null>(() =>
    code && state ? null : "Missing OAuth response. Try again."
  );

  useEffect(() => {
    if (!code || !state) return;

    handleOAuthCallback(code, state)
      .then((user) => {
        setUser(user);
        const redirectTo = sessionStorage.getItem(REDIRECT_KEY) || "/dashboard";
        sessionStorage.removeItem(REDIRECT_KEY);
        navigate(redirectTo, { replace: true });
      })
      .catch((err: Error) => {
        setError(err.message || "OAuth failed");
      });
  }, [code, state, navigate, setUser]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="rounded-3xl border border-border/60 bg-card p-8 text-center">
          <h1 className="text-2xl font-semibold">Sign-in failed</h1>
          <p className="mt-2 text-sm text-muted-foreground">{error}</p>
          <Button className="mt-6" onClick={() => navigate("/login")}>
            Back to login
          </Button>
        </div>
      </div>
    );
  }

  return <LoadingSpinner fullScreen label="Completing GitHub login" />;
}
