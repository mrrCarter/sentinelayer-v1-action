import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import {
  clearStoredToken,
  getStoredToken,
  initiateGitHubOAuth,
} from "@/lib/auth";
import type { User } from "@/types/api";
import { AuthContext } from "@/hooks/auth-context";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(() => Boolean(getStoredToken()));

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      return;
    }

    api.setToken(token);
    api
      .getMe()
      .then(setUser)
      .catch(() => {
        clearStoredToken();
        setUser(null);
      })
      .finally(() => setIsLoading(false));
  }, []);

  const login = useCallback(() => initiateGitHubOAuth(), []);
  const logout = useCallback(() => {
    clearStoredToken();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, isLoading, login, logout, setUser }),
    [user, isLoading, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
